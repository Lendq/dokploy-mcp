use crate::{ApiError, Shared, oauth};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Deserialize)]
struct Definition {
    name: String,
    description: String,
    method: String,
    path: String,
    #[serde(rename = "inputSchema")]
    schema: Value,
    annotations: Value,
}

struct Tool {
    method: reqwest::Method,
    path: String,
}

pub struct Catalog {
    tools: HashMap<String, Tool>,
    listing: Value,
}

impl Catalog {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let definitions: Vec<Definition> = serde_json::from_str(include_str!("../tools.json"))?;
        let mut tools = HashMap::new();
        let mut listing = Vec::new();
        for d in definitions {
            let readonly = d.method == "GET";
            let mut annotations = d.annotations;
            annotations["readOnlyHint"] = json!(readonly);
            annotations["destructiveHint"] = json!(!readonly);
            annotations["openWorldHint"] = json!(true);
            let security = json!([{"type":"oauth2","scopes":["mcp"]}]);
            listing.push(json!({"name":d.name,"description":d.description,"inputSchema":d.schema,
                "annotations":annotations,"securitySchemes":security,"_meta":{"securitySchemes":security}}));
            tools.insert(
                d.name,
                Tool {
                    method: d.method.parse()?,
                    path: d.path,
                },
            );
        }
        Ok(Self {
            tools,
            listing: json!({"tools":listing}),
        })
    }
}

fn authenticate(s: &Shared, h: &HeaderMap) -> Option<Response> {
    oauth::authenticated(s,h).err().map(|e| {
        let mut r = e.into_response();
        if r.status() == StatusCode::UNAUTHORIZED {
            r.headers_mut().insert(header::WWW_AUTHENTICATE,HeaderValue::from_str(&format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"mcp\"",s.base)).unwrap());
        }
        r
    })
}

pub async fn unsupported(State(s): State<Shared>, h: HeaderMap) -> Response {
    if let Some(r) = authenticate(&s, &h) {
        return r;
    }
    let mut r = StatusCode::METHOD_NOT_ALLOWED.into_response();
    r.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("POST"));
    r
}

fn rpc_error(id: Value, code: i32, message: &str) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})).into_response()
}

pub async fn handle(State(s): State<Shared>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if let Some(r) = authenticate(&s, &h) {
        return r;
    }
    if h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next() != Some("application/json"))
    {
        return ApiError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required").into_response();
    }
    let accept = h
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !accept.contains("application/json") || !accept.contains("text/event-stream") {
        return ApiError(StatusCode::NOT_ACCEPTABLE, "accept_json_and_event_stream")
            .into_response();
    }
    let Ok(m): Result<Value, _> = serde_json::from_slice(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            rpc_error(Value::Null, -32700, "Parse error"),
        )
            .into_response();
    };
    let id = m.get("id").cloned().unwrap_or(Value::Null);
    if !m.is_object()
        || m["jsonrpc"] != "2.0"
        || !m["method"].is_string()
        || m.get("id")
            .is_some_and(|v| !v.is_string() && !v.is_i64() && !v.is_u64())
        || m.get("params").is_some_and(|v| !v.is_object())
    {
        return (
            StatusCode::BAD_REQUEST,
            rpc_error(Value::Null, -32600, "Invalid Request"),
        )
            .into_response();
    }
    let method = m["method"].as_str().unwrap();
    let versions = ["2025-11-25", "2025-06-18", "2025-03-26"];
    if h.get("mcp-protocol-version")
        .is_some_and(|v| !versions.contains(&v.to_str().unwrap_or("")))
    {
        return ApiError(StatusCode::BAD_REQUEST, "unsupported_protocol_version").into_response();
    }
    if m.get("id").is_none() {
        // Stateless execution has no server notifications or pending client requests.
        return if method.starts_with("notifications/") {
            StatusCode::ACCEPTED.into_response()
        } else {
            (
                StatusCode::BAD_REQUEST,
                rpc_error(Value::Null, -32600, "Request ID required"),
            )
                .into_response()
        };
    }
    let params = &m["params"];
    let result = match method {
        "initialize" => {
            let Some(requested) = params["protocolVersion"].as_str() else {
                return rpc_error(id, -32602, "protocolVersion required");
            };
            if !params["capabilities"].is_object() || !params["clientInfo"].is_object() {
                return rpc_error(id, -32602, "capabilities and clientInfo required");
            }
            json!({"protocolVersion":if versions.contains(&requested) {requested} else {versions[0]},
                "capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"dokploy","version":env!("CARGO_PKG_VERSION")},
                "instructions":"Manage Dokploy projects and deployments. Read configuration before editing, preserve secrets, and delete resources only when explicitly requested by the user."})
        }
        "ping" => json!({}),
        "tools/list" => {
            if params.get("cursor").is_some() {
                return rpc_error(id, -32602, "Invalid cursor");
            }
            s.catalog.listing.clone()
        }
        "tools/call" => {
            let Some(name) = params["name"].as_str() else {
                return rpc_error(id, -32602, "Tool name required");
            };
            let Some(tool) = s.catalog.tools.get(name) else {
                return rpc_error(id, -32602, "Unknown tool");
            };
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            // Dokploy validates tool-specific constraints against its own API schema.
            if !arguments.is_object() {
                return rpc_error(id, -32602, "Invalid tool arguments");
            }
            match execute(&s, tool, arguments).await {
                Ok(data) => {
                    json!({"content":[{"type":"text","text":serde_json::to_string(&json!({"success":true,"data":data})).unwrap()}]})
                }
                Err(message) => json!({"isError":true,"content":[{"type":"text","text":message}]}),
            }
        }
        _ => return rpc_error(id, -32601, "Method not found"),
    };
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}

async fn execute(s: &Shared, t: &Tool, arguments: Value) -> Result<Value, String> {
    // The URL and method come exclusively from the bundled, reviewed catalog.
    let mut request = s
        .http
        .request(t.method.clone(), format!("{}{}", s.upstream, t.path));
    if t.method == reqwest::Method::GET {
        let query: Vec<(String, String)> = arguments
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect();
        request = request.query(&query);
    } else {
        request = request.json(&arguments);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| "Dokploy request failed or timed out".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Dokploy returned HTTP {}",
            response.status().as_u16()
        ));
    }
    const MAX: usize = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Dokploy response interrupted")?
    {
        if bytes.len() + chunk.len() > MAX {
            return Err("Dokploy response exceeds 4 MiB; request fewer records".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    let mut data: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Dokploy returned invalid JSON")?;
    redact(&mut data);
    Ok(data)
}

fn redact(v: &mut Value) {
    const FIELDS: &[&str] = &[
        "env",
        "buildargs",
        "composefile",
        "dockercompose",
        "environment",
        "buildsecrets",
        "previewbuildsecrets",
        "password",
        "token",
        "secret",
        "apikey",
        "secretaccesskey",
        "accesskey",
        "licensekey",
        "userkey",
        "privatekey",
        "privatekeypass",
        "encprivatekeypass",
        "sshkey",
        "sshprivatekey",
        "customgitsshkey",
        "dockerauth",
    ];
    match v {
        Value::Array(a) => a.iter_mut().for_each(redact),
        Value::Object(o) => {
            for (k, v) in o.iter_mut() {
                let key: String = k
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                if FIELDS.iter().any(|field| key.ends_with(field)) && !v.is_null() {
                    *v = json!("[REDACTED]");
                } else {
                    redact(v);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_and_nested_redaction() {
        let catalog = Catalog::load().unwrap();
        assert_eq!(catalog.tools.len(), 100);
        let mut data = json!({"name":"safe","items":[{"DOKPLOY_API_KEY":"secret","password":null,"previewEnv":"private","nested":{"refresh_token":"secret"}}]});
        redact(&mut data);
        assert_eq!(
            data,
            json!({"name":"safe","items":[{"DOKPLOY_API_KEY":"[REDACTED]","password":null,"previewEnv":"[REDACTED]","nested":{"refresh_token":"[REDACTED]"}}]})
        );
    }
}
