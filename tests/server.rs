use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dokploy_mcp::{Config, app};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

const BASE: &str = "https://mcp.example.com";
const PASSWORD: &str = "integration-password-with-at-least-32-characters";
const REDIRECT: &str = "https://chatgpt.com/connector_platform/oauth/callback";
const VERIFIER: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH";

fn router(dir: &TempDir) -> Router {
    app(Config {
        base_url: BASE.into(),
        dokploy_url: "https://dokploy.example.com".into(),
        api_key: "test-api-key".into(),
        password: PASSWORD.into(),
        database_path: dir.path().join("oauth.sqlite"),
    })
    .unwrap()
}

async fn request(
    r: &Router,
    method: &str,
    path: &str,
    body: String,
    token: Option<&str>,
    origin: Option<&str>,
) -> Response {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mcp.example.com")
        .header(
            "content-type",
            if path == "/oauth/register" || path == "/mcp" || path == "/" {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            },
        )
        .header("accept", "application/json, text/event-stream");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(origin) = origin {
        req = req.header("origin", origin);
    }
    r.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn json_response(res: Response, status: StatusCode) -> Value {
    assert_eq!(res.status(), status);
    serde_json::from_slice(&to_bytes(res.into_body(), 8 * 1024 * 1024).await.unwrap()).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
fn hidden(html: &str, name: &str) -> String {
    html.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}

async fn register(r: &Router, confidential: bool) -> Value {
    json_response(request(r,"POST","/oauth/register",json!({"redirect_uris":[REDIRECT],"token_endpoint_auth_method":if confidential {"client_secret_post"} else {"none"}}).to_string(),None,None).await,StatusCode::CREATED).await
}

async fn authorize(r: &Router, c: &Value) -> (String, String) {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER));
    let path = format!(
        "/oauth/authorize?{}",
        form(&[
            ("response_type", "code"),
            ("client_id", c["client_id"].as_str().unwrap()),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", "original-state"),
            ("resource", &format!("{BASE}/mcp"))
        ])
    );
    let res = request(r, "GET", &path, String::new(), None, None).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = String::from_utf8(to_bytes(res.into_body(), 65536).await.unwrap().to_vec()).unwrap();
    (hidden(&html, "code"), hidden(&html, "csrf"))
}

async fn exchange(r: &Router, c: &Value, code: &str, verifier: &str) -> Response {
    request(
        r,
        "POST",
        "/oauth/token",
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", c["client_id"].as_str().unwrap()),
            ("client_secret", c["client_secret"].as_str().unwrap_or("")),
            ("redirect_uri", REDIRECT),
            ("code", code),
            ("code_verifier", verifier),
        ]),
        None,
        None,
    )
    .await
}

async fn approved(r: &Router, c: &Value) -> (String, String) {
    let (code, csrf) = authorize(r, c).await;
    let res = request(
        r,
        "POST",
        "/oauth/approve",
        form(&[("code", &code), ("csrf", &csrf), ("password", PASSWORD)]),
        None,
        Some(BASE),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let redirect = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(
        redirect
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "original-state")
    );
    (code, csrf)
}

async fn rpc(r: &Router, token: &str, m: Value) -> Response {
    request(r, "POST", "/mcp", m.to_string(), Some(token), None).await
}

#[tokio::test]
async fn oauth_password_pkce_refresh_restart_and_revocation() {
    let dir = TempDir::new().unwrap();
    let r = router(&dir);
    let c = register(&r, true).await;
    let (code, csrf) = authorize(&r, &c).await;
    assert_eq!(
        exchange(&r, &c, &code, VERIFIER).await.status(),
        StatusCode::BAD_REQUEST,
        "cannot redeem before password approval"
    );
    let f = form(&[("code", &code), ("csrf", &csrf), ("password", PASSWORD)]);
    assert_eq!(
        request(&r, "POST", "/oauth/approve", f.clone(), None, None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&r, "POST", "/oauth/approve", f.clone(), None, Some(BASE))
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        request(&r, "POST", "/oauth/approve", f, None, Some(BASE))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        exchange(&r, &c, &code, "wrong-verifier").await.status(),
        StatusCode::BAD_REQUEST
    );
    let other = register(&r, false).await;
    assert_eq!(
        exchange(&r, &other, &code, VERIFIER).await.status(),
        StatusCode::BAD_REQUEST
    );
    let t = json_response(exchange(&r, &c, &code, VERIFIER).await, StatusCode::OK).await;
    assert_eq!(
        exchange(&r, &c, &code, VERIFIER).await.status(),
        StatusCode::BAD_REQUEST,
        "code must be single use"
    );
    let access = t["access_token"].as_str().unwrap();
    let refresh = t["refresh_token"].as_str().unwrap();
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    assert_eq!(rpc(&r, access, ping.clone()).await.status(), StatusCode::OK);
    let db = rusqlite::Connection::open(dir.path().join("oauth.sqlite")).unwrap();
    let stored: (String, String) = db
        .query_row("SELECT access,refresh FROM grants", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_ne!(stored.0, access);
    assert_ne!(stored.1, refresh);
    drop(db);
    drop(r);
    let r = router(&dir);
    assert_eq!(
        rpc(&r, access, ping.clone()).await.status(),
        StatusCode::OK,
        "token persists across restart"
    );
    let f = form(&[
        ("grant_type", "refresh_token"),
        ("client_id", c["client_id"].as_str().unwrap()),
        ("client_secret", c["client_secret"].as_str().unwrap()),
        ("refresh_token", refresh),
    ]);
    let renewed = json_response(
        request(&r, "POST", "/oauth/token", f.clone(), None, None).await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        request(&r, "POST", "/oauth/token", f, None, None)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        rpc(&r, access, ping.clone()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let access = renewed["access_token"].as_str().unwrap();
    assert_eq!(rpc(&r, access, ping.clone()).await.status(), StatusCode::OK);
    assert_eq!(
        request(
            &r,
            "POST",
            "/oauth/revoke",
            form(&[
                ("client_id", c["client_id"].as_str().unwrap()),
                ("client_secret", c["client_secret"].as_str().unwrap()),
                ("token", access)
            ]),
            None,
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        rpc(&r, access, ping).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn root_endpoint_discovers_tools_with_an_existing_oauth_grant() {
    let dir = TempDir::new().unwrap();
    let r = router(&dir);
    assert_eq!(
        request(&r, "POST", "/", "{}".into(), None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let c = register(&r, false).await;
    let (code, _) = approved(&r, &c).await;
    let t = json_response(exchange(&r, &c, &code, VERIFIER).await, StatusCode::OK).await;
    let access = t["access_token"].as_str().unwrap();
    let initialized = json_response(
        request(
            &r,
            "POST",
            "/",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2026-07-28","capabilities":{},
            "clientInfo":{"name":"test","version":"1"}}})
            .to_string(),
            Some(access),
            None,
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    let tools = json_response(
        request(
            &r,
            "POST",
            "/",
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list",
            "params":{}})
            .to_string(),
            Some(access),
            None,
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 100);
    assert_eq!(
        request(&r, "GET", "/", String::new(), Some(access), None)
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn stateless_mcp_catalog_validation_and_errors() {
    let dir = TempDir::new().unwrap();
    let r = router(&dir);
    let c = register(&r, false).await;
    let (code, _) = approved(&r, &c).await;
    let t = json_response(exchange(&r, &c, &code, VERIFIER).await, StatusCode::OK).await;
    let access = t["access_token"].as_str().unwrap();
    for id in 0..20 {
        let res = rpc(&r,access,json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).await;
        assert!(res.headers().get("mcp-session-id").is_none());
        let result = json_response(res, StatusCode::OK).await;
        assert_eq!(result["result"]["protocolVersion"], "2025-11-25");
    }
    let tools = json_response(
        rpc(
            &r,
            access,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 100);
    for tool in tools["result"]["tools"].as_array().unwrap() {
        assert_eq!(tool["securitySchemes"][0]["scopes"], json!(["mcp"]));
    }
    let result = json_response(rpc(&r,access,json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"application-create","arguments":[]}})).await,StatusCode::OK).await;
    assert_eq!(result["error"]["code"], -32602);
    assert_eq!(
        rpc(
            &r,
            access,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        request(&r, "GET", "/mcp", String::new(), Some(access), None)
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        request(&r, "DELETE", "/mcp", String::new(), Some(access), None)
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    let malformed =
        json_response(rpc(&r, access, json!([{}])).await, StatusCode::BAD_REQUEST).await;
    assert_eq!(malformed["error"]["code"], -32600);
    let unknown = json_response(
        rpc(
            &r,
            access,
            json!({"jsonrpc":"2.0","id":"x","method":"unknown"}),
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(unknown["error"]["code"], -32601);
}

#[tokio::test]
async fn discovery_origin_redirect_limits_and_expiration() {
    let dir = TempDir::new().unwrap();
    let r = router(&dir);
    let res = request(&r, "POST", "/mcp", "{}".into(), None, None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("/.well-known/oauth-protected-resource/mcp")
    );
    assert_eq!(
        request(
            &r,
            "GET",
            "/oauth/authorize",
            String::new(),
            None,
            Some("https://evil.example")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    for uri in [
        "https://evil.example/callback",
        "http://chatgpt.com/callback",
        "https://chatgpt.com@evil.example/",
        "https://chatgpt.com/callback#fragment",
    ] {
        assert_eq!(
            request(
                &r,
                "POST",
                "/oauth/register",
                json!({"redirect_uris":[uri]}).to_string(),
                None,
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let metadata = json_response(
        request(
            &r,
            "GET",
            "/.well-known/oauth-protected-resource/mcp",
            String::new(),
            None,
            None,
        )
        .await,
        StatusCode::OK,
    )
    .await;
    assert_eq!(metadata["resource"], format!("{BASE}/mcp"));
    let c = register(&r, false).await;
    let (code, _) = approved(&r, &c).await;
    let t = json_response(exchange(&r, &c, &code, VERIFIER).await, StatusCode::OK).await;
    let db = rusqlite::Connection::open(dir.path().join("oauth.sqlite")).unwrap();
    db.execute("UPDATE grants SET expires=0", []).unwrap();
    assert_eq!(
        rpc(
            &r,
            t["access_token"].as_str().unwrap(),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"})
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let invalid_host = Request::builder()
        .uri("/.well-known/oauth-authorization-server")
        .header("host", "evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        r.clone().oneshot(invalid_host).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&r, "POST", "/mcp", "x".repeat(1024 * 1024 + 1), None, None)
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn wrong_password_rotates_csrf_and_lockout_survives_restart() {
    let dir = TempDir::new().unwrap();
    let r = router(&dir);
    let c = register(&r, false).await;
    let (code, mut csrf) = authorize(&r, &c).await;
    for _ in 0..5 {
        let res = request(
            &r,
            "POST",
            "/oauth/approve",
            form(&[("code", &code), ("csrf", &csrf), ("password", "wrong")]),
            None,
            Some(BASE),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let html =
            String::from_utf8(to_bytes(res.into_body(), 65536).await.unwrap().to_vec()).unwrap();
        let new_csrf = hidden(&html, "csrf");
        assert_ne!(csrf, new_csrf);
        csrf = new_csrf;
    }
    drop(r);
    let r = router(&dir);
    assert_eq!(
        request(
            &r,
            "POST",
            "/oauth/approve",
            form(&[("code", &code), ("csrf", &csrf), ("password", PASSWORD)]),
            None,
            Some(BASE)
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}
