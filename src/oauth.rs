use crate::{ApiError, ApiResult, Shared, bad, now, store};
use axum::{
    Json,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use url::Url;

pub fn digest(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes()))
}
fn equal(a: &str, b: &str) -> bool {
    bool::from(digest(a).as_bytes().ct_eq(digest(b).as_bytes()))
}
fn random() -> String {
    let mut b = [0; 32];
    getrandom::fill(&mut b).expect("OS randomness unavailable");
    URL_SAFE_NO_PAD.encode(b)
}

pub async fn metadata(State(s): State<Shared>) -> Json<Value> {
    Json(json!({
        "issuer":s.base,"authorization_endpoint":format!("{}/oauth/authorize",s.base),
        "token_endpoint":format!("{}/oauth/token",s.base),"registration_endpoint":format!("{}/oauth/register",s.base),
        "revocation_endpoint":format!("{}/oauth/revoke",s.base),
        "response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],
        "code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none","client_secret_post"],
        "revocation_endpoint_auth_methods_supported":["none","client_secret_post"],"scopes_supported":["mcp"]
    }))
}

pub async fn resource_metadata(State(s): State<Shared>) -> Json<Value> {
    Json(
        json!({"resource":format!("{}/mcp",s.base),"authorization_servers":[s.base],
        "scopes_supported":["mcp"],"bearer_methods_supported":["header"]}),
    )
}

#[derive(Deserialize)]
pub struct Registration {
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
    client_name: Option<String>,
}

pub async fn register(State(s): State<Shared>, Json(r): Json<Registration>) -> ApiResult<Response> {
    if r.redirect_uris.is_empty()
        || r.redirect_uris.len() > 5
        || r.redirect_uris.iter().any(|raw| {
            if raw.len() > 2048 {
                return true;
            }
            let Ok(u) = Url::parse(raw) else {
                return true;
            };
            // Hosted callbacks (ChatGPT, claude.ai) must be HTTPS on the default port;
            // native clients such as Claude Code use an HTTP loopback callback (RFC 8252).
            let hosted = u.scheme() == "https"
                && matches!(u.host_str(), Some("chatgpt.com" | "claude.ai"))
                && u.port().is_none();
            let loopback =
                u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1"));
            !(hosted || loopback)
                || !u.username().is_empty()
                || u.password().is_some()
                || u.fragment().is_some()
        })
    {
        return Err(bad("invalid_redirect_uri"));
    }
    let method = r
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_post");
    if !matches!(method, "none" | "client_secret_post") {
        return Err(bad("invalid_client_metadata"));
    }
    let id = random();
    let secret = (method == "client_secret_post").then(random);
    let mut db = s.db.lock().unwrap();
    let tx = db.transaction()?;
    store::cleanup(&tx)?;
    let count: u64 = tx.query_row("SELECT count(*) FROM clients", [], |r| r.get(0))?;
    if count >= 128 {
        tx.execute("DELETE FROM clients WHERE id IN (SELECT id FROM clients WHERE id NOT IN (SELECT client FROM grants) AND id NOT IN (SELECT client FROM pending) ORDER BY created LIMIT 1)", [])?;
        if tx.query_row("SELECT count(*) FROM clients", [], |r| r.get::<_, u64>(0))? >= 128 {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "client_capacity"));
        }
    }
    tx.execute(
        "INSERT INTO clients VALUES (?,?,?,?)",
        params![
            id,
            secret.as_deref().map(digest),
            serde_json::to_string(&r.redirect_uris).unwrap(),
            now()
        ],
    )?;
    tx.commit()?;
    let mut response = json!({"client_id":id,"client_id_issued_at":now(),"redirect_uris":r.redirect_uris,
        "token_endpoint_auth_method":method,"grant_types":["authorization_code","refresh_token"],"response_types":["code"]});
    if let Some(secret) = secret {
        response["client_secret"] = json!(secret);
        response["client_secret_expires_at"] = json!(0);
    }
    if let Some(name) = r.client_name {
        response["client_name"] = json!(name.chars().take(256).collect::<String>());
    }
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

fn target(s: &Shared, resource: Option<&String>) -> ApiResult<()> {
    if resource.is_some_and(|r| r != &s.base && r != &format!("{}/mcp", s.base)) {
        return Err(bad("invalid_target"));
    }
    Ok(())
}

pub async fn authorize(
    State(s): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Html<String>> {
    target(&s, q.get("resource"))?;
    if q.get("response_type").map(String::as_str) != Some("code")
        || q.get("scope").is_some_and(|s| s != "mcp")
    {
        return Err(bad("invalid_request"));
    }
    let challenge = value(&q, "code_challenge");
    if value(&q, "code_challenge_method") != "S256"
        || challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(bad("invalid_pkce"));
    }
    let db = s.db.lock().unwrap();
    store::cleanup(&db)?;
    let redirects: Option<String> = db
        .query_row(
            "SELECT redirects FROM clients WHERE id=?",
            [value(&q, "client_id")],
            |r| r.get(0),
        )
        .optional()?;
    let redirects: Vec<String> = redirects
        .and_then(|r| serde_json::from_str(&r).ok())
        .ok_or(bad("invalid_client"))?;
    if !redirects.iter().any(|u| u == value(&q, "redirect_uri")) {
        return Err(bad("invalid_redirect_uri"));
    }
    if db.query_row("SELECT count(*) FROM pending", [], |r| r.get::<_, u64>(0))? >= 256 {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "authorization_capacity",
        ));
    }
    let code = random();
    let csrf = random();
    db.execute("INSERT INTO pending (code,csrf,client,redirect,challenge,state,expires) VALUES (?,?,?,?,?,?,?)",
        params![digest(&code),digest(&csrf),value(&q,"client_id"),value(&q,"redirect_uri"),challenge,value(&q,"state"),now()+600])?;
    Ok(Html(page(&code, &csrf, "")))
}

fn page(code: &str, csrf: &str, error: &str) -> String {
    // Only generated base64url identifiers and fixed server messages enter this template.
    format!(
        r#"<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dokploy verbinden</title><style>body{{font:16px system-ui;background:#101a18;color:#f4f6f5;max-width:400px;margin:12vh auto;padding:24px}}h1{{font-size:30px}}p{{color:#bdccc4}}input,button{{box-sizing:border-box;width:100%;padding:14px;margin:8px 0;border-radius:10px;border:1px solid #4c6158;font:inherit}}button{{background:#c4efcf;color:#13251b;cursor:pointer}}small{{color:#f4ba9e}}</style><h1>Dokploy verbinden</h1><p>ChatGPT erhält Zugriff auf deine Dokploy-Werkzeuge.</p><form method="post" action="/oauth/approve"><input type="hidden" name="code" value="{code}"><input type="hidden" name="csrf" value="{csrf}"><label for="password">Passwort</label><input id="password" name="password" type="password" required autofocus autocomplete="current-password"><small>{error}</small><button>Zugriff erlauben</button></form></html>"#
    )
}

pub async fn approve(
    State(s): State<Shared>,
    Form(f): Form<HashMap<String, String>>,
) -> ApiResult<Response> {
    let code = value(&f, "code");
    let db = s.db.lock().unwrap();
    let row: Option<(String, String, bool)> = db
        .query_row(
            "SELECT csrf,redirect,approved FROM pending WHERE code=? AND expires>?",
            params![digest(code), now()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (csrf, redirect, approved) = row.ok_or(bad("invalid_request"))?;
    if approved || !equal(&digest(value(&f, "csrf")), &csrf) {
        return Err(ApiError(StatusCode::FORBIDDEN, "invalid_csrf"));
    }
    let (failures, locks, until): (u32, u32, u64) = db.query_row(
        "SELECT failures,locks,until FROM login WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if now() < until {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            Html(page(
                code,
                value(&f, "csrf"),
                "Zu viele Versuche. Bitte später erneut versuchen.",
            )),
        )
            .into_response());
    }
    if !equal(&digest(value(&f, "password")), &s.password_hash) {
        let failures = failures + 1;
        let locks = if failures >= 5 {
            (locks + 1).min(10)
        } else {
            locks
        };
        let until = if failures >= 5 {
            now() + 5 * 2u64.pow(locks - 1)
        } else {
            0
        };
        db.execute(
            "UPDATE login SET failures=?, locks=?, until=? WHERE id=1",
            params![failures, locks, until],
        )?;
        let csrf = random();
        db.execute(
            "UPDATE pending SET csrf=? WHERE code=?",
            params![digest(&csrf), digest(code)],
        )?;
        return Ok((
            StatusCode::UNAUTHORIZED,
            Html(page(code, &csrf, "Falsches Passwort.")),
        )
            .into_response());
    }
    db.execute("UPDATE login SET failures=0,locks=0,until=0 WHERE id=1", [])?;
    db.execute("UPDATE pending SET approved=1 WHERE code=?", [digest(code)])?;
    let state: String = db.query_row(
        "SELECT state FROM pending WHERE code=?",
        [digest(code)],
        |r| r.get(0),
    )?;
    let mut uri = Url::parse(&redirect).map_err(|_| bad("invalid_redirect_uri"))?;
    uri.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", &state);
    Ok(Redirect::to(uri.as_str()).into_response())
}

fn value<'a>(map: &'a HashMap<String, String>, key: &str) -> &'a str {
    map.get(key).map(String::as_str).unwrap_or("")
}

fn client(db: &Connection, f: &HashMap<String, String>) -> ApiResult<()> {
    let secret: Option<Option<String>> = db
        .query_row(
            "SELECT secret FROM clients WHERE id=?",
            [value(f, "client_id")],
            |r| r.get(0),
        )
        .optional()?;
    match secret {
        Some(None) => Ok(()),
        Some(Some(hash)) if equal(&digest(value(f, "client_secret")), &hash) => Ok(()),
        _ => Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_client")),
    }
}

/// Refresh tokens stay valid for 90 days after their last use.
const REFRESH_TTL: u64 = 90 * 24 * 3600;

pub async fn token(
    State(s): State<Shared>,
    Form(f): Form<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    target(&s, f.get("resource"))?;
    if f.get("scope").is_some_and(|v| v != "mcp") {
        return Err(bad("invalid_scope"));
    }
    let mut db = s.db.lock().unwrap();
    let tx = db.transaction()?;
    store::cleanup(&tx)?;
    client(&tx, &f)?;
    let client_id = value(&f, "client_id");
    let refresh_expires = match value(&f, "grant_type") {
        "authorization_code" => {
            let row: Option<(String,String,String,bool)> = tx.query_row("SELECT client,redirect,challenge,approved FROM pending WHERE code=? AND expires>?",
                params![digest(value(&f,"code")),now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            let (owner, redirect, challenge, approved) = row.ok_or(bad("invalid_grant"))?;
            let verifier = value(&f, "code_verifier");
            if !approved
                || owner != client_id
                || redirect != value(&f, "redirect_uri")
                || !(43..=128).contains(&verifier.len())
                || !verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                || !equal(&digest(verifier), &challenge)
            {
                return Err(bad("invalid_grant"));
            }
            tx.execute(
                "DELETE FROM pending WHERE code=?",
                [digest(value(&f, "code"))],
            )?;
            now() + REFRESH_TTL
        }
        "refresh_token" => {
            let expiry: Option<u64> = tx.query_row("SELECT refresh_expires FROM grants WHERE refresh=? AND client=? AND refresh_expires>?",
                params![digest(value(&f,"refresh_token")),client_id,now()],|r|r.get(0)).optional()?;
            expiry.ok_or(bad("invalid_grant"))?;
            tx.execute(
                "DELETE FROM grants WHERE refresh=?",
                [digest(value(&f, "refresh_token"))],
            )?;
            // Sliding window: each refresh keeps an actively used sign-in alive.
            now() + REFRESH_TTL
        }
        _ => return Err(bad("unsupported_grant_type")),
    };
    if tx.query_row(
        "SELECT count(*) FROM grants WHERE client=?",
        [client_id],
        |r| r.get::<_, u64>(0),
    )? >= 16
    {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "token_capacity"));
    }
    let access = random();
    let refresh = random();
    tx.execute(
        "INSERT INTO grants VALUES (?,?,?,?,?)",
        params![
            digest(&access),
            digest(&refresh),
            client_id,
            now() + 3600,
            refresh_expires
        ],
    )?;
    tx.commit()?;
    Ok(Json(
        json!({"access_token":access,"refresh_token":refresh,"token_type":"Bearer","expires_in":3600,"scope":"mcp"}),
    ))
}

pub async fn revoke(
    State(s): State<Shared>,
    Form(f): Form<HashMap<String, String>>,
) -> ApiResult<StatusCode> {
    let db = s.db.lock().unwrap();
    client(&db, &f)?;
    let token = digest(value(&f, "token"));
    db.execute(
        "DELETE FROM grants WHERE client=? AND (access=? OR refresh=?)",
        params![value(&f, "client_id"), token, token],
    )?;
    Ok(StatusCode::OK)
}

pub fn authenticated(s: &Shared, h: &HeaderMap) -> ApiResult<()> {
    let token = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let valid = if let Some(token) = token {
        let db = s.db.lock().unwrap();
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM grants WHERE access=? AND expires>?)",
            params![digest(token), now()],
            |r| r.get::<_, bool>(0),
        )?
    } else {
        false
    };
    if valid {
        Ok(())
    } else {
        Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}
