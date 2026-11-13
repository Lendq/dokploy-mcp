mod mcp;
mod oauth;
mod store;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use tower_http::cors::CorsLayer;
use url::Url;

pub struct Config {
    pub base_url: String,
    pub dokploy_url: String,
    pub api_key: String,
    pub password: String,
    pub database_path: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            base_url: std::env::var("BASE_URL")?,
            dokploy_url: std::env::var("DOKPLOY_URL")?,
            api_key: std::env::var("DOKPLOY_API_KEY")?,
            password: std::env::var("MCP_LOGIN_PASSWORD")?,
            database_path: std::env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "/data/oauth.sqlite".into())
                .into(),
        })
    }
}

struct AppState {
    base: String,
    host: String,
    upstream: String,
    password_hash: String,
    db: Mutex<rusqlite::Connection>,
    http: reqwest::Client,
    catalog: mcp::Catalog,
    rates: Mutex<HashMap<String, (u64, u32)>>,
    requests: Semaphore,
}

type Shared = Arc<AppState>;
type ApiResult<T> = Result<T, ApiError>;

struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        eprintln!("OAuth storage operation failed");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "storage_unavailable")
    }
}

fn bad(message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn https_url(raw: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let u = Url::parse(raw)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err(
            "URLs must be HTTPS origins without credentials, paths, queries or fragments".into(),
        );
    }
    Ok(u)
}

pub fn app(config: Config) -> Result<Router, Box<dyn std::error::Error>> {
    let base = https_url(&config.base_url)?;
    let upstream = https_url(&config.dokploy_url)?;
    if config.password.len() < 32 || config.api_key.is_empty() {
        return Err("A password of at least 32 bytes and a Dokploy API key are required".into());
    }
    let mut headers = reqwest::header::HeaderMap::new();
    let mut key = HeaderValue::from_str(&config.api_key)?;
    key.set_sensitive(true);
    headers.insert("x-api-key", key);
    let state = Arc::new(AppState {
        host: base[url::Position::BeforeHost..url::Position::AfterPort].into(),
        base: base.as_str().trim_end_matches('/').into(),
        upstream: format!("{}api", upstream.as_str()),
        password_hash: oauth::digest(&config.password),
        db: Mutex::new(store::open(&config.database_path)?),
        http: reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(2)
            .build()?,
        catalog: mcp::Catalog::load()?,
        rates: Mutex::new(HashMap::new()),
        requests: Semaphore::new(4),
    });
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_str(&state.base)?,
            HeaderValue::from_static("https://chatgpt.com"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::HeaderName::from_static("mcp-protocol-version"),
        ]);
    let endpoint = post(mcp::handle)
        .get(mcp::unsupported)
        .delete(mcp::unsupported);
    Ok(Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth::resource_metadata),
        )
        .route("/oauth/register", post(oauth::register))
        .route("/oauth/authorize", get(oauth::authorize))
        .route("/oauth/approve", post(oauth::approve))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
        .route("/", endpoint.clone())
        .route("/mcp", endpoint)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), security))
        .layer(cors)
        .with_state(state))
}

async fn security(State(s): State<Shared>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path != "/health"
        && req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(&s.host)
    {
        return bad("invalid_host").into_response();
    }
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    if origin.is_some_and(|v| v != s.base && v != "https://chatgpt.com")
        || (path == "/oauth/approve" && origin != Some(&s.base))
    {
        return ApiError(StatusCode::FORBIDDEN, "invalid_origin").into_response();
    }
    let Ok(_permit) = s.requests.try_acquire() else {
        return ApiError(StatusCode::TOO_MANY_REQUESTS, "server_busy").into_response();
    };
    if matches!(
        path,
        "/oauth/register"
            | "/oauth/authorize"
            | "/oauth/token"
            | "/oauth/approve"
            | "/oauth/revoke"
    ) {
        let mut rates = s.rates.lock().unwrap();
        let slot = rates.entry(path.into()).or_insert((now(), 0));
        if now() >= slot.0 + 60 {
            *slot = (now(), 0);
        }
        slot.1 += 1;
        if slot.1 > 60 {
            let mut response =
                ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            return response;
        }
    }
    let mut response = match tokio::time::timeout(Duration::from_secs(95), next.run(req)).await {
        Ok(r) => r,
        Err(_) => ApiError(StatusCode::GATEWAY_TIMEOUT, "request_timeout").into_response(),
    };
    for (key, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "same-origin"),
        ("strict-transport-security", "max-age=31536000"),
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com https://claude.ai http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'",
        ),
    ] {
        response.headers_mut().insert(
            header::HeaderName::from_static(key),
            HeaderValue::from_static(value),
        );
    }
    response
}
