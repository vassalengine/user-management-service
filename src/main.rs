use axum::{
    Router, serve,
    body::Body,
    extract::{ConnectInfo, Request},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post}
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use std::{
    fs,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    timeout::TimeoutLayer,
    trace::{DefaultOnFailure, DefaultOnResponse, MakeSpan, TraceLayer}
};
use tracing::{error, info, info_span, Level, Span};
use tracing_panic::panic_hook;
use tracing_subscriber::{
    EnvFilter,
    layer::SubscriberExt,
    util::SubscriberInitExt
};

mod app;
mod auth_provider;
mod core;
mod db;
mod discourse;
mod extractors;
mod errors;
mod handlers;
mod jwt;
mod model;
mod prod_core;
mod search;
mod signature;
mod sqlite;

use crate::{
    app::{AppState, DiscourseUpdateConfig},
    core::CoreArc,
    discourse::login::DiscourseAuth,
    errors::AppError,
    jwt::EncodingKey,
    prod_core::ProdCore,
    sqlite::SqlxDatabaseClient
};

impl From<&AppError> for StatusCode {
    fn from(err: &AppError) -> Self {
        match err {
            AppError::BadMimeType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::MalformedQuery => StatusCode::BAD_REQUEST,
            AppError::RequestError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::JTWError(_) => StatusCode::UNAUTHORIZED,
            AppError::SsoError(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct HttpError {
    error: String
}

impl From<AppError> for HttpError {
    fn from(err: AppError) -> Self {
        HttpError { error: format!("{}", err) }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = StatusCode::from(&self);
        let body = Json(HttpError::from(self));
        (code, body).into_response()
    }
}

fn real_addr(request: &Request) -> String {
    // If we're behind a proxy, get IP from X-Forwarded-For header
    match request.headers().get("x-forwarded-for") {
        Some(addr) => addr.to_str()
            .map(String::from)
            .ok(),
        None => request.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.ip().to_string())
    }
    .unwrap_or_else(|| "<unknown>".into())
}

#[derive(Clone, Debug)]
struct SpanMaker {
    include_headers: bool
}

impl SpanMaker {
    pub fn new() -> Self {
        Self { include_headers: false }
    }

    pub fn include_headers(mut self, include_headers: bool) -> Self {
        self.include_headers = include_headers;
        self
    }
}

impl MakeSpan<Body> for SpanMaker {
    fn make_span(&mut self, request: &Request<Body>) -> Span {
        if self.include_headers {
            info_span!(
                "request",
                source = %real_addr(request),
                method = %request.method(),
                uri = %request.uri(),
                version = ?request.version(),
                headers = ?request.headers()
            )
        }
        else {
            info_span!(
                "request",
                source = %real_addr(request),
                method = %request.method(),
                uri = %request.uri(),
                version = ?request.version()
            )
        }
    }
}

fn routes(api: &str, log_headers: bool) -> Router<AppState> {
    Router::new()
        .route(
            &format!("{api}/"),
            get(handlers::root_get)
        )
        .route(
            &format!("{api}/login"),
            post(handlers::login_post)
        )
        .route(
            &format!("{api}/refresh"),
            post(handlers::refresh_post)
        )
        .route(
            &format!("{api}/sso/completeLogin"),
            get(handlers::sso_complete_login_get)
        )
        .route(
            &format!("{api}/sso/completeLogout"),
            get(handlers::sso_complete_logout_get)
        )
        .route(
            &format!("{api}/sso/login"),
            get(handlers::sso_login_get)
        )
        .route(
            &format!("{api}/sso/logout"),
            get(handlers::sso_logout_get)
        )
// TODO: move Discourse webhook outside of the api
        .route(
            &format!("{api}/sso/userEvent"),
            post(handlers::sso_user_event_post)
        )
// TODO: users tests
        .route(
            &format!("{api}/users"),
            get(handlers::users_get)
        )
        .route(
            &format!("{api}/users/{{username}}"),
            get(handlers::users_username_get)
        )
        .route(
            &format!("{api}/users/{{username}}/avatar/{{size}}"),
            get(handlers::users_username_avatar_size_get)
        )
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::very_permissive())
                // ensure requests don't block shutdown
                .layer(TimeoutLayer::new(Duration::from_secs(10)))
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(SpanMaker::new().include_headers(log_headers))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::WARN))
        )
}

// TODO: rate limiting

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("{0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("{0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("{0}")]
    Database(#[from] sqlx::Error),
    #[error("{0}")]
    IOError(#[from] io::Error)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())
        .expect("failed to install signal handler");

    // Docker sends SIGQUIT for some unfathomable reason
    let mut quit = signal(SignalKind::quit())
        .expect("failed to install signal handler");

    let mut terminate = signal(SignalKind::terminate())
        .expect("failed to install signal handler");

    tokio::select! {
        _ = interrupt.recv() => info!("received SIGINT"),
        _ = quit.recv() => info!("received SIGQUIT"),
        _ = terminate.recv() => info!("received SIGTERM")
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub db_path: String,
    pub access_key: String,
    pub access_key_ttl: i64,
    pub refresh_ttl: i64,
    pub api_base_path: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub discourse_url: String,
    // See: discourse connect provider secrets *
    pub discourse_sso_secret: String,
    // See: discourse webhooks
    pub discourse_update_secret: String,
    pub log_headers: bool
}

async fn run() -> Result<(), StartupError> {
    info!("Reading config.toml");
    let config: Config = toml::from_str(&fs::read_to_string("config.toml")?)?;

    info!("Opening database {}", config.db_path);
    let db_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&format!("sqlite://{}", &config.db_path))
        .await?;

    let core = ProdCore {
        db: SqlxDatabaseClient(db_pool),
        discourse_url: config.discourse_url.clone(),
        discourse_sso_secret: config.discourse_sso_secret.into_bytes(),
        now: Utc::now,
        auth: DiscourseAuth::new(&config.discourse_url),
        access_key: EncodingKey::from_secret(config.access_key.as_bytes()),
        access_key_ttl: config.access_key_ttl,
        refresh_ttl: config.refresh_ttl
    };

    let duc = DiscourseUpdateConfig {
        secret: config.discourse_update_secret.into_bytes()
    };

    let state = AppState {
        core: Arc::new(core) as CoreArc,
        discourse_update_config: Arc::new(duc)
    };

    let app = routes(
        &config.api_base_path,
        config.log_headers
    ).with_state(state);

    let ip: IpAddr = config.listen_ip.parse()?;
    let addr = SocketAddr::from((ip, config.listen_port));
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on {}", addr);

    serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>()
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    // set up logging
    // TODO: make log location configurable
    let file_appender = tracing_appender::rolling::daily("", "ums.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| {
                [
                    // log this crate at info level
                    &format!("{}=info", env!("CARGO_CRATE_NAME")),
                    // tower_http is noisy below info
                    "tower_http=info",
                    // axum::rejection=trace shows rejections from extractors
                    "axum::rejection=trace",
                    // every panic is a fatal error
                    "tracing_panic=error"
                ].join(",").into()
            })
        )
        .with(tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(non_blocking)
        )
        .init();

    // ensure that panics are logged
    std::panic::set_hook(Box::new(panic_hook));

    info!("Starting");

    if let Err(e) = run().await {
        error!("{}", e);
    }

    info!("Exiting");
}

#[cfg(test)]
mod test {
    use super::*;

    use async_trait::async_trait;
    use axum::{
        body::{self, Body, Bytes},
        http::{
            Method, Request,
            header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE}
        }
    };
    use axum_extra::extract::cookie::{Cookie, SameSite};
    use const_format::formatcp;
    use mime::{APPLICATION_JSON, TEXT_PLAIN};
    use once_cell::sync::Lazy;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use time::OffsetDateTime;
    use tower::ServiceExt; // for oneshot

    use crate::{
        core::{Core, CoreError},
        model::{LoginParams, LoginResponse, RefreshResponse, UserUpdatePost, UserUpdateParams},
        signature::make_signature
    };

    const API_V1: &str = "/api/v1";

    const REFRESH_KEY: &[u8] = b"@wlD+3L)EHdv28u)OFWx@83_*TxhVf9IdUncaAz6ICbM~)j+dH=sR2^LXp(tW31z";

    async fn body_bytes(r: Response) -> Bytes {
        body::to_bytes(r.into_body(), usize::MAX).await.unwrap()
    }

    async fn body_as<D: for<'a> Deserialize<'a>>(r: Response) -> D {
        serde_json::from_slice::<D>(&body_bytes(r).await).unwrap()
    }

    async fn body_empty(r: Response) -> bool {
        body_bytes(r).await.is_empty()
    }

    async fn try_request(state: AppState, request: Request<Body>) -> Response {
        routes(API_V1, false)
            .with_state(state)
            .oneshot(request)
            .await
            .unwrap()
    }

    #[derive(Clone)]
    struct NoAuthCore;

    #[async_trait]
    impl Core for NoAuthCore {}

    fn test_state_no_auth() -> AppState {
        AppState {
            core: Arc::new(NoAuthCore) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[derive(Clone)]
    struct OkAuthCore;

    #[async_trait]
    impl Core for OkAuthCore {
        async fn login(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<Value, AppError>
        {
            Ok(json!({ "user": { "id": 42 } }))
        }

        fn issue_access(
            &self,
            _uid: i64,
        ) -> Result<(String, i64), AppError>
        {
            Ok(("woohoo".into(), 0))
        }

        async fn issue_refresh(
            &self,
            _uid: i64,
        ) -> Result<(String, i64), AppError>
        {
            Ok(("so refreshing".into(), 0))
        }

        async fn verify_refresh(
            &self,
            _session_id: &str
        ) -> Result<Option<i64>, CoreError>
        {
            Ok(Some(0))
        }
    }

    fn test_state_ok_auth() -> AppState {
        AppState {
            core: Arc::new(OkAuthCore) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[derive(Clone)]
    struct FailAuthCore;

    #[async_trait]
    impl Core for FailAuthCore {
        async fn login(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<Value, AppError>
        {
            Err(AppError::Unauthorized)
        }
    }

    fn test_state_fail_auth() -> AppState {
        AppState {
            core: Arc::new(FailAuthCore) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[derive(Clone)]
    struct ErrorAuthCore;

    #[async_trait]
    impl Core for ErrorAuthCore {
        async fn login(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<Value, AppError>
        {
            Err(AppError::InternalError)
        }

        async fn issue_refresh(
            &self,
            _uid: i64,
        ) -> Result<(String, i64), AppError>
        {
            Err(AppError::InternalError)
        }
    }

    fn test_state_error_auth() -> AppState {
        AppState {
            core: Arc::new(ErrorAuthCore) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[tokio::test]
    async fn root_ok() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&body_bytes(response).await[..], b"hello world");
    }

    #[tokio::test]
    async fn login_ok() {
        let response = try_request(
            test_state_ok_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(
                        &LoginParams {
                            username: "skroob".into(),
                            password: "12345".into()
                        }
                    )
                    .unwrap()
                ))
                .unwrap()
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_as::<LoginResponse>(response).await,
            LoginResponse {
                access: "woohoo".into(),
                refresh: "so refreshing".into()
            }
        );
    }

    #[tokio::test]
    async fn login_wrong_method() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/login"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn login_no_content_type() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .body(Body::from(
                    serde_json::to_vec(
                        &LoginParams {
                            username: "skroob".into(),
                            password: "12345".into()
                        }
                    )
                    .unwrap()
                ))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn login_no_payload() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_not_json() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, TEXT_PLAIN.as_ref())
                .body(Body::from("total garbage"))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn login_no_username() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(r#"{ "password": "bob" }"#))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_no_password() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(r#"{ "username": "bob" }"#))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_usermame_not_string() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(r#"{ "username": 3, "password": "x" }"#))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_password_not_string() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(r#"{ "username": "x", "password": 3 }"#))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_failed() {
        let response = try_request(
            test_state_fail_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(
                        &LoginParams {
                            username: "skroob".into(),
                            password: "12345".into()
                        }
                    )
                    .unwrap()
                ))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_error() {
        let response = try_request(
            test_state_error_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/login"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(
                        &LoginParams {
                            username: "skroob".into(),
                            password: "12345".into()
                        }
                    )
                    .unwrap()
                ))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn refresh_ok() {
        let response = try_request(
            test_state_ok_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(format!("{API_V1}/refresh"))
                .header(AUTHORIZATION, "Bearer so refreshing")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_as::<RefreshResponse>(response).await,
            RefreshResponse {
                token: "woohoo".into()
            }
        );
    }

    #[tokio::test]
    async fn refresh_wrong_method() {
        let response = try_request(
            test_state_no_auth(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/refresh"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn refresh_failed_no_token() {
        let response = try_request(
            test_state_fail_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/refresh"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_failed_bad_token() {
        let response = try_request(
            test_state_fail_auth(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/refresh"))
                .header(AUTHORIZATION, "bogus")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_error() {
    }

    #[derive(Clone)]
    struct OkUpdateUser;

    #[async_trait]
    impl Core for OkUpdateUser {
        async fn update_user(
            &self,
            _params: &UserUpdateParams
        ) -> Result<(), CoreError> {
            Ok(())
        }
    }

    fn test_state_ok_update_user() -> AppState {
        AppState {
            core: Arc::new(OkUpdateUser) as CoreArc,
            discourse_update_config: Arc::new(
                DiscourseUpdateConfig {
                    secret: "12345".into()
                }
            )
        }
    }

    static UPDATE_MSG: Lazy<Vec<u8>> = Lazy::new(||
        serde_json::to_vec(
            &UserUpdatePost {
                user: UserUpdateParams {
                    id: 3,
                    username: "bob".into(),
                    avatar_template: "".into()
                }
            }
        ).unwrap()
    );

    fn update_msg_sig(secret: &str) -> String {
        let sig = make_signature(&UPDATE_MSG, secret.as_bytes());
        format!("sha256={}", hex::encode(sig))
    }

    #[tokio::test]
    async fn users_post_ok() {
        let hval = update_msg_sig("12345");
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .header("X-Discourse-Event-Signature", hval)
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_empty(response).await);
    }

    #[tokio::test]
    async fn users_post_no_signature_header() {
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn users_post_bad_signature_header() {
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .header("X-Discourse-Event-Signature", "bogus")
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn users_post_bad_signature_header_prefix() {
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .header("X-Discourse-Event-Signature", "sha257=ff")
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn users_post_bad_signature_header_hash() {
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .header("X-Discourse-Event-Signature", "sha256=bogus")
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn users_post_signature_mismatch() {
        let hval = update_msg_sig("54321");
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .header("X-Discourse-Event-Signature", hval)
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn users_post_no_mime_type() {
        let hval = update_msg_sig("12345");
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header("X-Discourse-Event-Signature", hval)
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn users_post_bad_mime_type() {
        let hval = update_msg_sig("12345");
        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, TEXT_PLAIN.as_ref())
                .header("X-Discourse-Event-Signature", hval)
                .body(Body::from(UPDATE_MSG.clone()))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn users_post_wrong_json() {
        let b = serde_json::to_vec(r#"{ "garbage": "whatever" }"#).unwrap();

        let secret = "12345";
        let sig = make_signature(&b, secret.as_bytes());
        let hval = format!("sha256={}", hex::encode(sig));

        let response = try_request(
            test_state_ok_update_user(),
            Request::builder()
                .method(Method::POST)
                .uri(formatcp!("{API_V1}/sso/userEvent"))
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .header("X-Discourse-Event-Signature", hval)
                .body(Body::from(b))
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn cookies(response: &Response) -> Vec<Cookie<'_>> {
        let mut cookies = response.headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|hv| Cookie::parse(hv.to_str().unwrap()).unwrap())
            .collect::<Vec<_>>();

        cookies.sort_by(|a, b| a.name().cmp(b.name()));
        cookies
    }

    #[track_caller]
    fn assert_cookie_expired(cookie: Cookie, name: &str) {
        assert_eq!(cookie.name(), name);
        assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
        assert!(cookie.expires_datetime().unwrap() < OffsetDateTime::now_utc());
    }

    #[derive(Clone)]
    struct OkSsoLogin;

    #[async_trait]
    impl Core for OkSsoLogin {
        fn build_sso_request(
            &self,
            _returnto: &str,
            _login: bool
        ) -> (String, String) {
            ("abcde".into(), "https://example.com".into())
        }
    }

    fn test_state_ok_sso_login() -> AppState {
        AppState {
            core: Arc::new(OkSsoLogin) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[tokio::test]
    async fn sso_login_ok() {
        let response = try_request(
            test_state_ok_sso_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/login?returnto=here"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            cookies(&response),
            [ Cookie::new("nonce", "abcde") ]
        );
    }

    #[tokio::test]
    async fn sso_login_missing_returnto() {
        let response = try_request(
            test_state_ok_sso_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/login"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sso_logout_ok() {
        let response = try_request(
            test_state_ok_sso_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/logout?returnto=here"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        assert_eq!(
            cookies(&response),
            [ Cookie::new("nonce", "abcde") ]
        );
    }

    #[tokio::test]
    async fn sso_logout_missing_returnto() {
        let response = try_request(
            test_state_ok_sso_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/logout"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[derive(Clone)]
    struct OkSsoCompleteLogin;

    #[async_trait]
    impl Core for OkSsoCompleteLogin {
        fn verify_sso_response(
            &self,
            _nonce_expected: &str,
            _sso: &str,
            _sig: &str
        ) -> Result<(i64, String, Option<String>), AppError> {
            Ok((3, "bob".into(), Some("Bob".into())))
        }

        fn issue_access(
            &self,
            _uid: i64
        ) -> Result<(String, i64), AppError>
        {
            Ok(("token!".into(), 0))
        }

        async fn issue_refresh(
            &self,
            _uid: i64
        ) -> Result<(String, i64), AppError>
        {
            Ok(("refresh!".into(), 0))
        }
    }

    fn test_state_ok_sso_complete_login() -> AppState {
        AppState {
            core: Arc::new(OkSsoCompleteLogin) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[tokio::test]
    async fn sso_complete_login_ok() {
        let response = try_request(
            test_state_ok_sso_complete_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogin?sso=&sig=&returnto=here"))
                .header(COOKIE, "nonce=abcde")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let mut c = cookies(&response).into_iter();
        // cookies iterate in alphabetical order by name
        assert_eq!(
            c.next().unwrap(),
            Cookie::build(("name", "Bob"))
                .path("/")
                .secure(true)
                .same_site(SameSite::Lax)
                .expires(OffsetDateTime::UNIX_EPOCH)
        );
        assert_cookie_expired(c.next().unwrap(), "nonce");
        assert_eq!(
            c.next().unwrap(),
            Cookie::build(("refresh", "refresh!"))
                .path("/")
                .secure(true)
                .same_site(SameSite::Lax)
                .expires(OffsetDateTime::UNIX_EPOCH)
        );
        assert_eq!(
            c.next().unwrap(),
            Cookie::build(("token", "token!"))
                .path("/")
                .secure(true)
                .same_site(SameSite::Lax)
                .expires(OffsetDateTime::UNIX_EPOCH)
        );
        assert_eq!(
            c.next().unwrap(),
            Cookie::build(("username", "bob"))
                .path("/")
                .secure(true)
                .same_site(SameSite::Lax)
                .expires(OffsetDateTime::UNIX_EPOCH)
        );
        assert_eq!(c.next(), None);
    }

    #[tokio::test]
    async fn sso_complete_login_missing_sso() {
        let response = try_request(
            test_state_ok_sso_complete_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogin?sig=&returnto="))
                .header(COOKIE, "nonce=abcde")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sso_complete_login_missing_sig() {
        let response = try_request(
            test_state_ok_sso_complete_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogin?sso=&returnto="))
                .header(COOKIE, "nonce=abcde")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sso_complete_login_missing_returnto() {
        let response = try_request(
            test_state_ok_sso_complete_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogin?sso=&sig="))
                .header(COOKIE, "nonce=abcde")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sso_complete_login_missing_nonce() {
        let response = try_request(
            test_state_ok_sso_complete_login(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogin?sso=&sig=&returnto="))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[derive(Clone)]
    struct DummyCore;

    #[async_trait]
    impl Core for DummyCore {}

    fn test_state_ok_sso_complete_logout() -> AppState {
        AppState {
            core: Arc::new(DummyCore) as CoreArc,
            discourse_update_config: Default::default()
        }
    }

    #[tokio::test]
    async fn sso_complete_logout_ok() {
        let response = try_request(
            test_state_ok_sso_complete_logout(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogout?returnto=here"))
                .header(COOKIE, "nonce=abcde; name=Bob; username=bob")
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let mut c = cookies(&response).into_iter();
        assert_cookie_expired(c.next().unwrap(), "name");
        assert_cookie_expired(c.next().unwrap(), "nonce");
        assert_cookie_expired(c.next().unwrap(), "username");
        assert_eq!(c.next(), None);
    }

    #[tokio::test]
    async fn sso_complete_logout_missing_returnto() {
        let response = try_request(
            test_state_ok_sso_complete_logout(),
            Request::builder()
                .method(Method::GET)
                .uri(formatcp!("{API_V1}/sso/completeLogout"))
                .body(Body::empty())
                .unwrap()
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
