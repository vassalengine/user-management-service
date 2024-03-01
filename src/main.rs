use axum::{
    BoxError, Router, serve,
    error_handling::HandleErrorLayer,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post}
};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration
};
use tokio::net::TcpListener;
use tower::{
    ServiceBuilder,
    buffer::BufferLayer,
    limit::RateLimitLayer
};
use tower_http::cors::CorsLayer;

mod app;
mod avatar;
mod auth_provider;
mod config;
mod core;
mod db;
mod discourse;
mod errors;
mod handlers;
mod jwt;
mod jwt_provider;
mod model;
mod prod_core;
mod sqlite;
mod sso;

use crate::{
    app::AppState,
    config::{AuthArc, IssuerArc},
    core::CoreArc,
    discourse::DiscourseAuth,
    errors::{AppError, HttpError},
    jwt::JWTIssuer,
    prod_core::ProdCore,
    sqlite::SqlxDatabaseClient
};

impl From<auth_provider::Failure> for AppError {
    fn from(e: auth_provider::Failure) -> Self {
        match e {
            auth_provider::Failure::Error(err) => {
                // All auth provider errors are 500 for us; put the auth
                // provider status into the message if there is one.
                AppError::ServerError(HttpError {
                    status: 500,
                    message: match err.status {
                        Some(s) => format!("{} {}", s, err.message),
                        None => err.message
                    }
                })
            },
            auth_provider::Failure::Unauthorized => {
                AppError::Unauthorized
            }
        }
    }
}

impl From<jwt_provider::Error> for AppError {
    fn from(e: jwt_provider::Error) -> Self {
        AppError::ServerError(HttpError {
            status: 500,
            message: e.message
        })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            },
            AppError::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "TODO!".into())
            },
            AppError::DatabaseError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            },
            AppError::ServerError(e)
            | AppError::ClientError(e) => {
                match StatusCode::from_u16(e.status) {
                    Ok(s) => (s, e.message),
                    // should not happen
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.message)
                }
            },
            AppError::RequestError(e) => {
                eprintln!("{e}");
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            },
            AppError::SsoError(_) => {
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

fn routes(api: &str) -> Router<AppState> {
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
        .route(
            &format!("{api}/users/:username/avatar/:size"),
            get(handlers::users_username_avatar_size_get)
        )
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::very_permissive())
        )
}

// TODO: rate limiting

#[tokio::main]
async fn main() {
    let listen_ip = [0, 0, 0, 0];
    let listen_port = 4000;
    
    let db_path = "users.db";
    let api_base_path = "/api/v1";

    let jwt_key = b"@wlD+3L)EHdv28u)OFWx@83_*TxhVf9IdUncaAz6ICbM~)j+dH=sR2^LXp(tW31z";
    let discourse_url = "https://forum.vassalengine.org";
    // See: discourse connect provider secrets *
    let discourse_shared_secret = b"";

// TODO: handle error?
    let db_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&format!("sqlite://{}", db_path))
        .await
        .unwrap();

    let core = ProdCore {
        db: SqlxDatabaseClient(db_pool),
        discourse_url: discourse_url.into(),
        discourse_shared_secret: discourse_shared_secret.into(),
        auth: DiscourseAuth::new(&discourse_url),
        issuer: JWTIssuer::new(jwt_key)
    };

    let state = AppState {
        core: Arc::new(core) as CoreArc
    };

    let app = routes(api_base_path)
        .with_state(state)
        .layer(
            ServiceBuilder::new().layer(
                HandleErrorLayer::new(|err: BoxError| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled error: {}", err)
                    )
                })
            )
            .buffer(1024)
            .rate_limit(5, Duration::from_secs(1))
        );

    let addr = SocketAddr::from((listen_ip, listen_port));
    let listener = TcpListener::bind(addr)
        .await
        .unwrap();
    serve(listener, app)
        .await
        .unwrap();
}

#[cfg(test)]
mod test {
    use super::*;

    use axum::{
        async_trait,
        body::{self, Body, Bytes},
        http::{
            Method, Request,
            header::CONTENT_TYPE,
        },
    };
    use const_format::formatcp;
    use mime::{APPLICATION_JSON, TEXT_PLAIN};
    use serde::Deserialize;
    use tower::ServiceExt; // for oneshot

    use crate::{
        auth_provider::{AuthProvider, Failure},
        core::Core,
        jwt_provider::Issuer,
        model::{LoginParams, Token}
    };

    const API_V1: &str = "/api/v1";

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
        routes(API_V1)
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
            core: Arc::new(NoAuthCore) as CoreArc
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
        ) -> Result<Token, AppError>
        {
            Ok(Token { token: "woohoo".into() })
        }
    }

    fn test_state_ok_auth() -> AppState {
        AppState {
            core: Arc::new(OkAuthCore) as CoreArc
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
        ) -> Result<Token, AppError>
        {
            Err(AppError::Unauthorized)
        }
    }

    fn test_state_fail_auth() -> AppState {
        AppState {
            core: Arc::new(FailAuthCore) as CoreArc
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
        ) -> Result<Token, AppError>
        {
            Err(AppError::InternalError)
        }
    }

    fn test_state_error_auth() -> AppState {
        AppState {
            core: Arc::new(ErrorAuthCore) as CoreArc
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
            body_as::<Token>(response).await,
            Token { token: "woohoo".into() }
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
}
