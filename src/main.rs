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
    config::{Config, ConfigArc},
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
            AppError::SsoError(e) => {
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

fn routes(
    api: &str,
    auth: DiscourseAuth,
    issuer: JWTIssuer
) -> Router<AppState>
{
    let login_post = move |body| handlers::login_post(body, auth, issuer);

    Router::new()
        .route(
            &format!("{api}/"),
            get(handlers::root_get)
        )
        .route(
            &format!("{api}/login"),
            post(login_post)
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

    let config = Config {
        discourse_url: "https://forum.vassalengine.org".into(),
        // discourse connect provider secrets *
        discourse_shared_secret: b"=WW,GKV9Jgk)j\"h".into(),
        jwt_key: b"@wlD+3L)EHdv28u)OFWx@83_*TxhVf9IdUncaAz6ICbM~)j+dH=sR2^LXp(tW31z".into(),
    };

// TODO: handle error?
    let db_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&format!("sqlite://{}", db_path))
        .await
        .unwrap();

    let auth = DiscourseAuth::new(&config.discourse_url);
    let issuer = JWTIssuer::new(&config.jwt_key);

    let core = ProdCore {
        db: SqlxDatabaseClient(db_pool)
    };

    let state = AppState {
        config: Arc::new(config) as ConfigArc,
        core: Arc::new(core) as CoreArc
    };

    let app = routes(api_base_path, auth, issuer)
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

    struct FakeIssuer;

    impl Issuer for FakeIssuer {
        fn issue(
            &self,
            _username: &str,
            _duration: u64
        ) -> Result<String, jwt_provider::Error>
        {
            Ok("woohoo".into())
        }
    }

    struct NoAuth;

    impl AuthProvider for NoAuth {
        async fn login(
            &self,
            _username: &str,
            _password: &str
        ) -> Result<String, Failure>
        {
            Err(Failure::Error(auth_provider::Error {
                status: Some(500),
                message: "Should never be called".into()
            }))
        }
    }

    fn test_app_no_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(handlers::root_get))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| handlers::login_post(body, NoAuth, FakeIssuer))
            )
    }

    struct OkAuth;

    impl AuthProvider for OkAuth {
        async fn login(
            &self,
            _username: &str,
            _password: &str
        ) -> Result<String, Failure>
        {
            Ok("auth ok".into())
        }
    }

    fn test_app_ok_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(handlers::root_get))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| handlers::login_post(body, OkAuth, FakeIssuer))
            )
    }

    struct FailAuth;

    impl AuthProvider for FailAuth {
        async fn login(
            &self,
            _username: &str,
            _password: &str
        ) -> Result<String, Failure>
        {
            Err(Failure::Unauthorized)
        }
    }

    fn test_app_fail_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(handlers::root_get))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| handlers::login_post(body, FailAuth, FakeIssuer))
            )
    }

    struct ErrorAuth;

    impl AuthProvider for ErrorAuth {
        async fn login(
            &self,
            _username: &str,
            _password: &str
        ) -> Result<String, Failure>
        {
            Err(Failure::Error(auth_provider::Error {
                status: Some(500),
                message: "Auth provider had an error".into()
            }))
        }
    }

    fn test_app_error_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(handlers::root_get))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| handlers::login_post(body, ErrorAuth, FakeIssuer))
            )
    }

    #[tokio::test]
    async fn root_ok() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(formatcp!("{API_V1}/"))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&body_bytes(response).await[..], b"hello world");
    }

    #[tokio::test]
    async fn login_ok() {
        let app = test_app_ok_auth();

        let response = app
            .oneshot(
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
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_as::<Token>(response).await,
            Token { token: "woohoo".into() }
        );
    }

    #[tokio::test]
    async fn login_wrong_method() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(formatcp!("{API_V1}/login"))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn login_no_content_type() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
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
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn login_no_payload() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(formatcp!("{API_V1}/login"))
                    .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_not_json() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(formatcp!("{API_V1}/login"))
                    .header(CONTENT_TYPE, TEXT_PLAIN.as_ref())
                    .body(Body::from("total garbage"))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn login_no_username() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(formatcp!("{API_V1}/login"))
                    .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                    .body(Body::from(r#"{ "password": "bob" }"#))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_no_password() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(formatcp!("{API_V1}/login"))
                    .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                    .body(Body::from(r#"{ "username": "bob" }"#))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_usermame_not_string() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(formatcp!("{API_V1}/login"))
                    .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                    .body(Body::from(r#"{ "username": 3, "password": "x" }"#))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_password_not_string() {
        let app = test_app_no_auth();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(formatcp!("{API_V1}/login"))
                    .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                    .body(Body::from(r#"{ "username": "x", "password": 3 }"#))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn login_failed() {
        let app = test_app_fail_auth();

        let response = app
            .oneshot(
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
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_error() {
        let app = test_app_error_auth();

        let response = app
            .oneshot(
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
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
