#![feature(async_fn_in_trait)]

use axum::{
    Router, Server,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post}
};
use const_format::formatcp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;

mod avatar;
mod auth_provider;
mod discourse;
mod jwt;
mod jwt_provider;

use crate::{
    avatar::get_avatar,
    auth_provider::AuthProvider,
    discourse::DiscourseAuth,
    jwt::JWTIssuer,
    jwt_provider::Issuer
};

async fn root() -> &'static str {
    "hello world"
}

struct HttpError {
    status: u16,
    message: String
}

enum AppError {
    Unauthorized,
    ServerError(HttpError),
    ClientError(HttpError)
}

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
                (StatusCode::UNAUTHORIZED, "Unauthorized".to_string())
            },
            AppError::ServerError(e)
            | AppError::ClientError(e) => {
                match StatusCode::from_u16(e.status) {
                    Ok(s) => (s, e.message),
                    // should not happen
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.message)
                }
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct LoginParams {
    username: String,
    password: String
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Token {
    token: String
}

async fn login_handler<A: AuthProvider, I: Issuer>(params: Json<LoginParams>, auth: A, issuer: I) -> Result<Json<Token>, AppError> {
    let _r = auth.login(&params.username, &params.password).await?;
    let token = issuer.issue(&params.username, 8 * 60 * 60)?;
    Ok(Json(Token { token }))
}

#[derive(Debug)]
struct Config {
    discourse_url: String,
    jwt_key: Vec<u8>,
    api_base_path: String,
    listen_ip: [u8; 4],
    listen_port: u16 
}

fn app(config: &Config) -> Router {
    let auth = DiscourseAuth::new(&config.discourse_url);
    let issuer = JWTIssuer::new(&config.jwt_key);
    let login_handler_actual = move |body| login_handler(body, auth, issuer);

    Router::new()
        .route(&format!("{}/", config.api_base_path), get(root))
        .route(
            &format!("{}/login", config.api_base_path),
            post(login_handler_actual)
        )
}

#[tokio::main]
async fn main() {
    let config = Config {
        discourse_url: "https://forum.vassalengine.org".into(),
        jwt_key: b"@wlD+3L)EHdv28u)OFWx@83_*TxhVf9IdUncaAz6ICbM~)j+dH=sR2^LXp(tW31z".to_vec(),
        api_base_path: "/api/v1".into(),
        listen_ip: [0, 0, 0, 0],
        listen_port: 3000
    };

    let addr = SocketAddr::from((config.listen_ip, config.listen_port));
    Server::bind(&addr)
        .serve(app(&config).into_make_service())
        .await
        .unwrap();
}

#[cfg(test)]
mod test {
    use super::*;

    use auth_provider::Failure;

    use axum::{
        body::{self, Body, Bytes},
        http::{
            Method, Request,
            header::CONTENT_TYPE,
        },
    };
    use mime::{APPLICATION_JSON, TEXT_PLAIN};
    use tower::ServiceExt; // for oneshot

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
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| login_handler(body, NoAuth, FakeIssuer))
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
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| login_handler(body, OkAuth, FakeIssuer))
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
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| login_handler(body, FailAuth, FakeIssuer))
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
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(|body| login_handler(body, ErrorAuth, FakeIssuer))
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
