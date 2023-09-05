#![feature(async_fn_in_trait)]
#![feature(decl_macro)]

mod auth_provider;
mod discourse;
mod jwt;
mod jwt_provider;

use auth_provider::AuthProvider;
use discourse::DiscourseAuth;

use axum::{
    Router, Server,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{ get, post }
};
use const_format::formatcp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const BASE_URL: &str = "https://forum.vassalengine.org/";

const API_V1: &str = "/api/v1";

async fn root() -> &'static str {
    "hello world"
}

#[derive(Debug, Deserialize, Serialize)]
struct Login {
    username: String,
    password: String
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Token {
    token: String
}

// TODO: return errors as JSON

enum AppError {
    Unauthorized,
    InternalError,
    HttpError
}

impl From<auth_provider::Failure> for AppError {
    fn from(e: auth_provider::Failure) -> Self {
        match e {
            auth_provider::Failure::Error(err) => {
                AppError::InternalError
            },
            auth_provider::Failure::Unauthorized => {
                AppError::Unauthorized
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "Unauthorized")
            },
            AppError::InternalError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            },
            AppError::HttpError => {
                (StatusCode::BAD_REQUEST, "Bad Request")
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}



async fn login_handler<A: AuthProvider>(payload: Json<Login>, auth: A) -> Result<Json<Token>, AppError> {
    let r = auth.login(&payload.username, &payload.password).await?;
    Ok(Json(Token { token: "token".into() }))
}

fn app() -> Router {
    Router::new()
        .route(formatcp!("{API_V1}/"), get(root))
        .route(
            formatcp!("{API_V1}/login"),
            post(move |body| login_handler(body, DiscourseAuth::new(BASE_URL)))
        )
}

#[tokio::main]
async fn main() {
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3000);
    Server::bind(&socket)
        .serve(app().into_make_service())
        .await
        .unwrap();
}

#[cfg(test)]
mod test {
    use super::*;

    use auth_provider::Failure;

    use axum::{
        body::Body,
        http::{
            Method, Request,
            header::CONTENT_TYPE,
        },
    };
    use mime::{APPLICATION_JSON, TEXT_PLAIN};
    use tower::ServiceExt; // for oneshot

    struct NoAuth;

    impl AuthProvider for NoAuth {
        async fn login(&self, _username: &str, _password: &str) -> Result<String, Failure> {
            Err(Failure::Error(auth_provider::Error {
                status: Some(500),
                message: "Should never be called".into()
            }))
        }
    }

/*
    fn test_app<A: AuthProvider + Default>() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post({
                    let auth = A::default();
                    move |body| login_handler(body, auth)
                })
            )
    }
*/

    fn test_app_no_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(move |body| login_handler(body, NoAuth {}))
            )
    }

    struct OkAuth;

    impl AuthProvider for OkAuth {
        async fn login(&self, _username: &str, _password: &str) -> Result<String, Failure> {
            Ok("auth ok".into())
        }
    }

    fn test_app_ok_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(move |body| login_handler(body, OkAuth {}))
            )
    }

    struct FailAuth;

    impl AuthProvider for FailAuth {
        async fn login(&self, _username: &str, _password: &str) -> Result<String, Failure> {
            Err(Failure::Unauthorized)
        }
    }

    fn test_app_fail_auth() -> Router {
        Router::new()
            .route(formatcp!("{API_V1}/"), get(root))
            .route(
                formatcp!("{API_V1}/login"),
                post(move |body| login_handler(body, FailAuth {}))
            )
    }

    struct ErrorAuth;

    impl AuthProvider for ErrorAuth {
        async fn login(&self, _username: &str, _password: &str) -> Result<String, Failure> {
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
                post(move |body| login_handler(body, ErrorAuth {}))
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"hello world");
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
                            &Login {
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Token = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, Token { token: "token".into() });
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
                            &Login {
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
                            &Login {
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
                            &Login {
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
