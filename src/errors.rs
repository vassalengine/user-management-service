use thiserror::Error;

use crate::{
    auth_provider,
    core::CoreError,
    discourse::sso::SsoResponseError,
    jwt
};

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("request to Discourse failed: {0}")]
    ClientError(#[from] reqwest::Error),
    #[error("request to Discourse failed: {0}: {1} {2}")]
    HttpError(String, u16, String)
}

// TODO: review messages
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Unsupported media type")]
    BadMimeType,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error")]
    InternalError,
    #[error("Bad request")]
    MalformedQuery,
    #[error("{0}")]
    DatabaseError(String),
    #[error("JWT error")]
    JTWError(#[from] jwt::Error),
    #[error("Request error")]
    RequestError(#[from] RequestError),
    #[error("SSO failed")]
    SsoError(#[from] SsoResponseError)
}

impl From<CoreError> for AppError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::DatabaseError(e) => AppError::DatabaseError(e.to_string()),
            CoreError::RequestError(e) => AppError::RequestError(e)
        }
    }
}

impl From<auth_provider::Failure> for AppError {
    fn from(e: auth_provider::Failure) -> Self {
        match e {
            auth_provider::Failure::Error(err) => {
                // All auth provider errors are 500 for us; put the auth
                // provider status into the message if there is one.
                AppError::RequestError(
                    RequestError::HttpError(
                        "".into(),
                        err.status.unwrap_or(500),
                        err.message
                    )
                )
            },
            auth_provider::Failure::Unauthorized => {
                AppError::Unauthorized
            }
        }
    }
}
