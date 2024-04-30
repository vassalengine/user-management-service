use thiserror::Error;

use crate::{
    core::CoreError,
    jwt::JWTError,
    sso::SsoResponseError
};

#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("request to Discourse failed: {0}")]
    ClientError(#[from] reqwest::Error),
    #[error("request to Discourse failed: {0}: {1} {2}")]
    HttpError(String, u16, String)
}

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
    JTWError(#[from] JWTError),
    #[error("Server error")]
    ServerError(HttpError),
    #[error("Client error")]
    ClientError(HttpError),
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
