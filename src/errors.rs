use thiserror::Error;

use crate::{
    db::DatabaseError,
    jwt::JWTError,
    sso::SsoResponseError
};

#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error")]
    InternalError,
    #[error("Database error")]
    DatabaseError(#[from] DatabaseError),
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
