use async_trait::async_trait;
use serde_json::Value;
use std::{
    mem,
    sync::Arc
};
use thiserror::Error;

use crate::{
    errors::{AppError, RequestError},
    model::{Token, UserUpdateParams}
};

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Database errror: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Request error: {0}")]
    RequestError(#[from] RequestError)
}

impl PartialEq for CoreError {
    fn eq(&self, other: &Self) -> bool {
        // sqlx::Error is not PartialEq, so we must exclude it
        mem::discriminant(self) == mem::discriminant(other) &&
        !matches!(self, CoreError::DatabaseError(_))
    }
}

#[async_trait]
pub trait Core {
    async fn get_user_search(
        &self,
        _term: &str,
        _limit: u32
    ) -> Result<Value, CoreError> {
        unimplemented!();
    }

    fn get_user_search_url(
        &self,
        _term: &str,
        _limit: u32
    ) -> Result<String, CoreError> {
        unimplemented!();
    }

    fn get_user_url(
        &self,
        _username: &str
    ) -> Result<String, CoreError> {
        unimplemented!();
    }

    async fn update_user(
        &self,
        _params: &UserUpdateParams
    ) -> Result<(), CoreError> {
        unimplemented!();
    }

    async fn get_avatar_url(
        &self,
        _username: &str,
        _size: u32
    ) -> Result<String, CoreError> {
        unimplemented!();
    }

    fn build_sso_request(
        &self,
        _returnto: &str,
        _login: bool
    ) -> (String, String) {
        unimplemented!();
    }

    fn verify_sso_response(
        &self,
        _nonce_expected: &str,
        _sso: &str,
        _sig: &str
    ) -> Result<(i64, String, Option<String>), AppError> {
        unimplemented!();
    }

    async fn login(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<Value, AppError>
    {
        unimplemented!();
    }

    fn issue_jwt(
        &self,
        _uid: i64
    ) -> Result<Token, AppError>
    {
        unimplemented!();
    }
}

pub type CoreArc = Arc<dyn Core + Send + Sync>;
