use axum::async_trait;
use serde_json::Value;
use std::sync::Arc;

use crate::{
    errors::AppError,
    model::{Token, UserUpdateParams}
};

#[async_trait]
pub trait Core {
    async fn update_user(
        &self,
        _params: &UserUpdateParams
    ) -> Result<(), AppError> {
        unimplemented!();
    }

    async fn get_avatar_url(
        &self,
        _username: &str,
        _size: u32
    ) -> Result<String, AppError> {
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
