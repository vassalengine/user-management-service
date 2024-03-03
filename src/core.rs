use axum::async_trait;
use std::sync::Arc;

use crate::{
    errors::AppError,
    model::Token
};

#[async_trait]
pub trait Core {
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
    ) -> Result<(String, Option<String>), AppError> {
        unimplemented!();
    }

    async fn login(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<(), AppError>
    {
        unimplemented!();
    }

    fn issue_jwt(
        &self,
        _username: &str
    ) -> Result<Token, AppError>
    {
        unimplemented!();
    }
}

pub type CoreArc = Arc<dyn Core + Send + Sync>;
