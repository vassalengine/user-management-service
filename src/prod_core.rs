use axum::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    auth_provider::AuthProvider,
    core::Core,
    db::DatabaseClient,
    discourse::DiscourseAuth,
    errors::AppError,
    jwt::JWTIssuer,
    model::{Token, UserUpdateParams},
    search::user_search,
    sso::{build_sso_request, verify_sso_response}
};

pub struct ProdCore<C: DatabaseClient> {
    pub db: C,
    pub discourse_url: String,
    pub discourse_sso_secret: Vec<u8>,
    pub now: fn() -> DateTime<Utc>,
    pub auth: DiscourseAuth,
    pub issuer: JWTIssuer
}

#[async_trait]
impl<C: DatabaseClient + Send + Sync> Core for ProdCore<C> {
    async fn update_user(
        &self,
        params: &UserUpdateParams
    ) -> Result<(), AppError> {
        Ok(self.db.update_user(params).await?)
    }

    async fn get_avatar_url(
        &self,
        username: &str,
        size: u32
    ) -> Result<String, AppError> {
        // get the avatar template
        let tmpl = self.db.get_user_avatar_template(username).await?;

        // make a URL from the template
        let avatar_url = format!(
            "{}{}",
            self.discourse_url,
            tmpl.replace("{size}", &size.to_string())
        );

        Ok(avatar_url)
    }

    fn build_sso_request(
        &self,
        returnto: &str,
        is_login: bool
    ) -> (String, String) {
        build_sso_request(
            &self.discourse_sso_secret,
            &self.discourse_url,
            returnto,
            is_login
        )
    }

    fn verify_sso_response(
        &self,
        nonce_expected: &str,
        sso: &str,
        sig: &str
    ) -> Result<(i64, String, Option<String>), AppError> {
        Ok(
            verify_sso_response(
                &self.discourse_sso_secret,
                nonce_expected,
                sso,
                sig
            )?
        )
    }

    async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Value, AppError>
    {
        Ok(self.auth.login(username, password).await?)
    }

    fn issue_jwt(
        &self,
        uid: i64
    ) -> Result<Token, AppError>
    {
        Ok(
            Token {
                token: self.issuer.issue(
                    uid,
                    (self.now)().timestamp(),
                    8 * 60 * 60
                )?
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

}
