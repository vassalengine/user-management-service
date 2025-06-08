use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    auth_provider::AuthProvider,
    core::{Core, CoreError},
    db::DatabaseClient,
    discourse::{
        login::DiscourseAuth,
        sso::{build_sso_request, verify_sso_response}
    },
    errors::AppError,
    jwt::{self, EncodingKey},
    model::UserUpdateParams,
    search::user_search
};

pub struct ProdCore<C: DatabaseClient> {
    pub db: C,
    pub discourse_url: String,
    pub discourse_sso_secret: Vec<u8>,
    pub now: fn() -> DateTime<Utc>,
    pub auth: DiscourseAuth,
    pub access_key: EncodingKey,
    pub access_key_ttl: u64,
    pub refresh_key: EncodingKey,
    pub refresh_key_ttl: u64
}

#[async_trait]
impl<C: DatabaseClient + Send + Sync> Core for ProdCore<C> {
    async fn get_user_search(
        &self,
        term: &str,
        limit: u32
    ) -> Result<Value, CoreError> {
        Ok(user_search(&self.discourse_url, term, limit).await?)
    }

    fn get_user_search_url(
        &self,
        term: &str,
        limit: u32
    ) -> Result<String, CoreError> {
        Ok(
            format!(
                "{}/u/search/users?term={}&include_groups=false&limit={}",
                self.discourse_url,
                term,
                limit
            )
        )
    }

    fn get_user_url(
        &self,
        username: &str
    ) -> Result<String, CoreError> {
        Ok(format!("{}/u/{username}", self.discourse_url))
    }

    async fn update_user(
        &self,
        params: &UserUpdateParams
    ) -> Result<(), CoreError> {
        Ok(self.db.update_user(params).await?)
    }

    async fn get_avatar_url(
        &self,
        username: &str,
        size: u32
    ) -> Result<String, CoreError> {
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

    fn issue_access(
        &self,
        uid: i64
    ) -> Result<String, AppError>
    {
        let now = (self.now)().timestamp()
            .try_into()
            .or(Err(AppError::InternalError))?;
        Ok(jwt::issue(
            &self.access_key,
            uid,
            now,
            now + self.access_key_ttl
        )?)
    }

    fn issue_refresh(
        &self,
        uid: i64
    ) -> Result<String, AppError>
    {
        let now = (self.now)().timestamp()
            .try_into()
            .or(Err(AppError::InternalError))?;
        Ok(jwt::issue(
            &self.refresh_key,
            uid,
            now,
            now + self.refresh_key_ttl
        )?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

}
