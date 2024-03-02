use axum::async_trait;

use crate::{
    avatar::get_avatar_template,
    auth_provider::AuthProvider,
    core::Core,
    db::DatabaseClient,
    discourse::DiscourseAuth,
    errors::AppError,
    jwt::JWTIssuer,
    model::Token,
    sso::{build_sso_request, verify_sso_response}
};

pub struct ProdCore<C: DatabaseClient> {
    pub db: C,
    pub discourse_url: String,
    pub discourse_shared_secret: Vec<u8>,
    pub auth: DiscourseAuth,
    pub issuer: JWTIssuer
}

#[async_trait]
impl<C: DatabaseClient + Send + Sync> Core for ProdCore<C> {
    async fn get_avatar_url(
        &self,
        username: &str,
        size: u32
    ) -> Result<String, AppError> {
        // get the avatar template
        let tmpl = match self.db.get_user_avatar_template(username).await? {
            Some(tmpl) => tmpl,
            None => {
                let tmpl = get_avatar_template(
                    &self.discourse_url,
                    username
                ).await?;
                self.db.update_user_avatar_template(username, &tmpl).await?;
                tmpl
            }
        };

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
        login: bool
    ) -> (String, String) {
        build_sso_request(
            &self.discourse_shared_secret,
            &self.discourse_url,
            returnto,
            login
        )
    }

    fn verify_sso_response(
        &self,
        nonce_expected: &str,
        sso: &str,
        sig: &str
    ) -> Result<(String, Option<String>), AppError> {
        Ok(
            verify_sso_response(
                &self.discourse_shared_secret,
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
    ) -> Result<Token, AppError>
    {
        let _r = self.auth.login(username, password).await?;
        let token = self.issuer.issue(username, 8 * 60 * 60)?;
        Ok(Token { token })
    }
}

#[cfg(test)]
mod test {
    use super::*;

}
