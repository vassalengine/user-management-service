use axum::async_trait;

use crate::{
    avatar::get_avatar_template,
    core::Core,
    db::DatabaseClient,
    errors::AppError
};

#[derive(Clone)]
pub struct ProdCore<C: DatabaseClient> {
    pub db: C
}

#[async_trait]
impl<C: DatabaseClient + Send + Sync> Core for ProdCore<C> {
    async fn get_avatar_url(
        &self,
        discourse_url: &str,
        username: &str,
        size: u32
    ) -> Result<String, AppError> {
        let tmpl = match self.db.get_user_avatar_template(username).await? {
            Some(tmpl) => tmpl,
            None => {
                let tmpl = get_avatar_template(discourse_url, username).await?;
                self.db.update_user_avatar_template(username, &tmpl).await?;
                tmpl
            }
        };

        let avatar_url = format!(
            "{discourse_url}{}",
            tmpl.replace("{size}", &size.to_string())
        );

        Ok(avatar_url)
    }
}
