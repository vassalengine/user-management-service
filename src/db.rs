use axum::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct DatabaseError(#[from] sqlx::Error);

#[async_trait]
pub trait DatabaseClient {
    async fn get_user_avatar_template(
        &self,
        _username: &str
    ) -> Result<Option<String>, DatabaseError>
    {
        unimplemented!();
    }

    async fn update_user_avatar_template(
        &self,
        _username: &str,
        _avatar_template: &str
    ) -> Result<(), DatabaseError>
    {
        unimplemented!();
    }
}
