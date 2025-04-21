use async_trait::async_trait;
use sqlx::{
    Database, Executor,
    sqlite::Sqlite
};

use crate::{
    core::CoreError,
    db::DatabaseClient,
    model::UserUpdateParams
};

#[derive(Clone)]
pub struct SqlxDatabaseClient<DB: Database>(pub sqlx::Pool<DB>);

#[async_trait]
impl DatabaseClient for SqlxDatabaseClient<Sqlite> {
    async fn get_user_avatar_template(
        &self,
        username: &str
    ) -> Result<String, CoreError>
    {
        get_user_avatar_template(&self.0, username).await
    }

    async fn update_user(
        &self,
        params: &UserUpdateParams
    ) -> Result<(), CoreError>
    {
        update_user(&self.0, params).await
    }
}

async fn get_user_avatar_template<'e, E>(
    ex: E,
    username: &str
) -> Result<String, CoreError>
where
    E: Executor<'e, Database = Sqlite>
{
    Ok(
        sqlx::query_scalar!(
            "
SELECT avatar_template
FROM users
WHERE username = ?
            ",
            username
        )
        .fetch_one(ex)
        .await?
    )
}

async fn update_user<'e, E>(
    ex: E,
    params: &UserUpdateParams
) -> Result<(), CoreError>
where
    E: Executor<'e, Database = Sqlite>
{
    sqlx::query!(
        "
INSERT OR REPLACE INTO users (
    user_id,
    username,
    avatar_template
)
VALUES (?, ?, ?)
        ",
        params.id,
        params.username,
        params.avatar_template
    )
    .execute(ex)
    .await?;

    Ok(())
}
