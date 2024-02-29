use axum::async_trait;
use sqlx::{
    Database, Executor,
    sqlite::Sqlite
};

use crate::db::{DatabaseClient, DatabaseError};

#[derive(Clone)]
pub struct SqlxDatabaseClient<DB: Database>(pub sqlx::Pool<DB>);

#[async_trait]
impl DatabaseClient for SqlxDatabaseClient<Sqlite> {
    async fn get_user_avatar_template(
        &self,
        username: &str
    ) -> Result<Option<String>, DatabaseError>
    {
        get_user_avatar_template(&self.0, username).await
    }

    async fn update_user_avatar_template(
        &self,
        username: &str,
        avatar_template: &str
    ) -> Result<(), DatabaseError>
    {
        update_user_avatar_template(&self.0, username, avatar_template).await
    }
}

async fn get_user_avatar_template<'e, E>(
    ex: E,
    username: &str
) -> Result<Option<String>, DatabaseError>
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
        .fetch_optional(ex)
        .await?
    )
}

// TODO: should probably use real user ids
// TODO: can we get avatar updates from the discourse web hook?

async fn update_user_avatar_template<'e, E>(
    ex: E,
    username: &str,
    avatar_template: &str
) -> Result<(), DatabaseError>
where
    E: Executor<'e, Database = Sqlite>
{
    sqlx::query!(
        "
INSERT OR REPLACE INTO users (
    username,
    avatar_template
)
VALUES (?, ?)
        ",
        username,
        avatar_template
    )
    .execute(ex)
    .await?;

    Ok(())
}
