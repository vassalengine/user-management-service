use axum::async_trait;
use sqlx::{
    Database,
    sqlite::Sqlite
};

use crate::db::DatabaseClient;

#[derive(Clone)]
pub struct SqlxDatabaseClient<DB: Database>(pub sqlx::Pool<DB>);

#[async_trait]
impl DatabaseClient for SqlxDatabaseClient<Sqlite> {
}
