use axum::async_trait;

use crate::{
    core::Core,
    db::DatabaseClient
};

#[derive(Clone)]
pub struct ProdCore<C: DatabaseClient> {
    pub db: C
}

#[async_trait]
impl<C: DatabaseClient + Send + Sync> Core for ProdCore<C> {
}
