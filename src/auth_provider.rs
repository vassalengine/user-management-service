use axum::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Error {
    pub status: Option<u16>,
    pub message: String
}

#[derive(Debug)]
pub enum Failure {
    Unauthorized,
    Error(Error)
}

#[async_trait]
pub trait AuthProvider {
    async fn login(
        &self,
        username: &str,
        password: &str
    ) -> Result<String, Failure>;
}
