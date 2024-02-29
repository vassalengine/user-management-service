use axum::async_trait;
use std::sync::Arc;

use crate::errors::AppError;

#[async_trait]
pub trait Core {
    async fn get_avatar_url(
        &self,
        _discourse_url: &str,
        _username: &str,
        _size: u32
    ) -> Result<String, AppError> {
        unimplemented!();
    }
}

pub type CoreArc = Arc<dyn Core + Send + Sync>;
