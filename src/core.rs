use axum::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait Core {
}

pub type CoreArc = Arc<dyn Core + Send + Sync>;
