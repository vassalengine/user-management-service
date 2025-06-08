use axum::extract::FromRef;
use std::sync::Arc;

use crate::{
    core::CoreArc,
    jwt::DecodingKey
};

#[derive(Default)]
pub struct DiscourseUpdateConfig {
    pub secret: Vec<u8>
}

#[derive(Clone, FromRef)]
pub struct AppState {
    pub core: CoreArc,
    pub discourse_update_config: Arc<DiscourseUpdateConfig>,
    pub refresh_key: DecodingKey
}
