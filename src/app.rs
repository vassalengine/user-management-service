use axum::extract::FromRef;

use crate::{
    config::ConfigArc,
    core::CoreArc,
};

#[derive(Clone, FromRef)]
pub struct AppState {
    pub config: ConfigArc,
    pub core: CoreArc
}
