use axum::extract::FromRef;

use crate::{
    core::CoreArc,
};

#[derive(Clone, FromRef)]
pub struct AppState {
    pub core: CoreArc
}
