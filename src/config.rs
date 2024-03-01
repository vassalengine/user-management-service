use std::sync::Arc;

use crate::{
    auth_provider::AuthProvider,
    jwt_provider::Issuer
};

pub type AuthArc = Arc<dyn AuthProvider + Send + Sync>;
pub type IssuerArc = Arc<dyn Issuer + Send + Sync>;
