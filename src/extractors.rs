use axum::{
    async_trait,
    body::{self, Body, Bytes},
    extract::{FromRef, FromRequest, FromRequestParts, Json, Request, State},
    http::{
        header::HeaderValue,
        request::Parts
    }
};
use serde::de::DeserializeOwned;
use std::sync::Arc;
// TODO: replace with into_ok() when that's available
use unwrap_infallible::UnwrapInfallible;

use crate::{
    app::DiscourseUpdateConfig,
    errors::AppError,
    signature::verify_signature
};

async fn get_state<S, T>(
    parts: &mut Parts,
    state: &S
) -> T 
where
    S: Send + Sync,
    T: FromRef<S>
{
    State::<T>::from_request_parts(parts, state)
        .await
        .unwrap_infallible()
        .0
}

pub struct DiscourseEvent<E>(pub E);

#[async_trait]
impl<S, T> FromRequest<S> for DiscourseEvent<T>
where
    S: Send + Sync,
    Arc<DiscourseUpdateConfig>: FromRef<S>,
    Bytes: FromRequest<S>,
    T: DeserializeOwned
{
    type Rejection = AppError;

    async fn from_request(
        req: Request,
        state: &S
    ) -> Result<Self, Self::Rejection>
    {
        let sig = match req.headers().get("X-Discourse-Event-Signature") {
            Some(val) => match val.as_bytes().strip_prefix(b"sha256=") {
                Some(hex) => hex::decode(hex)
                    .or(Err(AppError::Unauthorized)),
                None => Err(AppError::Unauthorized)
            },
            None => Err(AppError::Unauthorized)
        }?;

        let (mut parts, body) = req.into_parts();

        let bytes = body::to_bytes(body, usize::MAX)
            .await
            .or(Err(AppError::InternalError))?;

        let duc: Arc<DiscourseUpdateConfig> = get_state(&mut parts, state)
            .await; 

        verify_signature(&bytes, &duc.secret, &sig)
            .or(Err(AppError::Unauthorized))?;

        let Json(payload) = Json::<T>::from_bytes(&bytes)
            .or(Err(AppError::InternalError))?;

        Ok(DiscourseEvent(payload))
    }    
}
