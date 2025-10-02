use axum::{
    RequestPartsExt,
    body::{self, Bytes},
    extract::{FromRef, FromRequest, FromRequestParts, Json, Request, State},
    http::{
        header::CONTENT_TYPE,
        request::Parts
    }
};
use axum_extra::{
    TypedHeader,
    headers::{
        Authorization,
        authorization::Bearer
    }
};
use mime::{APPLICATION_JSON, Mime};
use serde::de::DeserializeOwned;
use std::sync::Arc;

use crate::{
    app::DiscourseUpdateConfig,
    core::CoreArc,
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
    let Ok(s) = State::<T>::from_request_parts(parts, state)
        .await;
    s.0
}

pub struct User(pub i64);

impl<S> FromRequestParts<S> for User
where
    S: Send + Sync,
    CoreArc: FromRef<S>
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S
    ) -> Result<Self, Self::Rejection>
    {
        // get the bearer token from the Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader::<Authorization<Bearer>>>()
            .await
            .or(Err(AppError::Unauthorized))?;

        // verify the token
        let core: CoreArc = get_state(parts, state).await;
        let uid = core.verify_refresh(bearer.token())
            .await?
            .ok_or(AppError::Unauthorized)?;

        Ok(User(uid))
    }
}

pub struct DiscourseEvent<E>(pub E);

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
        let (mut parts, body) = req.into_parts();

        // check that the Content-Type is application/json
        parts.headers.get(CONTENT_TYPE)
            .and_then(|hv| hv.to_str().ok()) 
            .and_then(|ct| ct.parse::<Mime>().ok())
            .filter(|mime| mime == &APPLICATION_JSON)
            .ok_or(AppError::BadMimeType)?;

        // get the signature from the header
        let sig = match parts.headers.get("X-Discourse-Event-Signature") {
            Some(val) => match val.as_bytes().strip_prefix(b"sha256=") {
                Some(hex) => hex::decode(hex)
                    .or(Err(AppError::Unauthorized)),
                None => Err(AppError::Unauthorized)
            },
            None => Err(AppError::Unauthorized)
        }?;

        // get the body and verify the signature
        let bytes = body::to_bytes(body, usize::MAX)
            .await
            .or(Err(AppError::MalformedQuery))?;

        let duc: Arc<DiscourseUpdateConfig> = get_state(&mut parts, state)
            .await; 

        verify_signature(&bytes, &duc.secret, &sig)
            .or(Err(AppError::Unauthorized))?;

        // it checks out, parse the JSON
        let Json(payload) = Json::<T>::from_bytes(&bytes)
            .or(Err(AppError::MalformedQuery))?;

        Ok(DiscourseEvent(payload))
    }
}
