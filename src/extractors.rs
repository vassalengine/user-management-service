use axum::{
    RequestPartsExt,
    body::Bytes,
    extract::{FromRef, FromRequest, FromRequestParts, Request},
    http::request::Parts
};
use axum_extra::{
    TypedHeader,
    headers::{
        Authorization,
        authorization::Bearer
    }
};
use glc::discourse::parse_event;
use serde::de::DeserializeOwned;
use std::sync::Arc;

use crate::{
    app::DiscourseUpdateConfig,
    core::CoreArc,
    errors::AppError,
};

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
        let core = CoreArc::from_ref(state);
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
        let (parts, body) = req.into_parts();
        let uc = Arc::<DiscourseUpdateConfig>::from_ref(state);
        let payload = parse_event(&parts.headers, body, &uc.secret).await?;
        Ok(DiscourseEvent(payload))
    }
}
