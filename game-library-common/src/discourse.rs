use axum::{
    body::{self, Body, Bytes},
    response::Json,
    http::header::CONTENT_TYPE
};
use http::header::HeaderMap;
use mime::{APPLICATION_JSON, Mime};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::signature::verify_signature;

#[derive(Debug, Error)]
pub enum DiscourseEventError {
    #[error("Unsupported media type")]
    BadMimeType,
    #[error("Bad request")]
    MalformedQuery,
    #[error("Unauthorized")]
    Unauthorized
}

fn check_json_type(headers: &HeaderMap) -> Result<(), DiscourseEventError> {
    // check that the Content-Type is application/json
    headers.get(CONTENT_TYPE)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|ct| ct.parse::<Mime>().ok())
        .filter(|mime| mime == &APPLICATION_JSON)
        .and(Some(()))
        .ok_or(DiscourseEventError::BadMimeType)
}

fn get_signature(headers: &HeaderMap) -> Result<Vec<u8>, DiscourseEventError> {
    // get the signature from the header
    match headers.get("X-Discourse-Event-Signature") {
        Some(val) => match val.as_bytes().strip_prefix(b"sha256=") {
            Some(hex) => hex::decode(hex)
                .or(Err(DiscourseEventError::Unauthorized)),
            None => Err(DiscourseEventError::Unauthorized)
        },
        None => Err(DiscourseEventError::Unauthorized)
    }
}

async fn get_bytes(body: Body) -> Result<Bytes, DiscourseEventError> {
    // get the body and verify the signature
    body::to_bytes(body, usize::MAX)
        .await
        .or(Err(DiscourseEventError::MalformedQuery))
}

pub async fn parse_event<T>(
    headers: &HeaderMap,
    body: Body,
    secret: &[u8]
) -> Result<T, DiscourseEventError>
where
    T: DeserializeOwned
{
    check_json_type(headers)?;
    let sig = get_signature(headers)?;
    let bytes = get_bytes(body).await?;

    verify_signature(&bytes, secret, &sig)
        .or(Err(DiscourseEventError::Unauthorized))?;

    // it checks out, parse the JSON
    Json::<T>::from_bytes(&bytes)
        .map(|j| j.0)
        .or(Err(DiscourseEventError::MalformedQuery))
}
