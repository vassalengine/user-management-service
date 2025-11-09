use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::request::Parts
};

pub async fn get_state<S, T>(
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
