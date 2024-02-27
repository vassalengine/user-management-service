use axum::{
    extract::Path,
    response::Json
};

use crate::{
    auth_provider::AuthProvider,
    errors::AppError,
    jwt_provider::Issuer,
    model::{LoginParams, Token}
};

pub async fn root_get() -> &'static str {
    "hello world"
}

pub async fn login_post<A, I>(
    Json(params): Json<LoginParams>,
    auth: A,
    issuer: I
) -> Result<Json<Token>, AppError>
where
    A: AuthProvider,
    I: Issuer
{
    let _r = auth.login(&params.username, &params.password).await?;
    let token = issuer.issue(&params.username, 8 * 60 * 60)?;
    Ok(Json(Token { token }))
}
