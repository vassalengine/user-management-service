use axum::{
    extract::Path,
    response::Json
};

use crate::{
    auth_provider::AuthProvider,
    avatar::get_avatar,
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

pub async fn user_avatar_get(
    Path(username): Path<String>
) -> Result<Json<String>, AppError>
{
    let url = format!("https://forum.vassalengine.org/u/{}.json", username);
    Ok(Json(get_avatar(&url).await?))
}
