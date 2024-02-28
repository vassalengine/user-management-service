use axum::{
    extract::{Path, Query},
    response::{Json, Redirect}
};
use axum_extra::extract::cookie::{Cookie, CookieJar};

use crate::{
    auth_provider::AuthProvider,
    avatar::get_avatar,
    errors::AppError,
    jwt_provider::Issuer,
    model::{LoginParams, SsoLoginParams, SsoLoginResponseParams, SsoLogoutResponseParams, Token},
    sso::{make_sso_request, verify_sso_response}
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

fn start_sso_request(
    params: &SsoLoginParams,
    jar: CookieJar,
    login: bool
) -> Result<(CookieJar, Redirect), AppError>
{
    let (nonce, url) = make_sso_request(&params.returnto, login);
    Ok(
        (
            jar.add(Cookie::new("nonce", nonce)),
            Redirect::to(&url)
        )
    )
}

pub async fn sso_login_get(
    Query(params): Query<SsoLoginParams>,
    jar: CookieJar
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&params, jar, true)
}

pub async fn sso_logout_get(
    Query(params): Query<SsoLoginParams>,
    jar: CookieJar
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&params, jar, false)
}

pub async fn sso_complete_login_get(
    Query(params): Query<SsoLoginResponseParams>,
    jar: CookieJar
) -> Result<(CookieJar, Redirect), AppError>
{
    let nonce_expected = jar.get("nonce")
        .ok_or(AppError::InternalError)?
        .value()
        .to_owned();

    let (username, name) = verify_sso_response(
        &params.sso,
        &params.sig,
        &nonce_expected
    )?;

    let jar = if let Some(name) = name {
        jar.add(Cookie::new("name", name))
    }
    else {
        jar
    }
    .remove(Cookie::from("nonce"))
    .add(Cookie::new("username", username));

    Ok((jar, Redirect::to(&params.returnto)))
}

pub async fn sso_complete_logout_get(
    Query(params): Query<SsoLogoutResponseParams>,
    jar: CookieJar
) -> Result<(CookieJar, Redirect), AppError>
{
    Ok(
        (
            jar.remove(Cookie::from("nonce"))
                .remove(Cookie::from("username"))
                .remove(Cookie::from("name")),
            Redirect::to(&params.returnto)
        )
    )
}

pub async fn user_avatar_get(
    Path(username): Path<String>
) -> Result<Json<String>, AppError>
{
// FIXME: don't hard-code URL
    let url = format!("https://forum.vassalengine.org/u/{}.json", username);
    Ok(Json(get_avatar(&url).await?))
}
