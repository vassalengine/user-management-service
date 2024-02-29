use axum::{
    extract::{Path, Query, State},
    response::{Json, Redirect}
};
use axum_extra::extract::cookie::{Cookie, CookieJar};

use crate::{
    app::AppState,
    auth_provider::AuthProvider,
    config::{Config, ConfigArc},
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
    config: &Config,
    params: &SsoLoginParams,
    jar: CookieJar,
    login: bool
) -> Result<(CookieJar, Redirect), AppError>
{
    let (nonce, url) = make_sso_request(
        &config.discourse_shared_secret,
        &config.discourse_url,
        &params.returnto,
        login
    );

    Ok(
        (
            jar.add(Cookie::new("nonce", nonce)),
            Redirect::to(&url)
        )
    )
}

pub async fn sso_login_get(
    Query(params): Query<SsoLoginParams>,
    jar: CookieJar,
    State(config): State<ConfigArc>
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&config, &params, jar, true)
}

pub async fn sso_logout_get(
    Query(params): Query<SsoLoginParams>,
    jar: CookieJar,
    State(config): State<ConfigArc>
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&config, &params, jar, false)
}

pub async fn sso_complete_login_get(
    Query(params): Query<SsoLoginResponseParams>,
    jar: CookieJar,
    State(config): State<ConfigArc>
) -> Result<(CookieJar, Redirect), AppError>
{
    let nonce_expected = jar.get("nonce")
        .ok_or(AppError::Unauthorized)?
        .value()
        .to_owned();

    let (username, name) = verify_sso_response(
        &config.discourse_shared_secret,
        &nonce_expected,
        &params.sso,
        &params.sig
    )?;

    // TODO: issue JWT and return it with the cookies

    let jar = if let Some(name) = name {
        jar.add(Cookie::build(("name", name)).path("/"))
    }
    else {
        jar
    }
    .remove(Cookie::from("nonce"))
    .add(Cookie::build(("username", username)).path("/"));

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
                .remove(Cookie::build(("username", "")).path("/"))
                .remove(Cookie::build(("name", "")).path("/")),
            Redirect::to(&params.returnto)
        )
    )
}

#[axum::debug_handler]
pub async fn users_username_avatar_size_get(
    Path((username, size)): Path<(String, u32)>,
    State(state): State<AppState>
) -> Result<Redirect, AppError>
{
    Ok(
        Redirect::to(
            &state.core.get_avatar_url(
                &state.config.discourse_url,
                &username,
                size
            ).await?
        )
    )
}
