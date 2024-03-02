use axum::{
    extract::{Path, Query, State},
    response::{Json, Redirect}
};
use axum_extra::extract::cookie::{Cookie, CookieJar};

use crate::{
    app::AppState,
    core::CoreArc,
    errors::AppError,
    model::{LoginParams, SsoLoginParams, SsoLoginResponseParams, SsoLogoutResponseParams, Token}
};

pub async fn root_get() -> &'static str {
    "hello world"
}

pub async fn login_post(
    State(state): State<AppState>,
    Json(params): Json<LoginParams>
) -> Result<Json<Token>, AppError>
{
    Ok(Json(state.core.login(&params.username, &params.password).await?))
}

fn start_sso_request(
    core: &CoreArc,
    params: &SsoLoginParams,
    jar: CookieJar,
    is_login: bool
) -> Result<(CookieJar, Redirect), AppError>
{
    let (nonce, url) = core.build_sso_request(
        &params.returnto,
        is_login
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
    State(state): State<AppState>
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&state.core, &params, jar, true)
}

pub async fn sso_logout_get(
    Query(params): Query<SsoLoginParams>,
    jar: CookieJar,
    State(state): State<AppState>
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&state.core, &params, jar, false)
}

pub async fn sso_complete_login_get(
    Query(params): Query<SsoLoginResponseParams>,
    jar: CookieJar,
    State(state): State<AppState>
) -> Result<(CookieJar, Redirect), AppError>
{
    let nonce_expected = jar.get("nonce")
        .ok_or(AppError::Unauthorized)?
        .value()
        .to_owned();

    let (username, name) = state.core.verify_sso_response(
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

pub async fn users_username_avatar_size_get(
    Path((username, size)): Path<(String, u32)>,
    State(state): State<AppState>
) -> Result<Redirect, AppError>
{
    Ok(
        Redirect::to(
            &state.core.get_avatar_url(
                &username,
                size
            ).await?
        )
    )
}
