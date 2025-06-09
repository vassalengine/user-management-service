use axum::{
    extract::{Path, Query, State},
    response::{Json, Redirect}
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::OffsetDateTime;
use serde_json::Value;

use crate::{
    core::CoreArc,
    errors::AppError,
    extractors::{DiscourseEvent, User},
    model::{LoginParams, LoginResponse, RefreshResponse, SsoLoginParams, SsoLoginResponseParams, SsoLogoutResponseParams, UserSearchParams, UserUpdatePost}
};

pub async fn root_get() -> &'static str {
    "hello world"
}

pub async fn login_post(
    State(core): State<CoreArc>,
    Json(params): Json<LoginParams>
) -> Result<Json<LoginResponse>, AppError>
{
    let resp = core.login(&params.username, &params.password).await?;
    let uid = resp.pointer("/user/id")
        .and_then(Value::as_i64)
        .ok_or(AppError::InternalError)?;

    Ok(Json(LoginResponse {
        access: core.issue_access(uid)?.0,
        refresh: core.issue_refresh(uid).await?.0
    }))
}

pub async fn refresh_post(
    user: User,
    State(core): State<CoreArc>
) -> Result<Json<RefreshResponse>, AppError>
{
    Ok(Json(RefreshResponse {
        token: core.issue_access(user.0)?.0
    }))
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
    State(core): State<CoreArc>
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&core, &params, jar, true)
}

pub async fn sso_logout_get(
    Query(params): Query<SsoLoginParams>,
    jar: CookieJar,
    State(core): State<CoreArc>
) -> Result<(CookieJar, Redirect), AppError> {
    start_sso_request(&core, &params, jar, false)
}

pub async fn sso_complete_login_get(
    Query(params): Query<SsoLoginResponseParams>,
    jar: CookieJar,
    State(core): State<CoreArc>
) -> Result<(CookieJar, Redirect), AppError>
{
    let nonce_expected = jar.get("nonce")
        .ok_or(AppError::Unauthorized)?
        .value()
        .to_owned();

    let (uid, username, name) = core.verify_sso_response(
        &nonce_expected,
        &params.sso,
        &params.sig
    )?;

// TODO: Set exipiry on cookies other than access token to match refresh token
// TODO: Access token can be a session token?

    let (access_token, access_exp) = core.issue_access(uid)?;
    let (refresh_token, refresh_exp) = core.issue_refresh(uid).await?;

    let access_exp = OffsetDateTime::from_unix_timestamp(access_exp)
        .or(Err(AppError::InternalError))?;

    let refresh_exp = OffsetDateTime::from_unix_timestamp(refresh_exp)
        .or(Err(AppError::InternalError))?;

    let jar = if let Some(name) = name {
        jar.add(Cookie::build(("name", name))
            .path("/")
            .secure(true)
            .same_site(SameSite::Lax)
            .expires(refresh_exp)
        )
    }
    else {
        jar
    }
    .remove(Cookie::from("nonce"))
    .add(Cookie::build(("username", username))
        .path("/")
        .secure(true)
        .same_site(SameSite::Lax)
        .expires(refresh_exp)
    )
    .add(Cookie::build(("token", access_token))
        .path("/")
        .secure(true)
        .same_site(SameSite::Lax)
        .expires(access_exp)
    )
    .add(Cookie::build(("refresh", refresh_token))
        .path("/")
        .secure(true)
        .same_site(SameSite::Lax)
        .expires(refresh_exp)
    );

    Ok((jar, Redirect::to(&params.returnto)))
}

pub async fn sso_complete_logout_get(
    Query(params): Query<SsoLogoutResponseParams>,
    jar: CookieJar,
    State(core): State<CoreArc>
) -> Result<(CookieJar, Redirect), AppError>
{
    if let Some(refresh_token) = jar.get("refresh").map(Cookie::value) {
        core.revoke_refresh(refresh_token).await?;
    }

    Ok(
        (
            jar
                .remove(Cookie::build("name").path("/"))
                .remove(Cookie::build("nonce"))
                .remove(Cookie::build("token").path("/"))
                .remove(Cookie::build("refresh").path("/"))
                .remove(Cookie::build("username").path("/")),
            Redirect::to(&params.returnto)
        )
    )
}

/*
pub async fn users_get(
    Query(params): Query<UserSearchParams>,
    State(state): State<AppState>
) -> Result<Redirect, AppError>
{
    Ok(
        Redirect::to(
            &state.core.get_user_search_url(&params.term, params.limit)?
        )
    )
}
*/

// FIXME: temporary CORS workaround
pub async fn users_get(
    Query(params): Query<UserSearchParams>,
    State(core): State<CoreArc>
) -> Result<Json<Value>, AppError>
{
    Ok(Json(core.get_user_search(&params.term, params.limit).await?))
}

pub async fn users_username_get(
    Path(username): Path<String>,
    State(core): State<CoreArc>
) -> Result<Redirect, AppError>
{
    Ok(Redirect::to(&core.get_user_url(&username)?))
}

pub async fn users_post(
    State(core): State<CoreArc>,
    DiscourseEvent(data): DiscourseEvent<UserUpdatePost>
) -> Result<(), AppError>
{
    Ok(core.update_user(&data.user).await?)
}

pub async fn users_username_avatar_size_get(
    Path((username, size)): Path<(String, u32)>,
    State(core): State<CoreArc>
) -> Result<Redirect, AppError>
{
    Ok(
        Redirect::to(
            &core.get_avatar_url(
                &username,
                size
            ).await?
        )
    )
}
