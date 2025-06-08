use axum::{
    extract::{Path, Query, State},
    response::{Json, Redirect}
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration;
use serde_json::Value;

use crate::{
    core::CoreArc,
    errors::AppError,
    extractors::DiscourseEvent,
    jwt::Claims,
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
        access: core.issue_access(uid)?,
        refresh: core.issue_refresh(uid)?
    }))
}

pub async fn refresh_post(
    claims: Claims,
    State(core): State<CoreArc>
) -> Result<Json<RefreshResponse>, AppError>
{
    Ok(Json(RefreshResponse {
        token: core.issue_access(claims.sub)?
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

    let access_token = core.issue_access(uid)?;
    let refresh_token = core.issue_refresh(uid)?;

    let jar = if let Some(name) = name {
        jar.add(Cookie::build(("name", name))
            .path("/").same_site(SameSite::Lax)
        )
    }
    else {
        jar
    }
    .remove(Cookie::from("nonce"))
    .add(Cookie::build(("username", username))
        .path("/")
        .same_site(SameSite::Lax)
    )
    .add(Cookie::build(("token", access_token))
        .path("/")
        .secure(true)
        .same_site(SameSite::Lax)
// FIXME: temporary
        .max_age(Duration::minutes(1))
    )
    .add(Cookie::build(("refresh", refresh_token))
        .path("/")
        .secure(true)
        .same_site(SameSite::Lax)
    );

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
