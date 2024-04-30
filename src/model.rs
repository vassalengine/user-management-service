use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginParams {
    pub username: String,
    pub password: String
}

#[derive(Debug, Deserialize)]
pub struct SsoLoginParams {
    pub returnto: String
}

#[derive(Debug, Deserialize)]
pub struct SsoLoginResponseParams {
    pub sso: String,
    pub sig: String,
    pub returnto: String
}

#[derive(Debug, Deserialize)]
pub struct SsoLogoutResponseParams {
    pub returnto: String
}

#[derive(Debug, Deserialize)]
pub struct UserSearchParams {
    pub term: String,
    pub limit: u32
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserUpdateParams {
    pub id: u32,
    pub username: String,
    pub avatar_template: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserUpdatePost {
    pub user: UserUpdateParams
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Token {
    pub token: String
}
