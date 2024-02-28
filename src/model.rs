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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Token {
    pub token: String
}
