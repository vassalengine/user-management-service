use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginParams {
    pub username: String,
    pub password: String
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Token {
    pub token: String
}
