use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Error {
    pub message: String
}

pub trait Issuer {
    fn issue(&self, username: &str, duration: u64) -> Result<String, Error>;
}

pub trait Verifier {
    fn verify(&self, token: &str) -> Result<String, Error>;
}
