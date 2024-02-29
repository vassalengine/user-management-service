use std::sync::Arc;

#[derive(Debug)]
pub struct Config {
    pub discourse_url: String,
    pub discourse_shared_secret: Vec<u8>,
    pub jwt_key: Vec<u8>
}

pub type ConfigArc = Arc<Config>;
