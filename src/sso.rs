use base64::{Engine as _};
use hmac::{Hmac, Mac};
use rand::distributions::{Alphanumeric, DistString};
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;

pub fn build_sso_request(
    shared_secret: &[u8],
    discourse_url: &str,
    returnto: &str,
    is_login: bool
) -> (String, String)
{
    // generate a nonce
    let mut rng = rand::thread_rng();
    let nonce = Alphanumeric.sample_string(&mut rng, 20);

    // create a payload with the nonce and the return URL
    let payload = if is_login {
        format!("nonce={nonce}&return_sso_url={returnto}")
    }
    else {
        format!("nonce={nonce}&return_sso_url={returnto}&logout=true")
    };

    // base64- and urlencode the payload
    let b64_payload = base64::engine::general_purpose::STANDARD.encode(payload);
    let enc_payload = urlencoding::encode(&b64_payload);

    // compute the signature
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
        .expect("HMAC can take key of any size");
    mac.update(b64_payload.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let hex_signature = hex::encode(code_bytes);

    // create the url
    let url = format!(
        "{}/session/sso_provider?sso={}&sig={}",
        discourse_url,
        enc_payload,
        hex_signature
    );

    (nonce, url)
}

#[derive(Debug, Error)]
pub enum SsoResponseError {
    #[error("base64 decoding failed")]
    Base64Decoding(#[from] base64::DecodeError),
    #[error("hex decoding failed")]
    HexDecoding(#[from] hex::FromHexError),
    #[error("missing user id")]
    MissingUserId,
    #[error("missing username")]
    MissingUsername,
    #[error("response nonce does not match sent nonce")]
    NonceMismatch,
    #[error("query parsing failed")]
    QueryParsing(#[from] serde_urlencoded::de::Error),
    #[error("digest verification failed")]
    Verify(#[from] digest::MacError)
}

// TODO: test
pub fn verify_sso_response(
    shared_secret: &[u8],
    nonce_expected: &str,
    sso: &str,
    sig: &str
) -> Result<(i64, String, Option<String>), SsoResponseError>
{
    // compute the digest and check the signature
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
        .expect("HMAC can take key of any size");
    mac.update(sso.as_bytes());
    let code_bytes = hex::decode(sig)?;
    mac.verify_slice(&code_bytes)?;

    // base64 decode the query
    let b = base64::engine::general_purpose::STANDARD.decode(sso)?;

    // unpack the query
    let qargs = serde_urlencoded::from_bytes::<HashMap<String, String>>(&b)?;

    // check that the nonce matches the one we sent
    qargs.get("nonce")
        .filter(|nonce_actual| *nonce_actual == nonce_expected)
        .ok_or(SsoResponseError::NonceMismatch)?;

    // fish out the username and name
    let username = qargs.get("username")
        .ok_or(SsoResponseError::MissingUsername)?
        .to_string();

    let name = qargs.get("name").cloned();

    let uid = qargs.get("external_id")
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or(SsoResponseError::MissingUserId)?;

    Ok((uid, username, name))
}
