use base64::{Engine as _};
use hmac::{Hmac, Mac};
use rand::distributions::{Alphanumeric, DistString};
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;

// TODO: make these configurable
const SHARED_SECRET: &[u8] = b"DSQh*Q`HQF$!hz2SuSl@";
const DISCOURSE_URL: &str = "https://forum.vassalengine.org";

pub fn make_sso_request(
    returnto: &str,
    login: bool
) -> (String, String)
{
    // generate a nonce
    let mut rng = rand::thread_rng();
    let nonce = Alphanumeric.sample_string(&mut rng, 20);

    // create a payload with the nonce and a return URL

    let payload = if login {
        format!("nonce={nonce}&return_sso_url={returnto}")
    }
    else {
        format!("nonce={nonce}&return_sso_url={returnto}&logout=true")
    };

    let b64_payload = base64::engine::general_purpose::STANDARD.encode(payload);
    let enc_payload = urlencoding::encode(&b64_payload);

    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET)
        .expect("HMAC can take key of any size");
    mac.update(b64_payload.as_bytes());

    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let hex_signature = hex::encode(code_bytes);

    let url = format!(
        "{}/session/sso_provider?sso={}&sig={}",
        DISCOURSE_URL,
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
    #[error("missing username")]
    MissingUsername,
    #[error("response nonce does not match sent nonce")]
    NonceMismatch,
    #[error("query parsing failed")]
    QueryParsing(#[from] serde_urlencoded::de::Error),
    #[error("digest verification failed")]
    Verify(#[from] digest::MacError)
}

pub fn verify_sso_response(
    sso: &str,
    sig: &str,
    nonce_expected: &str
) -> Result<(String, Option<String>), SsoResponseError>
{
    // compute the digest and check the signature
    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET)
        .expect("HMAC can take key of any size");

    mac.update(sso.as_bytes());

    let code_bytes = hex::decode(sig)?;

    mac.verify_slice(&code_bytes)?;

    // base64 decode the query
    let b = base64::engine::general_purpose::STANDARD
        .decode(sso)?;

    // unpack the query
    let qargs = serde_urlencoded::from_bytes::<HashMap<String, String>>(&b)?;

    let nonce_actual = qargs.get("nonce")
        .ok_or(SsoResponseError::NonceMismatch)?
        .to_string();

    // check that the nonce matches the one we sent
    if nonce_actual != nonce_expected {
        return Err(SsoResponseError::NonceMismatch);
    }

    // fish out the username and name
    let username = qargs.get("username")
        .ok_or(SsoResponseError::MissingUsername)?
        .to_string();

    let name = qargs.get("name").cloned();

    Ok((username, name))
}
