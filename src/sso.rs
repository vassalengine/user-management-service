use axum::{
    extract::Query,
    http::Uri
};
use base64::{Engine as _};
use hmac::{Hmac, Mac};
use rand::{
    self,
    distributions::{Alphanumeric, DistString}
};
use sha2::Sha256;
use std::collections::HashMap;

use crate::errors::AppError;

// TODO: make these configurable
const SHARED_SECRET: &[u8] = b"DSQh*Q`HQF$!hz2SuSl@";
const DISCOURSE_URL: &str = "https://forum.vassalengine.org";

pub fn make_sso_request(
    returnto: &str,
    login: bool
) -> Result<(String, String), AppError>
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
        .or(Err(AppError::InternalError))?;
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

    Ok((nonce, url))
}

pub fn verify_sso_response(
    sso: &str,
    sig: &str,
    returnto: &str,
    nonce_expected: &str
) -> Result<(String, Option<String>), AppError>
{
    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET)
        .or(Err(AppError::InternalError))?;

    mac.update(sso.as_bytes());

    let code_bytes = hex::decode(sig)
        .or(Err(AppError::InternalError))?;

    mac.verify_slice(&code_bytes)
        .or(Err(AppError::InternalError))?;

    let b = base64::engine::general_purpose::STANDARD
        .decode(sso)
        .or(Err(AppError::InternalError))?;

    let q = String::from_utf8(b)
        .or(Err(AppError::InternalError))?;

    let args = format!("/?{}", q);

    let uri: Uri = args.parse()
        .or(Err(AppError::InternalError))?;

    let Query(qargs): Query<HashMap<String, String>> = Query::try_from_uri(&uri)
        .or(Err(AppError::InternalError))?;

//    println!("{}", serde_json::to_string_pretty(&json!(qargs)).unwrap());
//    println!("{}", returnto);

    let nonce_actual = qargs.get("nonce")
        .ok_or(AppError::InternalError)?
        .to_string();

    // check that the nonce matches the one we sent
    if nonce_actual != nonce_expected {
        return Err(AppError::InternalError);
    }

    let username = qargs.get("username")
        .ok_or(AppError::InternalError)?
        .to_string();

    let name = qargs.get("name").cloned();

    Ok((username, name))
}
