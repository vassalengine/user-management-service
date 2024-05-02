use base64::{Engine as _};
use rand::distributions::{Alphanumeric, DistString};
use std::collections::HashMap;
use thiserror::Error;

use crate::signature::{make_signature, verify_signature};

fn encode_and_sign_payload(
    payload: &str,
    secret: &[u8]
) -> (String, String) {
    // base64- and urlencode the payload
    let b64_payload = base64::engine::general_purpose::STANDARD.encode(payload);
    let enc_payload = urlencoding::encode(&b64_payload);

    // compute the signature
    let sig_bytes = make_signature(b64_payload.as_bytes(), secret);
    let sig_hex = hex::encode(sig_bytes);

    (enc_payload.into_owned(), sig_hex)
}

pub fn build_sso_request_with_nonce(
    secret: &[u8],
    discourse_url: &str,
    returnto: &str,
    is_login: bool,
    nonce: &str
) -> String
{
    // create a payload with the nonce and the return URL
    let payload = if is_login {
        format!("nonce={nonce}&return_sso_url={returnto}")
    }
    else {
        format!("nonce={nonce}&return_sso_url={returnto}&logout=true")
    };

    let (payload, sig) = encode_and_sign_payload(&payload, secret);

    // create the url
    format!(
        "{}/session/sso_provider?sso={}&sig={}",
        discourse_url,
        payload,
        sig
    )
}

pub fn build_sso_request(
    secret: &[u8],
    discourse_url: &str,
    returnto: &str,
    is_login: bool
) -> (String, String)
{
    // generate a nonce
    let mut rng = rand::thread_rng();
    let nonce = Alphanumeric.sample_string(&mut rng, 20);

    let url = build_sso_request_with_nonce(
        secret,
        discourse_url,
        returnto,
        is_login,
        &nonce
    );

    (nonce, url)
}

#[derive(Debug, Error)]
pub enum SsoResponseError {
    #[error("url decoding failed")]
    URLDecoding(#[from] std::string::FromUtf8Error),
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

pub fn verify_sso_response(
    secret: &[u8],
    nonce_expected: &str,
    sso: &str,
    sig: &str
) -> Result<(i64, String, Option<String>), SsoResponseError>
{
    // url-decode sso
    let sso = urlencoding::decode(&sso)?;

    // compute the digest and check the signature
    verify_signature(sso.as_bytes(), secret, &hex::decode(sig)?)?;

    // base64 decode the query
    let b = base64::engine::general_purpose::STANDARD.decode(sso.as_ref())?;

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn build_sso_request_ok() {
        let url = build_sso_request_with_nonce(
            b"12345",
            "https://example.com",
            "back/to/here",
            false,
            "abcde"
        );

        assert_eq!(
            url,
            "https://example.com/session/sso_provider?sso=bm9uY2U9YWJjZGUmcmV0dXJuX3Nzb191cmw9YmFjay90by9oZXJlJmxvZ291dD10cnVl&sig=7ed822c6e2478a751c87ebed29af0be2ab5dbc776dd3e71eb78d1e2bf91cb2e8"
        );
    }

    #[test]
    fn verify_sso_response_ok() {
        let secret = b"12345";
        let nonce = "abcde";
        let username = "bob";
        let name = "Robert";
        let external_id = 42;

        let payload = format!("nonce={nonce}&username={username}&name={name}&external_id={external_id}");

        let (sso, sig) = encode_and_sign_payload(&payload, secret);

        assert_eq!(
            verify_sso_response(
                secret,
                nonce,
                &sso,
                &sig
            ).unwrap(),
            (external_id, username.into(), Some(name.into()))
        )
    }

    #[test]
    fn verify_sso_response_urldecoding_error() {
        assert!(
            matches!(
                verify_sso_response(
                    b"12345",
                    "abcde",
                    "%FF",  // invalid UTF-8 byte!
                    "xxx"
                ).unwrap_err(),
                SsoResponseError::URLDecoding(_)
            )
        );
    }

    #[test]
    fn verify_sso_response_hex_decoding_error() {
        assert!(
            matches!(
                verify_sso_response(
                    b"12345",
                    "abcde",
                    "abcd",
                    "abc"   // odd length!
                ).unwrap_err(),
                SsoResponseError::HexDecoding(_)
            )
        );
    }

    #[test]
    fn verify_sso_response_verify_error() {
        assert!(
            matches!(
                verify_sso_response(
                    b"12345",
                    "abcde",
                    "abcd",
                    "abcd"  // bogus signature!
                ).unwrap_err(),
                SsoResponseError::Verify(_)
            )
        );
    }

    #[test]
    fn verify_sso_response_base64_decode_error() {
        let secret = b"12345";

        let b64 = "xyz"; // odd length!
        let enc = urlencoding::encode(&b64);

        // compute the signature
        let sig_bytes = make_signature(b64.as_bytes(), secret);
        let sig = hex::encode(sig_bytes);

        assert!(
            matches!(
                verify_sso_response(secret, "abcde", &enc, &sig).unwrap_err(),
                SsoResponseError::Base64Decoding(_)
            )
        );
    }

    #[test]
    fn verify_sso_response_nonce_mismatch_error() {
        let secret = b"12345";
        let payload = "nonce=edcba";
        let (sso, sig) = encode_and_sign_payload(&payload, secret);

        assert!(
            matches!(
                verify_sso_response(secret, "abcde", &sso, &sig).unwrap_err(),
                SsoResponseError::NonceMismatch
            )
        );
    }

    #[test]
    fn verify_sso_response_missing_username_error() {
        let secret = b"12345";
        let nonce = "abcde";
        let payload = format!("nonce={nonce}");
        let (sso, sig) = encode_and_sign_payload(&payload, secret);

        assert!(
            matches!(
                verify_sso_response(secret, nonce, &sso, &sig).unwrap_err(),
                SsoResponseError::MissingUsername
            )
        );
    }

    #[test]
    fn verify_sso_response_missing_user_id_error() {
        let secret = b"12345";
        let nonce = "abcde";
        let payload = format!("nonce={nonce}&username=bob");
        let (sso, sig) = encode_and_sign_payload(&payload, secret);

        assert!(
            matches!(
                verify_sso_response(secret, nonce, &sso, &sig).unwrap_err(),
                SsoResponseError::MissingUserId
            )
        );
    }
}
