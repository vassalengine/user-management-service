/*
use hmac::{Hmac, Mac};
use sha2::Sha256;
use jwt::{
    AlgorithmType, Header, SignWithKey, Token, VerifyWithKey,
    claims::{Claims, RegisteredClaims},
    header::PrecomputedAlgorithmOnlyHeader
};
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

#[derive(Debug)]
pub struct Error {
    pub message: String
}

impl<E: ToString> From<E> for Error {
    fn from(e: E) -> Self {
        Error { message: e.to_string() }    
    }
}

pub fn expiry(seconds: u64) -> Result<u64, SystemTimeError> {
    Ok(
        (
            SystemTime::now().duration_since(UNIX_EPOCH)? +
            Duration::from_secs(seconds)
        ).as_secs()
    )
}

pub fn issue(key: &[u8], username: &str, expiry: u64) -> Result<String, Error> {

    let key: Hmac<Sha256> = Hmac::new_from_slice(key)?;

    let header = PrecomputedAlgorithmOnlyHeader(AlgorithmType::Hs256);

    let claims = RegisteredClaims {
        subject: Some(username.into()),
        expiration: Some(expiry),
        ..Default::default()
    };

    Ok(Token::new(header, claims).sign_with_key(&key)?.into())
}

pub fn verify(key: &[u8], token_str: &str) -> Result<String, Error> {

    let key: Hmac<Sha256> = Hmac::new_from_slice(key)?;
    let token: Token<Header, Claims, _> = Token::parse_unverified(token_str)?;
    let token = token.verify_with_key(&key)?;
//    let token: Token<Header, Claims, _> = token_str.verify_with_key(&key)?;

    println!("{:?}", token.header());
    println!("{:?}", token.claims());

    Ok(
        token.claims().registered.subject
            .clone()
            .ok_or("Missing sub claim")?
            .to_owned()
    )
}
*/

use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};

#[derive(Debug)]
pub struct Error {
    pub message: String
}

impl<E: ToString> From<E> for Error {
    fn from(e: E) -> Self {
        Error { message: e.to_string() }    
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    exp: u64
}

pub fn issue(key: &[u8], username: &str, expiry: u64) -> Result<String, Error> {
    let claims = Claims {
        sub: username.into(),
        exp: expiry
    };

    let key = EncodingKey::from_secret(key);

    Ok(encode(&Header::default(), &claims, &key)?)
}

pub fn verify(key: &[u8], token_str: &str) -> Result<String, Error> {
    let key = DecodingKey::from_secret(key);

    let token = decode::<Claims>(token_str, &key, &Validation::default())?;
    println!("{:?}", token);
    Ok(token.claims.sub)
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: &[u8] = b"@wlD+3L)EHdv28u)OFWx@83_*TxhVf9IdUncaAz6ICbM~)j+dH=sR2^LXp(tW31z";

    #[test]
    fn issue_ok() {
//        assert_eq!(issue(KEY, "skroob").unwrap(), "");
        assert_eq!(issue(KEY, "skroob", 1693870400).unwrap(), "");
    }

    #[test]
    fn verify_ok() {

        assert_eq!(verify(KEY, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJza3Jvb2IiLCJleHAiOjE2OTM4NzA0MDB9.JImeUPCkOiA6h-dh-Ef-iXCJW65UAx-pcdABOnBfO0U").unwrap(), "skroob");

    }

    #[test]
    fn verify_malformed() {
    }

    #[test]
    fn verify_no_subject() {
    }

    #[test]
    fn verify_expired() {
    }
}
