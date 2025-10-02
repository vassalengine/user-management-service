use jsonwebtoken::{Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("{0}")]
pub struct Error(#[from] jsonwebtoken::errors::Error);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Claims {
    pub sub: i64,
    pub iat: i64,
    pub exp: i64
}

#[derive(Clone)]
pub struct DecodingKey(jsonwebtoken::DecodingKey);

impl DecodingKey {
    pub fn from_secret(secret: &[u8]) -> Self {
        DecodingKey(jsonwebtoken::DecodingKey::from_secret(secret))
    }
}

pub fn verify(token: &str, key: &DecodingKey) -> Result<Claims, Error> {
    Ok(
        jsonwebtoken::decode::<Claims>(
            token,
            &key.0,
            &Validation::default()
        )?.claims
    )
}

#[derive(Clone)]
pub struct EncodingKey(jsonwebtoken::EncodingKey);

impl EncodingKey {
    pub fn from_secret(secret: &[u8]) -> Self {
        EncodingKey(jsonwebtoken::EncodingKey::from_secret(secret))
    }
}


pub fn issue(
    key: &EncodingKey,
    uid: i64,
    now: i64,
    expiry: i64
) -> Result<String, Error>
{
    let claims = Claims {
        sub: uid,
        iat: now,
        exp: expiry
    };

    Ok(jsonwebtoken::encode(&Header::default(), &claims, &key.0)?)
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY: &[u8] = b"@wlD+3L)EHdv28u)OFWx@83_*TxhVf9IdUncaAz6ICbM~)j+dH=sR2^LXp(tW31z";

    #[test]
    fn issue_ok() {
        let key = EncodingKey::from_secret(KEY);
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjQyLCJpYXQiOjAsImV4cCI6MTY5Mzg3MDQwMH0.qhkix8B5de6C1sJLPjUHwpMjU5xdP2YscqJtGOMb1Nc";
        assert_eq!(issue(&key, 42, 0, 1693870400).unwrap(), tok);
    }

    #[test]
    fn verify_ok() {
        // It's not possible to mock out std::SystemTime::now(), which
        // is used by jsonwebtoken to check expriation timestamps. The
        // encoded token has its expiration timestamp set to 899999999999,
        // which is in the year 30489. If you are still using this in the
        // year 30489, please accept my appologies for the failing test.

        /*
            {"typ": "JWT","alg": "HS256"}
            {"sub": 42, "iat": 0, "exp": 899999999999}
        */
        let key = DecodingKey::from_secret(KEY);
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjQyLCJpYXQiOjAsImV4cCI6ODk5OTk5OTk5OTk5fQ.TBKloSqXbgTRVlup1kK-SvOIPBPKWQ2Glx9wtxcCAbY";
        assert_eq!(
            verify(tok, &key).unwrap(),
            Claims {
                sub: 42,
                exp: 899999999999,
                iat: 0
            }
        );
    }

    #[test]
    fn verify_malformed() {
        let key = DecodingKey::from_secret(KEY);
        let tok = "bogus";
        assert!(verify(tok, &key).is_err());
    }

    #[test]
    fn verify_no_subject() {
        /*
            {"typ": "JWT","alg": "HS256"}
            {"exp": 1693870400}
        */
        let key = DecodingKey::from_secret(KEY);
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2OTM4NzA0MDB9.4OsPnUn4ea-v4f85Eb3WtBb7qQWXEWQjjxdn058IQhc";
        assert!(verify(tok, &key).is_err());
    }

    #[test]
    fn verify_expired() {
        // This test will fail if you run it before 1970. Don't do that.

        /*
            {"typ": "JWT","alg": "HS256"}
            {"exp": 0}
        */
        let key = DecodingKey::from_secret(KEY);
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjB9.RluhbuoRzQ_dryWPSrvOuO7K9TW-dUy4aENfybjoeCI";
        assert!(verify(tok, &key).is_err());
    }
}
