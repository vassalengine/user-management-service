use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JWTError(#[from] jsonwebtoken::errors::Error);

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: i64,
    iat: i64,
    exp: i64
}

fn issue(
    key: &EncodingKey,
    uid: i64,
    now: i64,
    expiry: i64
) -> Result<String, JWTError>
{
    let claims = Claims {
        sub: uid,
        iat: now,
        exp: expiry
    };

    Ok(encode(&Header::default(), &claims, key)?)
}

fn verify(key: &DecodingKey, token_str: &str) -> Result<i64, JWTError> {
    let token = decode::<Claims>(token_str, key, &Validation::default())?;
    Ok(token.claims.sub)
}

pub struct JWTIssuer {
    key: EncodingKey
}

impl JWTIssuer {
    pub fn new(key: &[u8]) -> Self {
        JWTIssuer {
            key: EncodingKey::from_secret(key)
        }
    }

    pub fn issue(
        &self,
        uid: i64,
        now: i64,
        duration: i64
    ) -> Result<String, JWTError>
    {
        issue(&self.key, uid, now, now + duration)
    }
}

pub struct JWTVerifier {
    key: DecodingKey
}

impl JWTVerifier {
    pub fn new(key: &[u8]) -> Self {
        JWTVerifier {
            key: DecodingKey::from_secret(key)
        }
    }

    pub fn verify(&self, token: &str) -> Result<i64, JWTError> {
        verify(&self.key, token)
    }
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
        assert_eq!(verify(&key, tok).unwrap(), 42);
    }

    #[test]
    fn verify_malformed() {
        let key = DecodingKey::from_secret(KEY);
        let tok = "bogus";
        assert!(verify(&key, tok).is_err());
    }

    #[test]
    fn verify_no_subject() {
        /*
            {"typ": "JWT","alg": "HS256"}
            {"exp": 1693870400}
        */
        let key = DecodingKey::from_secret(KEY);
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2OTM4NzA0MDB9.4OsPnUn4ea-v4f85Eb3WtBb7qQWXEWQjjxdn058IQhc";
        assert!(verify(&key, tok).is_err());
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
        assert!(verify(&key, tok).is_err());
    }
}
