use jsonwebtoken::{encode, decode, get_current_timestamp, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JWTError(#[from] jsonwebtoken::errors::Error);

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64
}

fn issue(
    key: &EncodingKey,
    username: &str,
    now: i64,
    expiry: i64
) -> Result<String, JWTError>
{
    let claims = Claims {
        sub: username.into(),
        iat: now,
        exp: expiry
    };

    Ok(encode(&Header::default(), &claims, key)?)
}

fn verify(key: &DecodingKey, token_str: &str) -> Result<String, JWTError> {
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
        username: &str,
        now: i64,
        duration: i64
    ) -> Result<String, JWTError>
    {
        issue(&self.key, username, now, now + duration)
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

    pub fn verify(&self, token: &str) -> Result<String, JWTError> {
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
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJza3Jvb2IiLCJpYXQiOjAsImV4cCI6MTY5Mzg3MDQwMH0.iAuKl7Q-ufqXYXGhxXYmyIUx0VO8rKEtNHMxZ8iw3CU";
        assert_eq!(issue(&key, "skroob", 0, 1693870400).unwrap(), tok);
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
            {"sub": "skroob", "iat": 0, "exp": 899999999999}
        */
        let key = DecodingKey::from_secret(KEY);
        let tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJza3Jvb2IiLCJpYXQiOjAsImV4cCI6ODk5OTk5OTk5OTk5fQ.eMEa-zrRyWnnoFn2FsTuv-Q40ah6vbE10Dw4JLuKbZ8";
        assert_eq!(verify(&key, tok).unwrap(), "skroob");
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
