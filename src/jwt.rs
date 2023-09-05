use crate::jwt_provider::{Error, Issuer, Verifier};

use jsonwebtoken::{encode, decode, get_current_timestamp, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};

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

fn issue(key: &EncodingKey, username: &str, expiry: u64) -> Result<String, Error> {
    let claims = Claims {
        sub: username.into(),
        exp: expiry
    };

    Ok(encode(&Header::default(), &claims, &key)?)
}

fn verify(key: &DecodingKey, token_str: &str) -> Result<String, Error> {
    let token = decode::<Claims>(token_str, &key, &Validation::default())?;
    Ok(token.claims.sub)
}

pub struct JWTIssuer {
    key: EncodingKey
}

impl Issuer for JWTIssuer {
    fn issue(&self, username: &str, duration: u64) -> Result<String, Error> {
        issue(&self.key, username, get_current_timestamp() + duration)
    }
}

pub struct JWTVerifier {
    key: DecodingKey
}

impl Verifier for JWTVerifier {
    fn verify(&self, token: &str) -> Result<String, Error> {
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
        let tok = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJza3Jvb2IiLCJleHAiOjE2OTM4NzA0MDB9.V_54o3AwhkPcIdP-2Pea3MJ2vS82hF8EA0wFseCv3ho";
        assert_eq!(issue(&key, "skroob", 1693870400).unwrap(), tok);
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
            {"sub": "skroob", "exp": 899999999999}
        */
        let key = DecodingKey::from_secret(KEY);
        let tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJza3Jvb2IiLCJleHAiOjg5OTk5OTk5OTk5OX0.9fL6Jbac5rsqs5G0h-0xkLaC2_m2lk0sZkfO3-1UnCQ";
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
