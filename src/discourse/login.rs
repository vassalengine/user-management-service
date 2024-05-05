use axum::async_trait;
use itertools::Itertools;
use mime::APPLICATION_JSON;
use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, COOKIE}
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

use crate::auth_provider::{AuthProvider, Error, Failure};

impl From<reqwest::Error> for Failure {
    fn from(e: reqwest::Error) -> Self {
        Failure::Error(Error {
            status: e.status().map(|s| s.as_u16()),
            message: e.to_string()
        })
    }
}

impl Error {
    async fn from(r: reqwest::Response) -> Self {
        Error {
            status: Some(r.status().as_u16()),
            message: r.text().await.unwrap_or_else(|e| e.to_string())
        }
    }
}

#[derive(Deserialize, Serialize)]
struct CsrfResult {
    csrf: String
}

async fn get_csrf(client: &Client, url: &str) -> Result<(String, String), Failure> {
    // do the GET
    let response = client.get(url)
        .header(ACCEPT, APPLICATION_JSON.as_ref())
        .send()
        .await?
        .error_for_status()?;

    // non-200 results are errors
    if response.status() != StatusCode::OK {
        return Err(Failure::Error(Error::from(response).await));
    }

    // collect the returned cookies
    let cookies = response.cookies()
        .map(|c| format!("{}={}", c.name(), c.value()))
        .join("; ");

    // return the token and the cookies
    Ok((response.json::<CsrfResult>().await?.csrf, cookies))
}

#[derive(Serialize)]
struct LoginParams<'a> {
    login: &'a str,
    password: &'a str,
    authenticity_token: &'a str
}

#[derive(Deserialize, Serialize)]
struct LoginFailure {
    error: String
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LoginResult {
    Failure(LoginFailure),
    Success(Value)
}

async fn post_login(
    client: &Client,
    url: &str,
    params: &LoginParams<'_>,
    cookies: &str
) -> Result<Value, Failure>
{
    let response = client.post(url)
        .json(params)
        .header(ACCEPT, APPLICATION_JSON.as_ref())
        .header(COOKIE, cookies)
        .send()
        .await?
        .error_for_status()?;

    let status = response.status();

    // non-200 results are errors
    if status != StatusCode::OK {
        return Err(Failure::Error(Error::from(response).await));
    }

    // Successful login returns a JSON blob.
    // Failed login returns JSON with an "error" key.
    match response.json::<LoginResult>().await? {
        LoginResult::Failure(_) => Err(Failure::Unauthorized),
        LoginResult::Success(r) => Ok(r)
    }
}

#[derive(Clone)]
pub struct DiscourseAuth {
    client: Client,
    csrf_url: String,
    login_url: String
}

const CSRF_ENDPOINT: &str = "/session/csrf.json";
const LOGIN_ENDPOINT: &str = "/session.json";

impl DiscourseAuth {
    pub fn new(url: &str) -> DiscourseAuth {
        DiscourseAuth {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            csrf_url: url.to_string() + CSRF_ENDPOINT,
            login_url: url.to_string() + LOGIN_ENDPOINT,
        }
    }
}

#[async_trait]
impl AuthProvider for DiscourseAuth {
    async fn login(&self, username: &str, password: &str) -> Result<Value, Failure> {
        let csrf = get_csrf(&self.client, &self.csrf_url).await?;

        let params = LoginParams {
            login: username,
            password,
            authenticity_token: &csrf.0
        };

        post_login(&self.client, &self.login_url, &params, &csrf.1).await
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use const_format::concatcp;
    use reqwest::dns::{Name, Resolve, Resolving};
    use serde_json::json;
    use std::io;
    use wiremock::{MockServer, Mock, ResponseTemplate, matchers};

    async fn setup_server(
        method: &str,
        endpoint: &str,
        rt: ResponseTemplate
    ) -> MockServer
    {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method(method))
            .and(matchers::path(endpoint))
            .respond_with(rt)
            .expect(1)
            .mount(&mock_server)
            .await;

        mock_server
    }

    async fn do_get_csrf(rt: ResponseTemplate) ->  Result<(String, String), Failure> {
        let mock_server = setup_server("GET", CSRF_ENDPOINT, rt).await;
        let client = Client::builder().build().unwrap();
        let url = mock_server.uri() + CSRF_ENDPOINT;
        get_csrf(&client, &url).await
    }

    const CSRF_COOKIE: &str = "_forum_session=CtNZjn%2FfXih4Rm1MSAB7EYxESfyxD4reX%2B0kLVzcjtDMXtY4hQkTvNox0%2B0%2B%2FlMwK0KKL9RbxeZFIRaOyDwA7GzlvRNX5nMhcp1Hr67ASKbUiwgdkJ1GxdIupTKG11Z1gkORI0B82oFvqwaIzOp3oTS9pn%2FThjHiBrZzMm%2BoJ%2F8ZXCcghRr0HFiBclg47ZIyey2tV%2BjUSCk16ewS4OGggzIBjSvb3bfR3vQtoYe4CWXW4S4Qo05R4OpYSyqigjvS%2FlS9kFKkv21boD%2FP%2FQK7Bc8xO%2FidCw%3D%3D--pBXLYbCbJA8tU3C3--rPovZg2sWFwkNj11Xm0FUg%3D%3D";

    const CSRF_SET_COOKIE: &str = concatcp!(CSRF_COOKIE, "; path=/; secure; HttpOnly; SameSite=Lax");

    const CSRF_TOKEN: &str = "4Q5FOfoKCiVkkODdx2Pq--eKeI1o29Ap1ooRWUO5QIubwWYn6_v6Rhy1x4UiP6Gb3U8FPLHTQ8uxjalN3Ri-Uw";

    #[tokio::test]
    async fn get_csrf_ok() {
        let rt = ResponseTemplate::new(200)
            .insert_header(
                "Set-Cookie",
                CSRF_SET_COOKIE
            )
            .set_body_json(
                CsrfResult {
                    csrf: CSRF_TOKEN.into()
                }
            );

        let result = do_get_csrf(rt).await.unwrap();
        assert_eq!(result.0, CSRF_TOKEN);
        assert_eq!(result.1, CSRF_COOKIE);
    }

    #[tokio::test]
    async fn get_csrf_truncated_json() {
        let json = serde_json::to_vec(
            &CsrfResult {
                csrf: CSRF_TOKEN.into()
            }
        ).unwrap();

        let rt = ResponseTemplate::new(200)
            .set_body_raw(
                // purposely truncate the JSON
                &json[..&json.len() - 1],
                APPLICATION_JSON.as_ref()
            );

        let result = do_get_csrf(rt).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn get_csrf_wrong_json() {
        let rt = ResponseTemplate::new(200)
            .set_body_json(
                json!({"extra": "more!"})
            );

        let result = do_get_csrf(rt).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn get_csrf_extra_json() {
        let rt = ResponseTemplate::new(200)
            .insert_header(
                "Set-Cookie",
                CSRF_SET_COOKIE
            )
            .set_body_json(
                json!(
                    {
                        "csrf": CSRF_TOKEN,
                        "extra": "more!"
                    }
                )
            );

        let result = do_get_csrf(rt).await.unwrap();
        assert_eq!(result.0, CSRF_TOKEN);
        assert_eq!(result.1, CSRF_COOKIE);
    }

    #[tokio::test]
    async fn get_csrf_not_json() {
        let rt = ResponseTemplate::new(200)
            .set_body_string("this is not JSON");

        let result = do_get_csrf(rt).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn get_csrf_wrong_type_of_success() {
        let rt = ResponseTemplate::new(201);

        let result = do_get_csrf(rt).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, Some(201));
        assert_eq!(err.message, "");
    }

    #[tokio::test]
    async fn get_csrf_error() {
        let rt = ResponseTemplate::new(418);

        let result = do_get_csrf(rt).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, Some(418));
    }

    async fn do_post_login(
        rt: ResponseTemplate,
        params: &LoginParams<'_>,
        cookies: &str
    ) ->  Result<Value, Failure>
    {
        let mock_server = setup_server("POST", LOGIN_ENDPOINT, rt).await;
        let client = Client::builder().build().unwrap();
        let url = mock_server.uri() + LOGIN_ENDPOINT;
        post_login(&client, &url, params, cookies).await
    }

    #[tokio::test]
    async fn post_login_ok() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let json = json!({ "user": "stuff" });

        let rt = ResponseTemplate::new(200)
            .set_body_json(json.clone());

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap();
        assert_eq!(result, json);
    }

    #[tokio::test]
    async fn post_login_truncated_json() {
        // This differs from get_csrf() in that we parse the JSON it returns,
        // but only pass on the JSON string returned by post_login().

        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let json = json!({ "user": "stuff" }).to_string();

        let rt = ResponseTemplate::new(200)
            .set_body_raw(
                // purposely truncate the JSON
                &json[..&json.len() - 1],
                APPLICATION_JSON.as_ref()
            );

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn post_login_not_json() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let rt = ResponseTemplate::new(200)
            .set_body_string("this is not JSON");

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn post_login_failed() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let err_msg = "Incorrect username, email or password";

        let rt = ResponseTemplate::new(200)
            .set_body_json(
                LoginFailure {
                    error: err_msg.into()
                }
            );

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap_err();
        assert!(matches!(result, Failure::Unauthorized));
    }

    #[tokio::test]
    async fn post_login_bad_auth_token() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: ""
        };

        let rt = ResponseTemplate::new(403);

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, Some(403));
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn post_login_no_session_cookie() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let rt = ResponseTemplate::new(403);

        let result = do_post_login(rt, &params, "").await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, Some(403));
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn post_login_error() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let rt = ResponseTemplate::new(500);

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, Some(500));
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn discourse_auth_ok() {
        let csrf_rt = ResponseTemplate::new(200)
            .insert_header(
                "Set-Cookie",
                CSRF_SET_COOKIE
            )
            .set_body_json(
                CsrfResult {
                    csrf: CSRF_TOKEN.into()
                }
            );

        let json = json!({ "user": "stuff" });

        let login_rt = ResponseTemplate::new(200)
            .set_body_json(json.clone());

        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path(CSRF_ENDPOINT))
            .respond_with(csrf_rt)
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path(LOGIN_ENDPOINT))
            .respond_with(login_rt)
            .expect(1)
            .mount(&mock_server)
            .await;

        let dauth = DiscourseAuth::new(&mock_server.uri());

        let result = dauth.login("skroob", "12345").await.unwrap();
        assert_eq!(result, json);
    }

    #[tokio::test]
    async fn discourse_auth_failed() {
        let csrf_rt = ResponseTemplate::new(200)
            .insert_header(
                "Set-Cookie",
                CSRF_SET_COOKIE
            )
            .set_body_json(
                CsrfResult {
                    csrf: CSRF_TOKEN.into()
                }
            );

        let err_msg = "Incorrect username, email or password";
        let login_rt = ResponseTemplate::new(200)
            .set_body_json(
                LoginFailure {
                    error: err_msg.into()
                }
            );

        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path(CSRF_ENDPOINT))
            .respond_with(csrf_rt)
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path(LOGIN_ENDPOINT))
            .respond_with(login_rt)
            .expect(1)
            .mount(&mock_server)
            .await;

        let dauth = DiscourseAuth::new(&mock_server.uri());

        let result = dauth.login("skroob", "12345").await.unwrap_err();
        assert!(matches!(result, Failure::Unauthorized));
    }

    struct NonResolver;

    impl Resolve for NonResolver {
        fn resolve(&self, _name: Name) -> Resolving {
            Box::pin(async {
                Err(Box::new(io::Error::from(io::ErrorKind::Other))
                        as Box::<dyn std::error::Error + Send + Sync>)
            })
        }
    }

    #[tokio::test]
    async fn discourse_auth_dns_failure() {
        let dauth = DiscourseAuth {
            client: Client::builder()
                .dns_resolver(std::sync::Arc::new(NonResolver))
                .build()
                .unwrap(),
            csrf_url: "http://localhost".into(),
            login_url: "".into(),
        };

        let result = dauth.login("skroob", "12345").await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }

    #[tokio::test]
    async fn discourse_auth_failed_to_connect() {
        // Timeout immediately to simulate connection failure
        let dauth = DiscourseAuth {
            client: Client::builder()
                .timeout(Duration::from_nanos(1))
                .build()
                .unwrap(),
            csrf_url: "http://localhost".into(),
            login_url: "".into(),
        };

        let result = dauth.login("skroob", "12345").await.unwrap_err();
        assert!(matches!(result, Failure::Error(_)));
        let Failure::Error(err) = result else { unreachable!() };
        assert_eq!(err.status, None);
        assert!(!err.message.is_empty());
    }
}
