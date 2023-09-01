use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, COOKIE, CONTENT_TYPE, HeaderValue}
};
use serde::{Deserialize, Serialize};
use std::convert::From;

#[derive(Debug)]
pub struct Error {
    status: Option<u16>,
    message: String
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error {
            status: e.status().map(|s| s.as_u16()),
            message: e.to_string()
        }
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

const MIME_JSON: &str = "application/json";

#[derive(Deserialize, Serialize)]
struct CsrfResult {
    csrf: String
}

async fn get_csrf(client: &Client, url: &str) -> Result<(String, String), Error> {
    // do the GET
    let response = client.get(url)
        .header(ACCEPT, MIME_JSON)
        .send()
        .await?
        .error_for_status()?;

    // non-200 results are errors
    if response.status() != StatusCode::OK {
        return Err(Error::from(response).await);
    }

    // collect the returned cookies
    let cookies = response.cookies()
        .map(|c| format!("{}={}", c.name(), c.value()))
        .collect::<Vec<String>>()
        .join("; ");

    // return the token and the cookies
    Ok(
        (
            response.json::<CsrfResult>().await?.csrf,
            cookies
        )
    )
}

#[derive(Serialize)]
struct LoginParams<'a> {
    login: &'a str,
    password: &'a str,
    authenticity_token: &'a str
}

#[derive(Deserialize, Serialize)]
struct LoginFailure<'a> {
    error: &'a str
}

async fn post_login(client: &Client, url: &str, params: &LoginParams<'_>, cookies: &str) -> Result<String, Error>
{
    // This is slightly weird. Successful login returns a JSON blob. Failed
    // login returns JSON with an "error" key. We don't want to parse the
    // success JSON here, so we only try parsing the error JSON and pass on
    // the success JSON as text.

    let response = client.post(url)
        .json(params)
        .header(ACCEPT, MIME_JSON)
        .header(COOKIE, cookies)
        .send()
        .await?
        .error_for_status()?;

    let status = response.status();

    // non-200 results are errors
    if status != StatusCode::OK {
        return Err(Error::from(response).await);
    }

    // non-JSON results are errors
    if response.headers().get(CONTENT_TYPE) != Some(&HeaderValue::from_static(MIME_JSON)) {
        return Err(Error::from(response).await);
    }

    let text = response.text().await?;

    match serde_json::from_str::<LoginFailure>(&text) {
        // failure is a 200!
        Ok(failed) => Err(Error {
            status: Some(status.as_u16()),
            message: failed.error.into()
        }),
        // we failed to parse as a failure, so we succeeded
        Err(_) => Ok(text)
    }
}

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
            client: Client::builder().build().unwrap(),
            csrf_url: url.to_string() + CSRF_ENDPOINT,
            login_url: url.to_string() + LOGIN_ENDPOINT,
        }
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<String, Error> {
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
    use serde_json::json;
    use wiremock::{MockServer, Mock, ResponseTemplate, matchers};

    async fn setup_server(method: &str, endpoint: &str, rt: ResponseTemplate) -> MockServer {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method(method))
            .and(matchers::path(endpoint))
            .respond_with(rt)
            .expect(1)
            .mount(&mock_server)
            .await;

        mock_server
    }

    async fn do_get_csrf(rt: ResponseTemplate) ->  Result<(String, String), Error> {
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
                MIME_JSON
            );

        let result = do_get_csrf(rt).await.unwrap_err();
        assert_eq!(result.status, None);
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn get_csrf_wrong_json() {
        let rt = ResponseTemplate::new(200)
            .set_body_json(
                json!({"extra": "more!"})
            );

        let result = do_get_csrf(rt).await.unwrap_err();
        assert_eq!(result.status, None);
        assert!(!result.message.is_empty());
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
        assert_eq!(result.status, None);
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn get_csrf_wrong_type_of_success() {
        let rt = ResponseTemplate::new(201);

        let result = do_get_csrf(rt).await.unwrap_err();
        assert_eq!(result.status, Some(201));
        assert_eq!(result.message, "");
    }

    #[tokio::test]
    async fn get_csrf_error() {
        let rt = ResponseTemplate::new(418);

        let result = do_get_csrf(rt).await.unwrap_err();
        assert_eq!(result.status, Some(418));
    }

    async fn do_post_login(rt: ResponseTemplate, params: &LoginParams<'_>, cookies: &str) ->  Result<String, Error> {
        let mock_server = setup_server("POST", LOGIN_ENDPOINT, rt).await;
        let client = Client::builder().build().unwrap();
        let url = mock_server.uri() + LOGIN_ENDPOINT;
        post_login(&client, &url, &params, &cookies).await
    }

    #[tokio::test]
    async fn post_login_ok() {
        let params = LoginParams {
            login: "skroob",
            password: "12345",
            authenticity_token: CSRF_TOKEN
        };

        let json = json!({ "user": "stuff" });
        let json_str = json.to_string();

        let rt = ResponseTemplate::new(200)
            .set_body_json(json);

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap();
        assert_eq!(result, json_str);
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
                MIME_JSON
            );

        let result = do_post_login(rt, &params, CSRF_COOKIE).await.unwrap();
        assert_eq!(result, &json[..&json.len() - 1]);
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
        assert_eq!(result.status, Some(200));
        assert!(!result.message.is_empty());
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
        assert_eq!(result.status, Some(200));
        assert_eq!(result.message, err_msg);
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
        assert_eq!(result.status, Some(403));
        assert!(!result.message.is_empty());
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
        assert_eq!(result.status, Some(403));
        assert!(!result.message.is_empty());
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
        assert_eq!(result.status, Some(500));
        assert!(!result.message.is_empty());
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

        let login_rt = ResponseTemplate::new(200);

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

// TODO
        let result = dauth.login("skroob", "12345").await.unwrap_err();
        assert_eq!(result.status, Some(200));
    }

/*
    macro_rules! aw {
      ($e:expr) => {
          tokio_test::block_on($e)
      };
    }

     #[test]
    fn get_csrf_xxx() {
        let client = Client::builder()
//            .cookie_store(true)
            .build()
            .unwrap();

        let url = "https://forum.vassalengine.org/session/csrf.json";

        let csrf = aw!(get_csrf(&client, url)).unwrap();
        assert_eq!(csrf.0, "");
    }

    #[test]
    fn login_xxx() {
        let client = Client::builder()
            .build()
            .unwrap();

        let csrf_url = "https://forum.vassalengine.org/session/csrf.json";
        let csrf = aw!(get_csrf(&client, csrf_url)).unwrap();

        let login_url = "https://forum.vassalengine.org/session.json";
        let login_params = LoginParams {
//            login: "skroob",
//            password: "12345",
            authenticity_token: &csrf.0
//            authenticity_token: ""
        };

        let result = aw!(post_login(&client, login_url, &login_params, &csrf.1)).unwrap();
//        let result = aw!(post_login(&client, login_url, &login_params, "")).unwrap();
        assert_eq!(result, "");
    }
*/
}
