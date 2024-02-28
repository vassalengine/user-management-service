use mime::APPLICATION_JSON;
use reqwest::{
    Client, StatusCode,
    header::ACCEPT
};
use serde::Deserialize;

use crate::auth_provider::{Error, Failure};

#[derive(Deserialize)]
struct User {
    avatar_template: String
}

#[derive(Deserialize)]
struct Reply {
    user: User
}

//pub async fn get_avatar(client: &Client, url: &str) -> Result<String, Failure> {
pub async fn get_avatar_template(
    discourse_url: &str,
    username: &str
) -> Result<String, Failure> {
    let url = format!("{discourse_url}/u/{username}.json");

    // TODO: pass in client?
    let client = Client::builder().build().unwrap();

    // do the GET
    let response = client.get(url)
        .header(ACCEPT, APPLICATION_JSON.as_ref())
        .send()
        .await?
        .error_for_status()?;

    // non-200 results are errors
    if response.status() != StatusCode::OK {
        return Err(Failure::Error(
            Error {
                status: Some(response.status().as_u16()),
                message: response.text().await.unwrap_or_else(|e| e.to_string())
            }
        ));
    }

    Ok(response.json::<Reply>().await?.user.avatar_template)
}
