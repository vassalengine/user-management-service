use mime::APPLICATION_JSON;
use reqwest::{
    Client, StatusCode,
    header::ACCEPT
};
use serde::Deserialize;

use crate::errors::RequestError;

#[derive(Deserialize)]
struct User {
    avatar_template: String
}

#[derive(Deserialize)]
struct Reply {
    user: User
}

// TODO: special handling for 429

pub async fn get_avatar_template(
    discourse_url: &str,
    username: &str
) -> Result<String, RequestError> {
    let url = format!("{discourse_url}/u/{username}.json");

    // TODO: pass in client?
    let client = Client::builder().build()?;

    // Do the GET
    let response = client.get(&url)
        .header(ACCEPT, APPLICATION_JSON.as_ref())
        .send()
        .await?;

    // Anything except 200 is an error
    match response.status() {
        StatusCode::OK => Ok(
            response.json::<Reply>().await?.user.avatar_template
        ),
        _ => Err(
            RequestError::HttpError(
                url,
                response.status().as_u16(),
                response.text().await.unwrap_or("".into())
            )
        )
    }
}
