use mime::APPLICATION_JSON;
use reqwest::{
    Client, StatusCode,
    header::ACCEPT
};
use serde_json::Value;

use crate::errors::RequestError;

pub async fn user_search(
    discourse_url: &str,
    term: &str,
    limit: u32
) -> Result<Value, RequestError> {

    let url = format!(
        "{}/u/search/users?term={}&include_groups=false&limit={}",
        discourse_url,
        term,
        limit
    );

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
            response.json::<Value>().await?
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
