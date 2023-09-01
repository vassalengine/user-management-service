#![feature(decl_macro)]

pub mod discourse;

use rocket::{
    Request, catch, catchers, get, launch, post, routes, uri,
    http::Status,
    serde::{
        Deserialize, Serialize,
        json::{Json, Value, json}
    }
};

#[catch(default)]
fn default_catcher(status: Status, _request: &Request) -> Value {
    json!({
        "error": status.reason()
    })
}

#[get("/projects")]
fn get_projects() -> &'static str {
    "!!!"
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Login<'a> {
    username: &'a str,
    password: &'a str
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct Token {
    token: String
}

#[post("/login", format = "json", data = "<payload>", rank = 0)]
async fn login(payload: Json<Login<'_>>) -> Result<Json<Token>, Status> {
    println!("{}", payload.username);
    println!("{}", payload.password);
    Err(Status::NotImplemented)
}

#[post("/login", rank = 1)]
fn login_non_json() -> Result<(), Status> {
    // reject non-JSON Content-Types
    Err(Status::BadRequest)
}

const API_V1: &str = "/api/v1";

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount(API_V1, routes![get_projects, login, login_non_json])
        .register("/", catchers![default_catcher])
}

#[cfg(test)]
mod test {
    use super::*;

    use rocket::http::ContentType;
    use rocket::local::blocking::Client;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(crate = "rocket::serde")]
    struct ErrorMessage {
        error: String
    }

    #[test]
    fn login_no_content_type() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .body(r#"{ "username": "bob", "password": 12345 }"#)
            .dispatch();

        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::BadRequest.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_no_payload() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .dispatch();

        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::BadRequest.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_not_json() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .body("total garbage")
            .dispatch();
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::BadRequest.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_no_password() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .body(r#"{ "username": "bob" }"#)
            .dispatch();
        assert_eq!(response.status(), Status::UnprocessableEntity);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::UnprocessableEntity.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_username_not_string() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .body(r#"{ "username": 3, "password": "12345" }"#)
            .dispatch();
        assert_eq!(response.status(), Status::UnprocessableEntity);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::UnprocessableEntity.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_no_username() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .body(r#"{ "password": "12345" }"#)
            .dispatch();
        assert_eq!(response.status(), Status::UnprocessableEntity);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::UnprocessableEntity.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_password_not_string() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .body(r#"{ "username": "skroob", "password": 12345 }"#)
            .dispatch();
        assert_eq!(response.status(), Status::UnprocessableEntity);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::UnprocessableEntity.reason().unwrap().to_string()
            })
        );
    }

    #[test]
    fn login_ok() {
        let client = Client::tracked(rocket()).unwrap();
        let base = uri!("/api/v1");
        let response = client.post(uri!(base, login))
            .header(ContentType::JSON)
            .body(r#"{ "username": "skroob", "password": "12345" }"#)
            .dispatch();
        assert_eq!(response.status(), Status::NotImplemented);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        assert_eq!(
            response.into_json::<ErrorMessage>(),
            Some(ErrorMessage{
                error: Status::NotImplemented.reason().unwrap().to_string()
            })
        );
    }
}
