pub struct HttpError {
    pub status: u16,
    pub message: String
}

pub enum AppError {
    Unauthorized,
    ServerError(HttpError),
    ClientError(HttpError)
}
