pub struct HttpError {
    pub status: u16,
    pub message: String
}

pub enum AppError {
    Unauthorized,
    InternalError,
    ServerError(HttpError),
    ClientError(HttpError)
}
