use reqwest::StatusCode;
use thiserror::Error;
use url::ParseError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("invalid base url: {0}")]
    InvalidBaseUrl(#[from] ParseError),
    #[error("http client error: {0}")]
    HttpClient(reqwest::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("unprocessable entity: {0}")]
    UnprocessableEntity(String),
    #[error("unexpected response status {status}: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },
    #[error("failed to parse response: {0}")]
    Deserialize(#[from] serde_json::Error),
}

impl ApiError {
    pub fn from_reqwest_error(err: reqwest::Error) -> Self {
        ApiError::HttpClient(err)
    }

    pub fn is_connect_error(&self) -> bool {
        matches!(self, ApiError::HttpClient(err) if err.is_connect())
    }

    pub fn is_timeout_error(&self) -> bool {
        matches!(self, ApiError::HttpClient(err) if err.is_timeout())
    }
}
