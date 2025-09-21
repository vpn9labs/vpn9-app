use std::time::Duration;

use crate::error::ApiError;
use crate::models::{
    AuthRequest, AuthResponse, CreateDevicePayload, CreateDeviceRequest, DeviceRecord,
    RelayTopology, VerifyDeviceRequest,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Client as HttpClient, RequestBuilder, StatusCode};
use tokio::time::sleep;
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RETRIES: usize = 3;
const INITIAL_BACKOFF_MS: u64 = 200;

#[derive(Clone)]
pub struct Client {
    base_url: Url,
    http: HttpClient,
    max_retries: usize,
}

impl Client {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ApiError> {
        let mut url = Url::parse(base_url.as_ref())?;
        if !url.path().ends_with('/') {
            url = url.join("./")?;
        }

        let http = HttpClient::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(ApiError::from_reqwest_error)?;

        Ok(Self {
            base_url: url,
            http,
            max_retries: DEFAULT_MAX_RETRIES,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, ApiError> {
        Ok(self.base_url.join(path)?)
    }

    async fn send_with_retry<F>(&self, mut build: F) -> Result<reqwest::Response, ApiError>
    where
        F: FnMut() -> RequestBuilder,
    {
        let mut attempt = 0usize;
        let mut backoff_ms = INITIAL_BACKOFF_MS;

        loop {
            attempt += 1;
            let request = build();
            let result = request.send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    let should_retry = status == StatusCode::REQUEST_TIMEOUT
                        || status == StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error();

                    if should_retry && attempt < self.max_retries {
                        let mut wait_ms = backoff_ms;
                        if let Some(retry_after) = response.headers().get(RETRY_AFTER) {
                            if let Ok(value) = retry_after.to_str() {
                                if let Ok(seconds) = value.parse::<u64>() {
                                    wait_ms = seconds.saturating_mul(1000);
                                }
                            }
                        }
                        sleep(Duration::from_millis(wait_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1500);
                        continue;
                    }

                    return Ok(response);
                }
                Err(err) => {
                    if attempt < self.max_retries && (err.is_connect() || err.is_timeout()) {
                        sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1500);
                        continue;
                    }
                    return Err(ApiError::from_reqwest_error(err));
                }
            }
        }
    }

    pub async fn login(
        &self,
        passphrase: &str,
        client_label: Option<&str>,
    ) -> Result<AuthResponse, ApiError> {
        let url = self.endpoint("auth/token")?;
        let payload = AuthRequest {
            passphrase: passphrase.to_string(),
            client_label: client_label.map(|label| label.to_string()),
        };
        let http = self.http.clone();

        let response = self
            .send_with_retry(|| {
                let body = payload.clone();
                http.post(url.clone())
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body)
            })
            .await?;

        self.handle_auth_response(response).await
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthResponse, ApiError> {
        let url = self.endpoint("auth/refresh")?;
        let payload = crate::models::RefreshRequest {
            refresh_token: refresh_token.to_string(),
        };
        let http = self.http.clone();

        let response = self
            .send_with_retry(|| {
                let body = payload.clone();
                http.post(url.clone())
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body)
            })
            .await?;

        self.handle_auth_response(response).await
    }

    pub async fn verify_device(
        &self,
        access_token: &str,
        public_key: &str,
    ) -> Result<DeviceRecord, ApiError> {
        let url = self.endpoint("devices/verify")?;
        let payload = VerifyDeviceRequest {
            public_key: public_key.to_string(),
        };
        let http = self.http.clone();
        let token_header = format!("Bearer {access_token}");

        let response = self
            .send_with_retry(|| {
                let body = payload.clone();
                http.post(url.clone())
                    .header(AUTHORIZATION, token_header.clone())
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body)
            })
            .await?;

        self.handle_device_response(response).await
    }

    pub async fn register_device(
        &self,
        access_token: &str,
        public_key: &str,
    ) -> Result<DeviceRecord, ApiError> {
        let url = self.endpoint("devices")?;
        let payload = CreateDeviceRequest {
            device: CreateDevicePayload {
                public_key: public_key.to_string(),
            },
        };
        let http = self.http.clone();
        let token_header = format!("Bearer {access_token}");

        let response = self
            .send_with_retry(|| {
                let body = payload.clone();
                http.post(url.clone())
                    .header(AUTHORIZATION, token_header.clone())
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body)
            })
            .await?;

        self.handle_device_response(response).await
    }

    pub async fn list_relays(&self, access_token: &str) -> Result<RelayTopology, ApiError> {
        let url = self.endpoint("relays")?;
        let http = self.http.clone();
        let token_header = format!("Bearer {access_token}");

        let response = self
            .send_with_retry(|| {
                http.get(url.clone())
                    .header(AUTHORIZATION, token_header.clone())
                    .header(ACCEPT, "application/json")
            })
            .await?;

        self.parse_json_response::<RelayTopology>(response).await
    }

    async fn handle_auth_response(
        &self,
        response: reqwest::Response,
    ) -> Result<AuthResponse, ApiError> {
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::UnexpectedStatus { status, body });
        }

        response
            .json::<AuthResponse>()
            .await
            .map_err(ApiError::from_reqwest_error)
    }

    async fn handle_device_response(
        &self,
        response: reqwest::Response,
    ) -> Result<DeviceRecord, ApiError> {
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }
        if status == StatusCode::NOT_FOUND {
            return Err(ApiError::NotFound);
        }
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::UnprocessableEntity(body));
        }
        if !(status.is_success() || status == StatusCode::CREATED) {
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::UnexpectedStatus { status, body });
        }

        response
            .json::<crate::models::CreateDeviceResponse>()
            .await
            .map(|wrapper| wrapper.device)
            .map_err(ApiError::from_reqwest_error)
    }

    async fn parse_json_response<T>(&self, response: reqwest::Response) -> Result<T, ApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        response
            .json::<T>()
            .await
            .map_err(ApiError::from_reqwest_error)
    }
}
