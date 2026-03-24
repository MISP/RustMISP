use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use url::Url;

use crate::error::{MispError, MispResult};

/// Async client for the MISP REST API.
///
/// Create via [`MispClient::new`] for simple usage, or
/// [`MispClient::builder`] for advanced configuration.
#[derive(Debug, Clone)]
pub struct MispClient {
    base_url: Url,
    #[allow(dead_code)] // Used in later iterations for key rotation
    api_key: String,
    client: Client,
}

/// Builder for constructing a [`MispClient`] with advanced options.
#[derive(Debug)]
pub struct MispClientBuilder {
    url: String,
    key: String,
    ssl_verify: bool,
    timeout: Option<Duration>,
    proxy: Option<String>,
    headers: HashMap<String, String>,
}

impl MispClientBuilder {
    fn new(url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            key: key.into(),
            ssl_verify: true,
            timeout: None,
            proxy: None,
            headers: HashMap::new(),
        }
    }

    /// Disable TLS certificate verification.
    pub fn ssl_verify(mut self, verify: bool) -> Self {
        self.ssl_verify = verify;
        self
    }

    /// Set a request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set an HTTP proxy URL.
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Add a custom header to all requests.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Build the [`MispClient`].
    pub fn build(self) -> MispResult<MispClient> {
        let base_url = normalize_url(&self.url)?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        default_headers.insert(
            "Authorization",
            HeaderValue::from_str(&self.key).map_err(|e| {
                MispError::InvalidInput(format!("Invalid API key header value: {e}"))
            })?,
        );
        for (k, v) in &self.headers {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| MispError::InvalidInput(format!("Invalid header name '{k}': {e}")))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| MispError::InvalidInput(format!("Invalid header value: {e}")))?;
            default_headers.insert(name, val);
        }

        let mut builder = Client::builder()
            .default_headers(default_headers)
            .danger_accept_invalid_certs(!self.ssl_verify);

        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }

        if let Some(proxy_url) = &self.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| MispError::InvalidInput(format!("Invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;

        Ok(MispClient {
            base_url,
            api_key: self.key,
            client,
        })
    }
}

impl MispClient {
    /// Create a new MISP client.
    ///
    /// # Arguments
    /// * `url` - Base URL of the MISP instance (e.g. `https://misp.example.com`)
    /// * `key` - MISP API key (automation key)
    /// * `ssl_verify` - Whether to verify TLS certificates
    pub fn new(
        url: impl Into<String>,
        key: impl Into<String>,
        ssl_verify: bool,
    ) -> MispResult<Self> {
        Self::builder(url, key).ssl_verify(ssl_verify).build()
    }

    /// Create a builder for advanced client configuration.
    pub fn builder(url: impl Into<String>, key: impl Into<String>) -> MispClientBuilder {
        MispClientBuilder::new(url, key)
    }

    /// Get the base URL of this client.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ── Internal request helpers ──────────────────────────────────────

    /// Prepare and send an HTTP request to the MISP API.
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> MispResult<Response> {
        let url = self.base_url.join(path)?;
        log::debug!("{} {}", method, url);

        let mut req = self.client.request(method, url);
        if let Some(body) = body {
            req = req.json(body);
        }

        let response = req.send().await?;
        Ok(response)
    }

    /// Send a GET request and parse the JSON response.
    async fn get(&self, path: &str) -> MispResult<Value> {
        let response = self.request(Method::GET, path, None).await?;
        self.check_response(response).await
    }

    /// Send a POST request with a JSON body and parse the response.
    async fn post(&self, path: &str, body: &Value) -> MispResult<Value> {
        let response = self.request(Method::POST, path, Some(body)).await?;
        self.check_response(response).await
    }

    /// Send a HEAD request and return whether the resource exists (2xx).
    #[allow(dead_code)] // Used in later iterations for exists checks
    async fn head(&self, path: &str) -> MispResult<bool> {
        let response = self.request(Method::HEAD, path, None).await?;
        Ok(response.status().is_success())
    }

    /// Check an HTTP response for errors and parse the body as JSON.
    async fn check_response(&self, response: Response) -> MispResult<Value> {
        let status = response.status();

        if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            let text = response.text().await.unwrap_or_default();
            return Err(MispError::AuthError(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text
            )));
        }

        if status == StatusCode::NOT_FOUND {
            let text = response.text().await.unwrap_or_default();
            return Err(MispError::NotFound(text));
        }

        if !status.is_success() {
            let code = status.as_u16();
            let text = response.text().await.unwrap_or_default();
            // Try to extract a message from the JSON body
            if let Ok(json) = serde_json::from_str::<Value>(&text) {
                let message = json["message"]
                    .as_str()
                    .or_else(|| json["errors"].as_str())
                    .unwrap_or(&text)
                    .to_string();
                return Err(MispError::ApiError {
                    status: code,
                    message,
                });
            }
            return Err(MispError::ApiError {
                status: code,
                message: text,
            });
        }

        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;
        Ok(json)
    }

    // ── Server / Instance Info ────────────────────────────────────────

    /// Load `describeTypes` from the bundled JSON file.
    pub fn describe_types_local(&self) -> MispResult<Value> {
        let data = include_str!("../data/describeTypes.json");
        let json: Value = serde_json::from_str(data)?;
        Ok(json)
    }

    /// Fetch `describeTypes` from the remote MISP instance.
    pub async fn describe_types_remote(&self) -> MispResult<Value> {
        self.get("attributes/describeTypes.json").await
    }

    /// Get the MISP instance version.
    pub async fn misp_instance_version(&self) -> MispResult<Value> {
        self.get("servers/getVersion").await
    }

    /// Get the recommended PyMISP version for this MISP instance.
    pub async fn version(&self) -> MispResult<Value> {
        self.get("servers/getPyMISPVersion.json").await
    }

    /// Get all server settings.
    pub async fn server_settings(&self) -> MispResult<Value> {
        self.get("servers/serverSettings").await
    }

    /// Get a specific server setting.
    pub async fn get_server_setting(&self, setting: &str) -> MispResult<Value> {
        self.get(&format!("servers/getSetting/{setting}")).await
    }

    /// Set a specific server setting.
    pub async fn set_server_setting(
        &self,
        setting: &str,
        value: impl Into<Value>,
    ) -> MispResult<Value> {
        let body = serde_json::json!({ "value": value.into() });
        self.post(&format!("servers/serverSettingsEdit/{setting}"), &body)
            .await
    }

    /// Query the ACL system for debugging.
    pub async fn remote_acl(&self, debug_type: Option<&str>) -> MispResult<Value> {
        let path = match debug_type {
            Some(dt) => format!("servers/queryACL/{dt}"),
            None => "servers/queryACL".to_string(),
        };
        self.get(&path).await
    }

    /// Get the database schema diagnostic.
    pub async fn db_schema_diagnostic(&self) -> MispResult<Value> {
        self.get("servers/schemaDiagnostics").await
    }
}

/// Ensure the URL has a trailing slash so `Url::join` works correctly.
fn normalize_url(url: &str) -> MispResult<Url> {
    let mut s = url.to_string();
    if !s.ends_with('/') {
        s.push('/');
    }
    Url::parse(&s).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_adds_trailing_slash() {
        let u = normalize_url("https://misp.example.com").unwrap();
        assert_eq!(u.as_str(), "https://misp.example.com/");
    }

    #[test]
    fn normalize_url_preserves_trailing_slash() {
        let u = normalize_url("https://misp.example.com/").unwrap();
        assert_eq!(u.as_str(), "https://misp.example.com/");
    }

    #[test]
    fn normalize_url_preserves_path() {
        let u = normalize_url("https://misp.example.com/misp").unwrap();
        assert_eq!(u.as_str(), "https://misp.example.com/misp/");
    }

    #[test]
    fn client_new_valid() {
        let client = MispClient::new("https://misp.example.com", "test-api-key", false);
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url.as_str(), "https://misp.example.com/");
        assert_eq!(client.api_key, "test-api-key");
    }

    #[test]
    fn client_new_invalid_url() {
        let client = MispClient::new("not a url :::", "key", true);
        assert!(client.is_err());
    }

    #[test]
    fn client_builder_with_options() {
        let client = MispClient::builder("https://misp.example.com", "key123")
            .ssl_verify(false)
            .timeout(Duration::from_secs(30))
            .header("X-Custom", "value")
            .build();
        assert!(client.is_ok());
    }

    #[test]
    fn describe_types_local_loads() {
        let client = MispClient::new("https://misp.example.com", "key", false).unwrap();
        let result = client.describe_types_local();
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json["result"].is_object());
    }

    #[tokio::test]
    async fn request_preparation_sets_auth_header() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "my-test-key-12345", false).unwrap();

        Mock::given(method("GET"))
            .and(header("Authorization", "my-test-key-12345"))
            .and(header("Accept", "application/json"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let result = client.get("test/endpoint").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["ok"], true);
    }

    #[tokio::test]
    async fn check_response_auth_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "bad-key", false).unwrap();

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let result = client.get("test").await;
        assert!(matches!(result, Err(MispError::AuthError(_))));
    }

    #[tokio::test]
    async fn check_response_not_found() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
            .mount(&server)
            .await;

        let result = client.get("missing").await;
        assert!(matches!(result, Err(MispError::NotFound(_))));
    }

    #[tokio::test]
    async fn check_response_api_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"message": "Internal error"})),
            )
            .mount(&server)
            .await;

        let result = client.get("error").await;
        match result {
            Err(MispError::ApiError { status, message }) => {
                assert_eq!(status, 500);
                assert_eq!(message, "Internal error");
            }
            other => panic!("Expected ApiError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn head_returns_true_for_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let exists = client.head("events/view/1").await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn head_returns_false_for_404() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let exists = client.head("events/view/999").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn post_sends_json_body() {
        use wiremock::matchers::{body_json, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let body = serde_json::json!({"value": "test-setting"});

        Mock::given(method("POST"))
            .and(body_json(&body))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"saved": true})),
            )
            .mount(&server)
            .await;

        let result = client.post("servers/serverSettingsEdit/test", &body).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn misp_instance_version_mock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = MispClient::new(server.uri(), "key", false).unwrap();

        let version_response = serde_json::json!({
            "version": "2.4.180",
            "perm_sync": false,
            "perm_sighting": false
        });

        Mock::given(method("GET"))
            .and(path("/servers/getVersion"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&version_response))
            .mount(&server)
            .await;

        let result = client.misp_instance_version().await.unwrap();
        assert_eq!(result["version"], "2.4.180");
    }
}
