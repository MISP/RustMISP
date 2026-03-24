use thiserror::Error;

/// All errors that can occur when using RustMISP.
#[derive(Debug, Error)]
pub enum MispError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),

    /// The MISP server returned an error response.
    #[error("MISP API error ({status}): {message}")]
    ApiError {
        /// HTTP status code returned by the MISP server.
        status: u16,
        /// Error message from the MISP server.
        message: String,
    },

    /// Authentication failed (invalid API key or insufficient permissions).
    #[error("Authentication error: {0}")]
    AuthError(String),

    /// The requested resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Invalid input provided to a method.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// An entity (event, attribute, etc.) is missing a required field.
    #[error("Missing field: {0}")]
    MissingField(String),

    /// The MISP instance version is not compatible.
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),

    /// I/O error (file operations, etc.).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// The server returned an unexpected response format.
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    /// A search query was malformed.
    #[error("Invalid search: {0}")]
    InvalidSearch(String),

    /// An operation timed out.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// TLS/SSL certificate error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// A feature-gated tool was used without enabling the feature.
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
}

/// Convenience type alias for Results using [`MispError`].
pub type MispResult<T> = Result<T, MispError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn api_error_display() {
        let err = MispError::ApiError {
            status: 403,
            message: "Forbidden".into(),
        };
        assert_eq!(err.to_string(), "MISP API error (403): Forbidden");
    }

    #[test]
    fn auth_error_display() {
        let err = MispError::AuthError("Invalid API key".into());
        assert_eq!(err.to_string(), "Authentication error: Invalid API key");
    }

    #[test]
    fn not_found_display() {
        let err = MispError::NotFound("Event 42".into());
        assert_eq!(err.to_string(), "Not found: Event 42");
    }

    #[test]
    fn invalid_input_display() {
        let err = MispError::InvalidInput("empty name".into());
        assert_eq!(err.to_string(), "Invalid input: empty name");
    }

    #[test]
    fn missing_field_display() {
        let err = MispError::MissingField("info".into());
        assert_eq!(err.to_string(), "Missing field: info");
    }

    #[test]
    fn version_mismatch_display() {
        let err = MispError::VersionMismatch("requires >= 2.4.150".into());
        assert_eq!(err.to_string(), "Version mismatch: requires >= 2.4.150");
    }

    #[test]
    fn io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = MispError::from(io_err);
        assert!(matches!(err, MispError::IoError(_)));
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn json_error_from() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = MispError::from(json_err);
        assert!(matches!(err, MispError::JsonError(_)));
    }

    #[test]
    fn url_error_from() {
        let url_err = url::Url::parse("not a url :::").unwrap_err();
        let err = MispError::from(url_err);
        assert!(matches!(err, MispError::UrlError(_)));
    }

    #[test]
    fn unexpected_response_display() {
        let err = MispError::UnexpectedResponse("got HTML".into());
        assert_eq!(err.to_string(), "Unexpected response: got HTML");
    }

    #[test]
    fn invalid_search_display() {
        let err = MispError::InvalidSearch("bad query".into());
        assert_eq!(err.to_string(), "Invalid search: bad query");
    }

    #[test]
    fn timeout_display() {
        let err = MispError::Timeout("30s exceeded".into());
        assert_eq!(err.to_string(), "Timeout: 30s exceeded");
    }

    #[test]
    fn tls_error_display() {
        let err = MispError::TlsError("cert expired".into());
        assert_eq!(err.to_string(), "TLS error: cert expired");
    }

    #[test]
    fn feature_not_enabled_display() {
        let err = MispError::FeatureNotEnabled("tools-file".into());
        assert_eq!(err.to_string(), "Feature not enabled: tools-file");
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        // MispError should be Send + Sync for use across async boundaries
        // Note: reqwest::Error is Send+Sync, so this should work
        assert_send_sync::<MispError>();
    }

    #[test]
    fn error_implements_std_error() {
        let err = MispError::NotFound("test".into());
        // Verify it implements std::error::Error (source() returns None for leaf variants)
        let _: &dyn Error = &err;
    }

    #[test]
    fn misp_result_type_alias() {
        let ok: MispResult<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: MispResult<i32> = Err(MispError::NotFound("test".into()));
        assert!(err.is_err());
    }
}
