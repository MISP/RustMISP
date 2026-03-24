use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP sync server — represents a remote MISP instance for push/pull synchronisation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispServer {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// URL of the remote MISP instance.
    #[serde(default)]
    pub url: String,

    /// Display name for this server link.
    #[serde(default)]
    pub name: String,

    /// API authentication key for the remote server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authkey: Option<String>,

    /// Organisation ID on the local instance that owns this link.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Whether push synchronisation is enabled.
    #[serde(default, with = "flexible_bool")]
    pub push: bool,

    /// Whether pull synchronisation is enabled.
    #[serde(default, with = "flexible_bool")]
    pub pull: bool,

    /// Whether to push sightings to this server.
    #[serde(default, with = "flexible_bool")]
    pub push_sightings: bool,

    /// Whether to push galaxy clusters to this server.
    #[serde(default, with = "flexible_bool")]
    pub push_galaxy_clusters: bool,

    /// Whether to pull galaxy clusters from this server.
    #[serde(default, with = "flexible_bool")]
    pub pull_galaxy_clusters: bool,

    /// Organisation ID on the remote instance.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub remote_org_id: Option<i64>,

    /// Whether to cache the remote server's data.
    #[serde(default, with = "flexible_bool")]
    pub caching_enabled: bool,

    /// Whether to publish events after pull.
    #[serde(default, with = "flexible_bool")]
    pub publish_without_email: bool,

    /// Whether to unpublish events before pushing.
    #[serde(default, with = "flexible_bool")]
    pub unpublish_event: bool,

    /// Whether self-signed certificates are accepted.
    #[serde(default, with = "flexible_bool")]
    pub self_signed: bool,

    /// Internal flag — whether the link uses an internal (trusted) connection.
    #[serde(default, with = "flexible_bool")]
    pub internal: bool,

    /// Whether to skip proxy for this server connection.
    #[serde(default, with = "flexible_bool")]
    pub skip_proxy: bool,

    /// Priority level for pull ordering.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub priority: Option<i64>,

    /// Last pull timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lastpulledid: Option<String>,

    /// Last push timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lastpushedid: Option<String>,
}

impl MispServer {
    /// Create a new server with URL and name.
    pub fn new(url: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: None,
            url: url.into(),
            name: name.into(),
            authkey: None,
            org_id: None,
            push: false,
            pull: false,
            push_sightings: false,
            push_galaxy_clusters: false,
            pull_galaxy_clusters: false,
            remote_org_id: None,
            caching_enabled: false,
            publish_without_email: false,
            unpublish_event: false,
            self_signed: false,
            internal: false,
            skip_proxy: false,
            priority: None,
            lastpulledid: None,
            lastpushedid: None,
        }
    }
}

impl Default for MispServer {
    fn default() -> Self {
        Self::new("", "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_new_defaults() {
        let s = MispServer::new("https://misp.example.com", "Partner MISP");
        assert_eq!(s.url, "https://misp.example.com");
        assert_eq!(s.name, "Partner MISP");
        assert!(s.id.is_none());
        assert!(!s.push);
        assert!(!s.pull);
    }

    #[test]
    fn server_serde_roundtrip() {
        let s = MispServer {
            id: Some(1),
            url: "https://misp.partner.org".into(),
            name: "Partner".into(),
            authkey: Some("abc123key".into()),
            org_id: Some(1),
            push: true,
            pull: true,
            push_sightings: true,
            push_galaxy_clusters: false,
            pull_galaxy_clusters: true,
            remote_org_id: Some(2),
            caching_enabled: true,
            publish_without_email: false,
            unpublish_event: false,
            self_signed: true,
            internal: false,
            skip_proxy: false,
            priority: Some(1),
            lastpulledid: Some("12345".into()),
            lastpushedid: Some("12340".into()),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MispServer = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn server_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "url": "https://misp.remote.org",
            "name": "Remote MISP",
            "authkey": "secretkey123",
            "org_id": "1",
            "push": "1",
            "pull": "1",
            "push_sightings": "0",
            "push_galaxy_clusters": "0",
            "pull_galaxy_clusters": "1",
            "remote_org_id": "3",
            "caching_enabled": "1",
            "self_signed": "1",
            "internal": "0",
            "skip_proxy": "0",
            "priority": "1"
        }"#;
        let s: MispServer = serde_json::from_str(json).unwrap();
        assert_eq!(s.id, Some(5));
        assert_eq!(s.url, "https://misp.remote.org");
        assert!(s.push);
        assert!(s.pull);
        assert!(!s.push_sightings);
        assert!(s.pull_galaxy_clusters);
        assert!(s.caching_enabled);
        assert!(s.self_signed);
    }

    #[test]
    fn server_deserialize_minimal() {
        let json = r#"{"url": "https://misp.local", "name": "Local"}"#;
        let s: MispServer = serde_json::from_str(json).unwrap();
        assert_eq!(s.url, "https://misp.local");
        assert_eq!(s.name, "Local");
        assert!(s.id.is_none());
        assert!(!s.push);
    }
}
