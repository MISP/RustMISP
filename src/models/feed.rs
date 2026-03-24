use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP feed — an external or internal source of threat intelligence data.
///
/// Feeds can be MISP-format, freetext, or CSV, and may be fetched, cached,
/// and correlated with local events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispFeed {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Display name for the feed.
    #[serde(default)]
    pub name: String,

    /// Organisation or entity providing this feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// URL of the feed.
    #[serde(default)]
    pub url: String,

    /// Feed rules as JSON string (filtering rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,

    /// Whether this feed is enabled.
    #[serde(default, with = "flexible_bool")]
    pub enabled: bool,

    /// Distribution level of events created from this feed.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Sharing group ID (when distribution = 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,

    /// Tag ID to apply to events from this feed.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub tag_id: Option<i64>,

    /// Whether the default tag should be applied.
    #[serde(default, with = "flexible_bool")]
    pub default_tag: bool,

    /// Whether to pull from this feed automatically.
    #[serde(default, with = "flexible_bool")]
    pub pull_rules: bool,

    /// Source format: "misp", "freetext", "csv".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_format: Option<String>,

    /// Fixed event UUID — if set, all attributes go into one event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_event: Option<String>,

    /// Whether to delta-merge (only add new attributes, don't duplicate).
    #[serde(default, with = "flexible_bool")]
    pub delta_merge: bool,

    /// Event ID that this feed populates (for fixed-event feeds).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<i64>,

    /// Whether to publish events after pulling.
    #[serde(default, with = "flexible_bool")]
    pub publish: bool,

    /// Whether to override IDS flag on attributes.
    #[serde(default, with = "flexible_bool")]
    pub override_ids: bool,

    /// Custom HTTP headers as JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,

    /// Whether caching is enabled for this feed.
    #[serde(default, with = "flexible_bool")]
    pub caching_enabled: bool,

    /// Whether to force fetching even if the feed hasn't changed.
    #[serde(default, with = "flexible_bool")]
    pub force_to_ids: bool,

    /// Organisation ID owning the feed.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub orgc_id: Option<i64>,

    /// Input source: "network" or "local".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_source: Option<String>,

    /// Whether to delete local data not in feed on next pull.
    #[serde(default, with = "flexible_bool")]
    pub delete_local_file: bool,

    /// Whether to look up existing attributes before creating new ones.
    #[serde(default, with = "flexible_bool")]
    pub lookup_visible: bool,
}

impl MispFeed {
    /// Create a new feed with a name and URL.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            provider: None,
            url: url.into(),
            rules: None,
            enabled: false,
            distribution: None,
            sharing_group_id: None,
            tag_id: None,
            default_tag: false,
            pull_rules: false,
            source_format: None,
            fixed_event: None,
            delta_merge: false,
            event_id: None,
            publish: false,
            override_ids: false,
            headers: None,
            caching_enabled: false,
            force_to_ids: false,
            orgc_id: None,
            input_source: None,
            delete_local_file: false,
            lookup_visible: false,
        }
    }
}

impl Default for MispFeed {
    fn default() -> Self {
        Self::new("", "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_new_defaults() {
        let f = MispFeed::new("Abuse.ch URLhaus", "https://urlhaus.abuse.ch/feeds");
        assert_eq!(f.name, "Abuse.ch URLhaus");
        assert_eq!(f.url, "https://urlhaus.abuse.ch/feeds");
        assert!(f.id.is_none());
        assert!(!f.enabled);
    }

    #[test]
    fn feed_serde_roundtrip() {
        let f = MispFeed {
            id: Some(1),
            name: "CIRCL OSINT".into(),
            provider: Some("CIRCL".into()),
            url: "https://www.circl.lu/doc/misp/feed-osint".into(),
            rules: None,
            enabled: true,
            distribution: Some(3),
            sharing_group_id: None,
            tag_id: Some(10),
            default_tag: true,
            pull_rules: false,
            source_format: Some("misp".into()),
            fixed_event: None,
            delta_merge: true,
            event_id: None,
            publish: true,
            override_ids: false,
            headers: None,
            caching_enabled: true,
            force_to_ids: false,
            orgc_id: Some(1),
            input_source: Some("network".into()),
            delete_local_file: false,
            lookup_visible: true,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: MispFeed = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn feed_deserialize_misp_format() {
        let json = r#"{
            "id": "3",
            "name": "Botvrij.eu",
            "provider": "Botvrij",
            "url": "https://www.botvrij.eu/data/feed-osint",
            "enabled": "1",
            "distribution": "3",
            "source_format": "misp",
            "caching_enabled": "1",
            "delta_merge": "0",
            "publish": "1",
            "override_ids": "0",
            "force_to_ids": "0",
            "orgc_id": "1",
            "input_source": "network"
        }"#;
        let f: MispFeed = serde_json::from_str(json).unwrap();
        assert_eq!(f.id, Some(3));
        assert_eq!(f.name, "Botvrij.eu");
        assert!(f.enabled);
        assert_eq!(f.distribution, Some(3));
        assert!(f.caching_enabled);
        assert!(f.publish);
        assert!(!f.delta_merge);
    }

    #[test]
    fn feed_deserialize_minimal() {
        let json = r#"{"name": "Test Feed", "url": "https://example.com/feed"}"#;
        let f: MispFeed = serde_json::from_str(json).unwrap();
        assert_eq!(f.name, "Test Feed");
        assert!(!f.enabled);
        assert!(f.id.is_none());
    }
}
