use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP warninglist — a list of known-benign values (IPs, domains, etc.)
/// used to suppress false positives during correlation.
///
/// Warninglists help analysts quickly identify indicators that match
/// well-known infrastructure (e.g., Google DNS, Cloudflare IPs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispWarninglist {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Name of the warninglist (e.g., "List of known IPv4 public DNS resolvers").
    #[serde(default)]
    pub name: String,

    /// Type of matching (e.g., "string", "substring", "hostname", "cidr").
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub warninglist_type: Option<String>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Version of the warninglist definition.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<i64>,

    /// Whether this warninglist is enabled.
    #[serde(default, with = "flexible_bool")]
    pub enabled: bool,

    /// Number of entries in this warninglist.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub warninglist_entry_count: Option<i64>,

    /// Attribute categories this warninglist applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_attributes: Option<String>,
}

impl MispWarninglist {
    /// Create a new warninglist with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            warninglist_type: None,
            description: None,
            version: None,
            enabled: false,
            warninglist_entry_count: None,
            valid_attributes: None,
        }
    }
}

impl Default for MispWarninglist {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warninglist_new_defaults() {
        let w = MispWarninglist::new("Test list");
        assert_eq!(w.name, "Test list");
        assert!(w.id.is_none());
        assert!(!w.enabled);
    }

    #[test]
    fn warninglist_serde_roundtrip() {
        let w = MispWarninglist {
            id: Some(10),
            name: "List of known public DNS resolvers".into(),
            warninglist_type: Some("string".into()),
            description: Some("Known DNS resolvers".into()),
            version: Some(3),
            enabled: true,
            warninglist_entry_count: Some(42),
            valid_attributes: Some("ip-src, ip-dst".into()),
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: MispWarninglist = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn warninglist_deserialize_misp_format() {
        let json = r#"{
            "id": "10",
            "name": "List of known public DNS resolvers",
            "type": "string",
            "description": "Known DNS resolvers",
            "version": "3",
            "enabled": "1",
            "warninglist_entry_count": "42",
            "valid_attributes": "ip-src, ip-dst"
        }"#;
        let w: MispWarninglist = serde_json::from_str(json).unwrap();
        assert_eq!(w.id, Some(10));
        assert_eq!(w.name, "List of known public DNS resolvers");
        assert_eq!(w.warninglist_type.as_deref(), Some("string"));
        assert!(w.enabled);
        assert_eq!(w.warninglist_entry_count, Some(42));
    }

    #[test]
    fn warninglist_type_field_rename() {
        let w = MispWarninglist {
            warninglist_type: Some("cidr".into()),
            ..MispWarninglist::new("test")
        };
        let json = serde_json::to_string(&w).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["type"], "cidr");
        assert!(val.get("warninglist_type").is_none());
    }
}
