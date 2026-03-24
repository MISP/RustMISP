use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP noticelist — informational notices attached to attributes
/// based on their values (e.g., RFC 1918 private IP ranges).
///
/// Unlike warninglists (which suppress false positives), noticelists
/// display informational messages to help analysts interpret indicators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispNoticelist {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Short name of the noticelist.
    #[serde(default)]
    pub name: String,

    /// Full expanded name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded_name: Option<String>,

    /// Reference URL or identifier.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<Vec<String>>,

    /// Geographical area this noticelist applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geographical_area: Option<Vec<String>>,

    /// Version of the noticelist definition.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<i64>,

    /// Whether this noticelist is enabled on the instance.
    #[serde(default, with = "flexible_bool")]
    pub enabled: bool,
}

impl MispNoticelist {
    /// Create a new noticelist with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            expanded_name: None,
            reference: None,
            geographical_area: None,
            version: None,
            enabled: false,
        }
    }
}

impl Default for MispNoticelist {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noticelist_new_defaults() {
        let n = MispNoticelist::new("rfc1918");
        assert_eq!(n.name, "rfc1918");
        assert!(n.id.is_none());
        assert!(!n.enabled);
    }

    #[test]
    fn noticelist_serde_roundtrip() {
        let n = MispNoticelist {
            id: Some(5),
            name: "rfc1918".into(),
            expanded_name: Some("RFC 1918 — Private IP ranges".into()),
            reference: Some(vec!["https://tools.ietf.org/html/rfc1918".into()]),
            geographical_area: Some(vec!["world".into()]),
            version: Some(2),
            enabled: true,
        };
        let json = serde_json::to_string(&n).unwrap();
        let back: MispNoticelist = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn noticelist_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "name": "rfc1918",
            "expanded_name": "RFC 1918 — Private IP ranges",
            "ref": ["https://tools.ietf.org/html/rfc1918"],
            "geographical_area": ["world"],
            "version": "2",
            "enabled": "1"
        }"#;
        let n: MispNoticelist = serde_json::from_str(json).unwrap();
        assert_eq!(n.id, Some(5));
        assert_eq!(n.name, "rfc1918");
        assert!(n.enabled);
        assert_eq!(n.reference.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn noticelist_ref_field_rename() {
        let n = MispNoticelist {
            reference: Some(vec!["https://example.com".into()]),
            ..MispNoticelist::new("test")
        };
        let json = serde_json::to_string(&n).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val.get("ref").is_some());
        assert!(val.get("reference").is_none());
    }
}
