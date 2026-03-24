use serde::{Deserialize, Serialize};

use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP taxonomy — a classification scheme for tagging events and attributes.
///
/// Taxonomies provide standardised vocabularies (e.g., TLP, admiralty-scale,
/// OSINT) that can be enabled on a MISP instance and used to create tags.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispTaxonomy {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Machine-readable namespace (e.g., "tlp", "admiralty-scale").
    #[serde(default)]
    pub namespace: String,

    /// Human-readable description of the taxonomy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Version number of the taxonomy definition.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<i64>,

    /// Whether this taxonomy is enabled on the instance.
    #[serde(default, with = "flexible_bool")]
    pub enabled: bool,

    /// Whether tags from this taxonomy are mutually exclusive.
    #[serde(default, with = "flexible_bool")]
    pub exclusive: bool,

    /// Whether tagging with this taxonomy is required before publishing.
    #[serde(default, with = "flexible_bool")]
    pub required: bool,

    /// Whether highlighting is enabled for this taxonomy.
    #[serde(default, with = "flexible_bool")]
    pub highlighted: bool,

    /// Number of existing tags from this taxonomy.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub existing_tag_count: Option<i64>,
}

impl MispTaxonomy {
    /// Create a new taxonomy with a namespace.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            id: None,
            namespace: namespace.into(),
            description: None,
            version: None,
            enabled: false,
            exclusive: false,
            required: false,
            highlighted: false,
            existing_tag_count: None,
        }
    }
}

impl Default for MispTaxonomy {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_new_defaults() {
        let t = MispTaxonomy::new("tlp");
        assert_eq!(t.namespace, "tlp");
        assert!(t.id.is_none());
        assert!(!t.enabled);
        assert!(!t.exclusive);
        assert!(!t.required);
    }

    #[test]
    fn taxonomy_serde_roundtrip() {
        let t = MispTaxonomy {
            id: Some(1),
            namespace: "tlp".into(),
            description: Some("Traffic Light Protocol".into()),
            version: Some(5),
            enabled: true,
            exclusive: true,
            required: false,
            highlighted: false,
            existing_tag_count: Some(4),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: MispTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn taxonomy_deserialize_misp_format() {
        let json = r#"{
            "id": "1",
            "namespace": "tlp",
            "description": "Traffic Light Protocol",
            "version": "5",
            "enabled": "1",
            "exclusive": "0",
            "required": "1",
            "highlighted": "0",
            "existing_tag_count": "4"
        }"#;
        let t: MispTaxonomy = serde_json::from_str(json).unwrap();
        assert_eq!(t.id, Some(1));
        assert_eq!(t.namespace, "tlp");
        assert!(t.enabled);
        assert!(!t.exclusive);
        assert!(t.required);
        assert_eq!(t.existing_tag_count, Some(4));
    }

    #[test]
    fn taxonomy_deserialize_boolean_formats() {
        let json = r#"{
            "namespace": "test",
            "enabled": true,
            "exclusive": false,
            "required": "true",
            "highlighted": "false"
        }"#;
        let t: MispTaxonomy = serde_json::from_str(json).unwrap();
        assert!(t.enabled);
        assert!(!t.exclusive);
        assert!(t.required);
        assert!(!t.highlighted);
    }
}
