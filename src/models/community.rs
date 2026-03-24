use serde::{Deserialize, Serialize};

use super::serde_helpers::string_or_i64_opt;

/// A MISP community — a group of organisations sharing threat intelligence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispCommunity {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID of the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Community name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Description of the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL of the community's MISP instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Type of community.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub community_type: Option<String>,

    /// Email address for the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Logo (base64-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,

    /// Sector the community covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector: Option<String>,

    /// Nationality of the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,

    /// Organisation running the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_serde_roundtrip() {
        let c = MispCommunity {
            id: Some(1),
            uuid: Some("aabb-ccdd".into()),
            name: Some("Test Community".into()),
            description: Some("A test community".into()),
            url: Some("https://misp.example.com".into()),
            community_type: Some("public".into()),
            email: Some("admin@example.com".into()),
            logo: None,
            sector: Some("IT".into()),
            nationality: Some("International".into()),
            org: None,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: MispCommunity = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn community_deserialize_misp_format() {
        let json = r#"{
            "id": "10",
            "uuid": "aabb-ccdd",
            "name": "CTI League",
            "description": "Threat intel sharing community",
            "url": "https://misp.cti-league.com",
            "type": "public"
        }"#;
        let c: MispCommunity = serde_json::from_str(json).unwrap();
        assert_eq!(c.id, Some(10));
        assert_eq!(c.name.as_deref(), Some("CTI League"));
        assert_eq!(c.community_type.as_deref(), Some("public"));
    }
}
