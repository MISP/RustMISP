use serde::{Deserialize, Serialize};

use super::serde_helpers::string_or_i64_opt;

/// A blocklisted event UUID — events matching these UUIDs will not be synced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispEventBlocklist {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// The event UUID to blocklist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_uuid: Option<String>,

    /// Timestamp when the blocklist entry was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Free-text comment explaining why the event is blocklisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Original event info string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_info: Option<String>,

    /// Name of the organisation that created the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_orgc: Option<String>,

    /// Organisation UUID that created the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orgc_uuid: Option<String>,
}

/// A blocklisted organisation UUID — events from these orgs will not be synced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispOrganisationBlocklist {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// The organisation UUID to blocklist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_uuid: Option<String>,

    /// Timestamp when the blocklist entry was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Free-text comment explaining why the organisation is blocklisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Name of the blocklisted organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_blocklist_serde_roundtrip() {
        let bl = MispEventBlocklist {
            id: Some(1),
            event_uuid: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            created: Some("2024-01-15 10:00:00".into()),
            comment: Some("Known false positive".into()),
            event_info: Some("Test event".into()),
            event_orgc: Some("ORGC".into()),
            orgc_uuid: Some("660e8400-e29b-41d4-a716-446655440000".into()),
        };
        let json = serde_json::to_string(&bl).unwrap();
        let back: MispEventBlocklist = serde_json::from_str(&json).unwrap();
        assert_eq!(bl, back);
    }

    #[test]
    fn event_blocklist_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "event_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "comment": "Blocklisted",
            "event_info": "Spam event"
        }"#;
        let bl: MispEventBlocklist = serde_json::from_str(json).unwrap();
        assert_eq!(bl.id, Some(5));
        assert_eq!(
            bl.event_uuid.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn organisation_blocklist_serde_roundtrip() {
        let bl = MispOrganisationBlocklist {
            id: Some(2),
            org_uuid: Some("770e8400-e29b-41d4-a716-446655440000".into()),
            created: Some("2024-02-01 12:00:00".into()),
            comment: Some("Untrusted org".into()),
            org_name: Some("BadOrg".into()),
        };
        let json = serde_json::to_string(&bl).unwrap();
        let back: MispOrganisationBlocklist = serde_json::from_str(&json).unwrap();
        assert_eq!(bl, back);
    }

    #[test]
    fn organisation_blocklist_deserialize_misp_format() {
        let json = r#"{
            "id": "3",
            "org_uuid": "770e8400-e29b-41d4-a716-446655440000",
            "org_name": "BadOrg"
        }"#;
        let bl: MispOrganisationBlocklist = serde_json::from_str(json).unwrap();
        assert_eq!(bl.id, Some(3));
        assert_eq!(bl.org_name.as_deref(), Some("BadOrg"));
    }
}
