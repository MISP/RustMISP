use serde::{Deserialize, Serialize};

use super::organisation::MispOrganisation;
use super::serde_helpers::{flexible_bool, string_or_i64_opt};

/// A MISP sharing group — defines a custom set of organisations and servers
/// that may receive shared events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispSharingGroup {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID of the sharing group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Display name.
    #[serde(default)]
    pub name: String,

    /// Human-readable description of the sharing group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Releasability statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releasability: Option<String>,

    /// Whether this sharing group is local-only (not synchronised).
    #[serde(default, with = "flexible_bool")]
    pub local: bool,

    /// Whether this sharing group is active.
    #[serde(default, with = "flexible_bool")]
    pub active: bool,

    /// Whether the sharing group allows roaming (all connected instances).
    #[serde(default, with = "flexible_bool")]
    pub roaming: bool,

    /// Organisation ID of the creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Organisation UUID of the creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organisation_uuid: Option<String>,

    /// Timestamp of creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Timestamp of last modification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,

    /// Whether the current user can edit this sharing group.
    #[serde(default, with = "flexible_bool")]
    pub editable: bool,

    /// The creator organisation (nested, read-only).
    #[serde(
        default,
        rename = "Organisation",
        skip_serializing_if = "Option::is_none"
    )]
    pub organisation: Option<MispOrganisation>,

    /// Organisations in this sharing group (nested, read-only).
    #[serde(
        default,
        rename = "SharingGroupOrg",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_org: Option<Vec<SharingGroupOrg>>,

    /// Servers in this sharing group (nested, read-only).
    #[serde(
        default,
        rename = "SharingGroupServer",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_server: Option<Vec<SharingGroupServer>>,
}

/// An organisation entry within a sharing group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharingGroupOrg {
    /// Unique identifier of this sharing group org entry.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// ID of the parent sharing group.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,

    /// ID of the organisation.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Whether this organisation can extend (re-share) the sharing group.
    #[serde(default, with = "flexible_bool")]
    pub extend: bool,

    /// Nested organisation details (read-only).
    #[serde(
        default,
        rename = "Organisation",
        skip_serializing_if = "Option::is_none"
    )]
    pub organisation: Option<MispOrganisation>,
}

/// A server entry within a sharing group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharingGroupServer {
    /// Unique identifier of this sharing group server entry.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// ID of the parent sharing group.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,

    /// ID of the server.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_id: Option<i64>,

    /// Whether all organisations on this server receive the data.
    #[serde(default, with = "flexible_bool")]
    pub all_orgs: bool,
}

impl MispSharingGroup {
    /// Create a new sharing group with a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            name: name.into(),
            description: None,
            releasability: None,
            local: false,
            active: true,
            roaming: false,
            org_id: None,
            organisation_uuid: None,
            created: None,
            modified: None,
            editable: false,
            organisation: None,
            sharing_group_org: None,
            sharing_group_server: None,
        }
    }
}

impl Default for MispSharingGroup {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_group_new_defaults() {
        let sg = MispSharingGroup::new("NATO TLP:AMBER");
        assert_eq!(sg.name, "NATO TLP:AMBER");
        assert!(sg.id.is_none());
        assert!(sg.active);
        assert!(!sg.roaming);
    }

    #[test]
    fn sharing_group_serde_roundtrip() {
        let sg = MispSharingGroup {
            id: Some(1),
            uuid: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            name: "Test SG".into(),
            description: Some("A test sharing group".into()),
            releasability: Some("TLP:GREEN".into()),
            local: false,
            active: true,
            roaming: false,
            org_id: Some(1),
            organisation_uuid: Some("abcd-1234".into()),
            created: Some("2024-01-01 00:00:00".into()),
            modified: Some("2024-06-15 12:00:00".into()),
            editable: true,
            organisation: None,
            sharing_group_org: None,
            sharing_group_server: None,
        };
        let json = serde_json::to_string(&sg).unwrap();
        let back: MispSharingGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(sg, back);
    }

    #[test]
    fn sharing_group_deserialize_misp_format() {
        let json = r#"{
            "id": "10",
            "uuid": "550e8400-e29b-41d4-a716-446655440000",
            "name": "CIRCL Partners",
            "description": "Sharing group for CIRCL partners",
            "releasability": "TLP:AMBER",
            "local": "0",
            "active": "1",
            "roaming": "0",
            "org_id": "1",
            "organisation_uuid": "abcd-1234",
            "created": "2024-01-01 00:00:00",
            "modified": "2024-06-15 12:00:00",
            "editable": "1",
            "Organisation": {
                "id": "1",
                "name": "CIRCL",
                "uuid": "orgUuid"
            },
            "SharingGroupOrg": [
                {
                    "id": "1",
                    "sharing_group_id": "10",
                    "org_id": "1",
                    "extend": "1",
                    "Organisation": {"id": "1", "name": "CIRCL"}
                }
            ],
            "SharingGroupServer": [
                {
                    "id": "1",
                    "sharing_group_id": "10",
                    "server_id": "0",
                    "all_orgs": "1"
                }
            ]
        }"#;
        let sg: MispSharingGroup = serde_json::from_str(json).unwrap();
        assert_eq!(sg.id, Some(10));
        assert_eq!(sg.name, "CIRCL Partners");
        assert!(sg.active);
        assert!(!sg.roaming);
        assert!(sg.editable);
        assert!(sg.organisation.is_some());
        let orgs = sg.sharing_group_org.unwrap();
        assert_eq!(orgs.len(), 1);
        assert!(orgs[0].extend);
        let servers = sg.sharing_group_server.unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].all_orgs);
    }

    #[test]
    fn sharing_group_deserialize_minimal() {
        let json = r#"{"name": "Minimal SG"}"#;
        let sg: MispSharingGroup = serde_json::from_str(json).unwrap();
        assert_eq!(sg.name, "Minimal SG");
        assert!(sg.id.is_none());
    }
}
