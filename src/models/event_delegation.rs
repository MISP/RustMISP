use serde::{Deserialize, Serialize};

use super::serde_helpers::string_or_i64_opt;

/// An event delegation request — transfers event ownership to another organisation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispEventDelegation {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// The event being delegated.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_id: Option<i64>,

    /// The requesting organisation ID.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// The target organisation ID to delegate to.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub requester_org_id: Option<i64>,

    /// Distribution level for the delegated event.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Message from the delegator to the target organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Sharing group ID (when distribution == 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,

    /// Event info.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_info: Option<String>,

    /// Organisation details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<serde_json::Value>,

    /// Requester organisation details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_org: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_delegation_serde_roundtrip() {
        let d = MispEventDelegation {
            id: Some(1),
            event_id: Some(42),
            org_id: Some(5),
            requester_org_id: Some(3),
            distribution: Some(1),
            message: Some("Please take ownership".into()),
            sharing_group_id: None,
            event_info: Some("Malware report".into()),
            org: None,
            requester_org: None,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: MispEventDelegation = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn event_delegation_deserialize_misp_format() {
        let json = r#"{
            "id": "7",
            "event_id": "42",
            "org_id": "5",
            "requester_org_id": "3",
            "distribution": "1",
            "message": "Delegation request"
        }"#;
        let d: MispEventDelegation = serde_json::from_str(json).unwrap();
        assert_eq!(d.id, Some(7));
        assert_eq!(d.event_id, Some(42));
        assert_eq!(d.distribution, Some(1));
    }
}
