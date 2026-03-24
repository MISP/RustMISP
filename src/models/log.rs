use serde::{Deserialize, Serialize};

use super::serde_helpers::string_or_i64_opt;

/// A MISP audit log entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispLog {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// Title/summary of the log entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Timestamp when the action was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// The model that was acted upon (e.g., "Event", "Attribute").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// The ID of the model object.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub model_id: Option<i64>,

    /// The action performed (e.g., "add", "edit", "delete").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// The user ID who performed the action.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_id: Option<i64>,

    /// Description of the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,

    /// Email of the user who performed the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Organisation performing the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

    /// Description text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// IP address from which the action was performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_serde_roundtrip() {
        let log = MispLog {
            id: Some(100),
            title: Some("Event created".into()),
            created: Some("2024-01-15 10:30:00".into()),
            model: Some("Event".into()),
            model_id: Some(42),
            action: Some("add".into()),
            user_id: Some(1),
            change: Some("info => Test event".into()),
            email: Some("admin@example.com".into()),
            org: Some("ORGNAME".into()),
            description: Some("Event (42) created".into()),
            ip: Some("192.168.1.1".into()),
        };
        let json = serde_json::to_string(&log).unwrap();
        let back: MispLog = serde_json::from_str(&json).unwrap();
        assert_eq!(log, back);
    }

    #[test]
    fn log_deserialize_misp_format() {
        let json = r#"{
            "id": "100",
            "title": "Event created",
            "created": "2024-01-15 10:30:00",
            "model": "Event",
            "model_id": "42",
            "action": "add",
            "user_id": "1",
            "email": "admin@example.com"
        }"#;
        let log: MispLog = serde_json::from_str(json).unwrap();
        assert_eq!(log.id, Some(100));
        assert_eq!(log.model.as_deref(), Some("Event"));
        assert_eq!(log.action.as_deref(), Some("add"));
    }
}
