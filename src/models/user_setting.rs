use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::serde_helpers::string_or_i64_opt;

/// A MISP user setting — a key/value pair storing per-user configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispUserSetting {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// The setting key (e.g. "dashboard", "homepage").
    #[serde(default)]
    pub setting: String,

    /// The setting value (arbitrary JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,

    /// User ID this setting belongs to.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_id: Option<i64>,
}

impl MispUserSetting {
    /// Create a new user setting with a key.
    pub fn new(setting: impl Into<String>) -> Self {
        Self {
            id: None,
            setting: setting.into(),
            value: None,
            user_id: None,
        }
    }
}

impl Default for MispUserSetting {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_setting_new_defaults() {
        let us = MispUserSetting::new("dashboard");
        assert_eq!(us.setting, "dashboard");
        assert!(us.id.is_none());
        assert!(us.value.is_none());
        assert!(us.user_id.is_none());
    }

    #[test]
    fn user_setting_serde_roundtrip() {
        let us = MispUserSetting {
            id: Some(1),
            setting: "homepage".into(),
            value: Some(serde_json::json!({"path": "/events/index"})),
            user_id: Some(1),
        };
        let json = serde_json::to_string(&us).unwrap();
        let back: MispUserSetting = serde_json::from_str(&json).unwrap();
        assert_eq!(us, back);
    }

    #[test]
    fn user_setting_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "setting": "dashboard_access",
            "value": {"widgets": ["eventTimeline", "trendsWidget"]},
            "user_id": "1"
        }"#;
        let us: MispUserSetting = serde_json::from_str(json).unwrap();
        assert_eq!(us.id, Some(5));
        assert_eq!(us.setting, "dashboard_access");
        assert!(us.value.is_some());
        assert_eq!(us.user_id, Some(1));
    }

    #[test]
    fn user_setting_deserialize_minimal() {
        let json = r#"{"setting": "theme"}"#;
        let us: MispUserSetting = serde_json::from_str(json).unwrap();
        assert_eq!(us.setting, "theme");
        assert!(us.id.is_none());
    }

    #[test]
    fn user_setting_string_value() {
        let us = MispUserSetting {
            id: None,
            setting: "publish_alert_filter".into(),
            value: Some(serde_json::json!("enabled")),
            user_id: Some(2),
        };
        let json = serde_json::to_string(&us).unwrap();
        let back: MispUserSetting = serde_json::from_str(&json).unwrap();
        assert_eq!(us, back);
    }
}
