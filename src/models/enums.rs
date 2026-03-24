use serde::{Deserialize, Serialize};

/// MISP distribution levels controlling who can see shared data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Distribution {
    /// Your organisation only.
    #[serde(rename = "0")]
    YourOrganisationOnly = 0,
    /// This community only.
    #[serde(rename = "1")]
    ThisCommunityOnly = 1,
    /// Connected communities.
    #[serde(rename = "2")]
    ConnectedCommunities = 2,
    /// All communities.
    #[serde(rename = "3")]
    AllCommunities = 3,
    /// Sharing group.
    #[serde(rename = "4")]
    SharingGroup = 4,
    /// Inherit from parent event.
    #[serde(rename = "5")]
    InheritEvent = 5,
}

/// MISP threat level indicating severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum ThreatLevel {
    /// High threat.
    #[serde(rename = "1")]
    High = 1,
    /// Medium threat.
    #[serde(rename = "2")]
    Medium = 2,
    /// Low threat.
    #[serde(rename = "3")]
    Low = 3,
    /// Undefined threat level.
    #[serde(rename = "4")]
    Undefined = 4,
}

/// MISP analysis state of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Analysis {
    /// Initial analysis.
    #[serde(rename = "0")]
    Initial = 0,
    /// Ongoing analysis.
    #[serde(rename = "1")]
    Ongoing = 1,
    /// Analysis complete.
    #[serde(rename = "2")]
    Complete = 2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn distribution_serialize_roundtrip() {
        let variants = [
            (Distribution::YourOrganisationOnly, "\"0\""),
            (Distribution::ThisCommunityOnly, "\"1\""),
            (Distribution::ConnectedCommunities, "\"2\""),
            (Distribution::AllCommunities, "\"3\""),
            (Distribution::SharingGroup, "\"4\""),
            (Distribution::InheritEvent, "\"5\""),
        ];
        for (variant, expected_json) in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected_json, "serialize {:?}", variant);
            let deserialized: Distribution = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, variant, "roundtrip {:?}", variant);
        }
    }

    #[test]
    fn distribution_deserialize_all_variants() {
        for i in 0..=5 {
            let json = format!("\"{}\"", i);
            let d: Distribution = serde_json::from_str(&json).unwrap();
            assert_eq!(d as i32, i);
        }
    }

    #[test]
    fn distribution_invalid_value() {
        let result = serde_json::from_str::<Distribution>("\"6\"");
        assert!(result.is_err());
    }

    #[test]
    fn threat_level_serialize_roundtrip() {
        let variants = [
            (ThreatLevel::High, "\"1\""),
            (ThreatLevel::Medium, "\"2\""),
            (ThreatLevel::Low, "\"3\""),
            (ThreatLevel::Undefined, "\"4\""),
        ];
        for (variant, expected_json) in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected_json, "serialize {:?}", variant);
            let deserialized: ThreatLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, variant, "roundtrip {:?}", variant);
        }
    }

    #[test]
    fn threat_level_invalid_value() {
        let result = serde_json::from_str::<ThreatLevel>("\"0\"");
        assert!(result.is_err());
        let result = serde_json::from_str::<ThreatLevel>("\"5\"");
        assert!(result.is_err());
    }

    #[test]
    fn analysis_serialize_roundtrip() {
        let variants = [
            (Analysis::Initial, "\"0\""),
            (Analysis::Ongoing, "\"1\""),
            (Analysis::Complete, "\"2\""),
        ];
        for (variant, expected_json) in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected_json, "serialize {:?}", variant);
            let deserialized: Analysis = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, variant, "roundtrip {:?}", variant);
        }
    }

    #[test]
    fn analysis_invalid_value() {
        let result = serde_json::from_str::<Analysis>("\"3\"");
        assert!(result.is_err());
    }

    #[test]
    fn enums_in_struct_context() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestEvent {
            distribution: Distribution,
            threat_level: ThreatLevel,
            analysis: Analysis,
        }

        let event = TestEvent {
            distribution: Distribution::AllCommunities,
            threat_level: ThreatLevel::High,
            analysis: Analysis::Complete,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TestEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);

        // Verify the JSON has the expected numeric string format
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["distribution"], "3");
        assert_eq!(value["threat_level"], "1");
        assert_eq!(value["analysis"], "2");
    }

    #[test]
    fn enum_clone_copy_hash() {
        use std::collections::HashSet;

        let d = Distribution::SharingGroup;
        let d2 = d; // Copy
        let d3 = d; // Clone
        assert_eq!(d, d2);
        assert_eq!(d, d3);

        let mut set = HashSet::new();
        set.insert(Distribution::YourOrganisationOnly);
        set.insert(Distribution::AllCommunities);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Distribution::YourOrganisationOnly));
    }
}
