use serde::{Deserialize, Serialize};

use super::serde_helpers::string_or_i64_opt;

/// The type of analyst data entity.
///
/// Used to select the correct API endpoint when performing CRUD operations
/// on analyst data (notes, opinions, or relationships).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalystDataType {
    /// A note attached to a MISP object.
    Note,
    /// An opinion (0–100 score) attached to a MISP object.
    Opinion,
    /// A relationship between two MISP objects.
    Relationship,
}

impl AnalystDataType {
    /// Return the API path component for this analyst data type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Note => "Note",
            Self::Opinion => "Opinion",
            Self::Relationship => "Relationship",
        }
    }
}

impl std::fmt::Display for AnalystDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A MISP analyst note — free-text annotation attached to any MISP object.
///
/// Notes allow analysts to add context, observations, or commentary to
/// events, attributes, objects, or other MISP entities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispNote {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID (set by server or provided on creation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// The note body / content.
    #[serde(default)]
    pub note: String,

    /// Language of the note (e.g., "en").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// UUID of the object this note is attached to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_uuid: Option<String>,

    /// Type of the object this note is attached to (e.g., "Attribute", "Event").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,

    /// Authors of the note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authors: Option<String>,

    /// Creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Last modification timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,

    /// Organisation ID of the note creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Organisation UUID of the note creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orgc_uuid: Option<String>,

    /// Distribution level.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Sharing group ID (when distribution == 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,
}

impl MispNote {
    /// Create a new note with the given text.
    pub fn new(note: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            note: note.into(),
            language: None,
            object_uuid: None,
            object_type: None,
            authors: None,
            created: None,
            modified: None,
            org_id: None,
            orgc_uuid: None,
            distribution: None,
            sharing_group_id: None,
        }
    }

    /// Set the target object for this note.
    pub fn for_object(
        mut self,
        object_type: impl Into<String>,
        object_uuid: impl Into<String>,
    ) -> Self {
        self.object_type = Some(object_type.into());
        self.object_uuid = Some(object_uuid.into());
        self
    }
}

/// A MISP analyst opinion — a numeric score (0–100) with optional comment,
/// attached to any MISP object.
///
/// Opinions allow analysts to express agreement/disagreement with
/// the quality or accuracy of MISP data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispOpinion {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID (set by server or provided on creation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Opinion score from 0 (strongly disagree) to 100 (strongly agree).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub opinion: Option<i64>,

    /// Free-text comment explaining the opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// UUID of the object this opinion is attached to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_uuid: Option<String>,

    /// Type of the object this opinion is attached to (e.g., "Attribute", "Event").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,

    /// Authors of the opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authors: Option<String>,

    /// Creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Last modification timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,

    /// Organisation ID of the opinion creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Organisation UUID of the opinion creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orgc_uuid: Option<String>,

    /// Distribution level.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Sharing group ID (when distribution == 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,
}

impl MispOpinion {
    /// Create a new opinion with the given score (0–100).
    pub fn new(opinion: i64) -> Self {
        Self {
            id: None,
            uuid: None,
            opinion: Some(opinion),
            comment: None,
            object_uuid: None,
            object_type: None,
            authors: None,
            created: None,
            modified: None,
            org_id: None,
            orgc_uuid: None,
            distribution: None,
            sharing_group_id: None,
        }
    }

    /// Set the target object for this opinion.
    pub fn for_object(
        mut self,
        object_type: impl Into<String>,
        object_uuid: impl Into<String>,
    ) -> Self {
        self.object_type = Some(object_type.into());
        self.object_uuid = Some(object_uuid.into());
        self
    }

    /// Set the comment for this opinion.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// A MISP analyst relationship — a typed link between two MISP objects.
///
/// Relationships allow analysts to express connections between entities,
/// such as "attribute X is related to event Y".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MispRelationship {
    /// Unique numeric identifier (set by server).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<i64>,

    /// UUID (set by server or provided on creation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// The type of relationship (e.g., "related-to", "derived-from").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_type: Option<String>,

    /// UUID of the related (target) object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_object_uuid: Option<String>,

    /// Type of the related (target) object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_object_type: Option<String>,

    /// UUID of the source object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_uuid: Option<String>,

    /// Type of the source object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,

    /// Authors of the relationship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authors: Option<String>,

    /// Creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Last modification timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,

    /// Organisation ID of the relationship creator.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub org_id: Option<i64>,

    /// Organisation UUID of the relationship creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orgc_uuid: Option<String>,

    /// Distribution level.
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub distribution: Option<i64>,

    /// Sharing group ID (when distribution == 4).
    #[serde(
        default,
        with = "string_or_i64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub sharing_group_id: Option<i64>,
}

impl MispRelationship {
    /// Create a new relationship of the given type.
    pub fn new(relationship_type: impl Into<String>) -> Self {
        Self {
            id: None,
            uuid: None,
            relationship_type: Some(relationship_type.into()),
            related_object_uuid: None,
            related_object_type: None,
            object_uuid: None,
            object_type: None,
            authors: None,
            created: None,
            modified: None,
            org_id: None,
            orgc_uuid: None,
            distribution: None,
            sharing_group_id: None,
        }
    }

    /// Set the source object for this relationship.
    pub fn from_object(
        mut self,
        object_type: impl Into<String>,
        object_uuid: impl Into<String>,
    ) -> Self {
        self.object_type = Some(object_type.into());
        self.object_uuid = Some(object_uuid.into());
        self
    }

    /// Set the target (related) object for this relationship.
    pub fn to_object(
        mut self,
        related_object_type: impl Into<String>,
        related_object_uuid: impl Into<String>,
    ) -> Self {
        self.related_object_type = Some(related_object_type.into());
        self.related_object_uuid = Some(related_object_uuid.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_new_defaults() {
        let note = MispNote::new("This is suspicious");
        assert_eq!(note.note, "This is suspicious");
        assert!(note.id.is_none());
        assert!(note.object_uuid.is_none());
    }

    #[test]
    fn note_for_object() {
        let note = MispNote::new("Important finding").for_object("Event", "abc-123");
        assert_eq!(note.object_type.as_deref(), Some("Event"));
        assert_eq!(note.object_uuid.as_deref(), Some("abc-123"));
    }

    #[test]
    fn note_serde_roundtrip() {
        let note = MispNote {
            id: Some(1),
            uuid: Some("note-uuid-1234".into()),
            note: "Analyst observation".into(),
            language: Some("en".into()),
            object_uuid: Some("event-uuid-5678".into()),
            object_type: Some("Event".into()),
            authors: Some("analyst@example.com".into()),
            created: Some("2024-01-15 10:30:00".into()),
            modified: Some("2024-01-15 10:30:00".into()),
            org_id: Some(1),
            orgc_uuid: Some("org-uuid".into()),
            distribution: Some(0),
            sharing_group_id: None,
        };
        let json = serde_json::to_string(&note).unwrap();
        let back: MispNote = serde_json::from_str(&json).unwrap();
        assert_eq!(note, back);
    }

    #[test]
    fn note_deserialize_misp_format() {
        let json = r#"{
            "id": "5",
            "uuid": "note-uuid",
            "note": "Test note",
            "language": "en",
            "object_uuid": "target-uuid",
            "object_type": "Attribute",
            "authors": "user@test.com",
            "created": "2024-01-15 10:30:00",
            "modified": "2024-01-15 10:30:00",
            "org_id": "1",
            "distribution": "0"
        }"#;
        let note: MispNote = serde_json::from_str(json).unwrap();
        assert_eq!(note.id, Some(5));
        assert_eq!(note.note, "Test note");
        assert_eq!(note.object_type.as_deref(), Some("Attribute"));
    }

    #[test]
    fn opinion_new_defaults() {
        let opinion = MispOpinion::new(75);
        assert_eq!(opinion.opinion, Some(75));
        assert!(opinion.id.is_none());
        assert!(opinion.comment.is_none());
    }

    #[test]
    fn opinion_builder_methods() {
        let opinion = MispOpinion::new(90)
            .for_object("Event", "event-uuid")
            .with_comment("High confidence");
        assert_eq!(opinion.opinion, Some(90));
        assert_eq!(opinion.object_type.as_deref(), Some("Event"));
        assert_eq!(opinion.comment.as_deref(), Some("High confidence"));
    }

    #[test]
    fn opinion_serde_roundtrip() {
        let opinion = MispOpinion {
            id: Some(2),
            uuid: Some("opinion-uuid".into()),
            opinion: Some(85),
            comment: Some("Likely accurate".into()),
            object_uuid: Some("attr-uuid".into()),
            object_type: Some("Attribute".into()),
            authors: Some("analyst@example.com".into()),
            created: Some("2024-01-15 10:30:00".into()),
            modified: Some("2024-01-15 10:30:00".into()),
            org_id: Some(1),
            orgc_uuid: Some("org-uuid".into()),
            distribution: Some(1),
            sharing_group_id: None,
        };
        let json = serde_json::to_string(&opinion).unwrap();
        let back: MispOpinion = serde_json::from_str(&json).unwrap();
        assert_eq!(opinion, back);
    }

    #[test]
    fn opinion_deserialize_misp_format() {
        let json = r#"{
            "id": "10",
            "uuid": "opinion-uuid",
            "opinion": "75",
            "comment": "Mostly agree",
            "object_uuid": "target-uuid",
            "object_type": "Event",
            "org_id": "2",
            "distribution": "1"
        }"#;
        let opinion: MispOpinion = serde_json::from_str(json).unwrap();
        assert_eq!(opinion.id, Some(10));
        assert_eq!(opinion.opinion, Some(75));
        assert_eq!(opinion.comment.as_deref(), Some("Mostly agree"));
    }

    #[test]
    fn relationship_new_defaults() {
        let rel = MispRelationship::new("related-to");
        assert_eq!(rel.relationship_type.as_deref(), Some("related-to"));
        assert!(rel.id.is_none());
    }

    #[test]
    fn relationship_builder_methods() {
        let rel = MispRelationship::new("derived-from")
            .from_object("Attribute", "src-uuid")
            .to_object("Event", "dst-uuid");
        assert_eq!(rel.object_type.as_deref(), Some("Attribute"));
        assert_eq!(rel.object_uuid.as_deref(), Some("src-uuid"));
        assert_eq!(rel.related_object_type.as_deref(), Some("Event"));
        assert_eq!(rel.related_object_uuid.as_deref(), Some("dst-uuid"));
    }

    #[test]
    fn relationship_serde_roundtrip() {
        let rel = MispRelationship {
            id: Some(3),
            uuid: Some("rel-uuid".into()),
            relationship_type: Some("related-to".into()),
            related_object_uuid: Some("target-uuid".into()),
            related_object_type: Some("Event".into()),
            object_uuid: Some("source-uuid".into()),
            object_type: Some("Attribute".into()),
            authors: Some("analyst@example.com".into()),
            created: Some("2024-01-15 10:30:00".into()),
            modified: Some("2024-01-15 10:30:00".into()),
            org_id: Some(1),
            orgc_uuid: Some("org-uuid".into()),
            distribution: Some(0),
            sharing_group_id: None,
        };
        let json = serde_json::to_string(&rel).unwrap();
        let back: MispRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, back);
    }

    #[test]
    fn relationship_deserialize_misp_format() {
        let json = r#"{
            "id": "7",
            "uuid": "rel-uuid",
            "relationship_type": "derived-from",
            "related_object_uuid": "target-uuid",
            "related_object_type": "Event",
            "object_uuid": "source-uuid",
            "object_type": "Attribute",
            "org_id": "1",
            "distribution": "0"
        }"#;
        let rel: MispRelationship = serde_json::from_str(json).unwrap();
        assert_eq!(rel.id, Some(7));
        assert_eq!(rel.relationship_type.as_deref(), Some("derived-from"));
    }

    #[test]
    fn analyst_data_type_display() {
        assert_eq!(AnalystDataType::Note.as_str(), "Note");
        assert_eq!(AnalystDataType::Opinion.as_str(), "Opinion");
        assert_eq!(AnalystDataType::Relationship.as_str(), "Relationship");
        assert_eq!(format!("{}", AnalystDataType::Note), "Note");
    }
}
