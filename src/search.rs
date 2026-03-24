use serde::Serialize;
use serde_json::Value;

use crate::error::{MispError, MispResult};

/// Controller to search against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchController {
    /// Search against `/events/restSearch`.
    Events,
    /// Search against `/attributes/restSearch`.
    Attributes,
    /// Search against `/objects/restSearch`.
    Objects,
}

impl SearchController {
    /// Returns the REST search endpoint path for this controller.
    pub fn rest_search_path(&self) -> &'static str {
        match self {
            Self::Events => "events/restSearch",
            Self::Attributes => "attributes/restSearch",
            Self::Objects => "objects/restSearch",
        }
    }
}

/// Return format for search results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReturnFormat {
    /// JSON (default).
    Json,
    /// XML format.
    Xml,
    /// Comma-separated values.
    Csv,
    /// Plain text, one value per line.
    Text,
    /// STIX 1.x XML.
    Stix,
    /// STIX 2.x JSON.
    Stix2,
    /// Suricata IDS rules.
    Suricata,
    /// Snort IDS rules.
    Snort,
    /// YARA rules.
    Yara,
    /// Response Policy Zone (DNS).
    Rpz,
    /// OpenIOC XML.
    #[serde(rename = "openioc")]
    OpenIoc,
}

impl ReturnFormat {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Csv => "csv",
            Self::Text => "text",
            Self::Stix => "stix",
            Self::Stix2 => "stix2",
            Self::Suricata => "suricata",
            Self::Snort => "snort",
            Self::Yara => "yara",
            Self::Rpz => "rpz",
            Self::OpenIoc => "openioc",
        }
    }
}

/// Parameters for MISP REST search queries.
///
/// Use [`SearchBuilder`] for ergonomic construction, or build directly.
/// All fields are optional; only non-`None` values are included in the request.
#[derive(Debug, Clone, Default)]
pub struct SearchParameters {
    /// Filter by attribute value (string or complex query).
    pub value: Option<Value>,
    /// Filter by attribute type (e.g., `"ip-src"`, `"domain"`).
    pub type_attribute: Option<Value>,
    /// Filter by attribute category (e.g., `"Network activity"`).
    pub category: Option<Value>,
    /// Filter by organisation (name or ID).
    pub org: Option<Value>,
    /// Filter by tags (string, list, or complex query via [`build_complex_query`]).
    pub tags: Option<Value>,
    /// Filter by event ID(s).
    pub event_id: Option<Value>,
    /// Filter by UUID(s).
    pub uuid: Option<Value>,

    /// Start date filter (`YYYY-MM-DD`).
    pub date_from: Option<String>,
    /// End date filter (`YYYY-MM-DD`).
    pub date_to: Option<String>,
    /// Relative time filter (e.g., `"5d"`, `"12h"`).
    pub last: Option<String>,
    /// Attribute timestamp filter (epoch or relative).
    pub timestamp: Option<Value>,
    /// Event publish timestamp filter.
    pub publish_timestamp: Option<Value>,
    /// Event-level timestamp filter.
    pub event_timestamp: Option<Value>,

    /// Only return attributes not on any enabled warninglist.
    pub enforce_warninglist: Option<bool>,
    /// Filter by IDS flag.
    pub to_ids: Option<bool>,
    /// Include soft-deleted attributes (bool or `[0,1]` for both).
    pub deleted: Option<Value>,
    /// Filter by event published status.
    pub published: Option<bool>,
    /// Include attachment data (base64) in results.
    pub with_attachments: Option<bool>,

    /// Include the parent event UUID in attribute results.
    pub include_event_uuid: Option<bool>,
    /// Include event-level tags in attribute results.
    pub include_event_tags: Option<bool>,
    /// Include shadow attribute proposals.
    pub include_proposals: Option<bool>,
    /// Include correlation counts.
    pub include_correlations: Option<bool>,
    /// Include sightings data.
    pub include_sightings: Option<bool>,
    /// Include decay score information.
    pub include_decay_score: Option<bool>,
    /// Include the full decaying model definition.
    pub include_full_model: Option<bool>,
    /// Include event context in attribute results.
    pub include_context: Option<bool>,

    /// Maximum number of results to return.
    pub limit: Option<i64>,
    /// Page number for paginated results (1-based).
    pub page: Option<i64>,

    /// Filter by threat level (1=High, 2=Medium, 3=Low, 4=Undefined).
    pub threat_level_id: Option<Value>,
    /// Filter by analysis state (0=Initial, 1=Ongoing, 2=Complete).
    pub analysis: Option<Value>,
    /// Filter by distribution level.
    pub distribution: Option<Value>,
    /// Filter by sharing group ID.
    pub sharing_group_id: Option<Value>,
    /// Filter by object relation name.
    pub object_relation: Option<Value>,
    /// Filter by comment content.
    pub comment: Option<Value>,
    /// Filter by first_seen datetime.
    pub first_seen: Option<String>,
    /// Filter by last_seen datetime.
    pub last_seen: Option<String>,
    /// Specific attribute fields to return.
    pub requested_attributes: Option<Vec<String>>,
    /// Output format (defaults to JSON).
    pub return_format: Option<ReturnFormat>,
    /// Only return sharing group references, not full objects.
    pub sg_reference_only: Option<bool>,
    /// Search across all searchable fields.
    pub searchall: Option<bool>,
    /// Quick filter string applied across multiple fields.
    pub quickfilter: Option<String>,
    /// Decaying model to apply.
    pub decaying_model: Option<Value>,
    /// Minimum decay score threshold.
    pub score: Option<Value>,
    /// Exclude attributes that have decayed below the threshold.
    pub exclude_decayed: Option<bool>,
    /// Override parameters for the decaying model.
    pub model_overrides: Option<Value>,
    /// Return only event metadata (no attributes).
    pub metadata: Option<bool>,
    /// Filter by attribute-level timestamp.
    pub attribute_timestamp: Option<Value>,
    /// Filter by event info field.
    pub event_info: Option<String>,
    /// Omit CSV header row.
    pub headerless: Option<bool>,
}

impl SearchParameters {
    /// Convert these parameters into a JSON [`Value`] for the request body.
    /// Only non-`None` fields are included.
    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();

        macro_rules! insert_opt {
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    map.insert(stringify!($field).to_string(), serde_json::json!(v));
                }
            };
            ($field:ident, $key:expr) => {
                if let Some(ref v) = self.$field {
                    map.insert($key.to_string(), serde_json::json!(v));
                }
            };
        }

        insert_opt!(value);
        insert_opt!(type_attribute, "type");
        insert_opt!(category);
        insert_opt!(org);
        insert_opt!(tags);
        insert_opt!(event_id, "eventid");
        insert_opt!(uuid);

        insert_opt!(date_from, "from");
        insert_opt!(date_to, "to");
        insert_opt!(last);
        insert_opt!(timestamp);
        insert_opt!(publish_timestamp);
        insert_opt!(event_timestamp);

        insert_opt!(enforce_warninglist, "enforceWarninglist");
        insert_opt!(to_ids);
        insert_opt!(deleted);
        insert_opt!(published);
        insert_opt!(with_attachments, "withAttachments");

        insert_opt!(include_event_uuid, "includeEventUuid");
        insert_opt!(include_event_tags, "includeEventTags");
        insert_opt!(include_proposals, "includeProposals");
        insert_opt!(include_correlations, "includeCorrelations");
        insert_opt!(include_sightings, "includeSightings");
        insert_opt!(include_decay_score, "includeDecayScore");
        insert_opt!(include_full_model, "includeFullModel");
        insert_opt!(include_context, "includeContext");

        insert_opt!(limit);
        insert_opt!(page);

        insert_opt!(threat_level_id, "threat_level_id");
        insert_opt!(analysis);
        insert_opt!(distribution);
        insert_opt!(sharing_group_id, "sharing_group_id");
        insert_opt!(object_relation, "object_relation");
        insert_opt!(comment);
        insert_opt!(first_seen);
        insert_opt!(last_seen);

        if let Some(ref attrs) = self.requested_attributes {
            map.insert("requested_attributes".to_string(), serde_json::json!(attrs));
        }

        if let Some(ref rf) = self.return_format {
            map.insert("returnFormat".to_string(), serde_json::json!(rf.as_str()));
        }

        insert_opt!(sg_reference_only, "sgReferenceOnly");
        insert_opt!(searchall);
        insert_opt!(quickfilter);
        insert_opt!(decaying_model, "decayingModel");
        insert_opt!(score);
        insert_opt!(exclude_decayed, "excludeDecayed");
        insert_opt!(model_overrides, "modelOverrides");
        insert_opt!(metadata);
        insert_opt!(attribute_timestamp);
        insert_opt!(event_info, "event_info");
        insert_opt!(headerless);

        Value::Object(map)
    }
}

/// Fluent builder for constructing [`SearchParameters`].
///
/// # Example
/// ```
/// use rustmisp::search::{SearchBuilder, SearchController, ReturnFormat};
///
/// let params = SearchBuilder::new()
///     .value("malware.exe")
///     .type_attribute("filename")
///     .tags(vec!["tlp:white", "malware"])
///     .date_from("2024-01-01")
///     .enforce_warninglist(true)
///     .limit(50)
///     .return_format(ReturnFormat::Json)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SearchBuilder {
    params: SearchParameters,
}

impl SearchBuilder {
    /// Create a new empty search builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the value to search for (string or complex query).
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.params.value = Some(Value::String(value.into()));
        self
    }

    /// Set a complex value query (AND/OR/NOT).
    pub fn value_query(mut self, value: Value) -> Self {
        self.params.value = Some(value);
        self
    }

    /// Filter by attribute type (e.g. "ip-src", "filename").
    pub fn type_attribute(mut self, t: impl Into<String>) -> Self {
        self.params.type_attribute = Some(Value::String(t.into()));
        self
    }

    /// Filter by multiple attribute types.
    pub fn type_attributes(mut self, types: Vec<&str>) -> Self {
        self.params.type_attribute = Some(serde_json::json!(types));
        self
    }

    /// Filter by category (e.g. "Network activity").
    pub fn category(mut self, cat: impl Into<String>) -> Self {
        self.params.category = Some(Value::String(cat.into()));
        self
    }

    /// Filter by organisation (name or ID).
    pub fn org(mut self, org: impl Into<String>) -> Self {
        self.params.org = Some(Value::String(org.into()));
        self
    }

    /// Filter by tags (list of tag names).
    pub fn tags(mut self, tags: Vec<&str>) -> Self {
        self.params.tags = Some(serde_json::json!(tags));
        self
    }

    /// Filter by tags using a complex query (AND/OR/NOT).
    pub fn tags_query(mut self, tags: Value) -> Self {
        self.params.tags = Some(tags);
        self
    }

    /// Filter by event ID(s).
    pub fn event_id(mut self, id: i64) -> Self {
        self.params.event_id = Some(serde_json::json!(id));
        self
    }

    /// Filter by multiple event IDs.
    pub fn event_ids(mut self, ids: Vec<i64>) -> Self {
        self.params.event_id = Some(serde_json::json!(ids));
        self
    }

    /// Filter by UUID.
    pub fn uuid(mut self, uuid: impl Into<String>) -> Self {
        self.params.uuid = Some(Value::String(uuid.into()));
        self
    }

    /// Filter by start date (YYYY-MM-DD).
    pub fn date_from(mut self, date: impl Into<String>) -> Self {
        self.params.date_from = Some(date.into());
        self
    }

    /// Filter by end date (YYYY-MM-DD).
    pub fn date_to(mut self, date: impl Into<String>) -> Self {
        self.params.date_to = Some(date.into());
        self
    }

    /// Relative timestamp filter (e.g. "5d", "12h", "30m").
    pub fn last(mut self, last: impl Into<String>) -> Self {
        self.params.last = Some(last.into());
        self
    }

    /// Filter by attribute timestamp.
    pub fn timestamp(mut self, ts: Value) -> Self {
        self.params.timestamp = Some(ts);
        self
    }

    /// Filter by publish timestamp.
    pub fn publish_timestamp(mut self, ts: Value) -> Self {
        self.params.publish_timestamp = Some(ts);
        self
    }

    /// Filter by event timestamp.
    pub fn event_timestamp(mut self, ts: Value) -> Self {
        self.params.event_timestamp = Some(ts);
        self
    }

    /// Only return attributes matching warninglists.
    pub fn enforce_warninglist(mut self, enforce: bool) -> Self {
        self.params.enforce_warninglist = Some(enforce);
        self
    }

    /// Filter by to_ids flag.
    pub fn to_ids(mut self, to_ids: bool) -> Self {
        self.params.to_ids = Some(to_ids);
        self
    }

    /// Include deleted attributes.
    pub fn deleted(mut self, deleted: bool) -> Self {
        self.params.deleted = Some(serde_json::json!(deleted));
        self
    }

    /// Filter by published status.
    pub fn published(mut self, published: bool) -> Self {
        self.params.published = Some(published);
        self
    }

    /// Include attachment data in results.
    pub fn with_attachments(mut self, with: bool) -> Self {
        self.params.with_attachments = Some(with);
        self
    }

    /// Include event UUID in attribute results.
    pub fn include_event_uuid(mut self, include: bool) -> Self {
        self.params.include_event_uuid = Some(include);
        self
    }

    /// Include event-level tags in results.
    pub fn include_event_tags(mut self, include: bool) -> Self {
        self.params.include_event_tags = Some(include);
        self
    }

    /// Include proposals in results.
    pub fn include_proposals(mut self, include: bool) -> Self {
        self.params.include_proposals = Some(include);
        self
    }

    /// Include correlations in results.
    pub fn include_correlations(mut self, include: bool) -> Self {
        self.params.include_correlations = Some(include);
        self
    }

    /// Include sightings in results.
    pub fn include_sightings(mut self, include: bool) -> Self {
        self.params.include_sightings = Some(include);
        self
    }

    /// Include decay score in results.
    pub fn include_decay_score(mut self, include: bool) -> Self {
        self.params.include_decay_score = Some(include);
        self
    }

    /// Include full decaying model in results.
    pub fn include_full_model(mut self, include: bool) -> Self {
        self.params.include_full_model = Some(include);
        self
    }

    /// Include context in results.
    pub fn include_context(mut self, include: bool) -> Self {
        self.params.include_context = Some(include);
        self
    }

    /// Limit the number of results.
    pub fn limit(mut self, limit: i64) -> Self {
        self.params.limit = Some(limit);
        self
    }

    /// Set the page number for pagination.
    pub fn page(mut self, page: i64) -> Self {
        self.params.page = Some(page);
        self
    }

    /// Filter by threat level.
    pub fn threat_level_id(mut self, level: i64) -> Self {
        self.params.threat_level_id = Some(serde_json::json!(level));
        self
    }

    /// Filter by analysis level.
    pub fn analysis(mut self, analysis: i64) -> Self {
        self.params.analysis = Some(serde_json::json!(analysis));
        self
    }

    /// Filter by distribution level.
    pub fn distribution(mut self, dist: i64) -> Self {
        self.params.distribution = Some(serde_json::json!(dist));
        self
    }

    /// Filter by sharing group ID.
    pub fn sharing_group_id(mut self, sg_id: i64) -> Self {
        self.params.sharing_group_id = Some(serde_json::json!(sg_id));
        self
    }

    /// Filter by object relation.
    pub fn object_relation(mut self, rel: impl Into<String>) -> Self {
        self.params.object_relation = Some(Value::String(rel.into()));
        self
    }

    /// Filter by comment content.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.params.comment = Some(Value::String(comment.into()));
        self
    }

    /// Filter by first_seen timestamp.
    pub fn first_seen(mut self, ts: impl Into<String>) -> Self {
        self.params.first_seen = Some(ts.into());
        self
    }

    /// Filter by last_seen timestamp.
    pub fn last_seen(mut self, ts: impl Into<String>) -> Self {
        self.params.last_seen = Some(ts.into());
        self
    }

    /// Request specific attributes in the response.
    pub fn requested_attributes(mut self, attrs: Vec<&str>) -> Self {
        self.params.requested_attributes = Some(attrs.into_iter().map(String::from).collect());
        self
    }

    /// Set the return format.
    pub fn return_format(mut self, format: ReturnFormat) -> Self {
        self.params.return_format = Some(format);
        self
    }

    /// Only return sharing group references.
    pub fn sg_reference_only(mut self, sg_ref: bool) -> Self {
        self.params.sg_reference_only = Some(sg_ref);
        self
    }

    /// Search across all searchable fields.
    pub fn searchall(mut self, searchall: bool) -> Self {
        self.params.searchall = Some(searchall);
        self
    }

    /// Quick filter string.
    pub fn quickfilter(mut self, filter: impl Into<String>) -> Self {
        self.params.quickfilter = Some(filter.into());
        self
    }

    /// Filter by decaying model.
    pub fn decaying_model(mut self, model: Value) -> Self {
        self.params.decaying_model = Some(model);
        self
    }

    /// Filter by minimum decay score.
    pub fn score(mut self, score: Value) -> Self {
        self.params.score = Some(score);
        self
    }

    /// Exclude decayed attributes.
    pub fn exclude_decayed(mut self, exclude: bool) -> Self {
        self.params.exclude_decayed = Some(exclude);
        self
    }

    /// Set model overrides for decaying.
    pub fn model_overrides(mut self, overrides: Value) -> Self {
        self.params.model_overrides = Some(overrides);
        self
    }

    /// Only return metadata (no attributes).
    pub fn metadata(mut self, metadata: bool) -> Self {
        self.params.metadata = Some(metadata);
        self
    }

    /// Filter by attribute_timestamp.
    pub fn attribute_timestamp(mut self, ts: Value) -> Self {
        self.params.attribute_timestamp = Some(ts);
        self
    }

    /// Filter by event info field.
    pub fn event_info(mut self, info: impl Into<String>) -> Self {
        self.params.event_info = Some(info.into());
        self
    }

    /// Omit CSV headers (for CSV return format).
    pub fn headerless(mut self, headerless: bool) -> Self {
        self.params.headerless = Some(headerless);
        self
    }

    /// Build the [`SearchParameters`].
    pub fn build(self) -> SearchParameters {
        self.params
    }
}

/// Build a complex query combining OR, AND, and NOT parameters.
///
/// This produces the nested structure that MISP's restSearch expects
/// for combining positive and negative filters.
///
/// # Example
/// ```
/// use rustmisp::search::build_complex_query;
///
/// let query = build_complex_query(
///     Some(vec!["malware", "ransomware"]),  // OR
///     Some(vec!["tlp:white"]),              // AND
///     Some(vec!["false-positive"]),         // NOT
/// );
/// // Produces: {"OR": ["malware", "ransomware"], "AND": ["tlp:white"], "NOT": ["false-positive"]}
/// ```
pub fn build_complex_query(
    or_params: Option<Vec<&str>>,
    and_params: Option<Vec<&str>>,
    not_params: Option<Vec<&str>>,
) -> Value {
    let mut map = serde_json::Map::new();

    if let Some(or_vals) = or_params {
        map.insert("OR".to_string(), serde_json::json!(or_vals));
    }
    if let Some(and_vals) = and_params {
        map.insert("AND".to_string(), serde_json::json!(and_vals));
    }
    if let Some(not_vals) = not_params {
        map.insert("NOT".to_string(), serde_json::json!(not_vals));
    }

    Value::Object(map)
}

/// Parse a relative timestamp string (e.g. "5d", "12h", "30m") into seconds.
///
/// Supported suffixes:
/// - `s` — seconds
/// - `m` — minutes
/// - `h` — hours
/// - `d` — days
///
/// Returns `None` if the string cannot be parsed.
pub fn parse_relative_timestamp(input: &str) -> MispResult<i64> {
    let input = input.trim();
    if input.is_empty() {
        return Err(MispError::InvalidSearch(
            "empty timestamp string".to_string(),
        ));
    }

    let (num_str, suffix) = input.split_at(input.len() - 1);
    let num: i64 = num_str
        .parse()
        .map_err(|_| MispError::InvalidSearch(format!("invalid relative timestamp: {input}")))?;

    let multiplier = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => {
            return Err(MispError::InvalidSearch(format!(
                "unknown timestamp suffix '{suffix}', expected s/m/h/d"
            )));
        }
    };

    Ok(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_builder_produces_correct_json() {
        let params = SearchBuilder::new()
            .value("malware.exe")
            .type_attribute("filename")
            .category("Payload delivery")
            .tags(vec!["tlp:white", "malware"])
            .date_from("2024-01-01")
            .date_to("2024-12-31")
            .enforce_warninglist(true)
            .to_ids(true)
            .limit(50)
            .page(1)
            .return_format(ReturnFormat::Json)
            .build();

        let json = params.to_json();
        let obj = json.as_object().unwrap();

        assert_eq!(obj["value"], "malware.exe");
        assert_eq!(obj["type"], "filename");
        assert_eq!(obj["category"], "Payload delivery");
        assert_eq!(obj["tags"], serde_json::json!(["tlp:white", "malware"]));
        assert_eq!(obj["from"], "2024-01-01");
        assert_eq!(obj["to"], "2024-12-31");
        assert_eq!(obj["enforceWarninglist"], true);
        assert_eq!(obj["to_ids"], true);
        assert_eq!(obj["limit"], 50);
        assert_eq!(obj["page"], 1);
        assert_eq!(obj["returnFormat"], "json");
    }

    #[test]
    fn search_builder_omits_none_fields() {
        let params = SearchBuilder::new().value("test").build();
        let json = params.to_json();
        let obj = json.as_object().unwrap();

        assert_eq!(obj.len(), 1);
        assert_eq!(obj["value"], "test");
    }

    #[test]
    fn search_builder_all_include_flags() {
        let params = SearchBuilder::new()
            .include_event_uuid(true)
            .include_event_tags(true)
            .include_proposals(false)
            .include_correlations(true)
            .include_sightings(true)
            .include_decay_score(false)
            .build();

        let json = params.to_json();
        let obj = json.as_object().unwrap();

        assert_eq!(obj["includeEventUuid"], true);
        assert_eq!(obj["includeEventTags"], true);
        assert_eq!(obj["includeProposals"], false);
        assert_eq!(obj["includeCorrelations"], true);
        assert_eq!(obj["includeSightings"], true);
        assert_eq!(obj["includeDecayScore"], false);
    }

    #[test]
    fn search_builder_event_ids() {
        let params = SearchBuilder::new().event_ids(vec![1, 2, 3]).build();
        let json = params.to_json();
        assert_eq!(json["eventid"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn search_builder_type_attributes() {
        let params = SearchBuilder::new()
            .type_attributes(vec!["ip-src", "ip-dst"])
            .build();
        let json = params.to_json();
        assert_eq!(json["type"], serde_json::json!(["ip-src", "ip-dst"]));
    }

    #[test]
    fn complex_query_all_params() {
        let query = build_complex_query(
            Some(vec!["malware", "ransomware"]),
            Some(vec!["tlp:white"]),
            Some(vec!["false-positive"]),
        );
        let obj = query.as_object().unwrap();

        assert_eq!(obj["OR"], serde_json::json!(["malware", "ransomware"]));
        assert_eq!(obj["AND"], serde_json::json!(["tlp:white"]));
        assert_eq!(obj["NOT"], serde_json::json!(["false-positive"]));
    }

    #[test]
    fn complex_query_partial_params() {
        let query = build_complex_query(Some(vec!["malware"]), None, Some(vec!["benign"]));
        let obj = query.as_object().unwrap();

        assert_eq!(obj.len(), 2);
        assert_eq!(obj["OR"], serde_json::json!(["malware"]));
        assert_eq!(obj["NOT"], serde_json::json!(["benign"]));
        assert!(!obj.contains_key("AND"));
    }

    #[test]
    fn complex_query_empty() {
        let query = build_complex_query(None, None, None);
        let obj = query.as_object().unwrap();
        assert!(obj.is_empty());
    }

    #[test]
    fn parse_relative_timestamp_days() {
        assert_eq!(parse_relative_timestamp("5d").unwrap(), 432000);
    }

    #[test]
    fn parse_relative_timestamp_hours() {
        assert_eq!(parse_relative_timestamp("12h").unwrap(), 43200);
    }

    #[test]
    fn parse_relative_timestamp_minutes() {
        assert_eq!(parse_relative_timestamp("30m").unwrap(), 1800);
    }

    #[test]
    fn parse_relative_timestamp_seconds() {
        assert_eq!(parse_relative_timestamp("60s").unwrap(), 60);
    }

    #[test]
    fn parse_relative_timestamp_invalid_suffix() {
        let result = parse_relative_timestamp("5x");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MispError::InvalidSearch(_)));
    }

    #[test]
    fn parse_relative_timestamp_invalid_number() {
        let result = parse_relative_timestamp("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn parse_relative_timestamp_empty() {
        let result = parse_relative_timestamp("");
        assert!(result.is_err());
    }

    #[test]
    fn search_builder_with_complex_value_query() {
        let query = build_complex_query(
            Some(vec!["192.168.1.1", "10.0.0.1"]),
            None,
            Some(vec!["127.0.0.1"]),
        );
        let params = SearchBuilder::new()
            .value_query(query.clone())
            .type_attribute("ip-src")
            .build();

        let json = params.to_json();
        assert_eq!(json["value"], query);
        assert_eq!(json["type"], "ip-src");
    }

    #[test]
    fn search_builder_tags_query_with_complex() {
        let query = build_complex_query(
            Some(vec!["tlp:white", "tlp:green"]),
            None,
            Some(vec!["tlp:red"]),
        );
        let params = SearchBuilder::new().tags_query(query.clone()).build();

        let json = params.to_json();
        assert_eq!(json["tags"], query);
    }

    #[test]
    fn search_builder_relative_timestamp_last() {
        let params = SearchBuilder::new().last("5d").build();
        let json = params.to_json();
        assert_eq!(json["last"], "5d");
    }

    #[test]
    fn search_builder_metadata_only() {
        let params = SearchBuilder::new().metadata(true).published(true).build();
        let json = params.to_json();
        assert_eq!(json["metadata"], true);
        assert_eq!(json["published"], true);
    }

    #[test]
    fn search_builder_csv_headerless() {
        let params = SearchBuilder::new()
            .return_format(ReturnFormat::Csv)
            .headerless(true)
            .build();
        let json = params.to_json();
        assert_eq!(json["returnFormat"], "csv");
        assert_eq!(json["headerless"], true);
    }

    #[test]
    fn return_format_serialization() {
        assert_eq!(ReturnFormat::Json.as_str(), "json");
        assert_eq!(ReturnFormat::Stix2.as_str(), "stix2");
        assert_eq!(ReturnFormat::Suricata.as_str(), "suricata");
        assert_eq!(ReturnFormat::OpenIoc.as_str(), "openioc");
        assert_eq!(ReturnFormat::Rpz.as_str(), "rpz");
    }

    #[test]
    fn search_controller_paths() {
        assert_eq!(
            SearchController::Events.rest_search_path(),
            "events/restSearch"
        );
        assert_eq!(
            SearchController::Attributes.rest_search_path(),
            "attributes/restSearch"
        );
        assert_eq!(
            SearchController::Objects.rest_search_path(),
            "objects/restSearch"
        );
    }

    #[test]
    fn search_builder_decay_params() {
        let params = SearchBuilder::new()
            .decaying_model(serde_json::json!({"id": 1}))
            .score(serde_json::json!(50))
            .exclude_decayed(true)
            .model_overrides(serde_json::json!({"threshold": 30}))
            .build();

        let json = params.to_json();
        assert_eq!(json["decayingModel"], serde_json::json!({"id": 1}));
        assert_eq!(json["score"], 50);
        assert_eq!(json["excludeDecayed"], true);
        assert_eq!(json["modelOverrides"], serde_json::json!({"threshold": 30}));
    }
}
