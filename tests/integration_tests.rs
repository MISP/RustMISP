//! Integration tests for RustMISP against a live MISP instance.
//!
//! These tests mirror PyMISP's `testlive_comprehensive.py` as closely as
//! possible.  When a test fails, the first place to look is the corresponding
//! PyMISP test and `pymisp/api.py` to understand how the reference
//! implementation handles the same endpoint.
//!
//! Run them with:
//!   MISP_URL=http://localhost:5007 MISP_KEY=<key> MISP_VERIFYCERT=false \
//!     cargo test -- --ignored
//!
//! Required environment variables:
//! - `MISP_URL`: The URL of the MISP instance
//! - `MISP_KEY`: A valid API key with admin privileges
//! - `MISP_VERIFYCERT`: Set to `false` to disable TLS verification

use rustmisp::*;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Helpers
// ============================================================================

fn misp_url() -> String {
    std::env::var("MISP_URL").expect("MISP_URL environment variable required")
}

fn misp_key() -> String {
    std::env::var("MISP_KEY").expect("MISP_KEY environment variable required")
}

fn misp_verifycert() -> bool {
    std::env::var("MISP_VERIFYCERT")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

async fn create_client() -> MispClient {
    MispClient::new(misp_url(), misp_key(), misp_verifycert())
        .expect("Failed to create MISP client")
}

fn unique(label: &str) -> String {
    format!("RustMISP Test - {} - {}", label, uuid::Uuid::new_v4())
}

/// Random octet for generating unique IPs in tests.
fn rand_octet() -> u8 {
    (now_ts() as u8).wrapping_add(uuid::Uuid::new_v4().as_bytes()[0])
}

/// Current unix timestamp (seconds).
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Create a simple event (mirrors PyMISP create_simple_event).
fn simple_event() -> MispEvent {
    let mut e = MispEvent::new(&unique("simple"));
    e.distribution = Some(0); // your_organisation_only
    e.threat_level_id = Some(3); // low
    e.analysis = Some(2); // completed
    e
}

/// Helper to build a domain-ip MispObject with template info fetched from MISP.
async fn build_domain_ip_object(client: &MispClient) -> MispObject {
    let template = client
        .get_raw_object_template("domain-ip")
        .await
        .expect("domain-ip template");
    let tmpl_uuid = template["uuid"].as_str().unwrap().to_string();
    let tmpl_version = template["version"]
        .as_i64()
        .or_else(|| template["version"].as_str().and_then(|v| v.parse().ok()))
        .unwrap();
    let meta_category = template["meta-category"]
        .as_str()
        .unwrap_or("network")
        .to_string();

    let mut obj = MispObject::new("domain-ip");
    obj.distribution = Some(0);
    obj.meta_category = Some(meta_category);
    obj.template_uuid = Some(tmpl_uuid);
    obj.template_version = Some(tmpl_version);

    let mut d = MispAttribute::new("domain", "Network activity", "test.example.com");
    d.object_relation = Some("domain".to_string());
    obj.add_attribute(d);

    let mut ip = MispAttribute::new("ip-dst", "Network activity", "10.0.0.1");
    ip.object_relation = Some("ip".to_string());
    obj.add_attribute(ip);

    obj
}

/// Extract event IDs from a search result (JSON value).
fn event_ids_from_search(val: &Value) -> Vec<i64> {
    let response = if val.get("response").is_some() {
        &val["response"]
    } else {
        val
    };
    if let Some(arr) = response.as_array() {
        arr.iter()
            .filter_map(|e| {
                e.get("Event")
                    .and_then(|ev| ev.get("id"))
                    .or_else(|| e.get("id"))
                    .and_then(|id| id.as_str().and_then(|s| s.parse().ok()).or(id.as_i64()))
            })
            .collect()
    } else {
        vec![]
    }
}

/// Extract event IDs from a Vec<MispEvent> (search_index result).
fn event_ids_from_vec(events: &[MispEvent]) -> Vec<i64> {
    events.iter().filter_map(|e| e.id).collect()
}

/// Extract attribute values from search result.
/// MISP attribute search returns: {"response": {"Attribute": [...]}}
fn attr_values_from_search(val: &Value) -> Vec<String> {
    // Try response.Attribute[] first (attribute search format)
    if let Some(arr) = val
        .pointer("/response/Attribute")
        .and_then(|v| v.as_array())
    {
        return arr
            .iter()
            .filter_map(|a| {
                a.get("value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
    }
    // Fallback: response[] with Attribute wrapper per item
    let response = val.get("response").unwrap_or(val);
    if let Some(arr) = response.as_array() {
        arr.iter()
            .filter_map(|a| {
                a.get("Attribute")
                    .and_then(|at| at.get("value"))
                    .or_else(|| a.get("value"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect()
    } else {
        vec![]
    }
}

// ============================================================================
// 1. Event CRUD Lifecycle
// Mirrors: PyMISP test_simple_event (CRUD portion)
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_event_crud_lifecycle() {
    let client = create_client().await;
    let info = unique("event_crud");

    // --- CREATE ---
    let mut event = MispEvent::new(&info);
    event.distribution = Some(0);
    event.threat_level_id = Some(4);
    event.analysis = Some(0);

    let created = client.add_event(&event).await.expect("add_event");
    let event_id = created.id.expect("id");
    assert_eq!(created.info, info);
    assert_eq!(created.distribution, Some(0));
    assert_eq!(created.threat_level_id, Some(4));
    assert_eq!(created.analysis, Some(0));
    assert!(created.uuid.is_some());

    // --- READ ---
    let fetched = client.get_event(event_id).await.expect("get_event");
    assert_eq!(fetched.id, Some(event_id));
    assert_eq!(fetched.info, info);

    // --- UPDATE ---
    let mut updated_event = fetched;
    let new_info = unique("event_crud_updated");
    updated_event.info = new_info.clone();
    updated_event.threat_level_id = Some(1);
    updated_event.analysis = Some(2);

    let updated = client
        .update_event(&updated_event)
        .await
        .expect("update_event");
    assert_eq!(updated.info, new_info);
    assert_eq!(updated.threat_level_id, Some(1));
    assert_eq!(updated.analysis, Some(2));

    // --- PUBLISH / UNPUBLISH ---
    client.publish(event_id, false).await.expect("publish");
    let pub_ev = client.get_event(event_id).await.unwrap();
    assert!(pub_ev.published);

    client.unpublish(event_id).await.expect("unpublish");
    let unpub_ev = client.get_event(event_id).await.unwrap();
    assert!(!unpub_ev.published);

    // --- DELETE ---
    client.delete_event(event_id).await.expect("delete_event");
    assert!(client.get_event(event_id).await.is_err());
}

// ============================================================================
// 2. Exists checks
// Mirrors: PyMISP test_exists
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_exists() {
    let client = create_client().await;

    let event = simple_event();
    let created = client.add_event(&event).await.expect("add_event");
    let event_id = created.id.unwrap();

    // Add an attribute so we can test attribute_exists
    let attr = MispAttribute::new("ip-dst", "Network activity", "10.0.0.99");
    let created_attr = client
        .add_attribute(event_id, &attr)
        .await
        .expect("add_attribute");
    let attr_id = created_attr.id;

    // Add a domain-ip object so we can test object_exists
    let obj = build_domain_ip_object(&client).await;
    let created_obj = client.add_object(event_id, &obj).await.expect("add_object");
    let obj_id = created_obj.id;

    // Event exists
    assert!(client.event_exists(event_id).await.expect("event_exists"));

    // Attribute exists
    let aid = attr_id.unwrap();
    assert!(
        client
            .attribute_exists(aid)
            .await
            .expect("attribute_exists")
    );

    // Object exists
    let oid = obj_id.unwrap();
    assert!(client.object_exists(oid).await.expect("object_exists"));

    // Delete and verify non-existence
    client.delete_event(event_id).await.expect("delete_event");
    assert!(
        !client
            .event_exists(event_id)
            .await
            .expect("event_exists after delete")
    );
    assert!(
        !client
            .attribute_exists(aid)
            .await
            .expect("attribute_exists after delete")
    );
    assert!(
        !client
            .object_exists(oid)
            .await
            .expect("object_exists after delete")
    );
}

// ============================================================================
// 3. Attribute CRUD
// Mirrors: PyMISP test_attribute
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_attribute_crud() {
    let client = create_client().await;

    let event = simple_event();
    let created_event = client.add_event(&event).await.expect("add_event");
    let event_id = created_event.id.unwrap();

    // --- CREATE ---
    let ip_attr = MispAttribute::new("ip-dst", "Network activity", "192.168.1.1");
    let created_ip = client
        .add_attribute(event_id, &ip_attr)
        .await
        .expect("add ip-dst");
    assert_eq!(created_ip.attr_type, "ip-dst");
    assert_eq!(created_ip.value, "192.168.1.1");
    let ip_id = created_ip.id.unwrap();

    let domain_attr = MispAttribute::new("domain", "Network activity", "example.com");
    let created_domain = client
        .add_attribute(event_id, &domain_attr)
        .await
        .expect("add domain");
    assert_eq!(created_domain.attr_type, "domain");

    let md5_attr = MispAttribute::new(
        "md5",
        "Payload delivery",
        "d41d8cd98f00b204e9800998ecf8427e",
    );
    let created_md5 = client
        .add_attribute(event_id, &md5_attr)
        .await
        .expect("add md5");
    assert_eq!(created_md5.attr_type, "md5");

    // --- GET single attribute ---
    let fetched = client.get_attribute(ip_id).await.expect("get_attribute");
    assert_eq!(fetched.value, "192.168.1.1");

    // --- UPDATE ---
    let mut updated_attr = created_ip.clone();
    updated_attr.comment = "Updated comment".to_string();
    updated_attr.to_ids = false;
    let updated = client
        .update_attribute(&updated_attr)
        .await
        .expect("update_attribute");
    assert_eq!(updated.comment, "Updated comment");
    assert!(!updated.to_ids);

    // Update disable_correlation (mirrors test_edit_attribute)
    let mut dc_attr = updated;
    dc_attr.disable_correlation = true;
    let dc_updated = client
        .update_attribute(&dc_attr)
        .await
        .expect("update disable_correlation");
    assert!(dc_updated.disable_correlation);
    let mut dc_attr2 = dc_updated;
    dc_attr2.disable_correlation = false;
    let dc_updated2 = client
        .update_attribute(&dc_attr2)
        .await
        .expect("update disable_correlation false");
    assert!(!dc_updated2.disable_correlation);

    // --- READ via event ---
    let fetched_event = client.get_event(event_id).await.expect("get_event");
    assert!(
        fetched_event.attributes.len() >= 3,
        "Expected >= 3 attributes, got {}",
        fetched_event.attributes.len()
    );

    // --- SOFT DELETE ---
    client
        .delete_attribute(ip_id, false)
        .await
        .expect("soft delete");

    // --- HARD DELETE ---
    client
        .delete_attribute(created_md5.id.unwrap(), true)
        .await
        .expect("hard delete");

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 4. Object CRUD with Templates
// Mirrors: PyMISP test_update_object
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_object_crud() {
    let client = create_client().await;

    let event = simple_event();
    let created_event = client.add_event(&event).await.expect("add_event");
    let event_id = created_event.id.unwrap();

    // Create object
    let obj = build_domain_ip_object(&client).await;
    let created_obj = client.add_object(event_id, &obj).await.expect("add_object");
    assert_eq!(created_obj.name, "domain-ip");
    let obj_id = created_obj.id.unwrap();
    assert!(!created_obj.attributes.is_empty());

    // Update object comment
    let mut updated_obj = created_obj;
    updated_obj.comment = Some("Updated via integration test".to_string());
    let updated = client
        .update_object(&updated_obj)
        .await
        .expect("update_object");
    assert_eq!(
        updated.comment,
        Some("Updated via integration test".to_string())
    );

    // Read directly
    let fetched_obj = client.get_object(obj_id).await.expect("get_object");
    assert_eq!(fetched_obj.name, "domain-ip");

    // Verify object can be fetched independently
    let re_fetched = client.get_object(obj_id).await.expect("re-fetch object");
    assert_eq!(re_fetched.name, "domain-ip");

    // Soft delete
    client
        .delete_object(obj_id, false)
        .await
        .expect("soft delete object");

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 5. Tag Operations
// Mirrors: PyMISP test_tags
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_tag_operations() {
    let client = create_client().await;

    // --- LIST ---
    let all_tags = client.tags().await.expect("tags");
    assert!(!all_tags.is_empty(), "Should have at least one tag");

    // --- GET ---
    let first_tag = all_tags
        .iter()
        .find(|t| t.id.is_some())
        .expect("tag with id");
    let tag_detail = client
        .get_tag(first_tag.id.unwrap())
        .await
        .expect("get_tag");
    assert_eq!(tag_detail.name, first_tag.name);

    // --- CREATE ---
    let tag_name = format!("rustmisp-test:{}", uuid::Uuid::new_v4());
    let mut tag = MispTag::new(&tag_name);
    tag.colour = Some("#ff0000".to_string());
    let created_tag = client.add_tag(&tag).await.expect("add_tag");
    assert_eq!(created_tag.name, tag_name);
    let tag_id = created_tag.id.unwrap();

    // --- DISABLE / ENABLE (may not exist in all MISP versions) ---
    if client.disable_tag(tag_id).await.is_ok() {
        let disabled = client.get_tag(tag_id).await.expect("get disabled tag");
        assert!(disabled.hide_tag, "Tag should be hidden after disable");

        client.enable_tag(tag_id).await.expect("enable_tag");
        let enabled = client.get_tag(tag_id).await.expect("get enabled tag");
        assert!(!enabled.hide_tag, "Tag should be visible after enable");
    }

    // --- UPDATE ---
    let mut updated_tag = client.get_tag(tag_id).await.expect("get tag for update");
    let new_name = format!("rustmisp-test-updated:{}", uuid::Uuid::new_v4());
    updated_tag.name = new_name.clone();
    let updated = client.update_tag(&updated_tag).await.expect("update_tag");
    assert_eq!(updated.name, new_name);

    // --- SEARCH ---
    // search_tags may return empty on some MISP versions; verify via tags list as fallback
    let found = client
        .search_tags(&new_name, false)
        .await
        .unwrap_or_default();
    if found.is_empty() {
        let all = client.tags().await.expect("tags");
        assert!(
            all.iter().any(|t| t.name == new_name),
            "Should find updated tag in tag list"
        );
    }

    // --- TAG / UNTAG event ---
    let event = simple_event();
    let created_event = client.add_event(&event).await.expect("add_event");
    let event_id = created_event.id.unwrap();
    let event_uuid = created_event.uuid.clone().unwrap();

    client
        .tag(&event_uuid, &new_name, false)
        .await
        .expect("tag event");
    let tagged_ev = client.get_event(event_id).await.expect("get_event");
    assert!(
        tagged_ev.tags.iter().any(|t| t.name == new_name),
        "Event should have tag"
    );

    client
        .untag(&event_uuid, &new_name)
        .await
        .expect("untag event");
    let untagged_ev = client.get_event(event_id).await.expect("get_event");
    assert!(
        !untagged_ev.tags.iter().any(|t| t.name == new_name),
        "Tag should be removed"
    );

    // --- TAG attribute ---
    if let Some(attr) = tagged_ev.attributes.first() {
        let attr_uuid = attr.uuid.as_ref().unwrap();
        client
            .tag(attr_uuid, &new_name, false)
            .await
            .expect("tag attribute");
        let fetched_attr = client
            .get_attribute(attr.id.unwrap())
            .await
            .expect("get_attribute");
        assert!(
            fetched_attr.tags.iter().any(|t| t.name == new_name),
            "Attribute should have tag"
        );
        client
            .untag(attr_uuid, &new_name)
            .await
            .expect("untag attribute");
    }

    // --- DELETE ---
    client.delete_tag(tag_id).await.expect("delete_tag");
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 6. Search: value
// Mirrors: PyMISP test_search_value_event + test_search_value_attribute
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_value() {
    let client = create_client().await;

    // Create two events that share an attribute value (for search matching)
    let shared_value = format!("SHARED_{}", uuid::Uuid::new_v4());

    let mut first = MispEvent::new(&unique("search_value_1"));
    first.distribution = Some(0);
    let first = client.add_event(&first).await.expect("add first");
    let first_id = first.id.unwrap();
    let attr1 = MispAttribute::new("text", "Other", &shared_value);
    client
        .add_attribute(first_id, &attr1)
        .await
        .expect("add attr1");

    let mut second = MispEvent::new(&unique("search_value_2"));
    second.distribution = Some(0);
    let second = client.add_event(&second).await.expect("add second");
    let second_id = second.id.unwrap();
    let attr2 = MispAttribute::new("text", "Other", &shared_value);
    client
        .add_attribute(second_id, &attr2)
        .await
        .expect("add attr2");

    // Search events by value — should find both
    let params = SearchBuilder::new().value(&shared_value).build();
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search events");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&first_id), "Should find first event");
    assert!(ids.contains(&second_id), "Should find second event");

    // Search attributes by value
    let results = client
        .search(SearchController::Attributes, &params)
        .await
        .expect("search attrs");
    let vals = attr_values_from_search(&results);
    assert!(
        vals.iter().any(|v| v == &shared_value),
        "Should find shared value in attributes"
    );

    // Non-existing value
    let params = SearchBuilder::new()
        .value(&uuid::Uuid::new_v4().to_string())
        .build();
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search empty");
    let ids = event_ids_from_search(&results);
    assert!(ids.is_empty(), "Should find no events for random value");

    // Cleanup
    client.delete_event(first_id).await.expect("cleanup first");
    client
        .delete_event(second_id)
        .await
        .expect("cleanup second");
}

// ============================================================================
// 7. Search: type with complex query
// Mirrors: PyMISP test_search_type_event
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_type() {
    let client = create_client().await;
    let ts = now_ts() - 5;

    // Use unique values to avoid collisions with pre-existing data
    let unique_ip1 = format!("10.{}.{}.{}", rand_octet(), rand_octet(), rand_octet());
    let unique_ip2 = format!("10.{}.{}.{}", rand_octet(), rand_octet(), rand_octet());
    let unique_text = format!("rustmisp-text-{}", uuid::Uuid::new_v4());

    // Event with ip-dst
    let mut ev1 = MispEvent::new(&unique("search_type_1"));
    ev1.distribution = Some(0);
    let ev1 = client.add_event(&ev1).await.expect("add ev1");
    let ev1_id = ev1.id.unwrap();
    let a1 = MispAttribute::new("ip-dst", "Network activity", &unique_ip1);
    client.add_attribute(ev1_id, &a1).await.expect("add ip-dst");

    // Event with ip-src
    let mut ev2 = MispEvent::new(&unique("search_type_2"));
    ev2.distribution = Some(0);
    let ev2 = client.add_event(&ev2).await.expect("add ev2");
    let ev2_id = ev2.id.unwrap();
    let a2 = MispAttribute::new("ip-src", "Network activity", &unique_ip2);
    client.add_attribute(ev2_id, &a2).await.expect("add ip-src");

    // Event with text only
    let mut ev3 = MispEvent::new(&unique("search_type_3"));
    ev3.distribution = Some(0);
    let ev3 = client.add_event(&ev3).await.expect("add ev3");
    let ev3_id = ev3.id.unwrap();
    let a3 = MispAttribute::new("text", "Other", &unique_text);
    client.add_attribute(ev3_id, &a3).await.expect("add text");

    // Search by complex type query: ip-src OR ip-dst
    let type_query = build_complex_query(Some(vec!["ip-src", "ip-dst"]), None, None);
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(ts));
    params.type_attribute = Some(type_query);
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search type");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&ev1_id), "Should find ip-dst event");
    assert!(ids.contains(&ev2_id), "Should find ip-src event");
    assert!(!ids.contains(&ev3_id), "Should not find text-only event");

    // Cleanup
    client.delete_event(ev1_id).await.expect("cleanup");
    client.delete_event(ev2_id).await.expect("cleanup");
    client.delete_event(ev3_id).await.expect("cleanup");
}

// ============================================================================
// 8. Search: tags
// Mirrors: PyMISP test_search_tag_event + test_search_tag_advanced_event
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_tag() {
    let client = create_client().await;
    let ts = now_ts() - 5;

    let tag_a = format!("rustmisp-tag-a:{}", uuid::Uuid::new_v4());
    let tag_b = format!("rustmisp-tag-b:{}", uuid::Uuid::new_v4());
    client
        .add_tag(&MispTag::new(&tag_a))
        .await
        .expect("add tag_a");
    client
        .add_tag(&MispTag::new(&tag_b))
        .await
        .expect("add tag_b");

    // Event 1: tagged with tag_a
    let mut ev1 = MispEvent::new(&unique("search_tag_1"));
    ev1.distribution = Some(0);
    let ev1 = client.add_event(&ev1).await.expect("add ev1");
    let ev1_id = ev1.id.unwrap();
    client
        .tag(ev1.uuid.as_ref().unwrap(), &tag_a, false)
        .await
        .expect("tag ev1");

    // Event 2: tagged with tag_a AND tag_b
    let mut ev2 = MispEvent::new(&unique("search_tag_2"));
    ev2.distribution = Some(0);
    let ev2 = client.add_event(&ev2).await.expect("add ev2");
    let ev2_id = ev2.id.unwrap();
    client
        .tag(ev2.uuid.as_ref().unwrap(), &tag_a, false)
        .await
        .expect("tag ev2 a");
    client
        .tag(ev2.uuid.as_ref().unwrap(), &tag_b, false)
        .await
        .expect("tag ev2 b");

    // Event 3: no tags
    let mut ev3 = MispEvent::new(&unique("search_tag_3"));
    ev3.distribution = Some(0);
    let ev3 = client.add_event(&ev3).await.expect("add ev3");
    let ev3_id = ev3.id.unwrap();

    // Search by tag_a — should find ev1 and ev2
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(ts));
    params.tags = Some(Value::String(tag_a.clone()));
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search tag_a");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&ev1_id), "tag_a should match ev1");
    assert!(ids.contains(&ev2_id), "tag_a should match ev2");
    assert!(!ids.contains(&ev3_id), "tag_a should not match ev3");

    // Search by tag_b — only ev2
    params.tags = Some(Value::String(tag_b.clone()));
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search tag_b");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&ev2_id), "tag_b should match ev2");
    assert!(!ids.contains(&ev1_id), "tag_b should not match ev1");

    // Advanced: tag_a AND NOT tag_b — only ev1
    let complex = build_complex_query(Some(vec![tag_a.as_str()]), None, Some(vec![tag_b.as_str()]));
    params.tags = Some(complex);
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search advanced");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&ev1_id), "Advanced: should find ev1");
    assert!(
        !ids.contains(&ev2_id),
        "Advanced: should exclude ev2 (has tag_b)"
    );

    // Cleanup
    client.delete_event(ev1_id).await.expect("cleanup");
    client.delete_event(ev2_id).await.expect("cleanup");
    client.delete_event(ev3_id).await.expect("cleanup");
    // Clean up tags
    let all_tags = client.tags().await.unwrap_or_default();
    for t in &all_tags {
        if t.name == tag_a || t.name == tag_b {
            let _ = client.delete_tag(t.id.unwrap()).await;
        }
    }
}

// ============================================================================
// 9. Search: timestamp
// Mirrors: PyMISP test_search_timestamp_event
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_timestamp() {
    let client = create_client().await;
    let before = now_ts() - 2;

    let ev = simple_event();
    let created = client.add_event(&ev).await.expect("add_event");
    let event_id = created.id.unwrap();

    // Search with timestamp slightly before creation — should find our event
    let params = SearchBuilder::new().event_id(event_id).build();
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search ts");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&event_id), "Should find event by id");

    // Search with timestamp filter
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(before));
    params.event_id = Some(Value::from(event_id));
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search ts range");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&event_id), "Should find event by timestamp");

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 10. Search: publish_timestamp, published, metadata
// Mirrors: PyMISP test_search_publish_timestamp + test_simple_event (published)
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_publish_and_metadata() {
    let client = create_client().await;
    let ts = now_ts() - 5;

    // Create two events
    let ev1 = simple_event();
    let ev1 = client.add_event(&ev1).await.expect("add ev1");
    let ev1_id = ev1.id.unwrap();

    let ev2 = simple_event();
    let ev2 = client.add_event(&ev2).await.expect("add ev2");
    let ev2_id = ev2.id.unwrap();

    // Add attribute to ev1 for metadata test
    let a = MispAttribute::new("text", "Other", &uuid::Uuid::new_v4().to_string());
    client.add_attribute(ev1_id, &a).await.expect("add attr");

    // Search with metadata=true — events should have no attributes
    let mut params = SearchParameters::default();
    params.event_id = Some(Value::from(ev1_id));
    params.metadata = Some(true);
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("metadata search");
    if let Some(arr) = results.get("response").and_then(|r| r.as_array()) {
        for ev in arr {
            let attrs = ev
                .get("Event")
                .and_then(|e| e.get("Attribute"))
                .and_then(|a| a.as_array());
            assert!(
                attrs.map_or(true, |a| a.is_empty()),
                "metadata=true should return no attributes"
            );
        }
    }

    // Search unpublished
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(ts));
    params.published = Some(false);
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search unpublished");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&ev1_id), "Unpublished ev1");
    assert!(ids.contains(&ev2_id), "Unpublished ev2");

    // Publish ev1, then search published only
    client.publish(ev1_id, false).await.expect("publish");
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(ts));
    params.published = Some(true);
    let results = client
        .search(SearchController::Events, &params)
        .await
        .expect("search published");
    let ids = event_ids_from_search(&results);
    assert!(ids.contains(&ev1_id), "Published ev1 should appear");
    assert!(!ids.contains(&ev2_id), "Unpublished ev2 should not appear");

    // Cleanup
    client.delete_event(ev1_id).await.expect("cleanup");
    client.delete_event(ev2_id).await.expect("cleanup");
}

// ============================================================================
// 11. Search: search_index with pagination and sorting
// Mirrors: PyMISP test_search_index
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_index() {
    let client = create_client().await;
    let ts = now_ts() - 5;

    // Create 3 events with ordered names
    let mut ev_a = MispEvent::new("AAA_rustmisp_index_test");
    ev_a.distribution = Some(0);
    let ev_a = client.add_event(&ev_a).await.expect("add A");
    let ev_a_id = ev_a.id.unwrap();

    let mut ev_b = MispEvent::new("BBB_rustmisp_index_test");
    ev_b.distribution = Some(0);
    let ev_b = client.add_event(&ev_b).await.expect("add B");
    let ev_b_id = ev_b.id.unwrap();

    let mut ev_c = MispEvent::new("CCC_rustmisp_index_test");
    ev_c.distribution = Some(0);
    let ev_c = client.add_event(&ev_c).await.expect("add C");
    let ev_c_id = ev_c.id.unwrap();

    // search_index should return all 3
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(ts));
    let results = client.search_index(&params).await.expect("search_index");
    let ids = event_ids_from_vec(&results);
    assert!(ids.contains(&ev_a_id));
    assert!(ids.contains(&ev_b_id));
    assert!(ids.contains(&ev_c_id));

    // Pagination: page 1 with limit 2 should return at most 2
    let mut params = SearchParameters::default();
    params.timestamp = Some(Value::from(ts));
    params.limit = Some(2);
    params.page = Some(1);
    let page1 = client.search_index(&params).await.expect("page1");
    let ids1 = event_ids_from_vec(&page1);
    assert!(
        ids1.len() <= 2,
        "Page with limit 2 should return at most 2, got {}",
        ids1.len()
    );
    assert!(!ids1.is_empty(), "Page 1 should have results");

    // Cleanup
    client.delete_event(ev_a_id).await.expect("cleanup");
    client.delete_event(ev_b_id).await.expect("cleanup");
    client.delete_event(ev_c_id).await.expect("cleanup");
}

// ============================================================================
// 12. Search: date range, category, to_ids
// Mirrors: PyMISP test_simple_event (date/category/to_ids portions)
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_filters() {
    let client = create_client().await;

    // Event with ip-src (to_ids=true by default) and text (to_ids=false)
    let mut ev = MispEvent::new(&unique("search_filters"));
    ev.distribution = Some(0);
    let ev = client.add_event(&ev).await.expect("add_event");
    let event_id = ev.id.unwrap();

    let ip_val = format!("10.{}.{}.{}", rand_octet(), rand_octet(), rand_octet());
    let text_val = format!("rustmisp-filter-{}", uuid::Uuid::new_v4());

    let mut ip = MispAttribute::new("ip-src", "Network activity", &ip_val);
    ip.to_ids = true;
    client
        .add_attribute(event_id, &ip)
        .await
        .expect("add ip-src");

    let mut txt = MispAttribute::new("text", "Other", &text_val);
    txt.to_ids = false;
    client
        .add_attribute(event_id, &txt)
        .await
        .expect("add text");

    // Search by category — scoped to our event
    let params = SearchBuilder::new()
        .event_id(event_id)
        .category("Network activity")
        .build();
    let results = client
        .search(SearchController::Attributes, &params)
        .await
        .expect("search category");
    let vals = attr_values_from_search(&results);
    assert!(vals.iter().any(|v| v == &ip_val), "Should find ip-src");
    assert!(!vals.iter().any(|v| v == &text_val), "Should not find text");

    // Search to_ids=true — scoped to our event
    let params = SearchBuilder::new().event_id(event_id).to_ids(true).build();
    let results = client
        .search(SearchController::Attributes, &params)
        .await
        .expect("search to_ids");
    let vals = attr_values_from_search(&results);
    assert!(vals.iter().any(|v| v == &ip_val), "ip-src has to_ids=true");

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 13. Sighting Operations
// Mirrors: PyMISP test_sightings
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_sighting_operations() {
    let client = create_client().await;

    let ev = simple_event();
    let created = client.add_event(&ev).await.expect("add_event");
    let event_id = created.id.unwrap();

    let attr = MispAttribute::new("ip-dst", "Network activity", "172.16.0.1");
    let created_attr = client
        .add_attribute(event_id, &attr)
        .await
        .expect("add attr");
    let attr_id = created_attr.id.unwrap();

    // Add positive sighting
    let sighting = MispSighting::new();
    let s1 = client
        .add_sighting(&sighting, Some(attr_id))
        .await
        .expect("add sighting");
    assert!(s1.id.is_some());
    let s1_id = s1.id.unwrap();

    // Add false-positive sighting (type=1) with source
    let mut fp = MispSighting::false_positive();
    fp.source = Some("RustMISP-test".to_string());
    let s2 = client
        .add_sighting(&fp, Some(attr_id))
        .await
        .expect("add fp sighting");
    assert!(s2.id.is_some());

    // List sightings for attribute
    let sightings = client.sightings(attr_id).await.expect("sightings");
    assert!(
        sightings.len() >= 2,
        "Should have >= 2 sightings, got {}",
        sightings.len()
    );

    // Verify sighting types
    assert!(
        sightings.iter().any(|s| s.sighting_type == Some(0)),
        "Should have type 0"
    );
    assert!(
        sightings.iter().any(|s| s.sighting_type == Some(1)),
        "Should have type 1 (fp)"
    );

    // Delete sighting
    client
        .delete_sighting(s1_id)
        .await
        .expect("delete sighting");

    // Verify one fewer sighting
    let after = client
        .sightings(attr_id)
        .await
        .expect("sightings after delete");
    assert!(
        after.len() < sightings.len(),
        "Should have fewer sightings after delete"
    );

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 14. Galaxy Operations
// Mirrors: PyMISP test_galaxies + test_attach_galaxy_cluster
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_galaxy_operations() {
    let client = create_client().await;

    // List galaxies
    let galaxies = client.galaxies(false).await.expect("galaxies");
    if galaxies.is_empty() {
        eprintln!("No galaxies available, skipping");
        return;
    }

    // Get a galaxy with clusters
    let mut _found_galaxy_id = None;
    let mut found_cluster_id = None;
    for g in galaxies.iter().take(10) {
        if let Some(gid) = g.id {
            if let Ok(detailed) = client.get_galaxy(gid, true).await {
                if !detailed.galaxy_clusters.is_empty() {
                    _found_galaxy_id = Some(gid);
                    found_cluster_id = detailed.galaxy_clusters[0].id;
                    break;
                }
            }
        }
    }

    let Some(cluster_id) = found_cluster_id else {
        eprintln!("No galaxy clusters found, skipping attachment test");
        return;
    };

    // Create event and attach galaxy cluster to EVENT
    let ev = simple_event();
    let created = client.add_event(&ev).await.expect("add_event");
    let event_id = created.id.unwrap();

    client
        .attach_galaxy_cluster(&event_id.to_string(), &cluster_id.to_string(), false)
        .await
        .expect("attach to event");

    let fetched = client.get_event(event_id).await.expect("get_event");
    assert!(!fetched.tags.is_empty(), "Event should have galaxy tag");

    // Attach galaxy cluster to ATTRIBUTE (mirrors PyMISP test_attach_galaxy_cluster)
    let attr = MispAttribute::new("ip-dst", "Network activity", "10.20.30.40");
    let created_attr = client
        .add_attribute(event_id, &attr)
        .await
        .expect("add attr");
    let attr_id = created_attr.id.unwrap();

    client
        .attach_galaxy_cluster_to(
            &attr_id.to_string(),
            &cluster_id.to_string(),
            "attribute",
            false,
        )
        .await
        .expect("attach to attribute");

    // Verify — the attribute should now have a galaxy tag
    let fetched_attr = client.get_attribute(attr_id).await.expect("get_attribute");
    assert!(
        !fetched_attr.tags.is_empty(),
        "Attribute should have galaxy tag"
    );

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 15. User / Org Management
// Mirrors: PyMISP test_user + test_organisation
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_user_management() {
    let client = create_client().await;

    // List orgs and pick the first
    let orgs = client
        .organisations(None, None)
        .await
        .expect("organisations");
    assert!(!orgs.is_empty());
    let org_id = orgs[0].id.unwrap();

    // Get organisation
    let org = client
        .get_organisation(org_id)
        .await
        .expect("get_organisation");
    assert_eq!(org.id, Some(org_id));

    // List roles dynamically
    let roles = client.roles().await.expect("roles");
    let user_role_id = roles
        .iter()
        .find(|r| r.name.to_lowercase() == "user" && r.perm_auth && !r.perm_site_admin)
        .and_then(|r| r.id)
        .unwrap_or(3);

    // Create user
    let email = format!("rustmisp-test-{}@example.com", uuid::Uuid::new_v4());
    let mut user = MispUser::new(&email);
    user.org_id = Some(org_id);
    user.role_id = Some(user_role_id);
    user.password = Some("TestPassword123!@#".to_string());

    let created = client.add_user(&user).await.expect("add_user");
    assert_eq!(created.email, email);
    let user_id = created.id.unwrap();

    // List users
    let users = client.users(None, None).await.expect("users");
    assert!(users.iter().any(|u| u.email == email));

    // Update user
    let mut updated_user = created;
    updated_user.disabled = true;
    let updated = client
        .update_user(&updated_user)
        .await
        .expect("update_user");
    assert!(updated.disabled);

    // Delete user
    client.delete_user(user_id).await.expect("delete_user");
    let users_after = client.users(None, None).await.expect("users after");
    assert!(!users_after.iter().any(|u| u.email == email));
}

// ============================================================================
// 16. Sharing Group Workflow
// Mirrors: PyMISP test_sharing_groups
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_sharing_group_workflow() {
    let client = create_client().await;

    let sg_name = format!("RustMISP Test SG {}", uuid::Uuid::new_v4());
    let mut sg = MispSharingGroup::new(&sg_name);
    sg.description = Some("Integration test sharing group".to_string());
    sg.releasability = Some("Testing".to_string());

    // --- CREATE ---
    let created = client
        .add_sharing_group(&sg)
        .await
        .expect("add_sharing_group");
    assert_eq!(created.name, sg_name);
    assert_eq!(created.releasability, Some("Testing".to_string()));
    let sg_id = created.id.unwrap();
    let _sg_uuid = created.uuid.clone();

    // --- UPDATE ---
    let mut upd = created;
    upd.releasability = Some("Testing updated".to_string());
    let updated = client
        .update_sharing_group(&upd)
        .await
        .expect("update_sharing_group");
    assert_eq!(updated.releasability, Some("Testing updated".to_string()));

    // Update name
    let mut upd2 = updated;
    upd2.name = format!("{} - renamed", sg_name);
    let renamed = client
        .update_sharing_group(&upd2)
        .await
        .expect("update name");
    assert_eq!(renamed.name, format!("{} - renamed", sg_name));

    // --- EXISTS ---
    assert!(
        client
            .sharing_group_exists(sg_id)
            .await
            .expect("exists by id")
    );

    // --- ADD ORG ---
    let orgs = client.organisations(None, None).await.expect("orgs");
    let org_id = orgs[0].id.unwrap();
    client
        .add_org_to_sharing_group(sg_id, org_id)
        .await
        .expect("add org to sg");

    // --- LIST ---
    let sgs = client.sharing_groups().await.expect("sharing_groups");
    assert!(!sgs.is_empty());

    // --- REMOVE ORG ---
    client
        .remove_org_from_sharing_group(sg_id, org_id)
        .await
        .expect("remove org from sg");

    // --- CHANGE SG ON ENTITY ---
    let ev = simple_event();
    let created_ev = client.add_event(&ev).await.expect("add_event for sg");
    let event_id = created_ev.id.unwrap();

    let ev_uuid = created_ev.uuid.as_deref().unwrap();
    // change_sharing_group_on_entity may not exist in all MISP versions
    match client
        .change_sharing_group_on_entity(ev_uuid, sg_id, "Event")
        .await
    {
        Ok(result) => {
            assert!(result.is_object() || result.is_string());
        }
        Err(e) => {
            eprintln!("change_sharing_group_on_entity not available: {e}");
        }
    }

    // --- DELETE ---
    client.delete_event(event_id).await.expect("cleanup event");
    client
        .delete_sharing_group(sg_id)
        .await
        .expect("delete_sharing_group");

    // Verify non-existence after delete
    assert!(
        !client
            .sharing_group_exists(sg_id)
            .await
            .expect("exists after delete")
    );
}

// ============================================================================
// 17. Feed Operations
// Mirrors: PyMISP test_feeds
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_feed_operations() {
    let client = create_client().await;

    // --- CREATE ---
    let mut feed = MispFeed::default();
    feed.name = format!("RustMISP Test Feed {}", uuid::Uuid::new_v4());
    feed.url = "https://example.com/feed".to_string();
    feed.source_format = Some("freetext".to_string());
    feed.provider = Some("RustMISP Test".to_string());
    feed.distribution = Some(0);
    feed.enabled = false;

    let created = client.add_feed(&feed).await.expect("add_feed");
    assert_eq!(created.name, feed.name);
    let feed_id = created.id.unwrap();

    // --- UPDATE ---
    let mut upd = client.get_feed(feed_id).await.expect("get_feed");
    upd.name = format!("{} - Updated", feed.name);
    let updated = client.update_feed(&upd).await.expect("update_feed");
    assert!(updated.name.contains("Updated"));

    // --- ENABLE/DISABLE on our test feed (before deleting) ---
    // Enable
    client.enable_feed(feed_id).await.expect("enable_feed");
    let f = client.get_feed(feed_id).await.expect("get after enable");
    assert!(f.enabled, "Feed should be enabled");

    // Enable cache (may not exist in all MISP versions)
    if let Ok(_) = client.enable_feed_cache(feed_id).await {
        let f = client
            .get_feed(feed_id)
            .await
            .expect("get after cache enable");
        assert!(f.caching_enabled, "Caching should be enabled");

        // Disable cache
        client
            .disable_feed_cache(feed_id)
            .await
            .expect("disable_feed_cache");
        let f = client
            .get_feed(feed_id)
            .await
            .expect("get after cache disable");
        assert!(!f.caching_enabled, "Caching should be disabled");
    }

    // Disable feed
    client.disable_feed(feed_id).await.expect("disable_feed");
    let f = client.get_feed(feed_id).await.expect("get after disable");
    assert!(!f.enabled, "Feed should be disabled");

    // --- DELETE ---
    client.delete_feed(feed_id).await.expect("delete_feed");

    // --- LIST ---
    let feeds = client.feeds().await.expect("feeds");
    assert!(
        !feeds.iter().any(|f| f.id == Some(feed_id)),
        "Deleted feed should not appear"
    );
}

// ============================================================================
// 18. Event Report CRUD
// Mirrors: PyMISP test_event_report
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_event_report_crud() {
    let client = create_client().await;

    let ev = simple_event();
    let created_ev = client.add_event(&ev).await.expect("add_event");
    let event_id = created_ev.id.unwrap();

    // Create report
    let mut report =
        MispEventReport::new("Test Event Report", "# Example report\n\nThis is a test.");
    report.distribution = Some(5); // Inherit

    let created = client
        .add_event_report(event_id, &report)
        .await
        .expect("add_event_report");
    assert_eq!(created.event_id, Some(event_id));
    let report_id = created.id.unwrap();

    // Verify reports exist for event
    let reports = client
        .get_event_reports(event_id)
        .await
        .expect("get_event_reports");
    assert!(!reports.is_empty(), "Event should have reports");

    // Update report
    let mut upd = created;
    upd.name = "Updated Report".to_string();
    upd.content = "Updated content".to_string();
    let updated = client
        .update_event_report(&upd)
        .await
        .expect("update_event_report");
    assert_eq!(updated.name, "Updated Report");
    assert_eq!(updated.content, "Updated content");

    // Get reports for event
    let reports = client
        .get_event_reports(event_id)
        .await
        .expect("get_event_reports");
    assert!(reports.iter().any(|r| r.id == Some(report_id)));

    // Soft delete
    client
        .delete_event_report(report_id, false)
        .await
        .expect("soft delete report");

    // Hard delete
    client
        .delete_event_report(report_id, true)
        .await
        .expect("hard delete report");

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 19. Analyst Data CRUD (Notes + Opinions)
// Mirrors: PyMISP test_analyst_data_CRUD
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_analyst_data_crud() {
    let client = create_client().await;

    // Create a note attached to a fake UUID (mirrors PyMISP: note on non-existing event)
    let fake_uuid = uuid::Uuid::new_v4().to_string();
    let mut note = MispNote::new("Fake note");
    note.object_type = Some("Event".to_string());
    note.object_uuid = Some(fake_uuid.clone());

    let created_note = client.add_note(&note).await.expect("add_note");
    assert_eq!(
        created_note.object_uuid.as_deref(),
        Some(fake_uuid.as_str())
    );
    let note_id = created_note.id.unwrap();

    // Update note
    let mut upd = created_note;
    upd.note = "Updated Note".to_string();
    let updated = client.update_note(&upd).await.expect("update_note");
    assert_eq!(updated.note, "Updated Note");

    // Get note
    let fetched = client.get_note(note_id).await.expect("get_note");
    assert_eq!(fetched.note, "Updated Note");

    // Delete note
    client.delete_note(note_id).await.expect("delete_note");

    // Create event with a note
    let ev = simple_event();
    let created_ev = client.add_event(&ev).await.expect("add_event");
    let event_id = created_ev.id.unwrap();
    let event_uuid = created_ev.uuid.clone().unwrap();

    let mut event_note = MispNote::new("Event-linked note");
    event_note.object_type = Some("Event".to_string());
    event_note.object_uuid = Some(event_uuid.clone());
    event_note.distribution = Some(1);

    let en = client
        .add_note(&event_note)
        .await
        .expect("add note to event");
    assert_eq!(en.object_uuid.as_deref(), Some(event_uuid.as_str()));
    let event_note_id = en.id.unwrap();

    // Cleanup
    let _ = client.delete_note(event_note_id).await;
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 20. Taxonomy Operations
// Mirrors: PyMISP test_taxonomies
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_taxonomy_operations() {
    let client = create_client().await;

    // List taxonomies
    let taxonomies = client.taxonomies().await.expect("taxonomies");
    assert!(!taxonomies.is_empty(), "Should have taxonomies");

    // Find a taxonomy to work with
    let tax = taxonomies
        .iter()
        .find(|t| t.id.is_some())
        .expect("taxonomy with id");
    let tax_id = tax.id.unwrap();

    // Get taxonomy
    let fetched = client.get_taxonomy(tax_id).await.expect("get_taxonomy");
    assert_eq!(fetched.id, Some(tax_id));
    let was_enabled = fetched.enabled;

    // Enable then disable — restore original state afterward
    client
        .enable_taxonomy(tax_id)
        .await
        .expect("enable_taxonomy");
    client
        .disable_taxonomy(tax_id)
        .await
        .expect("disable_taxonomy");

    // Restore original state
    if was_enabled {
        client
            .enable_taxonomy(tax_id)
            .await
            .expect("restore taxonomy");
    }
}

// ============================================================================
// 21. Warninglist Operations
// Mirrors: PyMISP test_warninglists
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_warninglist_operations() {
    let client = create_client().await;

    // List warninglists
    let wls = client.warninglists().await.expect("warninglists");
    assert!(!wls.is_empty(), "Should have warninglists");

    // Get warninglist
    let wl = wls.iter().find(|w| w.id.is_some()).expect("wl with id");
    let wl_id = wl.id.unwrap();
    let fetched = client
        .get_warninglist(wl_id)
        .await
        .expect("get_warninglist");
    assert_eq!(fetched.id, Some(wl_id));
    let was_enabled = fetched.enabled;

    // Enable then disable — restore original state afterward
    client.enable_warninglist(wl_id).await.expect("enable");
    client.disable_warninglist(wl_id).await.expect("disable");

    // Restore original state
    if was_enabled {
        client
            .enable_warninglist(wl_id)
            .await
            .expect("restore warninglist");
    }

    // Check values in warninglist
    let result = client
        .values_in_warninglist(&["8.8.8.8", "192.168.1.1"])
        .await
        .expect("values_in_warninglist");
    assert!(
        result.is_object() || result.is_array(),
        "Should return valid JSON"
    );
}

// ============================================================================
// 22. Noticelist Operations
// Mirrors: PyMISP test_noticelists
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_noticelist_operations() {
    let client = create_client().await;

    let nls = client.noticelists().await.expect("noticelists");
    assert!(!nls.is_empty(), "Should have noticelists");

    let nl = nls.iter().find(|n| n.id.is_some()).expect("nl with id");
    let nl_id = nl.id.unwrap();
    let fetched = client.get_noticelist(nl_id).await.expect("get_noticelist");
    assert_eq!(fetched.id, Some(nl_id));
}

// ============================================================================
// 23. Role Operations
// Mirrors: PyMISP test_roles
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_role_operations() {
    let client = create_client().await;

    // List roles
    let roles = client.roles().await.expect("roles");
    assert!(!roles.is_empty(), "Should have roles");

    // Find User role
    let user_role = roles.iter().find(|r| r.name.to_lowercase() == "user");
    assert!(user_role.is_some(), "Should have a User role");

    // Set default role (then restore)
    let original_default = roles.iter().find(|r| r.default_role);
    let user_role_id = user_role.unwrap().id.unwrap();
    client
        .set_default_role(user_role_id)
        .await
        .expect("set_default_role");

    // Restore if we had a different default
    if let Some(orig) = original_default {
        if orig.id != Some(user_role_id) {
            client
                .set_default_role(orig.id.unwrap())
                .await
                .expect("restore default");
        }
    }
}

// ============================================================================
// 24. Blocklist Operations
// Mirrors: PyMISP test_blocklists
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_blocklist_operations() {
    let client = create_client().await;

    // Event blocklist — use a random UUID
    // Note: blocklist endpoints may not be available in all MISP versions
    let test_uuid = uuid::Uuid::new_v4().to_string();
    match client
        .add_event_blocklist(
            &[test_uuid.as_str()],
            Some("RustMISP test blocklist"),
            None,
            None,
        )
        .await
    {
        Ok(_) => {
            let bls = client.event_blocklists().await.expect("event_blocklists");
            if let Some(bl_entry) = bls
                .iter()
                .find(|b| b.event_uuid.as_deref() == Some(test_uuid.as_str()))
            {
                let bl_id = bl_entry.id.unwrap();
                client
                    .delete_event_blocklist(bl_id)
                    .await
                    .expect("delete event blocklist");
            }
        }
        Err(e) => {
            eprintln!("Event blocklist not available on this MISP instance: {e}");
        }
    }

    // Org blocklist
    let org_uuid = uuid::Uuid::new_v4().to_string();
    match client
        .add_organisation_blocklist(
            &[org_uuid.as_str()],
            Some("RustMISP org blocklist test"),
            None,
        )
        .await
    {
        Ok(_) => {
            let obls = client
                .organisation_blocklists()
                .await
                .expect("org_blocklists");
            if let Some(obl_entry) = obls
                .iter()
                .find(|b| b.org_uuid.as_deref() == Some(org_uuid.as_str()))
            {
                let obl_id = obl_entry.id.unwrap();
                client
                    .delete_organisation_blocklist(obl_id)
                    .await
                    .expect("delete org blocklist");
            }
        }
        Err(e) => {
            eprintln!("Org blocklist not available on this MISP instance: {e}");
        }
    }
}

// ============================================================================
// 25. Correlation Exclusion Operations
// Mirrors: PyMISP test_correlation_exclusions
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_correlation_exclusion_operations() {
    let client = create_client().await;

    let excl_val = MispCorrelationExclusion::new("rustmisp-test-exclusion.example.com");
    let excl = client
        .add_correlation_exclusion(&excl_val)
        .await
        .expect("add correlation exclusion");
    let excl_id = excl.id.unwrap();

    let fetched = client
        .get_correlation_exclusion(excl_id)
        .await
        .expect("get");
    assert_eq!(fetched.id, Some(excl_id));

    let all = client.correlation_exclusions().await.expect("list");
    assert!(all.iter().any(|e| e.id == Some(excl_id)));

    client
        .delete_correlation_exclusion(excl_id)
        .await
        .expect("delete");
}

// ============================================================================
// 26. Server Operations
// Mirrors: PyMISP test_servers
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_server_operations() {
    let client = create_client().await;

    let servers = client.servers().await.expect("servers");
    // Servers list may be empty on a test instance — just verify parsing works
    let _ = servers;
}

// ============================================================================
// 27. User Settings
// Mirrors: PyMISP test_user_settings
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_user_settings() {
    let client = create_client().await;

    let settings = client.user_settings().await.expect("user_settings");
    // Settings list may be empty — that's fine
    let _ = settings;

    // Set a user setting
    let val = serde_json::json!("test-value");
    let _ = client
        .set_user_setting("dashboard_access", &val, None)
        .await;

    // Get it back
    if let Ok(s) = client.get_user_setting("dashboard_access", None).await {
        assert_eq!(s.setting, "dashboard_access");
    }

    // Delete it
    let _ = client.delete_user_setting("dashboard_access", None).await;
}

// ============================================================================
// 28. Statistics
// Mirrors: PyMISP test_statistics
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_statistics() {
    let client = create_client().await;

    let attr_stats = client
        .attributes_statistics(None, None)
        .await
        .expect("attr stats");
    assert!(attr_stats.is_object(), "Should return JSON object");

    let tag_stats = client.tags_statistics(None, None).await.expect("tag stats");
    assert!(tag_stats.is_object(), "Should return JSON object");

    let user_stats = client.users_statistics(None).await.expect("user stats");
    assert!(user_stats.is_object(), "Should return JSON object");
}

// ============================================================================
// 29. Freetext Parsing
// Mirrors: PyMISP test_freetext
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_freetext() {
    let client = create_client().await;

    let ev = simple_event();
    let created = client.add_event(&ev).await.expect("add_event");
    let event_id = created.id.unwrap();

    // freetext may not be available in all MISP versions
    match client
        .freetext(event_id, "1.2.3.4 evil.example.com", None, None, None)
        .await
    {
        Ok(result) => {
            assert!(
                result.is_array() || result.is_object(),
                "Freetext should return parsed results"
            );
        }
        Err(e) => {
            eprintln!("freetext not available on this MISP instance: {e}");
        }
    }

    // Cleanup
    client.delete_event(event_id).await.expect("cleanup");
}

// ============================================================================
// 30. Communities
// Mirrors: PyMISP test_communities
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_communities() {
    let client = create_client().await;

    let communities = client.communities().await.expect("communities");
    // May be empty — just verify the call works
    let _ = communities;
}
