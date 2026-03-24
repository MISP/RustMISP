//! Integration tests for RustMISP against a live MISP instance.
//!
//! These tests require a running MISP instance and are marked with `#[ignore]`.
//! Run them with: `cargo test -- --ignored`
//!
//! Required environment variables:
//! - `MISP_URL`: The URL of the MISP instance (e.g., `https://localhost`)
//! - `MISP_KEY`: A valid API key with admin privileges
//! - `MISP_VERIFYCERT`: Set to `false` to disable TLS verification (default: `true`)

use rustmisp::*;

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

/// Generate a unique test event info string to avoid collisions.
fn test_event_info(label: &str) -> String {
    format!(
        "RustMISP Integration Test - {} - {}",
        label,
        uuid::Uuid::new_v4()
    )
}

// ============================================================================
// Event CRUD Lifecycle
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_event_crud_lifecycle() {
    let client = create_client().await;
    let info = test_event_info("event_crud");

    // --- CREATE ---
    let mut event = MispEvent::new(&info);
    event.distribution = Some(0); // Your org only
    event.threat_level_id = Some(4); // Undefined
    event.analysis = Some(0); // Initial

    let created = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created.id.expect("Created event should have an id");
    assert_eq!(created.info, info);
    assert_eq!(created.distribution, Some(0));
    assert_eq!(created.threat_level_id, Some(4));
    assert_eq!(created.analysis, Some(0));
    assert!(created.uuid.is_some());

    // --- READ ---
    let fetched = client
        .get_event(event_id)
        .await
        .expect("Failed to get event");
    assert_eq!(fetched.id, Some(event_id));
    assert_eq!(fetched.info, info);

    // --- UPDATE ---
    let mut updated_event = fetched;
    let new_info = test_event_info("event_crud_updated");
    updated_event.info = new_info.clone();
    updated_event.threat_level_id = Some(1); // High
    updated_event.analysis = Some(2); // Complete

    let updated = client
        .update_event(&updated_event)
        .await
        .expect("Failed to update event");
    assert_eq!(updated.info, new_info);
    assert_eq!(updated.threat_level_id, Some(1));
    assert_eq!(updated.analysis, Some(2));

    // --- PUBLISH / UNPUBLISH ---
    let _publish_result = client
        .publish(event_id, false)
        .await
        .expect("Failed to publish event");

    let published_event = client
        .get_event(event_id)
        .await
        .expect("Failed to get event");
    assert!(published_event.published);

    let _unpublish_result = client
        .unpublish(event_id)
        .await
        .expect("Failed to unpublish event");

    let unpublished_event = client
        .get_event(event_id)
        .await
        .expect("Failed to get event");
    assert!(!unpublished_event.published);

    // --- DELETE ---
    client
        .delete_event(event_id)
        .await
        .expect("Failed to delete event");

    // Verify deletion - get_event should fail or return deleted event
    let result = client.get_event(event_id).await;
    assert!(
        result.is_err(),
        "Event should not be retrievable after deletion"
    );
}

// ============================================================================
// Attribute CRUD with Types
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_attribute_crud_with_types() {
    let client = create_client().await;

    // Create a test event to hold attributes
    let mut event = MispEvent::new(test_event_info("attr_crud"));
    event.distribution = Some(0);
    let created_event = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created_event.id.unwrap();

    // --- CREATE various attribute types ---
    let ip_attr = MispAttribute::new("ip-dst", "Network activity", "192.168.1.1");
    let created_ip = client
        .add_attribute(event_id, &ip_attr)
        .await
        .expect("Failed to add ip-dst attribute");
    assert_eq!(created_ip.attr_type, "ip-dst");
    assert_eq!(created_ip.value, "192.168.1.1");
    let ip_attr_id = created_ip.id.unwrap();

    let domain_attr = MispAttribute::new("domain", "Network activity", "example.com");
    let created_domain = client
        .add_attribute(event_id, &domain_attr)
        .await
        .expect("Failed to add domain attribute");
    assert_eq!(created_domain.attr_type, "domain");

    let md5_attr = MispAttribute::new(
        "md5",
        "Payload delivery",
        "d41d8cd98f00b204e9800998ecf8427e",
    );
    let created_md5 = client
        .add_attribute(event_id, &md5_attr)
        .await
        .expect("Failed to add md5 attribute");
    assert_eq!(created_md5.attr_type, "md5");

    // --- UPDATE ---
    let mut updated_attr = created_ip.clone();
    updated_attr.comment = "Updated via integration test".to_string();
    updated_attr.to_ids = false;

    let updated = client
        .update_attribute(&updated_attr)
        .await
        .expect("Failed to update attribute");
    assert_eq!(updated.comment, "Updated via integration test");
    assert!(!updated.to_ids);

    // --- READ (via event) ---
    let fetched_event = client
        .get_event(event_id)
        .await
        .expect("Failed to get event");
    assert!(
        fetched_event.attributes.len() >= 3,
        "Event should have at least 3 attributes, got {}",
        fetched_event.attributes.len()
    );

    // --- DELETE (soft) ---
    client
        .delete_attribute(ip_attr_id, false)
        .await
        .expect("Failed to soft-delete attribute");

    // --- DELETE (hard) ---
    client
        .delete_attribute(created_md5.id.unwrap(), true)
        .await
        .expect("Failed to hard-delete attribute");

    // Cleanup
    client
        .delete_event(event_id)
        .await
        .expect("Failed to cleanup event");
}

// ============================================================================
// Object Creation with Templates
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_object_creation_with_templates() {
    let client = create_client().await;

    // Create a test event
    let mut event = MispEvent::new(test_event_info("object_crud"));
    event.distribution = Some(0);
    let created_event = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created_event.id.unwrap();

    // Create a domain-ip object
    let mut obj = MispObject::new("domain-ip");
    obj.distribution = Some(0);

    let mut domain_attr = MispAttribute::new("domain", "Network activity", "malware.example.com");
    domain_attr.to_ids = true;
    obj.add_attribute(domain_attr);

    let mut ip_attr = MispAttribute::new("ip", "Network activity", "10.0.0.1");
    ip_attr.to_ids = true;
    obj.add_attribute(ip_attr);

    let created_obj = client
        .add_object(event_id, &obj)
        .await
        .expect("Failed to add object");
    assert_eq!(created_obj.name, "domain-ip");
    let obj_id = created_obj.id.unwrap();
    assert!(!created_obj.attributes.is_empty());

    // --- UPDATE ---
    let mut updated_obj = created_obj;
    updated_obj.comment = Some("Updated via integration test".to_string());
    let updated = client
        .update_object(&updated_obj)
        .await
        .expect("Failed to update object");
    assert_eq!(
        updated.comment,
        Some("Updated via integration test".to_string())
    );

    // --- READ (directly) ---
    let fetched_obj = client
        .get_object(obj_id)
        .await
        .expect("Failed to get object");
    assert_eq!(fetched_obj.name, "domain-ip");

    // --- DELETE ---
    client
        .delete_object(obj_id, false)
        .await
        .expect("Failed to delete object");

    // Cleanup
    client
        .delete_event(event_id)
        .await
        .expect("Failed to cleanup event");
}

// ============================================================================
// Tag Operations
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_tag_operations() {
    let client = create_client().await;

    // Create a test event
    let mut event = MispEvent::new(test_event_info("tag_ops"));
    event.distribution = Some(0);
    let created_event = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created_event.id.unwrap();
    let event_uuid = created_event.uuid.clone().unwrap();

    // Create a custom tag
    let tag_name = format!("rustmisp-test:{}", uuid::Uuid::new_v4());
    let mut tag = MispTag::new(&tag_name);
    tag.colour = Some("#ff0000".to_string());

    let created_tag = client.add_tag(&tag).await.expect("Failed to create tag");
    assert_eq!(created_tag.name, tag_name);
    let tag_id = created_tag.id.unwrap();

    // List tags and verify our tag is there
    let all_tags = client.tags().await.expect("Failed to list tags");
    assert!(
        all_tags.iter().any(|t| t.name == tag_name),
        "Created tag should appear in tag list"
    );

    // Search tags
    let found = client
        .search_tags(&tag_name, true)
        .await
        .expect("Failed to search tags");
    assert!(!found.is_empty(), "Search should find the created tag");

    // Attach tag to event
    client
        .tag(&event_uuid, &tag_name, false)
        .await
        .expect("Failed to tag event");

    // Verify tag is on event
    let tagged_event = client
        .get_event(event_id)
        .await
        .expect("Failed to get event");
    assert!(
        tagged_event.tags.iter().any(|t| t.name == tag_name),
        "Event should have the tag attached"
    );

    // Remove tag from event
    client
        .untag(&event_uuid, &tag_name)
        .await
        .expect("Failed to untag event");

    let untagged_event = client
        .get_event(event_id)
        .await
        .expect("Failed to get event");
    assert!(
        !untagged_event.tags.iter().any(|t| t.name == tag_name),
        "Event should no longer have the tag"
    );

    // Cleanup
    client
        .delete_tag(tag_id)
        .await
        .expect("Failed to delete tag");
    client
        .delete_event(event_id)
        .await
        .expect("Failed to cleanup event");
}

// ============================================================================
// Search with Complex Queries
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_search_with_complex_queries() {
    let client = create_client().await;

    // Create events with specific attributes for searching
    let mut event = MispEvent::new(test_event_info("search_test"));
    event.distribution = Some(0);
    let created_event = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created_event.id.unwrap();

    // Add a searchable attribute
    let search_value = format!("10.99.{}.1", rand_octet());
    let attr = MispAttribute::new("ip-dst", "Network activity", &search_value);
    client
        .add_attribute(event_id, &attr)
        .await
        .expect("Failed to add attribute");

    // Search by value
    let mut params = SearchParameters::default();
    params.value = Some(serde_json::Value::String(search_value.clone()));
    params.type_attribute = Some(serde_json::Value::String("ip-dst".to_string()));

    let results = client
        .search(SearchController::Attributes, &params)
        .await
        .expect("Failed to search attributes");

    // Results should contain our attribute
    assert!(
        results.is_object() || results.is_array(),
        "Search should return valid JSON"
    );

    // Search using SearchBuilder
    let params2 = SearchBuilder::new()
        .value(&search_value)
        .type_attribute("ip-dst")
        .build();

    let results2 = client
        .search(SearchController::Attributes, &params2)
        .await
        .expect("Failed to search with builder");
    assert!(
        results2.is_object() || results2.is_array(),
        "SearchBuilder results should be valid JSON"
    );

    // Search with complex query (OR)
    let complex = build_complex_query(Some(vec![search_value.as_str()]), None, None);
    let mut params3 = SearchParameters::default();
    params3.value = Some(complex);

    let results3 = client
        .search(SearchController::Attributes, &params3)
        .await
        .expect("Failed to search with complex query");
    assert!(
        results3.is_object() || results3.is_array(),
        "Complex query results should be valid JSON"
    );

    // Cleanup
    client
        .delete_event(event_id)
        .await
        .expect("Failed to cleanup event");
}

// ============================================================================
// Sighting Operations
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_sighting_operations() {
    let client = create_client().await;

    // Create event with attribute
    let mut event = MispEvent::new(test_event_info("sighting_ops"));
    event.distribution = Some(0);
    let created_event = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created_event.id.unwrap();

    let attr = MispAttribute::new("ip-dst", "Network activity", "172.16.0.1");
    let created_attr = client
        .add_attribute(event_id, &attr)
        .await
        .expect("Failed to add attribute");
    let attr_id = created_attr.id.unwrap();

    // Add a positive sighting
    let sighting = MispSighting::new();
    let created_sighting = client
        .add_sighting(&sighting, Some(attr_id))
        .await
        .expect("Failed to add sighting");
    assert!(created_sighting.id.is_some());
    let sighting_id = created_sighting.id.unwrap();

    // Add a false positive sighting
    let fp_sighting = MispSighting::false_positive();
    let created_fp = client
        .add_sighting(&fp_sighting, Some(attr_id))
        .await
        .expect("Failed to add false positive sighting");
    assert!(created_fp.id.is_some());

    // List sightings
    let sightings = client
        .sightings(attr_id)
        .await
        .expect("Failed to list sightings");
    assert!(
        sightings.len() >= 2,
        "Should have at least 2 sightings, got {}",
        sightings.len()
    );

    // Delete sighting
    client
        .delete_sighting(sighting_id)
        .await
        .expect("Failed to delete sighting");

    // Cleanup
    client
        .delete_event(event_id)
        .await
        .expect("Failed to cleanup event");
}

// ============================================================================
// Galaxy Attachment
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_galaxy_attachment() {
    let client = create_client().await;

    // Create event
    let mut event = MispEvent::new(test_event_info("galaxy_ops"));
    event.distribution = Some(0);
    let created_event = client
        .add_event(&event)
        .await
        .expect("Failed to create event");
    let event_id = created_event.id.unwrap();
    let event_uuid = created_event.uuid.clone().unwrap();

    // List galaxies to find one to attach
    let galaxies = client
        .galaxies(false)
        .await
        .expect("Failed to list galaxies");
    if galaxies.is_empty() {
        eprintln!("No galaxies available, skipping galaxy attachment test");
        client.delete_event(event_id).await.expect("Cleanup");
        return;
    }

    // Get the first galaxy with clusters
    let mut found_cluster_uuid = None;
    for galaxy in galaxies.iter().take(5) {
        if let Some(galaxy_id) = galaxy.id {
            let detailed = client.get_galaxy(galaxy_id, true).await;
            if let Ok(g) = detailed {
                if !g.galaxy_clusters.is_empty() {
                    if let Some(ref uuid) = g.galaxy_clusters[0].uuid {
                        found_cluster_uuid = Some(uuid.clone());
                        break;
                    }
                }
            }
        }
    }

    if let Some(cluster_uuid) = found_cluster_uuid {
        // Attach galaxy cluster to event
        let result = client
            .attach_galaxy_cluster(&event_uuid, &cluster_uuid, false)
            .await
            .expect("Failed to attach galaxy cluster");

        // Verify the API call succeeded (galaxy is attached as a tag)
        let fetched = client
            .get_event(event_id)
            .await
            .expect("Failed to get event");
        // Galaxy clusters are attached as tags with the galaxy cluster's tag_name
        assert!(
            !fetched.tags.is_empty(),
            "Event should have galaxy cluster tag attached"
        );
        assert!(
            result.is_object() || result.is_string(),
            "Attach result should be valid JSON"
        );
    } else {
        eprintln!("No galaxy clusters found, skipping attachment verification");
    }

    // Cleanup
    client
        .delete_event(event_id)
        .await
        .expect("Failed to cleanup event");
}

// ============================================================================
// User/Org Management
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_user_org_management() {
    let client = create_client().await;

    // List organisations
    let orgs = client
        .organisations(None, None)
        .await
        .expect("Failed to list organisations");
    assert!(!orgs.is_empty(), "Should have at least one organisation");

    // Get the first org's ID for user creation
    let org_id = orgs[0].id.unwrap();

    // Create a test user
    let email = format!("rustmisp-test-{}@example.com", uuid::Uuid::new_v4());
    let mut user = MispUser::new(&email);
    user.org_id = Some(org_id);
    user.role_id = Some(3); // User role (typically)
    user.password = Some("TestPassword123!@#".to_string());

    let created_user = client.add_user(&user).await.expect("Failed to create user");
    assert_eq!(created_user.email, email);
    let user_id = created_user.id.unwrap();

    // List users and verify
    let users = client
        .users(None, None)
        .await
        .expect("Failed to list users");
    assert!(
        users.iter().any(|u| u.email == email),
        "Created user should appear in user list"
    );

    // Update user
    let mut updated_user = created_user;
    updated_user.disabled = true;
    let updated = client
        .update_user(&updated_user)
        .await
        .expect("Failed to update user");
    assert!(updated.disabled);

    // Delete user
    client
        .delete_user(user_id)
        .await
        .expect("Failed to delete user");

    // Verify deletion
    let users_after = client
        .users(None, None)
        .await
        .expect("Failed to list users");
    assert!(
        !users_after.iter().any(|u| u.email == email),
        "Deleted user should not appear in user list"
    );
}

// ============================================================================
// Sharing Group Workflow
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_sharing_group_workflow() {
    let client = create_client().await;

    // Create a sharing group
    let sg_name = format!("RustMISP Test SG {}", uuid::Uuid::new_v4());
    let mut sg = MispSharingGroup::new(&sg_name);
    sg.description = Some("Integration test sharing group".to_string());
    sg.releasability = Some("Test only".to_string());

    let created_sg = client
        .add_sharing_group(&sg)
        .await
        .expect("Failed to create sharing group");
    assert_eq!(created_sg.name, sg_name);
    let sg_id = created_sg.id.unwrap();

    // List sharing groups
    let all_sgs = client
        .sharing_groups()
        .await
        .expect("Failed to list sharing groups");
    assert!(
        all_sgs.iter().any(|s| s.name == sg_name),
        "Created sharing group should appear in list"
    );

    // Get sharing group
    let fetched = client
        .get_sharing_group(sg_id)
        .await
        .expect("Failed to get sharing group");
    assert_eq!(fetched.name, sg_name);

    // Update sharing group
    let mut updated_sg = fetched;
    let new_desc = "Updated description".to_string();
    updated_sg.description = Some(new_desc.clone());
    let updated = client
        .update_sharing_group(&updated_sg)
        .await
        .expect("Failed to update sharing group");
    assert_eq!(updated.description, Some(new_desc));

    // Delete sharing group
    client
        .delete_sharing_group(sg_id)
        .await
        .expect("Failed to delete sharing group");
}

// ============================================================================
// Feed Operations
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_feed_operations() {
    let client = create_client().await;

    // List feeds
    let _feeds = client.feeds().await.expect("Failed to list feeds");
    // Feeds list may be empty on a fresh instance, that's fine

    // Create a test feed
    let mut feed = MispFeed::default();
    feed.name = format!("RustMISP Test Feed {}", uuid::Uuid::new_v4());
    feed.url = "https://example.com/feed".to_string();
    feed.source_format = Some("freetext".to_string());
    feed.provider = Some("RustMISP Integration Test".to_string());
    feed.distribution = Some(0);
    feed.enabled = false;

    let created = client.add_feed(&feed).await.expect("Failed to create feed");
    assert_eq!(created.name, feed.name);
    let feed_id = created.id.unwrap();

    // Get feed
    let fetched = client.get_feed(feed_id).await.expect("Failed to get feed");
    assert_eq!(fetched.name, feed.name);

    // Update feed
    let mut updated_feed = fetched;
    updated_feed.provider = Some("Updated Provider".to_string());
    let updated = client
        .update_feed(&updated_feed)
        .await
        .expect("Failed to update feed");
    assert_eq!(updated.provider, Some("Updated Provider".to_string()));

    // Delete feed
    client
        .delete_feed(feed_id)
        .await
        .expect("Failed to delete feed");

    // Verify after listing
    let feeds_after = client.feeds().await.expect("Failed to list feeds");
    assert!(
        !feeds_after.iter().any(|f| f.id == Some(feed_id)),
        "Deleted feed should not appear in list"
    );
}

// ============================================================================
// Helper functions
// ============================================================================

/// Generate a pseudo-random octet for unique IP addresses.
fn rand_octet() -> u8 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (t % 256) as u8
}
