# RustMISP API Reference

Complete reference for every public method in the RustMISP library.
All examples assume `use rustmisp::*;` and a connected client.

---

## Table of Contents

- [Client Setup](#client-setup)
  - [MispClient (Async)](#mispclient-async)
  - [MispClientBuilder](#mispclientbuilder)
  - [MispClientBlocking](#mispclientblocking)
- [Server / Instance Info](#server--instance-info)
- [Events](#events)
- [Attributes](#attributes)
- [Tags](#tags)
- [Objects](#objects)
- [Object References](#object-references)
- [Object Templates](#object-templates)
- [Attribute Proposals (Shadow Attributes)](#attribute-proposals-shadow-attributes)
- [Sightings](#sightings)
- [Event Reports](#event-reports)
- [Analyst Data (Notes, Opinions, Relationships)](#analyst-data-notes-opinions-relationships)
- [Taxonomies](#taxonomies)
- [Warninglists](#warninglists)
- [Noticelists](#noticelists)
- [Galaxies](#galaxies)
- [Galaxy Clusters](#galaxy-clusters)
- [Galaxy Cluster Relations](#galaxy-cluster-relations)
- [Decaying Models](#decaying-models)
- [Correlation Exclusions](#correlation-exclusions)
- [Organisations](#organisations)
- [Users](#users)
- [User Registrations](#user-registrations)
- [Roles](#roles)
- [Servers (Sync)](#servers-sync)
- [Worker Management](#worker-management)
- [Feeds](#feeds)
- [Sharing Groups](#sharing-groups)
- [User Settings](#user-settings)
- [Search](#search)
  - [SearchBuilder](#searchbuilder)
  - [search()](#search-1)
  - [search_index()](#search_index)
  - [search_sightings()](#search_sightings)
  - [search_logs()](#search_logs)
  - [search_feeds()](#search_feeds)
  - [Freetext Import](#freetext-import)
  - [Complex Queries](#complex-queries)
- [Blocklists](#blocklists)
- [Communities](#communities)
- [Event Delegations](#event-delegations)
- [Advanced / Misc](#advanced--misc)
- [Standalone Functions](#standalone-functions)
- [Enums](#enums)
- [Tools](#tools)

---

## Client Setup

### MispClient (Async)

The primary async client. All API methods are `async` and return `MispResult<T>`.

```rust
use rustmisp::MispClient;

#[tokio::main]
async fn main() -> rustmisp::MispResult<()> {
    // Simple constructor
    let client = MispClient::new(
        "https://misp.example.com",
        "your-api-key",
        false, // ssl_verify
    )?;

    // Get the base URL
    println!("Connected to {}", client.base_url());

    Ok(())
}
```

### MispClientBuilder

Advanced configuration via the builder pattern.

```rust
use rustmisp::MispClientBuilder;
use std::time::Duration;

let client = MispClientBuilder::new("https://misp.example.com", "your-api-key")
    .ssl_verify(false)
    .timeout(Duration::from_secs(120))
    .proxy("http://proxy.example.com:8080")
    .header("X-Custom-Header", "value")
    .build()?;
```

| Method | Description |
|--------|-------------|
| `ssl_verify(bool)` | Enable/disable TLS certificate verification |
| `timeout(Duration)` | Set request timeout |
| `proxy(impl Into<String>)` | Set HTTP proxy URL |
| `header(name, value)` | Add a custom header to all requests |
| `build()` | Build the `MispClient` |

### MispClientBlocking

Synchronous wrapper (requires `blocking` feature). Same API, no `async`/`.await`.

```toml
[dependencies]
rustmisp = { version = "0.1", features = ["blocking"] }
```

```rust
use rustmisp::MispClientBlocking;

fn main() -> rustmisp::MispResult<()> {
    let client = MispClientBlocking::new(
        "https://misp.example.com",
        "your-api-key",
        false,
    )?;
    let events = client.events()?;
    println!("Found {} events", events.len());
    Ok(())
}
```

---

## Server / Instance Info

```rust
// Get MISP version
let version = client.misp_instance_version().await?;
println!("MISP version: {}", version);

// Alias for misp_instance_version
let version = client.version().await?;

// Get describe_types from the remote instance
let types = client.describe_types_remote().await?;

// Get all server settings
let settings = client.server_settings().await?;

// Get a specific setting
let setting = client.get_server_setting("MISP.baseurl").await?;

// Set a server setting
client.set_server_setting("MISP.welcome_text_top", "Hello").await?;

// Check remote ACL (debug)
let acl = client.remote_acl(Some("full")).await?;

// Database schema diagnostics
let diag = client.db_schema_diagnostic().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `describe_types_remote` | `() -> MispResult<Value>` | MISP type/category definitions |
| `misp_instance_version` | `() -> MispResult<Value>` | Version JSON |
| `version` | `() -> MispResult<Value>` | Alias for `misp_instance_version` |
| `server_settings` | `() -> MispResult<Value>` | All server settings |
| `get_server_setting` | `(setting: &str) -> MispResult<Value>` | Single setting value |
| `set_server_setting` | `(setting: &str, value: impl ToString) -> MispResult<Value>` | Confirmation |
| `remote_acl` | `(debug_type: Option<&str>) -> MispResult<Value>` | ACL debug info |
| `db_schema_diagnostic` | `() -> MispResult<Value>` | Schema diagnostic report |

---

## Events

```rust
use rustmisp::{MispEvent, Distribution};

// List all events
let events = client.events().await?;

// Get a single event
let event = client.get_event(42).await?;

// Check if an event exists
let exists = client.event_exists(42).await?;

// Create an event
let mut event = MispEvent::new("Suspicious phishing campaign");
event.distribution = Some(Distribution::YourOrganisationOnly as i64);
event.threat_level_id = Some(2); // Medium
event.analysis = Some(1);       // Ongoing
let created = client.add_event(&event).await?;
let event_id = created.id.unwrap();

// Update an event
let mut updated = created;
updated.info = "Updated: Phishing campaign targeting finance".to_string();
let updated = client.update_event(&updated).await?;

// Publish (with email alert)
client.publish(event_id, true).await?;

// Publish (without email alert)
client.publish(event_id, false).await?;

// Unpublish
client.unpublish(event_id).await?;

// Contact event reporter
client.contact_event_reporter(event_id, "Can you share more context?").await?;

// Enrich an event using expansion modules
client.enrich_event(event_id, Some(&["dns", "passivetotal"])).await?;

// Delete an event
client.delete_event(event_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `events` | `() -> MispResult<Vec<MispEvent>>` | All events |
| `get_event` | `(id: i64) -> MispResult<MispEvent>` | Single event with attributes |
| `event_exists` | `(id: i64) -> MispResult<bool>` | Whether the event exists |
| `add_event` | `(event: &MispEvent) -> MispResult<MispEvent>` | Created event |
| `update_event` | `(event: &MispEvent) -> MispResult<MispEvent>` | Updated event |
| `delete_event` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `publish` | `(id: i64, alert: bool) -> MispResult<Value>` | Publish (alert=send emails) |
| `unpublish` | `(id: i64) -> MispResult<Value>` | Unpublish event |
| `contact_event_reporter` | `(id: i64, message: &str) -> MispResult<Value>` | Send message to reporter |
| `enrich_event` | `(id: i64, modules: Option<&[&str]>) -> MispResult<Value>` | Enrichment results |

---

## Attributes

```rust
use rustmisp::MispAttribute;

// List all attributes
let attrs = client.attributes().await?;

// Get a single attribute
let attr = client.get_attribute(123).await?;

// Check if an attribute exists
let exists = client.attribute_exists(123).await?;

// Add an attribute to an event
let attr = MispAttribute::new("ip-dst", "Network activity", "198.51.100.42");
let created = client.add_attribute(event_id, &attr).await?;
let attr_id = created.id.unwrap();

// Update an attribute
let mut updated = created;
updated.comment = Some("Updated via RustMISP".to_string());
let updated = client.update_attribute(&updated).await?;

// Soft-delete an attribute
client.delete_attribute(attr_id, false).await?;

// Hard-delete an attribute
client.delete_attribute(attr_id, true).await?;

// Restore a soft-deleted attribute
client.restore_attribute(attr_id).await?;

// Enrich an attribute using expansion modules
client.enrich_attribute(attr_id, Some(&["dns"])).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `attributes` | `() -> MispResult<Vec<MispAttribute>>` | All attributes |
| `get_attribute` | `(id: i64) -> MispResult<MispAttribute>` | Single attribute |
| `attribute_exists` | `(id: i64) -> MispResult<bool>` | Whether it exists |
| `add_attribute` | `(event_id: i64, attr: &MispAttribute) -> MispResult<MispAttribute>` | Created attribute |
| `update_attribute` | `(attr: &MispAttribute) -> MispResult<MispAttribute>` | Updated attribute |
| `delete_attribute` | `(id: i64, hard: bool) -> MispResult<Value>` | Deletion confirmation |
| `restore_attribute` | `(id: i64) -> MispResult<Value>` | Restore soft-deleted |
| `enrich_attribute` | `(id: i64, modules: Option<&[&str]>) -> MispResult<Value>` | Enrichment results |

---

## Tags

```rust
use rustmisp::MispTag;

// List all tags
let tags = client.tags().await?;

// Get a single tag
let tag = client.get_tag(1).await?;

// Create a tag
let mut tag = MispTag::new("RustMISP:test");
tag.colour = Some("#ff0000".to_string());
let created = client.add_tag(&tag).await?;
let tag_id = created.id.unwrap();

// Update a tag
let mut updated = created;
updated.colour = Some("#00ff00".to_string());
let updated = client.update_tag(&updated).await?;

// Enable / disable a tag
client.disable_tag(tag_id).await?;
client.enable_tag(tag_id).await?;

// Search tags by name
let results = client.search_tags("tlp:", false).await?;     // substring match
let results = client.search_tags("tlp:white", true).await?; // exact match

// Attach a tag to an entity (event, attribute, etc.) by UUID
client.tag("550e8400-e29b-41d4-a716-446655440000", "tlp:white", false).await?;

// Attach as a local tag (not shared via sync)
client.tag("550e8400-e29b-41d4-a716-446655440000", "tlp:white", true).await?;

// Remove a tag from an entity
client.untag("550e8400-e29b-41d4-a716-446655440000", "tlp:white").await?;

// Delete a tag
client.delete_tag(tag_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `tags` | `() -> MispResult<Vec<MispTag>>` | All tags |
| `get_tag` | `(id: i64) -> MispResult<MispTag>` | Single tag |
| `add_tag` | `(tag: &MispTag) -> MispResult<MispTag>` | Created tag |
| `update_tag` | `(tag: &MispTag) -> MispResult<MispTag>` | Updated tag |
| `delete_tag` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `enable_tag` | `(id: i64) -> MispResult<Value>` | Enable a tag |
| `disable_tag` | `(id: i64) -> MispResult<Value>` | Disable a tag |
| `search_tags` | `(name: &str, strict: bool) -> MispResult<Vec<MispTag>>` | Matching tags |
| `tag` | `(uuid: &str, tag: &str, local: bool) -> MispResult<Value>` | Attach tag |
| `untag` | `(uuid: &str, tag: &str) -> MispResult<Value>` | Remove tag |

---

## Objects

```rust
use rustmisp::MispObject;

// Get a single object
let obj = client.get_object(1).await?;

// Check if an object exists
let exists = client.object_exists(1).await?;

// Create an object on an event
let mut obj = MispObject::new("domain-ip");
// (Attributes are typically set via the object template)
let created = client.add_object(event_id, &obj).await?;
let obj_id = created.id.unwrap();

// Update an object
let mut updated = created;
updated.comment = Some("Updated via RustMISP".to_string());
let updated = client.update_object(&updated).await?;

// Soft-delete an object
client.delete_object(obj_id, false).await?;

// Hard-delete an object
client.delete_object(obj_id, true).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `get_object` | `(id: i64) -> MispResult<MispObject>` | Single object |
| `object_exists` | `(id: i64) -> MispResult<bool>` | Whether it exists |
| `add_object` | `(event_id: i64, object: &MispObject) -> MispResult<MispObject>` | Created object |
| `update_object` | `(object: &MispObject) -> MispResult<MispObject>` | Updated object |
| `delete_object` | `(id: i64, hard: bool) -> MispResult<Value>` | Deletion confirmation |

---

## Object References

```rust
use rustmisp::MispObjectReference;

// Add a reference between two objects
let reference = MispObjectReference::new(
    "550e8400-e29b-41d4-a716-446655440000", // referenced object UUID
    "related-to",                             // relationship type
);
let created = client.add_object_reference(source_object_id, &reference).await?;

// Delete a reference
client.delete_object_reference(reference_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `add_object_reference` | `(object_id: i64, reference: &MispObjectReference) -> MispResult<MispObjectReference>` | Created reference |
| `delete_object_reference` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Object Templates

```rust
// List all object templates
let templates = client.object_templates().await?;

// Get a specific template by ID
let template = client.get_object_template(1).await?;

// Get raw template JSON by UUID or name
let raw = client.get_raw_object_template("domain-ip").await?;

// Update all templates from the MISP server
client.update_object_templates().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `object_templates` | `() -> MispResult<Vec<MispObjectTemplate>>` | All templates |
| `get_object_template` | `(id: i64) -> MispResult<MispObjectTemplate>` | Single template |
| `get_raw_object_template` | `(uuid_or_name: &str) -> MispResult<Value>` | Raw template JSON |
| `update_object_templates` | `() -> MispResult<Value>` | Update confirmation |

---

## Attribute Proposals (Shadow Attributes)

Proposals allow suggesting changes to attributes on events you don't own.

```rust
use rustmisp::MispShadowAttribute;

// List proposals for an event
let proposals = client.attribute_proposals(event_id).await?;

// Get a single proposal
let proposal = client.get_attribute_proposal(1).await?;

// Propose a new attribute on an event
let mut proposal = MispShadowAttribute::default();
proposal.type_ = Some("ip-dst".to_string());
proposal.value = Some("198.51.100.1".to_string());
proposal.category = Some("Network activity".to_string());
let created = client.add_attribute_proposal(event_id, &proposal).await?;

// Propose a modification to an existing attribute
let modified = client.update_attribute_proposal(attr_id, &proposal).await?;

// Accept a proposal (event owner)
client.accept_attribute_proposal(proposal_id).await?;

// Discard a proposal
client.discard_attribute_proposal(proposal_id).await?;

// Delete a proposal (proposer only)
client.delete_attribute_proposal(proposal_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `attribute_proposals` | `(event_id: i64) -> MispResult<Vec<MispShadowAttribute>>` | Proposals for event |
| `get_attribute_proposal` | `(id: i64) -> MispResult<MispShadowAttribute>` | Single proposal |
| `add_attribute_proposal` | `(event_id: i64, proposal: &MispShadowAttribute) -> MispResult<MispShadowAttribute>` | Created proposal |
| `update_attribute_proposal` | `(attribute_id: i64, proposal: &MispShadowAttribute) -> MispResult<MispShadowAttribute>` | Modified proposal |
| `delete_attribute_proposal` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `accept_attribute_proposal` | `(id: i64) -> MispResult<Value>` | Accept confirmation |
| `discard_attribute_proposal` | `(id: i64) -> MispResult<Value>` | Discard confirmation |

---

## Sightings

```rust
use rustmisp::MispSighting;

// List sightings for an attribute
let sightings = client.sightings(attr_id).await?;

// Add a sighting
let sighting = MispSighting::default();
let created = client.add_sighting(&sighting, Some(attr_id)).await?;

// Add a sighting by value (matches any attribute with that value)
let sighting = MispSighting::default();
let created = client.add_sighting(&sighting, None).await?;

// Delete a sighting
client.delete_sighting(sighting_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `sightings` | `(id: i64) -> MispResult<Vec<MispSighting>>` | Sightings for attribute |
| `add_sighting` | `(sighting: &MispSighting, attribute_id: Option<i64>) -> MispResult<MispSighting>` | Created sighting |
| `delete_sighting` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Event Reports

```rust
use rustmisp::MispEventReport;

// Get a single event report
let report = client.get_event_report(1).await?;

// List all reports for an event
let reports = client.get_event_reports(event_id).await?;

// Create a report
let report = MispEventReport::new("Incident Summary", "# Analysis\n\nDetails here...");
let created = client.add_event_report(event_id, &report).await?;
let report_id = created.id.unwrap();

// Update a report
let mut updated = created;
updated.content = Some("# Updated Analysis\n\nNew details...".to_string());
let updated = client.update_event_report(&updated).await?;

// Soft-delete a report
client.delete_event_report(report_id, false).await?;

// Hard-delete a report
client.delete_event_report(report_id, true).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `get_event_report` | `(id: i64) -> MispResult<MispEventReport>` | Single report |
| `get_event_reports` | `(event_id: i64) -> MispResult<Vec<MispEventReport>>` | Reports for event |
| `add_event_report` | `(event_id: i64, report: &MispEventReport) -> MispResult<MispEventReport>` | Created report |
| `update_event_report` | `(report: &MispEventReport) -> MispResult<MispEventReport>` | Updated report |
| `delete_event_report` | `(id: i64, hard: bool) -> MispResult<Value>` | Deletion confirmation |

---

## Analyst Data (Notes, Opinions, Relationships)

### Notes

```rust
use rustmisp::MispNote;

// Get a note
let note = client.get_note(1).await?;

// Add a note to any MISP object (event, attribute, etc.)
let mut note = MispNote::new("This IP was seen in previous campaigns");
note.object_uuid = Some("550e8400-e29b-41d4-a716-446655440000".to_string());
note.object_type = Some("Attribute".to_string());
let created = client.add_note(&note).await?;

// Update a note
let mut updated = created;
updated.note = "Updated: confirmed in 3 campaigns".to_string();
let updated = client.update_note(&updated).await?;

// Delete a note
client.delete_note(note_id).await?;
```

### Opinions

```rust
use rustmisp::MispOpinion;

// Get an opinion
let opinion = client.get_opinion(1).await?;

// Add an opinion
let mut opinion = MispOpinion::with_comment("Strongly agree with this assessment");
opinion.opinion = Some(100); // 0-100 scale
opinion.object_uuid = Some("550e8400-e29b-41d4-a716-446655440000".to_string());
opinion.object_type = Some("Event".to_string());
let created = client.add_opinion(&opinion).await?;

// Update an opinion
let mut updated = created;
updated.opinion = Some(50);
let updated = client.update_opinion(&updated).await?;

// Delete an opinion
client.delete_opinion(opinion_id).await?;
```

### Relationships

```rust
use rustmisp::MispRelationship;

// Get a relationship
let rel = client.get_relationship(1).await?;

// Add a relationship between two objects
let mut rel = MispRelationship::new("related-to");
rel.object_uuid = Some("uuid-source".to_string());
rel.object_type = Some("Attribute".to_string());
rel.related_object_uuid = Some("uuid-target".to_string());
rel.related_object_type = Some("Attribute".to_string());
let created = client.add_relationship(&rel).await?;

// Update a relationship
let mut updated = created;
updated.relationship_type = "derived-from".to_string();
let updated = client.update_relationship(&updated).await?;

// Delete a relationship
client.delete_relationship(rel_id).await?;
```

### Generic Analyst Data

```rust
use rustmisp::AnalystDataType;

// Generic get/add/update/delete for any analyst data type
let data = client.get_analyst_data(AnalystDataType::Note, 1).await?;

let body = serde_json::json!({"note": "test", "object_uuid": "...", "object_type": "Event"});
client.add_analyst_data(AnalystDataType::Note, &body).await?;

client.update_analyst_data(AnalystDataType::Note, 1, &body).await?;

client.delete_analyst_data(AnalystDataType::Note, 1).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `get_analyst_data` | `(data_type: AnalystDataType, id: i64) -> MispResult<Value>` | Raw JSON |
| `add_analyst_data` | `(data_type: AnalystDataType, data: &Value) -> MispResult<Value>` | Created data |
| `update_analyst_data` | `(data_type: AnalystDataType, id: i64, data: &Value) -> MispResult<Value>` | Updated data |
| `delete_analyst_data` | `(data_type: AnalystDataType, id: i64) -> MispResult<Value>` | Deletion confirmation |
| `get_note` | `(id: i64) -> MispResult<MispNote>` | Typed note |
| `add_note` | `(note: &MispNote) -> MispResult<MispNote>` | Created note |
| `update_note` | `(note: &MispNote) -> MispResult<MispNote>` | Updated note |
| `delete_note` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `get_opinion` | `(id: i64) -> MispResult<MispOpinion>` | Typed opinion |
| `add_opinion` | `(opinion: &MispOpinion) -> MispResult<MispOpinion>` | Created opinion |
| `update_opinion` | `(opinion: &MispOpinion) -> MispResult<MispOpinion>` | Updated opinion |
| `delete_opinion` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `get_relationship` | `(id: i64) -> MispResult<MispRelationship>` | Typed relationship |
| `add_relationship` | `(rel: &MispRelationship) -> MispResult<MispRelationship>` | Created relationship |
| `update_relationship` | `(rel: &MispRelationship) -> MispResult<MispRelationship>` | Updated relationship |
| `delete_relationship` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Taxonomies

```rust
// List all taxonomies
let taxonomies = client.taxonomies().await?;

// Get a single taxonomy with predicates/entries
let taxonomy = client.get_taxonomy(1).await?;

// Enable a taxonomy
client.enable_taxonomy(1).await?;

// Disable a taxonomy
client.disable_taxonomy(1).await?;

// Enable all tags for a taxonomy
client.enable_taxonomy_tags(1).await?;

// Disable all tags for a taxonomy
client.disable_taxonomy_tags(1).await?;

// Set a taxonomy as required (enforced on events)
client.set_taxonomy_required(1, true).await?;
client.set_taxonomy_required(1, false).await?;

// Update all taxonomies from the MISP server
client.update_taxonomies().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `taxonomies` | `() -> MispResult<Vec<MispTaxonomy>>` | All taxonomies |
| `get_taxonomy` | `(id: i64) -> MispResult<MispTaxonomy>` | Single taxonomy |
| `enable_taxonomy` | `(id: i64) -> MispResult<Value>` | Enable confirmation |
| `disable_taxonomy` | `(id: i64) -> MispResult<Value>` | Disable confirmation |
| `enable_taxonomy_tags` | `(id: i64) -> MispResult<Value>` | Enable tags |
| `disable_taxonomy_tags` | `(id: i64) -> MispResult<Value>` | Disable tags |
| `set_taxonomy_required` | `(id: i64, required: bool) -> MispResult<Value>` | Confirmation |
| `update_taxonomies` | `() -> MispResult<Value>` | Update confirmation |

---

## Warninglists

```rust
// List all warninglists
let warninglists = client.warninglists().await?;

// Get a specific warninglist
let wl = client.get_warninglist(1).await?;

// Enable a warninglist
client.enable_warninglist(1).await?;

// Disable a warninglist
client.disable_warninglist(1).await?;

// Toggle warninglists by ID(s) or name(s)
client.toggle_warninglist(
    Some(&[1, 2, 3]),  // IDs
    None,               // names
    true,               // enabled
).await?;

// Check if values are in any warninglist
let check = client.values_in_warninglist(&["8.8.8.8", "1.1.1.1"]).await?;

// Update all warninglists from the MISP server
client.update_warninglists().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `warninglists` | `() -> MispResult<Vec<MispWarninglist>>` | All warninglists |
| `get_warninglist` | `(id: i64) -> MispResult<MispWarninglist>` | Single warninglist |
| `toggle_warninglist` | `(ids: Option<&[i64]>, names: Option<&[&str]>, enabled: bool) -> MispResult<Value>` | Toggle result |
| `enable_warninglist` | `(id: i64) -> MispResult<Value>` | Enable confirmation |
| `disable_warninglist` | `(id: i64) -> MispResult<Value>` | Disable confirmation |
| `values_in_warninglist` | `(values: &[&str]) -> MispResult<Value>` | Match results |
| `update_warninglists` | `() -> MispResult<Value>` | Update confirmation |

---

## Noticelists

```rust
// List all noticelists
let noticelists = client.noticelists().await?;

// Get a specific noticelist
let nl = client.get_noticelist(1).await?;

// Enable a noticelist
client.enable_noticelist(1).await?;

// Disable a noticelist
client.disable_noticelist(1).await?;

// Update all noticelists from the MISP server
client.update_noticelists().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `noticelists` | `() -> MispResult<Vec<MispNoticelist>>` | All noticelists |
| `get_noticelist` | `(id: i64) -> MispResult<MispNoticelist>` | Single noticelist |
| `enable_noticelist` | `(id: i64) -> MispResult<Value>` | Enable confirmation |
| `disable_noticelist` | `(id: i64) -> MispResult<Value>` | Disable confirmation |
| `update_noticelists` | `() -> MispResult<Value>` | Update confirmation |

---

## Galaxies

```rust
// List all galaxies (optionally update first)
let galaxies = client.galaxies(false).await?;
let galaxies = client.galaxies(true).await?; // update then list

// Search galaxies by keyword
let results = client.search_galaxy("mitre-attack").await?;

// Get a single galaxy (with or without clusters)
let galaxy = client.get_galaxy(1, false).await?;
let galaxy = client.get_galaxy(1, true).await?; // include clusters

// Search clusters within a specific galaxy
let clusters = client.search_galaxy_clusters(
    1,           // galaxy_id
    "apt",       // search term
    None,        // context (optional)
).await?;

// Update all galaxies from the MISP server
client.update_galaxies().await?;

// Attach a galaxy cluster to an event
client.attach_galaxy_cluster("42", "123", false).await?;

// Attach a galaxy cluster to an attribute
client.attach_galaxy_cluster_to("42", "123", "attribute", true).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `galaxies` | `(update: bool) -> MispResult<Vec<MispGalaxy>>` | All galaxies |
| `search_galaxy` | `(value: &str) -> MispResult<Value>` | Search results |
| `get_galaxy` | `(id: i64, with_cluster: bool) -> MispResult<MispGalaxy>` | Single galaxy |
| `search_galaxy_clusters` | `(galaxy_id: i64, search: &str, context: Option<&str>) -> MispResult<Value>` | Matching clusters |
| `update_galaxies` | `() -> MispResult<Value>` | Update confirmation |
| `attach_galaxy_cluster` | `(target_id: &str, cluster_id: &str, local: bool) -> MispResult<Value>` | Attach to event |
| `attach_galaxy_cluster_to` | `(target_id: &str, cluster_id: &str, target_type: &str, local: bool) -> MispResult<Value>` | Attach to any entity |

---

## Galaxy Clusters

```rust
use rustmisp::MispGalaxyCluster;

// Get a single cluster
let cluster = client.get_galaxy_cluster(1).await?;

// Add a cluster to a galaxy
let cluster = MispGalaxyCluster::new("My Custom Cluster");
let created = client.add_galaxy_cluster(galaxy_id, &cluster).await?;

// Update a cluster
let mut updated = created;
updated.description = Some("Updated description".to_string());
let updated = client.update_galaxy_cluster(&updated).await?;

// Publish a cluster
client.publish_galaxy_cluster(cluster_id).await?;

// Fork a cluster to your own galaxy
let forked = client.fork_galaxy_cluster(galaxy_id, &cluster).await?;

// Delete a cluster (soft or hard)
client.delete_galaxy_cluster(cluster_id, false).await?;
client.delete_galaxy_cluster(cluster_id, true).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `get_galaxy_cluster` | `(id: i64) -> MispResult<MispGalaxyCluster>` | Single cluster |
| `add_galaxy_cluster` | `(galaxy_id: i64, cluster: &MispGalaxyCluster) -> MispResult<MispGalaxyCluster>` | Created cluster |
| `update_galaxy_cluster` | `(cluster: &MispGalaxyCluster) -> MispResult<MispGalaxyCluster>` | Updated cluster |
| `publish_galaxy_cluster` | `(id: i64) -> MispResult<Value>` | Publish confirmation |
| `fork_galaxy_cluster` | `(galaxy_id: i64, cluster: &MispGalaxyCluster) -> MispResult<MispGalaxyCluster>` | Forked cluster |
| `delete_galaxy_cluster` | `(id: i64, hard: bool) -> MispResult<Value>` | Deletion confirmation |

---

## Galaxy Cluster Relations

```rust
use rustmisp::MispGalaxyClusterRelation;

// Add a relation between clusters
let relation = MispGalaxyClusterRelation::new(
    "target-cluster-uuid",
    "similar-to",
);
let created = client.add_galaxy_cluster_relation(cluster_id, &relation).await?;

// Update a relation
let updated = client.update_galaxy_cluster_relation(&created).await?;

// Delete a relation
client.delete_galaxy_cluster_relation(relation_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `add_galaxy_cluster_relation` | `(cluster_id: i64, relation: &MispGalaxyClusterRelation) -> MispResult<MispGalaxyClusterRelation>` | Created relation |
| `update_galaxy_cluster_relation` | `(relation: &MispGalaxyClusterRelation) -> MispResult<MispGalaxyClusterRelation>` | Updated relation |
| `delete_galaxy_cluster_relation` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Decaying Models

```rust
// List all decaying models
let models = client.decaying_models().await?;

// Enable a model
client.enable_decaying_model(1).await?;

// Disable a model
client.disable_decaying_model(1).await?;

// Update all decaying models from the server
client.update_decaying_models().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `decaying_models` | `() -> MispResult<Vec<MispDecayingModel>>` | All models |
| `enable_decaying_model` | `(id: i64) -> MispResult<Value>` | Enable confirmation |
| `disable_decaying_model` | `(id: i64) -> MispResult<Value>` | Disable confirmation |
| `update_decaying_models` | `() -> MispResult<Value>` | Update confirmation |

---

## Correlation Exclusions

Exclude values from the automatic correlation engine.

```rust
use rustmisp::MispCorrelationExclusion;

// List all exclusions
let exclusions = client.correlation_exclusions().await?;

// Get a specific exclusion
let excl = client.get_correlation_exclusion(1).await?;

// Add an exclusion (e.g., for a common benign value)
let excl = MispCorrelationExclusion::new("8.8.8.8");
let created = client.add_correlation_exclusion(&excl).await?;

// Delete an exclusion
client.delete_correlation_exclusion(created.id.unwrap()).await?;

// Clean all correlation exclusions
client.clean_correlation_exclusions().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `correlation_exclusions` | `() -> MispResult<Vec<MispCorrelationExclusion>>` | All exclusions |
| `get_correlation_exclusion` | `(id: i64) -> MispResult<MispCorrelationExclusion>` | Single exclusion |
| `add_correlation_exclusion` | `(excl: &MispCorrelationExclusion) -> MispResult<MispCorrelationExclusion>` | Created exclusion |
| `delete_correlation_exclusion` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `clean_correlation_exclusions` | `() -> MispResult<Value>` | Cleanup confirmation |

---

## Organisations

```rust
use rustmisp::MispOrganisation;

// List all organisations (with optional scope filter)
let orgs = client.organisations(None, None).await?;         // all visible
let orgs = client.organisations(Some("local"), None).await?; // local only
let orgs = client.organisations(Some("external"), None).await?;

// Get a single organisation
let org = client.get_organisation(1).await?;

// Check if an organisation exists
let exists = client.organisation_exists(1).await?;

// Create an organisation
let mut org = MispOrganisation::new("ACME Corp");
org.description = Some("Test organisation".to_string());
org.nationality = Some("US".to_string());
org.sector = Some("Technology".to_string());
let created = client.add_organisation(&org).await?;

// Update an organisation
let mut updated = created;
updated.description = Some("Updated description".to_string());
let updated = client.update_organisation(&updated).await?;

// Delete an organisation
client.delete_organisation(org_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `organisations` | `(scope: Option<&str>, search: Option<&str>) -> MispResult<Vec<MispOrganisation>>` | Organisations list |
| `get_organisation` | `(id: i64) -> MispResult<MispOrganisation>` | Single organisation |
| `organisation_exists` | `(id: i64) -> MispResult<bool>` | Whether it exists |
| `add_organisation` | `(org: &MispOrganisation) -> MispResult<MispOrganisation>` | Created organisation |
| `update_organisation` | `(org: &MispOrganisation) -> MispResult<MispOrganisation>` | Updated organisation |
| `delete_organisation` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Users

```rust
use rustmisp::MispUser;

// List all users (with optional search)
let users = client.users(None, None).await?;
let users = client.users(Some("admin"), None).await?;

// Get a single user
let user = client.get_user(1).await?;

// Create a user
let mut user = MispUser::new("analyst@example.com");
user.org_id = Some(1);
user.role_id = Some(3); // Org Admin
user.password = Some("SecurePassword123!".to_string());
let created = client.add_user(&user).await?;
let user_id = created.id.unwrap();

// Update a user
let mut updated = created;
updated.disabled = true;
let updated = client.update_user(&updated).await?;

// Generate a new API auth key for a user
let new_key = client.get_new_authkey(user_id).await?;

// Change the current user's password
client.change_user_password("NewSecurePassword456!").await?;

// Delete a user
client.delete_user(user_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `users` | `(search: Option<&str>, org_id: Option<i64>) -> MispResult<Vec<MispUser>>` | Users list |
| `get_user` | `(id: i64) -> MispResult<MispUser>` | Single user |
| `get_new_authkey` | `(user_id: i64) -> MispResult<String>` | New API key |
| `add_user` | `(user: &MispUser) -> MispResult<MispUser>` | Created user |
| `update_user` | `(user: &MispUser) -> MispResult<MispUser>` | Updated user |
| `delete_user` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `change_user_password` | `(password: &str) -> MispResult<Value>` | Confirmation |

---

## User Registrations

```rust
// List pending registrations
let registrations = client.user_registrations().await?;

// Accept a registration (assign org and role)
client.accept_user_registration(
    registration_id,
    Some(1),  // org_id
    Some(3),  // role_id
    Some(false), // perm_sync
    Some(false), // perm_publish
    Some(false), // perm_admin
).await?;

// Discard a registration
client.discard_user_registration(registration_id).await?;

// Heartbeat: check for recent active users
let heartbeat = client.users_heartbeat().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `user_registrations` | `() -> MispResult<Vec<MispInbox>>` | Pending registrations |
| `accept_user_registration` | `(id: i64, org_id: Option<i64>, role_id: Option<i64>, perm_sync: Option<bool>, perm_publish: Option<bool>, perm_admin: Option<bool>) -> MispResult<Value>` | Accept confirmation |
| `discard_user_registration` | `(id: i64) -> MispResult<Value>` | Discard confirmation |
| `users_heartbeat` | `() -> MispResult<Value>` | Active users info |

---

## Roles

```rust
use rustmisp::MispRole;

// List all roles
let roles = client.roles().await?;

// Create a role
let mut role = MispRole::new("Custom Analyst");
role.perm_add = true;
role.perm_modify = true;
role.perm_modify_org = true;
role.perm_tagger = true;
role.perm_sighting = true;
let created = client.add_role(&role).await?;

// Update a role
let mut updated = created;
updated.perm_publish = true;
let updated = client.update_role(&updated).await?;

// Set a role as the default for new users
client.set_default_role(role_id).await?;

// Delete a role
client.delete_role(role_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `roles` | `() -> MispResult<Vec<MispRole>>` | All roles |
| `add_role` | `(role: &MispRole) -> MispResult<MispRole>` | Created role |
| `update_role` | `(role: &MispRole) -> MispResult<MispRole>` | Updated role |
| `set_default_role` | `(id: i64) -> MispResult<Value>` | Confirmation |
| `delete_role` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Servers (Sync)

```rust
use rustmisp::MispServer;

// List all sync servers
let servers = client.servers().await?;

// Get the sync configuration for this instance
let config = client.get_sync_config().await?;

// Import a server from sync config JSON
let config_json = serde_json::json!({...});
client.import_server(&config_json).await?;

// Add a sync server
let mut server = MispServer::new("https://remote-misp.example.com", "Remote MISP");
server.authkey = Some("remote-api-key".to_string());
let created = client.add_server(&server).await?;
let server_id = created.id.unwrap();

// Update a server
let mut updated = created;
updated.push = Some(true);
let updated = client.update_server(&updated).await?;

// Test server connectivity
let test = client.test_server(server_id).await?;

// Pull events from a remote server
client.server_pull(server_id, None).await?;           // pull all
client.server_pull(server_id, Some(42)).await?;        // pull specific event

// Push events to a remote server
client.server_push(server_id, None).await?;            // push all
client.server_push(server_id, Some(42)).await?;        // push specific event

// Delete a server
client.delete_server(server_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `servers` | `() -> MispResult<Vec<MispServer>>` | All servers |
| `get_sync_config` | `() -> MispResult<Value>` | Sync config JSON |
| `import_server` | `(server: &Value) -> MispResult<Value>` | Import confirmation |
| `add_server` | `(server: &MispServer) -> MispResult<MispServer>` | Created server |
| `update_server` | `(server: &MispServer) -> MispResult<MispServer>` | Updated server |
| `delete_server` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `server_pull` | `(id: i64, event_id: Option<i64>) -> MispResult<Value>` | Pull results |
| `server_push` | `(id: i64, event_id: Option<i64>) -> MispResult<Value>` | Push results |
| `test_server` | `(id: i64) -> MispResult<Value>` | Test results |

---

## Worker Management

```rust
// Update MISP instance
client.update_misp().await?;

// Get worker status
let workers = client.get_workers().await?;

// Restart all workers
client.restart_workers().await?;

// Restart only dead workers
client.restart_dead_workers().await?;

// Start a specific worker type
client.start_worker("default").await?;

// Stop a worker by PID
client.stop_worker_by_pid(12345).await?;

// Kill all workers
client.kill_all_workers().await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `update_misp` | `() -> MispResult<Value>` | Update status |
| `get_workers` | `() -> MispResult<Value>` | Worker status |
| `restart_workers` | `() -> MispResult<Value>` | Restart confirmation |
| `restart_dead_workers` | `() -> MispResult<Value>` | Restart confirmation |
| `start_worker` | `(worker_type: &str) -> MispResult<Value>` | Start confirmation |
| `stop_worker_by_pid` | `(pid: i64) -> MispResult<Value>` | Stop confirmation |
| `kill_all_workers` | `() -> MispResult<Value>` | Kill confirmation |

---

## Feeds

```rust
use rustmisp::MispFeed;

// List all feeds
let feeds = client.feeds().await?;

// Get a specific feed
let feed = client.get_feed(1).await?;

// Create a feed
let feed = MispFeed {
    name: "My Threat Feed".to_string(),
    url: "https://example.com/feed".to_string(),
    source_format: Some("freetext".to_string()),
    provider: Some("Example Provider".to_string()),
    distribution: Some(0),
    enabled: false,
    ..Default::default()
};
let created = client.add_feed(&feed).await?;
let feed_id = created.id.unwrap();

// Update a feed
let mut updated = created;
updated.name = "Updated Feed Name".to_string();
let updated = client.update_feed(&updated).await?;

// Enable / disable a feed
client.enable_feed(feed_id).await?;
client.disable_feed(feed_id).await?;

// Enable / disable feed caching
client.enable_feed_cache(feed_id).await?;
client.disable_feed_cache(feed_id).await?;

// Fetch a feed (download and import data)
client.fetch_feed(feed_id).await?;

// Cache operations
client.cache_feed(feed_id).await?;
client.cache_all_feeds().await?;
client.cache_freetext_feeds().await?;
client.cache_misp_feeds().await?;

// Compare feeds
let comparison = client.compare_feeds().await?;

// Load default feeds
client.load_default_feeds().await?;

// Delete a feed
client.delete_feed(feed_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `feeds` | `() -> MispResult<Vec<MispFeed>>` | All feeds |
| `get_feed` | `(id: i64) -> MispResult<MispFeed>` | Single feed |
| `add_feed` | `(feed: &MispFeed) -> MispResult<MispFeed>` | Created feed |
| `update_feed` | `(feed: &MispFeed) -> MispResult<MispFeed>` | Updated feed |
| `delete_feed` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `enable_feed` | `(id: i64) -> MispResult<Value>` | Enable confirmation |
| `disable_feed` | `(id: i64) -> MispResult<Value>` | Disable confirmation |
| `enable_feed_cache` | `(id: i64) -> MispResult<Value>` | Enable cache |
| `disable_feed_cache` | `(id: i64) -> MispResult<Value>` | Disable cache |
| `fetch_feed` | `(id: i64) -> MispResult<Value>` | Fetch results |
| `cache_all_feeds` | `() -> MispResult<Value>` | Cache all |
| `cache_feed` | `(id: i64) -> MispResult<Value>` | Cache single feed |
| `cache_freetext_feeds` | `() -> MispResult<Value>` | Cache freetext feeds |
| `cache_misp_feeds` | `() -> MispResult<Value>` | Cache MISP feeds |
| `compare_feeds` | `() -> MispResult<Value>` | Comparison results |
| `load_default_feeds` | `() -> MispResult<Value>` | Load defaults |

---

## Sharing Groups

```rust
use rustmisp::MispSharingGroup;

// List all sharing groups
let groups = client.sharing_groups().await?;

// Get a single sharing group
let sg = client.get_sharing_group(1).await?;

// Check if a sharing group exists
let exists = client.sharing_group_exists(1).await?;

// Create a sharing group
let mut sg = MispSharingGroup::new("Trusted Partners");
sg.description = Some("Sharing group for trusted partners".to_string());
sg.releasability = Some("Partners only".to_string());
let created = client.add_sharing_group(&sg).await?;
let sg_id = created.id.unwrap();

// Update a sharing group
let mut updated = created;
updated.description = Some("Updated description".to_string());
let updated = client.update_sharing_group(&updated).await?;

// Add an organisation to the sharing group
client.add_org_to_sharing_group(sg_id, org_id).await?;

// Remove an organisation from the sharing group
client.remove_org_from_sharing_group(sg_id, org_id).await?;

// Add a server to the sharing group
client.add_server_to_sharing_group(sg_id, server_id).await?;

// Remove a server from the sharing group
client.remove_server_from_sharing_group(sg_id, server_id).await?;

// Delete a sharing group
client.delete_sharing_group(sg_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `sharing_groups` | `() -> MispResult<Vec<MispSharingGroup>>` | All sharing groups |
| `get_sharing_group` | `(id: i64) -> MispResult<MispSharingGroup>` | Single sharing group |
| `sharing_group_exists` | `(id: i64) -> MispResult<bool>` | Whether it exists |
| `add_sharing_group` | `(sg: &MispSharingGroup) -> MispResult<MispSharingGroup>` | Created group |
| `update_sharing_group` | `(sg: &MispSharingGroup) -> MispResult<MispSharingGroup>` | Updated group |
| `delete_sharing_group` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `add_org_to_sharing_group` | `(sg_id: i64, org_id: i64) -> MispResult<Value>` | Confirmation |
| `remove_org_from_sharing_group` | `(sg_id: i64, org_id: i64) -> MispResult<Value>` | Confirmation |
| `add_server_to_sharing_group` | `(sg_id: i64, server_id: i64) -> MispResult<Value>` | Confirmation |
| `remove_server_from_sharing_group` | `(sg_id: i64, server_id: i64) -> MispResult<Value>` | Confirmation |

---

## User Settings

```rust
use rustmisp::MispUserSetting;

// List all user settings
let settings = client.user_settings().await?;

// Get a specific setting (for current user or a specific user)
let setting = client.get_user_setting("dashboard", None).await?;
let setting = client.get_user_setting("dashboard", Some(42)).await?;

// Set a user setting
client.set_user_setting(
    "publish_alert_filter",
    &serde_json::json!({"tags": ["tlp:white"]}),
    None, // current user
).await?;

// Set a setting for a specific user (admin only)
client.set_user_setting(
    "dashboard",
    &serde_json::json!({"widgets": []}),
    Some(42),
).await?;

// Delete a user setting
client.delete_user_setting("publish_alert_filter", None).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `user_settings` | `() -> MispResult<Vec<MispUserSetting>>` | All settings |
| `get_user_setting` | `(setting: &str, user_id: Option<i64>) -> MispResult<MispUserSetting>` | Single setting |
| `set_user_setting` | `(setting: &str, value: &Value, user_id: Option<i64>) -> MispResult<Value>` | Confirmation |
| `delete_user_setting` | `(setting: &str, user_id: Option<i64>) -> MispResult<Value>` | Deletion confirmation |

---

## Search

### SearchBuilder

Fluent API for building search queries with 40+ parameters.

```rust
use rustmisp::{SearchBuilder, SearchController, ReturnFormat};

let params = SearchBuilder::new()
    .value("malware.exe")
    .type_attribute("filename")
    .tags(vec!["tlp:white", "osint:source-type=\"blog-post\""])
    .published(true)
    .to_ids(true)
    .limit(100)
    .page(1)
    .return_format(ReturnFormat::Json)
    .build();

let results = client.search(SearchController::Events, &params).await?;
```

**All SearchBuilder methods** (each returns `Self` for chaining):

| Method | Parameter Type | Description |
|--------|---------------|-------------|
| `value` | `impl Into<String>` | Value to search for |
| `value_query` | `Value` | Complex value query (AND/OR/NOT) |
| `type_attribute` | `impl Into<String>` | Attribute type filter |
| `type_attributes` | `Vec<&str>` | Multiple attribute types |
| `category` | `impl Into<String>` | Category filter |
| `org` | `impl Into<String>` | Organisation filter |
| `tags` | `Vec<&str>` | Tag filters |
| `tags_query` | `Value` | Complex tag query |
| `event_id` | `i64` | Single event ID filter |
| `event_ids` | `Vec<i64>` | Multiple event IDs |
| `uuid` | `impl Into<String>` | UUID filter |
| `date_from` | `impl Into<String>` | Start date (YYYY-MM-DD) |
| `date_to` | `impl Into<String>` | End date (YYYY-MM-DD) |
| `last` | `impl Into<String>` | Relative time (e.g., "5d", "2h") |
| `timestamp` | `Value` | Unix timestamp or range |
| `publish_timestamp` | `Value` | Publish timestamp filter |
| `event_timestamp` | `Value` | Event timestamp filter |
| `attribute_timestamp` | `Value` | Attribute timestamp filter |
| `enforce_warninglist` | `bool` | Filter out warninglist matches |
| `to_ids` | `bool` | Filter by IDS flag |
| `deleted` | `bool` | Include deleted items |
| `published` | `bool` | Filter by published state |
| `with_attachments` | `bool` | Include attachment data |
| `include_event_uuid` | `bool` | Include event UUID in results |
| `include_event_tags` | `bool` | Include event tags |
| `include_proposals` | `bool` | Include proposals |
| `include_correlations` | `bool` | Include correlations |
| `include_sightings` | `bool` | Include sightings |
| `include_decay_score` | `bool` | Include decay scores |
| `include_full_model` | `bool` | Include full model data |
| `include_context` | `bool` | Include context |
| `limit` | `i64` | Max results per page |
| `page` | `i64` | Page number |
| `threat_level_id` | `i64` | Threat level filter (1-4) |
| `analysis` | `i64` | Analysis state filter (0-2) |
| `distribution` | `i64` | Distribution level filter |
| `sharing_group_id` | `i64` | Sharing group filter |
| `object_relation` | `impl Into<String>` | Object relation filter |
| `comment` | `impl Into<String>` | Comment filter |
| `first_seen` | `impl Into<String>` | First seen filter |
| `last_seen` | `impl Into<String>` | Last seen filter |
| `requested_attributes` | `Vec<&str>` | Specific attributes to return |
| `return_format` | `ReturnFormat` | Output format |
| `sg_reference_only` | `bool` | Only SG references |
| `searchall` | `bool` | Search all fields |
| `quickfilter` | `impl Into<String>` | Quick filter string |
| `decaying_model` | `Value` | Decaying model filter |
| `score` | `Value` | Decay score filter |
| `exclude_decayed` | `bool` | Exclude decayed |
| `model_overrides` | `Value` | Model override params |
| `metadata` | `bool` | Metadata only (no attributes) |
| `event_info` | `impl Into<String>` | Event info filter |
| `headerless` | `bool` | Omit CSV headers |

### search()

```rust
// Search events
let results = client.search(SearchController::Events, &params).await?;

// Search attributes
let results = client.search(SearchController::Attributes, &params).await?;

// Search objects
let results = client.search(SearchController::Objects, &params).await?;
```

### search_index()

Lightweight event metadata search.

```rust
use rustmisp::SearchParameters;

let params = SearchParameters {
    published: Some(true),
    limit: Some(10),
    ..Default::default()
};
let events = client.search_index(&params).await?;
for event in &events {
    println!("{}: {}", event.id.unwrap(), event.info);
}
```

### search_sightings()

```rust
let sightings = client.search_sightings(
    "attribute",     // context: "attribute" or "event"
    42,              // ID
    None,            // source
    None,            // type_sighting (0, 1, or 2)
    None,            // date_from
    None,            // date_to
    None,            // publish_timestamp
    None,            // last
    None,            // org
).await?;
```

### search_logs()

```rust
let logs = client.search_logs(
    Some(42),        // limit
    Some(1),         // page
    None,            // log_id
    None,            // title
    None,            // created
    None,            // model
    None,            // action
    None,            // user_id
    None,            // change
    None,            // email
    None,            // org
    None,            // description
    None,            // ip
).await?;
```

### search_feeds()

```rust
let results = client.search_feeds("8.8.8.8").await?;
```

### Freetext Import

Parse a block of text for IOCs and create attributes.

```rust
let result = client.freetext(
    event_id,
    "Found indicators: 198.51.100.42, malware.exe, evil@example.com",
    Some(true),  // adhere to warninglists
    Some(0),     // distribution
    None,        // sharing_group_id
).await?;
```

### Complex Queries

Build AND/OR/NOT queries for tags and values.

```rust
use rustmisp::build_complex_query;

// ip-src OR ip-dst
let q = build_complex_query(Some(vec!["ip-src", "ip-dst"]), None, None);

// tag_a AND tag_b
let q = build_complex_query(None, Some(vec!["tlp:white", "osint"]), None);

// tag_a AND NOT tag_b
let q = build_complex_query(Some(vec!["tlp:white"]), None, Some(vec!["tlp:red"]));

// Use with SearchBuilder
let params = SearchBuilder::new()
    .tags_query(build_complex_query(
        Some(vec!["tlp:white"]),
        None,
        Some(vec!["tlp:red"]),
    ))
    .build();
```

**Relative timestamp parsing:**

```rust
use rustmisp::parse_relative_timestamp;

let ts = parse_relative_timestamp("5d")?;  // 5 days ago as Unix timestamp
let ts = parse_relative_timestamp("2h")?;  // 2 hours ago
let ts = parse_relative_timestamp("30m")?; // 30 minutes ago
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `search` | `(controller: SearchController, params: &SearchParameters) -> MispResult<Value>` | Search results |
| `search_index` | `(params: &SearchParameters) -> MispResult<Vec<MispEvent>>` | Event metadata |
| `search_sightings` | `(context, id, source, type_, from, to, pub_ts, last, org) -> MispResult<Value>` | Sighting results |
| `search_logs` | `(limit, page, log_id, title, created, model, action, ...) -> MispResult<Value>` | Log entries |
| `search_feeds` | `(value: &str) -> MispResult<Value>` | Feed matches |
| `freetext` | `(event_id, string, warninglists, distribution, sg_id) -> MispResult<Value>` | Created attributes |

---

## Blocklists

### Event Blocklists

```rust
use rustmisp::MispEventBlocklist;

// List all event blocklists
let blocklists = client.event_blocklists().await?;

// Add an event to the blocklist
let entry = client.add_event_blocklist(
    "550e8400-e29b-41d4-a716-446655440000",
    Some("Spam event"),
    Some("Blocked by RustMISP"),
    Some("ACME Corp"),
).await?;

// Update a blocklist entry
client.update_event_blocklist(
    entry_id,
    Some("Updated comment"),
    None,
).await?;

// Delete a blocklist entry
client.delete_event_blocklist(entry_id).await?;
```

### Organisation Blocklists

```rust
use rustmisp::MispOrganisationBlocklist;

// List all organisation blocklists
let blocklists = client.organisation_blocklists().await?;

// Add an organisation to the blocklist
let entry = client.add_organisation_blocklist(
    "org-uuid-here",
    Some("Known spammer"),
    Some("Blocked by admin"),
    Some("Spam Org"),
).await?;

// Update a blocklist entry
client.update_organisation_blocklist(
    entry_id,
    Some("Updated comment"),
    None,
).await?;

// Delete a blocklist entry
client.delete_organisation_blocklist(entry_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `event_blocklists` | `() -> MispResult<Vec<MispEventBlocklist>>` | All event blocklists |
| `organisation_blocklists` | `() -> MispResult<Vec<MispOrganisationBlocklist>>` | All org blocklists |
| `add_event_blocklist` | `(uuid, comment, event_info, event_orgc) -> MispResult<MispEventBlocklist>` | Created entry |
| `add_organisation_blocklist` | `(uuid, comment, org_name, org_uuid) -> MispResult<MispOrganisationBlocklist>` | Created entry |
| `update_event_blocklist` | `(id, comment, event_info) -> MispResult<Value>` | Update confirmation |
| `update_organisation_blocklist` | `(id, comment, org_name) -> MispResult<Value>` | Update confirmation |
| `delete_event_blocklist` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |
| `delete_organisation_blocklist` | `(id: i64) -> MispResult<Value>` | Deletion confirmation |

---

## Communities

```rust
// List all communities
let communities = client.communities().await?;

// Get a specific community
let community = client.get_community(1).await?;

// Request access to a community
client.request_community_access(
    1,                              // community_id
    None,                           // requesting_user_email
    None,                           // anonymise
    None,                           // org_name
    None,                           // org_uuid
    None,                           // org_description
    Some("Requesting access"),      // message
    Some(true),                     // sync
    None,                           // org_type
    None,                           // mock (test mode)
).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `communities` | `() -> MispResult<Vec<MispCommunity>>` | All communities |
| `get_community` | `(id: i64) -> MispResult<MispCommunity>` | Single community |
| `request_community_access` | `(id, email, anonymise, org_name, org_uuid, org_desc, message, sync, org_type, mock) -> MispResult<Value>` | Request confirmation |

---

## Event Delegations

```rust
// List all event delegations
let delegations = client.event_delegations().await?;

// Delegate an event to another organisation
client.delegate_event(
    event_id,
    org_id,
    Some(1),                        // distribution
    Some("Please review this"),     // message
).await?;

// Accept a delegation
client.accept_event_delegation(delegation_id).await?;

// Discard a delegation
client.discard_event_delegation(delegation_id).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `event_delegations` | `() -> MispResult<Vec<MispEventDelegation>>` | All delegations |
| `delegate_event` | `(event_id: i64, org_id: i64, distribution: Option<i64>, message: Option<&str>) -> MispResult<Value>` | Delegation confirmation |
| `accept_event_delegation` | `(id: i64) -> MispResult<Value>` | Accept confirmation |
| `discard_event_delegation` | `(id: i64) -> MispResult<Value>` | Discard confirmation |

---

## Advanced / Misc

```rust
// Upload a STIX 1.x file
client.upload_stix(stix_xml_content, 1).await?;

// Upload a STIX 2.x file
client.upload_stix(stix_json_content, 2).await?;

// Raw API call to any endpoint
let result = client.direct_call("events/view/42", None).await?;           // GET
let result = client.direct_call("events/index", Some(&body)).await?;      // POST

// Push an event to ZMQ
client.push_event_to_zmq(event_id).await?;

// Change the sharing group on an entity
client.change_sharing_group_on_entity(
    entity_id,
    "event",           // entity_type
    sharing_group_id,
).await?;

// Statistics
let attr_stats = client.attributes_statistics(None, None).await?;
let attr_stats = client.attributes_statistics(Some("category"), Some(true)).await?;
let tag_stats = client.tags_statistics(None, None).await?;
let tag_stats = client.tags_statistics(Some("attribute"), Some(true)).await?;
let user_stats = client.users_statistics(None).await?;
```

| Method | Signature | Returns |
|--------|-----------|---------|
| `upload_stix` | `(data: &str, version: u8) -> MispResult<Value>` | Import results |
| `direct_call` | `(relative_path: &str, data: Option<&Value>) -> MispResult<Value>` | Raw response |
| `push_event_to_zmq` | `(id: i64) -> MispResult<Value>` | ZMQ confirmation |
| `change_sharing_group_on_entity` | `(id: i64, entity_type: &str, sg_id: i64) -> MispResult<Value>` | Confirmation |
| `attributes_statistics` | `(context: Option<&str>, percentage: Option<bool>) -> MispResult<Value>` | Statistics |
| `tags_statistics` | `(context: Option<&str>, percentage: Option<bool>) -> MispResult<Value>` | Statistics |
| `users_statistics` | `(context: Option<&str>) -> MispResult<Value>` | Statistics |

---

## Standalone Functions

These do not require an authenticated client.

### register_user

```rust
use rustmisp::register_user;

let result = register_user(
    "https://misp.example.com",
    "newuser@example.com",
    None,     // organisation (UUID or name)
    None,     // org_id
    None,     // org_name
    None,     // message
    None,     // custom_perms
    false,    // perm_sync
    false,    // perm_publish
    false,    // perm_admin
    false,    // verify_ssl
).await?;
```

### register_user_blocking

Same signature, synchronous. Requires `blocking` feature.

```rust
use rustmisp::register_user_blocking;

let result = register_user_blocking(
    "https://misp.example.com",
    "newuser@example.com",
    None, None, None, None, None,
    false, false, false, false,
)?;
```

---

## Enums

### Distribution

```rust
use rustmisp::Distribution;

Distribution::YourOrganisationOnly  // 0
Distribution::ThisCommunityOnly     // 1
Distribution::ConnectedCommunities  // 2
Distribution::AllCommunities        // 3
Distribution::SharingGroup          // 4
Distribution::Inherit               // 5
```

### ThreatLevel

```rust
use rustmisp::ThreatLevel;

ThreatLevel::High       // 1
ThreatLevel::Medium     // 2
ThreatLevel::Low        // 3
ThreatLevel::Undefined  // 4
```

### Analysis

```rust
use rustmisp::Analysis;

Analysis::Initial   // 0
Analysis::Ongoing   // 1
Analysis::Complete  // 2
```

### SearchController

```rust
use rustmisp::SearchController;

SearchController::Events      // /events/restSearch
SearchController::Attributes  // /attributes/restSearch
SearchController::Objects     // /objects/restSearch
```

### ReturnFormat

```rust
use rustmisp::ReturnFormat;

ReturnFormat::Json
ReturnFormat::Xml
ReturnFormat::Csv
ReturnFormat::Text
ReturnFormat::Stix
ReturnFormat::Stix2
ReturnFormat::Suricata
ReturnFormat::Snort
ReturnFormat::Yara
ReturnFormat::Rpz
ReturnFormat::OpenIoc
```

### AnalystDataType

```rust
use rustmisp::AnalystDataType;

AnalystDataType::Note
AnalystDataType::Opinion
AnalystDataType::Relationship
```

---

## Tools

Optional feature-gated modules for working with MISP data offline.

### GenericObjectGenerator (`tools-file` or `tools-all`)

Build MISP objects programmatically.

```rust
use rustmisp::tools::generic_object::GenericObjectGenerator;

let obj = GenericObjectGenerator::new("domain-ip")
    .add_attribute("domain", "domain", "example.com")
    .add_attribute("ip", "ip-dst", "198.51.100.42")
    .add_attribute_full("text", "text", "Notes here", false, Some("analyst comment"))
    .comment("Generated by RustMISP")
    .generate()?;

// obj is a MispObject ready to be added to an event
client.add_object(event_id, &obj).await?;
```

### FileObject (`tools-file`)

Generate a MISP `file` object from a file path or bytes, including MD5/SHA1/SHA256 hashes.

```rust
use rustmisp::tools::file_object::FileObject;

// From a file path
let file_obj = FileObject::new("/path/to/malware.exe")?;
let obj = file_obj.generate()?;
client.add_object(event_id, &obj).await?;

// From bytes
let file_obj = FileObject::from_bytes("sample.bin", &bytes)
    .set_filename("renamed.bin");
let obj = file_obj.generate()?;
```

### CsvLoader (`tools-csv`)

Import attributes from CSV files.

```rust
use rustmisp::tools::csv_loader::CsvLoader;

// From a file
let attrs = CsvLoader::from_file("/path/to/indicators.csv")?;
for attr in &attrs {
    client.add_attribute(event_id, attr).await?;
}

// From a string
let csv = "type,value,category\nip-dst,198.51.100.42,Network activity\n";
let attrs = CsvLoader::from_string(csv)?;
```

### FeedGenerator (`tools-feed`)

Generate MISP feed metadata.

```rust
use rustmisp::tools::feed::FeedGenerator;

let mut gen = FeedGenerator::new();
gen.add_event(&event);

let manifest = gen.generate_manifest()?;
let hashes = gen.generate_hashes();
let uuids = gen.event_uuids();
let json = gen.get_event_json("event-uuid-here");
```

### OpenIOC Loader (`tools-openioc`)

Import indicators from OpenIOC XML files.

```rust
use rustmisp::tools::openioc::load_openioc_file;

let attrs = load_openioc_file("/path/to/ioc.xml")?;
for attr in &attrs {
    client.add_attribute(event_id, attr).await?;
}

// From a string
use rustmisp::tools::openioc::load_openioc;
let attrs = load_openioc(xml_content)?;
```

---

## Error Handling

All methods return `MispResult<T>`, which is `Result<T, MispError>`.

```rust
use rustmisp::{MispError, MispResult};

match client.get_event(99999).await {
    Ok(event) => println!("Found: {}", event.info),
    Err(MispError::NotFound(msg)) => println!("Event not found: {msg}"),
    Err(MispError::AuthError(msg)) => println!("Auth failed: {msg}"),
    Err(MispError::ApiError { status, message }) => {
        println!("API error {status}: {message}");
    }
    Err(e) => println!("Other error: {e}"),
}
```

### MispError Variants

| Variant | Description |
|---------|-------------|
| `AuthError(String)` | Authentication failure (401/403) |
| `NotFound(String)` | Resource not found (404) |
| `ApiError { status, message }` | Other HTTP error |
| `InvalidInput(String)` | Invalid input data |
| `UnexpectedResponse(String)` | Unexpected response format |
| `MissingField(String)` | Required field missing |
| `JsonError(serde_json::Error)` | JSON serialization error |
| `HttpError(reqwest::Error)` | HTTP transport error |
| `UrlError(url::ParseError)` | URL parsing error |
| `IoError(std::io::Error)` | I/O error (tools) |
