# Manual Testing Guide

## Prerequisites

- A running MISP instance
- A valid API key with admin privileges
- Rust toolchain installed (`rustup`, `cargo`)

## Configuration

Export the connection details for your MISP instance:

```bash
export MISP_URL='http://localhost:5007'
export MISP_KEY='YOUR_API_KEY_HERE'
export MISP_VERIFYCERT=false   # set to true if your instance uses a trusted TLS cert
```

You can find your API key in **MISP > Administration > List Users**, or in a
helper file such as `tests/keys.py`.

## Running the Integration Tests

The integration tests are marked `#[ignore]` so they don't run during normal
`cargo test`. Run them explicitly with:

```bash
cargo test -- --ignored
```

All 10 tests should pass:

```
test test_event_crud_lifecycle ........... ok
test test_attribute_crud_with_types ...... ok
test test_object_creation_with_templates . ok
test test_tag_operations ................. ok
test test_search_with_complex_queries .... ok
test test_sighting_operations ............ ok
test test_galaxy_attachment .............. ok
test test_user_org_management ............ ok
test test_sharing_group_workflow ......... ok
test test_feed_operations ................ ok
```

To run a single test:

```bash
cargo test test_event_crud_lifecycle -- --ignored
```

## Running the Example Scripts

The `examples/` directory contains runnable scripts. Use `MISP_SSL_VERIFY`
(not `MISP_VERIFYCERT`) for examples — they use their own env var name:

```bash
export MISP_SSL_VERIFY=false   # only needed for self-signed certs

# Create an event, add attributes, tag and publish it, then clean up
cargo run --example basic_event

# Search for attributes
cargo run --example search_attributes

# Tag management
cargo run --example manage_tags

# Other examples
cargo run --example feed_operations
cargo run --example sharing_groups
cargo run --example galaxy_operations
cargo run --example sightings
cargo run --example user_management
```

## Quick Smoke Test Script

Save this as `examples/smoke_test.rs` and run it with
`cargo run --example smoke_test`:

```rust
//! Minimal smoke test: create an event with one attribute, verify, then delete.

use rustmisp::*;

#[tokio::main]
async fn main() -> MispResult<()> {
    let url = std::env::var("MISP_URL").expect("Set MISP_URL");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY");
    let ssl = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);

    let client = MispClient::new(&url, &key, ssl)?;

    // 1. Check connectivity
    let ver = client.misp_instance_version().await?;
    println!("[ok] Connected to MISP {ver}");

    // 2. Create event
    let mut event = MispEvent::new("RustMISP smoke test");
    event.distribution = Some(0);
    event.threat_level_id = Some(4);
    event.analysis = Some(0);

    let created = client.add_event(&event).await?;
    let eid = created.id.expect("event should have an id");
    println!("[ok] Created event #{eid}");

    // 3. Add attribute
    let attr = MispAttribute::new("ip-dst", "Network activity", "203.0.113.1");
    let created_attr = client.add_attribute(eid, &attr).await?;
    println!("[ok] Added attribute: {} = {}", created_attr.attr_type, created_attr.value);

    // 4. Fetch and verify
    let fetched = client.get_event(eid).await?;
    assert_eq!(fetched.attributes.len(), 1);
    println!("[ok] Verified event has 1 attribute");

    // 5. Clean up
    client.delete_event(eid).await?;
    println!("[ok] Deleted event #{eid}");

    println!("\nAll checks passed.");
    Ok(())
}
```

Or run it directly:

```bash
cargo run --example smoke_test
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `MISP_URL environment variable required` | Export `MISP_URL` and `MISP_KEY` |
| `AuthError: HTTP 403` | Check that your API key is valid and has admin rights |
| `TLS error` / certificate errors | Set `MISP_VERIFYCERT=false` (tests) or `MISP_SSL_VERIFY=false` (examples) |
| Timeouts | Verify the MISP instance is reachable at the URL you set |
