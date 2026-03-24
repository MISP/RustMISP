//! Demonstrate sighting operations: add, list, search, and delete.
//!
//! Sightings record that an indicator was observed (type 0), flagged as a
//! false positive (type 1), or marked as expired (type 2).
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example sightings
//! ```

use rustmisp::{
    Analysis, Distribution, MispAttribute, MispClient, MispEvent, MispResult, MispSighting,
    ThreatLevel,
};

#[tokio::main]
async fn main() -> MispResult<()> {
    let url = std::env::var("MISP_URL").expect("Set MISP_URL environment variable");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY environment variable");
    let ssl_verify = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let client = MispClient::new(&url, &key, ssl_verify)?;

    let version = client.misp_instance_version().await?;
    println!("Connected to MISP {version}");

    // ── 1. Create a temporary event with an attribute ────────────────

    let mut event = MispEvent::new("RustMISP example: sighting workflow");
    event.distribution = Some(Distribution::YourOrganisationOnly as i64);
    event.threat_level_id = Some(ThreatLevel::Low as i64);
    event.analysis = Some(Analysis::Initial as i64);

    let created = client.add_event(&event).await?;
    let event_id = created.id.expect("server should assign an id");
    println!("Created event #{event_id}");

    let attr = MispAttribute::new("ip-dst", "Network activity", "203.0.113.50");
    let created_attr = client.add_attribute(event_id, &attr).await?;
    let attr_id = created_attr
        .id
        .expect("server should assign an attribute id");
    println!("Added attribute #{attr_id} (ip-dst: 203.0.113.50)");

    // ── 2. Add a regular sighting (type 0 = seen) ───────────────────

    let mut sighting = MispSighting::new();
    sighting.source = Some("honeypot-alpha".into());
    let added = client.add_sighting(&sighting, Some(attr_id)).await?;
    let sighting_id = added.id.expect("server should assign a sighting id");
    println!("Added sighting #{sighting_id} (type 0 — seen, source: honeypot-alpha)");

    // ── 3. Add a false-positive sighting (type 1) ───────────────────

    let mut fp = MispSighting::false_positive();
    fp.source = Some("analyst-review".into());
    let added_fp = client.add_sighting(&fp, Some(attr_id)).await?;
    let fp_id = added_fp.id.expect("server should assign a sighting id");
    println!("Added sighting #{fp_id} (type 1 — false positive, source: analyst-review)");

    // ── 4. Add an expiration sighting (type 2) ──────────────────────

    let mut exp = MispSighting::expiration();
    exp.source = Some("feed-cleanup".into());
    let added_exp = client.add_sighting(&exp, Some(attr_id)).await?;
    let exp_id = added_exp.id.expect("server should assign a sighting id");
    println!("Added sighting #{exp_id} (type 2 — expiration, source: feed-cleanup)");

    // ── 5. List all sightings for the attribute ─────────────────────

    let all = client.sightings(attr_id).await?;
    println!("\nSightings for attribute #{attr_id}: {} total", all.len());
    for s in &all {
        let kind = match s.sighting_type {
            Some(0) => "seen",
            Some(1) => "false-positive",
            Some(2) => "expiration",
            _ => "unknown",
        };
        println!(
            "  - #{} type={kind} source={:?}",
            s.id.unwrap_or(0),
            s.source.as_deref().unwrap_or("(none)"),
        );
    }

    // ── 6. Search sightings by source ───────────────────────────────

    let results = client
        .search_sightings(
            "attribute",
            attr_id,
            Some("honeypot-alpha"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    println!("\nSearch results (source=honeypot-alpha): {results}");

    // ── 7. Delete sightings ─────────────────────────────────────────

    client.delete_sighting(sighting_id).await?;
    println!("\nDeleted sighting #{sighting_id}");
    client.delete_sighting(fp_id).await?;
    println!("Deleted sighting #{fp_id}");
    client.delete_sighting(exp_id).await?;
    println!("Deleted sighting #{exp_id}");

    // ── 8. Clean up ─────────────────────────────────────────────────

    client.delete_event(event_id).await?;
    println!("Deleted event #{event_id}");

    println!("\nSighting workflow complete.");
    Ok(())
}
