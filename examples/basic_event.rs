//! Create, populate, and publish a MISP event.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example basic_event
//! ```

use rustmisp::{
    Analysis, Distribution, MispAttribute, MispClient, MispEvent, MispResult, ThreatLevel,
};

#[tokio::main]
async fn main() -> MispResult<()> {
    // Read connection details from environment variables.
    let url = std::env::var("MISP_URL").expect("Set MISP_URL environment variable");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY environment variable");
    let ssl_verify = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    // Build the client.
    let client = MispClient::new(&url, &key, ssl_verify)?;

    // Verify connectivity.
    let version = client.misp_instance_version().await?;
    println!("Connected to MISP {version}");

    // Create a new event.
    let mut event = MispEvent::new("RustMISP example: suspicious activity");
    event.distribution = Some(Distribution::YourOrganisationOnly as i64);
    event.threat_level_id = Some(ThreatLevel::Medium as i64);
    event.analysis = Some(Analysis::Initial as i64);
    event.date = Some("2025-01-15".into());

    let created = client.add_event(&event).await?;
    let event_id = created.id.expect("server should assign an id");
    println!("Created event #{event_id}: {}", created.info);

    // Add attributes (indicators of compromise).
    let ip = MispAttribute::new("ip-dst", "Network activity", "198.51.100.42");
    let domain = MispAttribute::new("domain", "Network activity", "malware.example.com");
    let hash = MispAttribute::new(
        "sha256",
        "Payload delivery",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    client.add_attribute(event_id, &ip).await?;
    client.add_attribute(event_id, &domain).await?;
    client.add_attribute(event_id, &hash).await?;
    println!("Added 3 attributes to event #{event_id}");

    // Tag the event.
    let event_uuid = created
        .uuid
        .as_deref()
        .expect("server should assign a uuid");
    client.tag(event_uuid, "tlp:green", false).await?;
    client.tag(event_uuid, "type:OSINT", false).await?;
    println!("Tagged event with tlp:green and type:OSINT");

    // Fetch the full event back to confirm.
    let fetched = client.get_event(event_id).await?;
    println!(
        "Event #{} now has {} attribute(s) and {} tag(s)",
        event_id,
        fetched.attributes.len(),
        fetched.tags.len(),
    );

    // Publish the event (without email alert).
    client.publish(event_id, false).await?;
    println!("Event #{event_id} published");

    // Clean up: delete the example event.
    client.delete_event(event_id).await?;
    println!("Deleted event #{event_id}");

    Ok(())
}
