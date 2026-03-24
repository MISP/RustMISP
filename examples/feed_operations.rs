//! Manage MISP feeds: create, enable, cache, and clean up.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example feed_operations
//! ```

use rustmisp::{MispClient, MispFeed, MispResult};

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

    // ── List existing feeds ────────────────────────────────────────────
    let feeds = client.feeds().await?;
    println!("Server has {} feed(s) configured", feeds.len());

    // ── Create a new freetext feed ─────────────────────────────────────
    let mut feed = MispFeed::new(
        "RustMISP example feed",
        "https://example.com/indicators.txt",
    );
    feed.source_format = Some("freetext".into());
    feed.provider = Some("Example Provider".into());
    feed.enabled = false; // start disabled so we can enable explicitly

    let created = client.add_feed(&feed).await?;
    let feed_id = created.id.expect("server should assign an id");
    println!("Created feed #{feed_id}: {}", created.name);

    // ── Retrieve the feed ──────────────────────────────────────────────
    let fetched = client.get_feed(feed_id).await?;
    println!(
        "Feed #{}: provider={}, format={}, enabled={}",
        feed_id,
        fetched.provider.as_deref().unwrap_or("(none)"),
        fetched.source_format.as_deref().unwrap_or("misp"),
        fetched.enabled,
    );

    // ── Enable and disable the feed ────────────────────────────────────
    client.enable_feed(feed_id).await?;
    println!("Enabled feed #{feed_id}");

    client.disable_feed(feed_id).await?;
    println!("Disabled feed #{feed_id}");

    // ── Toggle caching ─────────────────────────────────────────────────
    client.enable_feed_cache(feed_id).await?;
    println!("Enabled caching for feed #{feed_id}");

    client.disable_feed_cache(feed_id).await?;
    println!("Disabled caching for feed #{feed_id}");

    // ── Clean up: delete the example feed ──────────────────────────────
    client.delete_feed(feed_id).await?;
    println!("Deleted feed #{feed_id}");

    Ok(())
}
