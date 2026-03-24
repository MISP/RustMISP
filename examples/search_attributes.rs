//! Search for attributes using the MISP restSearch API.
//!
//! Demonstrates `SearchBuilder`, `build_complex_query`, relative timestamps,
//! pagination, and different return formats.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example search_attributes
//! ```

use rustmisp::{
    MispClient, MispResult, ReturnFormat, SearchBuilder, SearchController, build_complex_query,
};

#[tokio::main]
async fn main() -> MispResult<()> {
    let url = std::env::var("MISP_URL").expect("Set MISP_URL environment variable");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY environment variable");
    let ssl_verify = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let client = MispClient::new(&url, &key, ssl_verify)?;

    // ── 1. Simple value search ──────────────────────────────────────────────
    // Find all attributes matching a specific IP address.
    let params = SearchBuilder::new()
        .value("198.51.100.42")
        .type_attribute("ip-dst")
        .limit(10)
        .build();

    let results = client.search(SearchController::Attributes, &params).await?;
    println!("=== Simple IP search ===");
    println!("{results:#}");

    // ── 2. Date-range search ────────────────────────────────────────────────
    // Find attributes added in the last 7 days with the to_ids flag set.
    let params = SearchBuilder::new()
        .last("7d")
        .to_ids(true)
        .enforce_warninglist(true)
        .include_event_tags(true)
        .limit(25)
        .build();

    let results = client.search(SearchController::Attributes, &params).await?;
    println!("\n=== Last 7 days (to_ids=true) ===");
    println!("{results:#}");

    // ── 3. Complex tag query (AND / OR / NOT) ───────────────────────────────
    // Find attributes tagged with (tlp:green OR tlp:white) AND malware,
    // but NOT tlp:red.
    let tag_query = build_complex_query(
        Some(vec!["tlp:green", "tlp:white"]),
        Some(vec!["malware"]),
        Some(vec!["tlp:red"]),
    );

    let params = SearchBuilder::new()
        .tags_query(tag_query)
        .published(true)
        .limit(20)
        .build();

    let results = client.search(SearchController::Attributes, &params).await?;
    println!("\n=== Complex tag query ===");
    println!("{results:#}");

    // ── 4. Multi-type search with pagination ────────────────────────────────
    // Search across several network indicator types, page 1.
    let params = SearchBuilder::new()
        .type_attributes(vec!["ip-src", "ip-dst", "domain", "hostname", "url"])
        .category("Network activity")
        .date_from("2025-01-01")
        .page(1)
        .limit(50)
        .include_event_uuid(true)
        .include_correlations(true)
        .build();

    let results = client.search(SearchController::Attributes, &params).await?;
    println!("\n=== Network indicators (page 1) ===");
    println!("{results:#}");

    // ── 5. CSV export ───────────────────────────────────────────────────────
    // Retrieve attributes as CSV for downstream processing.
    let params = SearchBuilder::new()
        .type_attribute("sha256")
        .to_ids(true)
        .limit(10)
        .return_format(ReturnFormat::Csv)
        .requested_attributes(vec!["uuid", "value", "type", "timestamp"])
        .build();

    let csv = client.search(SearchController::Attributes, &params).await?;
    println!("\n=== SHA-256 hashes (CSV) ===");
    println!("{csv}");

    // ── 6. Event-level search ───────────────────────────────────────────────
    // Search for events containing specific indicators.
    let params = SearchBuilder::new()
        .value("malware.example.com")
        .published(true)
        .limit(5)
        .build();

    let results = client.search(SearchController::Events, &params).await?;
    println!("\n=== Events containing domain ===");
    println!("{results:#}");

    Ok(())
}
