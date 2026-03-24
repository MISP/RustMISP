//! # RustMISP
//!
//! A Rust client library for the [MISP](https://www.misp-project.org/) REST API,
//! providing feature parity with [PyMISP](https://github.com/MISP/PyMISP).
//!
//! RustMISP offers strongly-typed data models, an ergonomic async API client,
//! and an optional blocking wrapper — with the performance and safety of Rust.
//!
//! ## Quick start
//!
//! ```no_run
//! use rustmisp::{MispClient, MispEvent};
//!
//! # async fn example() -> rustmisp::MispResult<()> {
//! let client = MispClient::new("https://misp.example.com", "your-api-key", false)?;
//! let events = client.events().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - `blocking` — enables the synchronous `MispClientBlocking` wrapper
//! - `tools-file` — file hashing and MISP object generation
//! - `tools-csv` — CSV-to-attribute import
//! - `tools-openioc` — OpenIOC import
//! - `tools-feed` — feed metadata generation

/// Async MISP API client and builder.
pub mod client;
/// Blocking (synchronous) MISP API client wrapper.
#[cfg(feature = "blocking")]
pub mod client_blocking;
/// Error types used throughout the crate.
pub mod error;
/// Data model structs for all MISP entity types.
pub mod models;
/// Search parameter builder and query helpers.
pub mod search;
/// Optional tool modules for file objects, CSV import, feeds, and OpenIOC.
pub mod tools;
/// Attribute type and category validation from `describeTypes.json`.
pub mod validation;

pub use client::{MispClient, MispClientBuilder, register_user};
#[cfg(feature = "blocking")]
pub use client_blocking::{MispClientBlocking, MispClientBlockingBuilder, register_user_blocking};
pub use error::{MispError, MispResult};
pub use models::attribute::MispAttribute;
pub use models::blocklist::{MispEventBlocklist, MispOrganisationBlocklist};
pub use models::community::MispCommunity;
pub use models::correlation::{MispCorrelationExclusion, MispDecayingModel};
pub use models::enums::{Analysis, Distribution, ThreatLevel};
pub use models::event::{MispEvent, MispEventOrg};
pub use models::event_delegation::MispEventDelegation;
pub use models::event_report::MispEventReport;
pub use models::feed::MispFeed;
pub use models::galaxy::{
    MispGalaxy, MispGalaxyCluster, MispGalaxyClusterElement, MispGalaxyClusterRelation,
};
pub use models::log::MispLog;
pub use models::noticelist::MispNoticelist;
pub use models::object::{MispObject, MispObjectReference, MispObjectTemplate};
pub use models::organisation::MispOrganisation;
pub use models::server::MispServer;
pub use models::shadow_attribute::MispShadowAttribute;
pub use models::sharing_group::{MispSharingGroup, SharingGroupOrg, SharingGroupServer};
pub use models::sighting::MispSighting;
pub use models::tag::MispTag;
pub use models::taxonomy::MispTaxonomy;
pub use models::user::{MispInbox, MispRole, MispUser};
pub use models::user_setting::MispUserSetting;
pub use models::warninglist::MispWarninglist;
pub use search::{
    ReturnFormat, SearchBuilder, SearchController, SearchParameters, build_complex_query,
    parse_relative_timestamp,
};
