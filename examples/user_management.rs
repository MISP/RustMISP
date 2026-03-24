//! Manage MISP users, organisations, and roles.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example user_management
//! ```

use rustmisp::{MispClient, MispOrganisation, MispResult, MispUser};

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

    // --- Organisation management ---

    // Create a test organisation.
    let mut org = MispOrganisation::new("RustMISP Example Org");
    org.description = Some("Created by the user_management example".into());
    org.nationality = Some("Internet".into());
    org.sector = Some("Technology".into());

    let created_org = client.add_organisation(&org).await?;
    let org_id = created_org.id.expect("server should assign an id");
    println!("Created organisation #{org_id}: {}", created_org.name);

    // List organisations.
    let orgs = client.organisations(None, None).await?;
    println!("Total organisations: {}", orgs.len());

    // Fetch the organisation back.
    let fetched_org = client.get_organisation(org_id).await?;
    println!(
        "Fetched org #{}: {} ({})",
        org_id,
        fetched_org.name,
        fetched_org.sector.as_deref().unwrap_or("no sector"),
    );

    // --- Role listing ---

    let roles = client.roles().await?;
    println!("Available roles ({}):", roles.len());
    for role in &roles {
        println!(
            "  #{}: {} (admin={}, sync={})",
            role.id.unwrap_or(0),
            role.name,
            role.perm_admin,
            role.perm_sync,
        );
    }

    // Pick the first non-admin role for the test user.
    let user_role = roles
        .iter()
        .find(|r| !r.perm_admin && !r.perm_site_admin && r.perm_auth)
        .expect("need at least one non-admin role with API access");
    let role_id = user_role.id.expect("role should have an id");

    // --- User management ---

    // Create a test user in the new organisation.
    let mut user = MispUser::new("rustmisp-example@example.com");
    user.org_id = Some(org_id);
    user.role_id = Some(role_id);
    user.password = Some("ChangeMe!234".into());
    user.change_pw = Some(true);

    let created_user = client.add_user(&user).await?;
    let user_id = created_user.id.expect("server should assign an id");
    println!(
        "Created user #{user_id}: {} (role: {})",
        created_user.email, user_role.name,
    );

    // List users.
    let users = client.users(None, None).await?;
    println!("Total users: {}", users.len());

    // Fetch the user back.
    let fetched_user = client.get_user(user_id).await?;
    println!(
        "Fetched user #{}: {} (org_id={})",
        user_id,
        fetched_user.email,
        fetched_user.org_id.unwrap_or(0),
    );

    // Update the user.
    let mut updated = fetched_user.clone();
    updated.contactalert = true;
    let updated_user = client.update_user(&updated).await?;
    println!(
        "Updated user #{}: contactalert={}",
        user_id, updated_user.contactalert,
    );

    // Reset the user's auth key.
    let new_key = client.get_new_authkey(user_id).await?;
    println!("Reset auth key for user #{user_id}: {}...", &new_key[..8]);

    // --- Clean up ---

    client.delete_user(user_id).await?;
    println!("Deleted user #{user_id}");

    client.delete_organisation(org_id).await?;
    println!("Deleted organisation #{org_id}");

    Ok(())
}
