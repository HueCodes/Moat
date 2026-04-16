//! Secret proxy example.
//!
//! Demonstrates Moat's handle-based secret management:
//!
//! 1. Operator stores secrets in the proxy with per-agent ACLs
//! 2. Authorized agents resolve handles to HTTP header injections
//! 3. Unauthorized agents are denied — they never see the raw value
//! 4. Access can be revoked at any time
//! 5. Secrets can be removed entirely

use moat_core::AgentKeypair;
use moat_runtime::SecretProxy;

fn main() {
    println!("=== Moat Secret Injection Example ===\n");

    // Create agents
    let api_agent = AgentKeypair::generate("api-agent").unwrap();
    let untrusted = AgentKeypair::generate("untrusted").unwrap();

    println!("API agent:  {}", api_agent.id());
    println!("Untrusted:  {}", untrusted.id());

    // --- Operator stores secrets ---
    let mut proxy = SecretProxy::new();

    // Only api_agent can access this secret
    let api_key_handle = proxy.store(
        "openai_api_key",
        "sk-proj-abc123secret",
        vec![api_agent.id()],
    );
    println!("\nStored secret 'openai_api_key' (ACL: api-agent only)");

    // Both agents can access this one
    let public_key_handle = proxy.store(
        "public_api_key",
        "pk-public-xyz",
        vec![api_agent.id(), untrusted.id()],
    );
    println!("Stored secret 'public_api_key' (ACL: both agents)");

    // --- Authorized resolution ---
    println!("\n--- Resolution attempts ---\n");

    // api_agent resolves the API key into an Authorization header
    let injection = proxy
        .resolve_for_header(&api_key_handle, api_agent.id(), "Authorization")
        .unwrap();
    println!(
        "api-agent resolves openai_api_key -> {}: {}",
        injection.header_name,
        // In production the runtime injects this directly into the HTTP request.
        // The agent never sees this value — we print it here only for demonstration.
        injection.secret_value,
    );

    // untrusted agent tries to resolve the same secret — denied
    let result = proxy.resolve_for_header(&api_key_handle, untrusted.id(), "Authorization");
    println!(
        "untrusted resolves openai_api_key -> {}",
        match &result {
            Ok(_) => "ALLOWED (unexpected!)".to_string(),
            Err(e) => format!("DENIED: {e}"),
        }
    );
    assert!(result.is_err());

    // Both can resolve the public key
    let pub_a = proxy
        .resolve_for_header(&public_key_handle, api_agent.id(), "X-Api-Key")
        .unwrap();
    let pub_b = proxy
        .resolve_for_header(&public_key_handle, untrusted.id(), "X-Api-Key")
        .unwrap();
    println!(
        "api-agent resolves public_api_key  -> {}: {}",
        pub_a.header_name, pub_a.secret_value
    );
    println!(
        "untrusted resolves public_api_key  -> {}: {}",
        pub_b.header_name, pub_b.secret_value
    );

    // --- Revocation ---
    println!("\n--- Revocation ---\n");

    proxy.revoke(&public_key_handle, untrusted.id());
    println!("Revoked untrusted's access to public_api_key");

    let result = proxy.resolve_for_header(&public_key_handle, untrusted.id(), "X-Api-Key");
    println!(
        "untrusted resolves public_api_key  -> {}",
        match &result {
            Ok(_) => "ALLOWED (unexpected!)".to_string(),
            Err(e) => format!("DENIED: {e}"),
        }
    );
    assert!(result.is_err());

    // api_agent still has access
    let still_ok = proxy
        .resolve_for_header(&public_key_handle, api_agent.id(), "X-Api-Key")
        .unwrap();
    println!(
        "api-agent resolves public_api_key  -> {}: {} (still works)",
        still_ok.header_name, still_ok.secret_value
    );

    // --- Removal ---
    println!("\n--- Secret removal ---\n");

    proxy.remove(&api_key_handle);
    println!("Removed openai_api_key entirely");

    let result = proxy.resolve_for_header(&api_key_handle, api_agent.id(), "Authorization");
    println!(
        "api-agent resolves openai_api_key  -> {}",
        match &result {
            Ok(_) => "ALLOWED (unexpected!)".to_string(),
            Err(e) => format!("DENIED: {e}"),
        }
    );
    assert!(result.is_err());

    println!("\nDone. Secrets were never exposed to unauthorized agents.");
}
