//! Basic two-agent communication example.
//!
//! Demonstrates the simplest Moat interaction: two agents exchange signed
//! messages through a relay, each authorized by scoped capability tokens.
//! The PEP verifies signatures, policy bindings, and capabilities on every hop.

use chrono::{Duration, Utc};
use moat_core::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, PolicyBinding, ResourceLimits, ScopeEntry,
};
use moat_relay::MessageRouter;
use moat_runtime::MonitorThresholds;

fn main() {
    println!("=== Moat Ping-Pong Example ===\n");

    // Shared policy binding — both agents must reference the same policy
    let policy = PolicyBinding::new("ping-pong-v1", b"ping pong policy");

    // Create the relay with default monitor thresholds
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    // --- Create two agents ---
    let alice = AgentKeypair::generate("alice").unwrap();
    let bob = AgentKeypair::generate("bob").unwrap();

    println!("Alice: {}", alice.id());
    println!("Bob:   {}", bob.id());

    // Register both agents and trust Alice as a root issuer
    for agent in [&alice, &bob] {
        router.registry.register(agent.identity.clone()).unwrap();
        router.pep.register_identity(agent.identity.clone());
    }
    router.pep.add_trusted_root(alice.id());

    // --- Alice creates tokens ---

    // Alice's own root token
    let mut alice_token =
        CapabilityToken::root(alice.id(), alice.id(), Utc::now() + Duration::hours(1));
    alice_token.allowed = vec![ScopeEntry {
        resource: "channel://ping-pong".into(),
        actions: vec!["send".into(), "receive".into()],
    }];
    alice_token.sign(&alice);

    // Bob gets an attenuated token — send-only, less fuel
    let mut bob_token = alice_token
        .attenuate(
            bob.id(),
            vec![ScopeEntry {
                resource: "channel://ping-pong".into(),
                actions: vec!["send".into()],
            }],
            vec![],
            ResourceLimits {
                max_fuel: Some(500_000),
                max_memory_bytes: Some(16 * 1024 * 1024),
                ..Default::default()
            },
            5,
        )
        .unwrap();
    bob_token.sign(&alice);

    println!("\nTokens issued:");
    println!("  Alice: send + receive on channel://ping-pong");
    println!("  Bob:   send only on channel://ping-pong");

    // --- Ping: Alice sends to Bob ---
    println!("\n--- Ping ---");
    let ping = AuthenticatedMessage::create(
        &alice,
        bob.id(),
        b"ping".to_vec(),
        alice_token.clone(),
        vec![],
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router.route(&ping, "channel://ping-pong", "send").unwrap();
    println!(
        "Alice -> Bob (send): {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // --- Pong: Bob replies ---
    println!("\n--- Pong ---");
    let pong = AuthenticatedMessage::create(
        &bob,
        alice.id(),
        b"pong".to_vec(),
        bob_token.clone(),
        vec![alice_token.clone()],
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router.route(&pong, "channel://ping-pong", "send").unwrap();
    println!(
        "Bob -> Alice (send): {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // --- Bob tries to receive (not in his token scope) ---
    println!("\n--- Scope enforcement ---");
    let bad_msg = AuthenticatedMessage::create(
        &bob,
        alice.id(),
        b"trying to receive".to_vec(),
        bob_token.clone(),
        vec![alice_token.clone()],
        policy.clone(),
        2,
    )
    .unwrap();

    let result = router
        .route(&bad_msg, "channel://ping-pong", "receive")
        .unwrap();
    println!(
        "Bob tries receive: {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // --- Audit trail ---
    println!("\n--- Audit log ({} entries) ---", router.audit_log.len());
    assert!(router.audit_log.verify_integrity().is_ok());
    println!("Integrity: verified");

    println!("\nDone.");
}
