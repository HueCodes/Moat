//! Basic two-agent communication example — uses the high-level `moat::Moat` facade.
//!
//! Alice grants Bob a send-only token. Bob's "ping" goes through. Bob's attempt
//! to `receive` is rejected at stage 3 because his attenuated token doesn't
//! carry that action.

use chrono::{Duration, Utc};
use moat_protocol::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, Moat, PolicyBinding, ResourceLimits,
    ScopeEntry,
};

fn main() {
    println!("=== Moat Ping-Pong Example ===\n");

    let alice = AgentKeypair::generate("alice").unwrap();
    let bob = AgentKeypair::generate("bob").unwrap();

    println!("Alice: {}", alice.id());
    println!("Bob:   {}", bob.id());

    // Build the whole runtime — registry, PEP, audit log, monitor — in one chain.
    let policy = PolicyBinding::new("ping-pong-v1", b"ping pong policy");
    let mut moat = Moat::builder()
        .policy(policy.clone())
        .agent(alice.identity.clone())
        .agent(bob.identity.clone())
        .trust_root(alice.id())
        .build()
        .unwrap();

    // Alice's self-issued root token: full send + receive on the channel.
    let mut alice_token =
        CapabilityToken::root(alice.id(), alice.id(), Utc::now() + Duration::hours(1));
    alice_token.allowed = vec![ScopeEntry {
        resource: "channel://ping-pong".into(),
        actions: vec!["send".into(), "receive".into()],
    }];
    alice_token.sign(&alice);

    // Attenuate for Bob: send only, less fuel.
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

    // --- Ping ---
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
    let result = moat.route(&ping, "channel://ping-pong", "send").unwrap();
    println!(
        "Alice -> Bob (send): {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // --- Pong ---
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
    let result = moat.route(&pong, "channel://ping-pong", "send").unwrap();
    println!(
        "Bob -> Alice (send): {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // --- Bob tries to receive (outside his scope) ---
    println!("\n--- Scope enforcement ---");
    let bad_msg = AuthenticatedMessage::create(
        &bob,
        alice.id(),
        b"trying to receive".to_vec(),
        bob_token,
        vec![alice_token],
        policy,
        2,
    )
    .unwrap();
    let result = moat
        .route(&bad_msg, "channel://ping-pong", "receive")
        .unwrap();
    println!(
        "Bob tries receive: {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // --- Audit trail ---
    println!("\n--- Audit log ({} entries) ---", moat.audit_log().len());
    assert!(moat.audit_log().verify_integrity().is_ok());
    println!("Integrity: verified");

    println!("\nDone.");
}
