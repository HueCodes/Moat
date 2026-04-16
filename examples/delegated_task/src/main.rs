//! Delegated task example.
//!
//! Demonstrates multi-level capability delegation:
//!
//! 1. A manager creates a broad token
//! 2. The manager delegates a narrower token to a team lead
//! 3. The team lead further delegates an even narrower token to a worker
//! 4. Each delegation monotonically attenuates scope and resource limits
//! 5. Attempts to escalate privileges at any level are rejected

use chrono::{Duration, Utc};
use moat_core::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, PolicyBinding, ResourceLimits, ScopeEntry,
};
use moat_relay::MessageRouter;
use moat_runtime::MonitorThresholds;

fn main() {
    println!("=== Moat Delegated Task Example ===\n");

    let policy = PolicyBinding::new("delegation-v1", b"delegation policy");
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    // --- Three-level hierarchy ---
    let manager = AgentKeypair::generate("manager").unwrap();
    let lead = AgentKeypair::generate("team-lead").unwrap();
    let worker = AgentKeypair::generate("worker").unwrap();

    for agent in [&manager, &lead, &worker] {
        router.registry.register(agent.identity.clone()).unwrap();
        router.pep.register_identity(agent.identity.clone());
    }
    router.pep.add_trusted_root(manager.id());

    println!("Hierarchy:");
    println!("  Manager:   {}", manager.id());
    println!("  Team Lead: {}", lead.id());
    println!("  Worker:    {}", worker.id());

    // --- Level 0: Manager's root token ---
    let mut manager_token =
        CapabilityToken::root(manager.id(), manager.id(), Utc::now() + Duration::hours(8));
    manager_token.allowed = vec![
        ScopeEntry {
            resource: "db://users".into(),
            actions: vec!["read".into(), "write".into(), "delete".into()],
        },
        ScopeEntry {
            resource: "db://analytics".into(),
            actions: vec!["read".into(), "write".into()],
        },
        ScopeEntry {
            resource: "api://billing".into(),
            actions: vec!["read".into(), "execute".into()],
        },
    ];
    manager_token.resource_limits = ResourceLimits {
        max_fuel: Some(50_000_000),
        max_memory_bytes: Some(512 * 1024 * 1024),
        ..Default::default()
    };
    manager_token.sign(&manager);
    println!("\nManager token: full access to db://users, db://analytics, api://billing");

    // --- Level 1: Delegate to team lead (no delete, no billing) ---
    let mut lead_token = manager_token
        .attenuate(
            lead.id(),
            vec![
                ScopeEntry {
                    resource: "db://users".into(),
                    actions: vec!["read".into(), "write".into()], // no delete
                },
                ScopeEntry {
                    resource: "db://analytics".into(),
                    actions: vec!["read".into()], // read-only
                },
                // api://billing not included — dropped entirely
            ],
            vec![],
            ResourceLimits {
                max_fuel: Some(10_000_000),
                max_memory_bytes: Some(128 * 1024 * 1024),
                ..Default::default()
            },
            5,
        )
        .unwrap();
    lead_token.sign(&manager);
    println!(
        "Lead token:    db://users (read+write), db://analytics (read) — depth {}",
        lead_token.delegation_depth
    );

    // --- Level 2: Lead delegates to worker (read-only on users) ---
    let mut worker_token = lead_token
        .attenuate(
            worker.id(),
            vec![ScopeEntry {
                resource: "db://users".into(),
                actions: vec!["read".into()], // read-only
            }],
            vec![],
            ResourceLimits {
                max_fuel: Some(1_000_000),
                max_memory_bytes: Some(32 * 1024 * 1024),
                ..Default::default()
            },
            5,
        )
        .unwrap();
    worker_token.sign(&lead);
    println!(
        "Worker token:  db://users (read) — depth {}",
        worker_token.delegation_depth
    );

    // --- Worker performs authorized action ---
    println!("\n--- Authorized actions ---\n");

    let msg = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"user lookup result".to_vec(),
        worker_token.clone(),
        vec![manager_token.clone(), lead_token.clone()],
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router.route(&msg, "db://users", "read").unwrap();
    println!(
        "Worker reads db://users: {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // --- Worker tries to write (not in its token) ---
    println!("\n--- Privilege escalation attempts ---\n");

    let msg2 = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"trying to write".to_vec(),
        worker_token.clone(),
        vec![manager_token.clone(), lead_token.clone()],
        policy.clone(),
        2,
    )
    .unwrap();

    let result = router.route(&msg2, "db://users", "write").unwrap();
    println!(
        "Worker writes db://users:      {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // Worker tries to access analytics (not in its token)
    let msg3 = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"trying analytics".to_vec(),
        worker_token.clone(),
        vec![manager_token.clone(), lead_token.clone()],
        policy.clone(),
        3,
    )
    .unwrap();

    let result = router.route(&msg3, "db://analytics", "read").unwrap();
    println!(
        "Worker reads db://analytics:   {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // Worker tries billing (removed two levels up)
    let msg4 = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"trying billing".to_vec(),
        worker_token.clone(),
        vec![manager_token.clone(), lead_token.clone()],
        policy.clone(),
        4,
    )
    .unwrap();

    let result = router.route(&msg4, "api://billing", "execute").unwrap();
    println!(
        "Worker executes api://billing:  {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // --- Demonstrate attenuation violation ---
    println!("\n--- Attenuation violation ---\n");

    // Lead tries to create a token broader than their own
    let escalation = lead_token.attenuate(
        worker.id(),
        vec![ScopeEntry {
            resource: "db://users".into(),
            actions: vec!["read".into(), "write".into(), "delete".into()], // delete not in lead's token
        }],
        vec![],
        ResourceLimits::default(),
        5,
    );
    println!(
        "Lead tries to grant delete to worker: {}",
        match &escalation {
            Ok(_) => "ALLOWED (unexpected!)".to_string(),
            Err(e) => format!("REJECTED: {e}"),
        }
    );
    assert!(escalation.is_err());

    // --- Audit ---
    println!("\n--- Audit log ({} entries) ---", router.audit_log.len());
    assert!(router.audit_log.verify_integrity().is_ok());
    println!("Integrity: verified");

    println!("\nDone. Capability attenuation enforced across three delegation levels.");
}
