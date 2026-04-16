//! Multi-agent orchestration example.
//!
//! Demonstrates a coordinator agent that delegates sub-tasks to three workers,
//! each with an attenuated capability token:
//!
//! - **reviewer**: can read code_review tool only
//! - **tester**: can execute test tool only
//! - **deployer**: can execute deploy tool only
//!
//! Shows:
//! 1. Coordinator creates workers with signed, attenuated tokens
//! 2. Workers execute within their scoped permissions
//! 3. A worker trying to exceed its token scope is blocked by the PEP
//! 4. Audit log captures the full pipeline
//! 5. Monitor tracks all actions

use chrono::{Duration, Utc};
use moat_core::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, PolicyBinding, ResourceLimits, ScopeEntry,
};
use moat_relay::MessageRouter;
use moat_runtime::MonitorThresholds;

fn main() {
    println!("=== Moat Orchestrated Pipeline Example ===\n");

    let policy = PolicyBinding::new("pipeline-v1", b"pipeline policy document");
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    // --- Create agents ---
    let coordinator = AgentKeypair::generate("coordinator").unwrap();
    let reviewer = AgentKeypair::generate("reviewer").unwrap();
    let tester = AgentKeypair::generate("tester").unwrap();
    let deployer = AgentKeypair::generate("deployer").unwrap();

    // Register all agents
    for agent in [&coordinator, &reviewer, &tester, &deployer] {
        router.registry.register(agent.identity.clone()).unwrap();
        router.pep.register_identity(agent.identity.clone());
    }
    router.pep.add_trusted_root(coordinator.id());

    println!("Agents registered:");
    println!("  coordinator: {}", coordinator.id());
    println!("  reviewer:    {}", reviewer.id());
    println!("  tester:      {}", tester.id());
    println!("  deployer:    {}", deployer.id());

    // --- Coordinator creates root token ---
    let mut coord_token = CapabilityToken::root(
        coordinator.id(),
        coordinator.id(),
        Utc::now() + Duration::hours(1),
    );
    coord_token.allowed = vec![
        ScopeEntry {
            resource: "tool://code_review".into(),
            actions: vec!["read".into(), "execute".into()],
        },
        ScopeEntry {
            resource: "tool://test".into(),
            actions: vec!["execute".into()],
        },
        ScopeEntry {
            resource: "tool://deploy".into(),
            actions: vec!["execute".into()],
        },
    ];
    coord_token.resource_limits = ResourceLimits {
        max_fuel: Some(10_000_000),
        max_memory_bytes: Some(128 * 1024 * 1024),
        ..Default::default()
    };
    coord_token.sign(&coordinator);

    println!("\nCoordinator root token: {}", coord_token.token_id);

    // --- Attenuate tokens for each worker ---

    // Reviewer: read-only access to code_review
    let mut reviewer_token = coord_token
        .attenuate(
            reviewer.id(),
            vec![ScopeEntry {
                resource: "tool://code_review".into(),
                actions: vec!["read".into()],
            }],
            vec![],
            ResourceLimits {
                max_fuel: Some(1_000_000),
                max_memory_bytes: Some(32 * 1024 * 1024),
                ..Default::default()
            },
            10,
        )
        .unwrap();
    reviewer_token.sign(&coordinator);
    println!(
        "Reviewer token:  {} (depth {})",
        reviewer_token.token_id, reviewer_token.delegation_depth
    );

    // Tester: execute-only on test tool
    let mut tester_token = coord_token
        .attenuate(
            tester.id(),
            vec![ScopeEntry {
                resource: "tool://test".into(),
                actions: vec!["execute".into()],
            }],
            vec![],
            ResourceLimits {
                max_fuel: Some(5_000_000),
                max_memory_bytes: Some(64 * 1024 * 1024),
                ..Default::default()
            },
            10,
        )
        .unwrap();
    tester_token.sign(&coordinator);
    println!(
        "Tester token:    {} (depth {})",
        tester_token.token_id, tester_token.delegation_depth
    );

    // Deployer: execute-only on deploy tool
    let mut deployer_token = coord_token
        .attenuate(
            deployer.id(),
            vec![ScopeEntry {
                resource: "tool://deploy".into(),
                actions: vec!["execute".into()],
            }],
            vec![],
            ResourceLimits {
                max_fuel: Some(2_000_000),
                max_memory_bytes: Some(32 * 1024 * 1024),
                ..Default::default()
            },
            10,
        )
        .unwrap();
    deployer_token.sign(&coordinator);
    println!(
        "Deployer token:  {} (depth {})",
        deployer_token.token_id, deployer_token.delegation_depth
    );

    // --- Execute the pipeline ---
    println!("\n--- Pipeline execution ---\n");

    // Step 1: Reviewer reads code review results
    let review_msg = AuthenticatedMessage::create(
        &reviewer,
        coordinator.id(),
        b"review: 2 issues found, 1 critical".to_vec(),
        reviewer_token.clone(),
        vec![coord_token.clone()],
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router
        .route(&review_msg, "tool://code_review", "read")
        .unwrap();
    println!(
        "Step 1 - Reviewer reads code_review: {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // Step 2: Tester runs tests
    let test_msg = AuthenticatedMessage::create(
        &tester,
        coordinator.id(),
        b"tests: 42 passed, 0 failed".to_vec(),
        tester_token.clone(),
        vec![coord_token.clone()],
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router.route(&test_msg, "tool://test", "execute").unwrap();
    println!(
        "Step 2 - Tester executes tests:      {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // Step 3: Deployer deploys
    let deploy_msg = AuthenticatedMessage::create(
        &deployer,
        coordinator.id(),
        b"deployed to staging".to_vec(),
        deployer_token.clone(),
        vec![coord_token.clone()],
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router
        .route(&deploy_msg, "tool://deploy", "execute")
        .unwrap();
    println!(
        "Step 3 - Deployer executes deploy:   {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(result.allowed);

    // --- Demonstrate scope enforcement ---
    println!("\n--- Scope enforcement ---\n");

    // Reviewer tries to execute (not in its scope)
    let bad_review_msg = AuthenticatedMessage::create(
        &reviewer,
        coordinator.id(),
        b"trying to execute".to_vec(),
        reviewer_token.clone(),
        vec![coord_token.clone()],
        policy.clone(),
        2,
    )
    .unwrap();

    let result = router
        .route(&bad_review_msg, "tool://code_review", "execute")
        .unwrap();
    println!(
        "Reviewer tries execute on code_review: {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // Tester tries to deploy (not in its scope)
    let bad_test_msg = AuthenticatedMessage::create(
        &tester,
        coordinator.id(),
        b"trying to deploy".to_vec(),
        tester_token.clone(),
        vec![coord_token.clone()],
        policy.clone(),
        2,
    )
    .unwrap();

    let result = router
        .route(&bad_test_msg, "tool://deploy", "execute")
        .unwrap();
    println!(
        "Tester tries execute on deploy:        {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // Deployer tries to read code_review (not in its scope)
    let bad_deploy_msg = AuthenticatedMessage::create(
        &deployer,
        coordinator.id(),
        b"trying to read reviews".to_vec(),
        deployer_token,
        vec![coord_token.clone()],
        policy.clone(),
        2,
    )
    .unwrap();

    let result = router
        .route(&bad_deploy_msg, "tool://code_review", "read")
        .unwrap();
    println!(
        "Deployer tries read on code_review:    {}",
        if result.allowed { "ALLOWED" } else { "DENIED" }
    );
    assert!(!result.allowed);

    // --- Audit summary ---
    println!("\n--- Audit log ---\n");
    assert!(router.audit_log.verify_integrity().is_ok());
    println!(
        "Total audit entries: {} (integrity verified)",
        router.audit_log.len()
    );

    for entry in router.audit_log.entries() {
        if let moat_runtime::AuditEventKind::PepDecision {
            sender_id,
            resource,
            action,
            allowed,
            reason,
            ..
        } = &entry.event
        {
            let agent_name = if *sender_id == reviewer.id() {
                "reviewer"
            } else if *sender_id == tester.id() {
                "tester"
            } else if *sender_id == deployer.id() {
                "deployer"
            } else {
                "unknown"
            };
            println!(
                "  [{}] {} {} on {} {}",
                entry.index,
                agent_name,
                action,
                resource,
                if *allowed {
                    "-> ALLOWED".to_string()
                } else {
                    format!("-> DENIED ({})", reason.as_deref().unwrap_or("unknown"))
                }
            );
        }
    }

    println!("\nPipeline complete. All scope enforcement working correctly.");
}
