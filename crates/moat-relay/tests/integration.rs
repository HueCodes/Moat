//! End-to-end integration test: two agents communicate through the full
//! Moat stack with PEP verification, capability attenuation, audit logging,
//! secret proxy, and runtime monitoring.

use chrono::{Duration, Utc};
use moat_core::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, PolicyBinding, ResourceLimits, ScopeEntry,
};
use moat_relay::MessageRouter;
use moat_runtime::{AuditEventKind, MonitorThresholds, SecretProxy};
use uuid::Uuid;

fn make_policy() -> PolicyBinding {
    PolicyBinding::new("integration-test-v1", b"integration test policy document")
}

/// Full end-to-end: register agents, exchange messages, verify PEP, check audit.
#[test]
fn two_agents_communicate_through_pep() {
    let policy = make_policy();
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    // Create two agents
    let agent_a = AgentKeypair::generate("agent-alpha").unwrap();
    let agent_b = AgentKeypair::generate("agent-beta").unwrap();

    // Register both
    router
        .registry
        .register(agent_a.identity.clone())
        .unwrap();
    router
        .registry
        .register(agent_b.identity.clone())
        .unwrap();
    router.pep.register_identity(agent_a.identity.clone());
    router.pep.register_identity(agent_b.identity.clone());

    // Agent A creates a capability token granting tool access
    let mut cap_a = CapabilityToken::root(
        agent_a.id(),
        agent_a.id(),
        Utc::now() + Duration::hours(1),
    );
    cap_a.allowed = vec![ScopeEntry {
        resource: "tool://*".into(),
        actions: vec!["execute".into(), "read".into()],
    }];
    cap_a.resource_limits = ResourceLimits {
        max_fuel: Some(1_000_000),
        max_memory_bytes: Some(64 * 1024 * 1024),
        network_allowed: false,
        ..Default::default()
    };

    // Agent A sends a message to Agent B
    let msg_1 = AuthenticatedMessage::create(
        &agent_a,
        agent_b.id(),
        b"please review this code".to_vec(),
        cap_a.clone(),
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router.route(&msg_1, "tool://code_review", "execute").unwrap();
    assert!(result.allowed, "valid message should be allowed");

    // Agent B responds
    let mut cap_b = CapabilityToken::root(
        agent_b.id(),
        agent_b.id(),
        Utc::now() + Duration::hours(1),
    );
    cap_b.allowed = vec![ScopeEntry {
        resource: "tool://*".into(),
        actions: vec!["execute".into()],
    }];
    cap_b.resource_limits = ResourceLimits::default();

    let msg_2 = AuthenticatedMessage::create(
        &agent_b,
        agent_a.id(),
        b"review complete, 3 issues found".to_vec(),
        cap_b,
        policy.clone(),
        1,
    )
    .unwrap();

    let result = router.route(&msg_2, "tool://report", "execute").unwrap();
    assert!(result.allowed, "response should be allowed");

    // Verify audit log integrity
    assert!(router.audit_log.verify_integrity().is_ok());
    assert_eq!(router.audit_log.len(), 2);

    // Verify audit contains correct entries
    let entries = router.audit_log.entries();
    match &entries[0].event {
        AuditEventKind::PepDecision {
            sender_id, allowed, ..
        } => {
            assert_eq!(*sender_id, agent_a.id());
            assert!(*allowed);
        }
        _ => panic!("expected PepDecision"),
    }
}

/// Invalid signatures are rejected at stage 1.
#[test]
fn invalid_signature_rejected() {
    let policy = make_policy();
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    let agent_a = AgentKeypair::generate("agent-alpha").unwrap();
    let agent_b = AgentKeypair::generate("agent-beta").unwrap();

    router.pep.register_identity(agent_a.identity.clone());
    router.pep.register_identity(agent_b.identity.clone());

    let mut cap = CapabilityToken::root(
        agent_a.id(),
        agent_a.id(),
        Utc::now() + Duration::hours(1),
    );
    cap.allowed = vec![ScopeEntry {
        resource: "tool://*".into(),
        actions: vec!["execute".into()],
    }];

    let mut msg = AuthenticatedMessage::create(
        &agent_a,
        agent_b.id(),
        b"hello".to_vec(),
        cap,
        policy.clone(),
        1,
    )
    .unwrap();

    // Tamper with payload after signing
    msg.payload = b"tampered payload".to_vec();

    let result = router.route(&msg, "tool://test", "execute").unwrap();
    assert!(!result.allowed, "tampered message must be rejected");

    // Audit records the rejection
    assert!(router.audit_log.verify_integrity().is_ok());
    match &router.audit_log.entries()[0].event {
        AuditEventKind::PepDecision { allowed, .. } => assert!(!allowed),
        _ => panic!("expected PepDecision"),
    }
}

/// Capability attenuation: delegated agent cannot exceed parent's permissions.
#[test]
fn capability_attenuation_enforced() {
    let policy = make_policy();
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    let manager = AgentKeypair::generate("manager").unwrap();
    let worker = AgentKeypair::generate("worker").unwrap();

    router.pep.register_identity(manager.identity.clone());
    router.pep.register_identity(worker.identity.clone());

    // Manager has broad tool access
    let mut manager_cap = CapabilityToken::root(
        manager.id(),
        manager.id(),
        Utc::now() + Duration::hours(1),
    );
    manager_cap.allowed = vec![ScopeEntry {
        resource: "tool://*".into(),
        actions: vec!["execute".into(), "read".into(), "write".into()],
    }];
    manager_cap.resource_limits = ResourceLimits {
        max_fuel: Some(1_000_000),
        max_memory_bytes: Some(64 * 1024 * 1024),
        network_allowed: true,
        allowed_hosts: vec!["api.example.com".into()],
        ..Default::default()
    };

    // Manager delegates to worker with restricted scope (read-only, one tool)
    let worker_cap = manager_cap
        .attenuate(
            worker.id(),
            vec![ScopeEntry {
                resource: "tool://code_review".into(),
                actions: vec!["read".into()],
            }],
            vec![],
            ResourceLimits {
                max_fuel: Some(500_000),
                max_memory_bytes: Some(32 * 1024 * 1024),
                ..Default::default()
            },
            10,
        )
        .unwrap();

    // Worker can read code_review
    let msg_ok = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"reading review".to_vec(),
        worker_cap.clone(),
        policy.clone(),
        1,
    )
    .unwrap();
    let result = router
        .route(&msg_ok, "tool://code_review", "read")
        .unwrap();
    assert!(result.allowed, "worker should be able to read code_review");

    // Worker cannot execute (not in attenuated scope)
    let msg_deny = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"trying to execute".to_vec(),
        worker_cap.clone(),
        policy.clone(),
        2,
    )
    .unwrap();
    let result = router
        .route(&msg_deny, "tool://code_review", "execute")
        .unwrap();
    assert!(
        !result.allowed,
        "worker should not be able to execute code_review"
    );

    // Worker cannot access tools outside scope
    let msg_deny2 = AuthenticatedMessage::create(
        &worker,
        manager.id(),
        b"trying other tool".to_vec(),
        worker_cap,
        policy.clone(),
        3,
    )
    .unwrap();
    let result = router
        .route(&msg_deny2, "tool://deploy", "read")
        .unwrap();
    assert!(
        !result.allowed,
        "worker should not access tools outside scope"
    );

    // Worker cannot broaden to get write access
    let broaden_result = manager_cap.attenuate(
        worker.id(),
        vec![ScopeEntry {
            resource: "file://*".into(), // not in parent scope
            actions: vec!["write".into()],
        }],
        vec![],
        ResourceLimits::default(),
        10,
    );
    assert!(
        broaden_result.is_err(),
        "attenuation must not broaden scope"
    );

    assert!(router.audit_log.verify_integrity().is_ok());
}

/// Secret proxy: agents get handles, not raw values.
#[test]
fn secret_proxy_handle_resolution() {
    let agent_a = AgentKeypair::generate("agent-a").unwrap();
    let agent_b = AgentKeypair::generate("agent-b").unwrap();

    let mut proxy = SecretProxy::new();

    // Store an API key accessible only to agent_a
    let handle = proxy.store("openai_key", "sk-secret-12345", vec![agent_a.id()]);

    // Agent A can resolve
    let injection = proxy
        .resolve_for_header(&handle, agent_a.id(), "Authorization")
        .unwrap();
    assert_eq!(injection.header_name, "Authorization");
    assert_eq!(injection.secret_value, "sk-secret-12345");

    // Agent B cannot resolve
    let result = proxy.resolve_for_header(&handle, agent_b.id(), "Authorization");
    assert!(result.is_err());

    // After revocation, agent A also cannot resolve
    proxy.revoke(&handle, agent_a.id());
    let result = proxy.resolve_for_header(&handle, agent_a.id(), "Authorization");
    assert!(result.is_err());
}

/// Runtime monitor detects when thresholds are crossed.
#[test]
fn monitor_alerts_on_excessive_actions() {
    let policy = make_policy();
    let mut router = MessageRouter::new(
        policy.clone(),
        MonitorThresholds {
            max_actions: 3,
            max_actions_per_type: 100,
            max_unique_resources: 100,
            max_cumulative_cost: 1000.0,
        },
    );

    let agent = AgentKeypair::generate("busy-agent").unwrap();
    router.pep.register_identity(agent.identity.clone());

    let mut cap = CapabilityToken::root(
        agent.id(),
        agent.id(),
        Utc::now() + Duration::hours(1),
    );
    cap.allowed = vec![ScopeEntry {
        resource: "tool://*".into(),
        actions: vec!["execute".into()],
    }];
    cap.resource_limits = ResourceLimits::default();

    // Send 3 messages (the 3rd should trigger an alert)
    for seq in 1..=3 {
        let msg = AuthenticatedMessage::create(
            &agent,
            Uuid::new_v4(),
            format!("action {}", seq).into_bytes(),
            cap.clone(),
            policy.clone(),
            seq,
        )
        .unwrap();
        let result = router
            .route(&msg, &format!("tool://task_{}", seq), "execute")
            .unwrap();
        assert!(result.allowed);

        if seq == 3 {
            assert_eq!(result.alerts.len(), 1);
            assert_eq!(result.alerts[0].alert_type, "max_actions_reached");
        }
    }

    // Audit log has PEP decisions + monitor alert
    assert!(router.audit_log.verify_integrity().is_ok());
    // 3 PEP decisions + 1 monitor alert = 4 entries
    assert_eq!(router.audit_log.len(), 4);
}

/// Replay protection: reusing a sequence number is detected.
#[test]
fn replay_protection() {
    let policy = make_policy();
    let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

    let agent = AgentKeypair::generate("replayer").unwrap();
    router.pep.register_identity(agent.identity.clone());

    let mut cap = CapabilityToken::root(
        agent.id(),
        agent.id(),
        Utc::now() + Duration::hours(1),
    );
    cap.allowed = vec![ScopeEntry {
        resource: "tool://*".into(),
        actions: vec!["execute".into()],
    }];

    // First message with seq=1 succeeds
    let msg1 = AuthenticatedMessage::create(
        &agent,
        Uuid::new_v4(),
        b"first".to_vec(),
        cap.clone(),
        policy.clone(),
        1,
    )
    .unwrap();
    let r1 = router.route(&msg1, "tool://test", "execute").unwrap();
    assert!(r1.allowed);

    // Replay with same seq=1 fails
    let msg2 = AuthenticatedMessage::create(
        &agent,
        Uuid::new_v4(),
        b"replay".to_vec(),
        cap,
        policy.clone(),
        1,
    )
    .unwrap();
    let r2 = router.route(&msg2, "tool://test", "execute").unwrap();
    assert!(!r2.allowed, "replayed sequence number must be rejected");
}
