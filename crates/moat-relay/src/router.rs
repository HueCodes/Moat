//! Message router: routes authenticated messages through the PEP.
//!
//! The router receives messages, validates them through the PEP, records
//! the decision in the audit log, and tracks actions via the monitor.
//!
//! Additional hardening:
//! - Recipient existence check (message must target a registered agent)
//! - Rate limiting (per-sender message volume cap within a time window)
//! - Message size limits (reject oversized payloads)
//! - Timestamp expiry (reject messages older than a configurable window)

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use moat_core::{AuthenticatedMessage, MoatError, PolicyBinding};
use moat_runtime::{
    AuditEventKind, AuditLog, MonitorThresholds, PolicyEnforcementPoint, RuntimeMonitor,
};

use crate::registry::AgentRegistry;

/// Configuration for router hardening limits.
#[derive(Debug, Clone)]
pub struct RouterLimits {
    /// Maximum payload size in bytes. None = no limit.
    pub max_payload_bytes: Option<usize>,
    /// Maximum message age before rejection. None = no expiry check.
    pub max_message_age: Option<Duration>,
    /// Maximum messages per sender within the rate window. None = no rate limit.
    pub rate_limit_max: Option<u64>,
    /// The time window for rate limiting.
    pub rate_limit_window: Duration,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: Some(1024 * 1024), // 1 MB
            max_message_age: Some(Duration::minutes(5)),
            rate_limit_max: None,
            rate_limit_window: Duration::minutes(1),
        }
    }
}

/// Per-sender rate tracking.
#[derive(Debug, Default)]
struct RateTracker {
    /// Timestamps of messages within the current window.
    timestamps: Vec<DateTime<Utc>>,
}

impl RateTracker {
    /// Record a message and return true if within limit.
    fn record(&mut self, now: DateTime<Utc>, window: Duration, max: u64) -> bool {
        let cutoff = now - window;
        self.timestamps.retain(|t| *t > cutoff);
        self.timestamps.push(now);
        self.timestamps.len() as u64 <= max
    }
}

/// Outcome of routing a message.
#[derive(Debug)]
pub struct RouteResult {
    pub allowed: bool,
    pub message_id: Uuid,
    pub alerts: Vec<moat_runtime::monitor::MonitorAlert>,
    /// If rejected before PEP, this contains the reason.
    pub pre_pep_rejection: Option<String>,
}

/// The message router integrates registry, PEP, audit, and monitor.
pub struct MessageRouter {
    pub registry: AgentRegistry,
    pub pep: PolicyEnforcementPoint,
    pub audit_log: AuditLog,
    pub monitor: RuntimeMonitor,
    pub limits: RouterLimits,
    rate_trackers: HashMap<Uuid, RateTracker>,
}

impl MessageRouter {
    pub fn new(policy: PolicyBinding, thresholds: MonitorThresholds) -> Self {
        Self {
            registry: AgentRegistry::new(),
            pep: PolicyEnforcementPoint::new(policy),
            audit_log: AuditLog::new(),
            monitor: RuntimeMonitor::new(thresholds),
            limits: RouterLimits::default(),
            rate_trackers: HashMap::new(),
        }
    }

    /// Create a router with custom limits.
    pub fn with_limits(
        policy: PolicyBinding,
        thresholds: MonitorThresholds,
        limits: RouterLimits,
    ) -> Self {
        Self {
            registry: AgentRegistry::new(),
            pep: PolicyEnforcementPoint::new(policy),
            audit_log: AuditLog::new(),
            monitor: RuntimeMonitor::new(thresholds),
            limits,
            rate_trackers: HashMap::new(),
        }
    }

    /// Route a message: validate via PEP, log to audit, track via monitor.
    pub fn route(
        &mut self,
        message: &AuthenticatedMessage,
        resource: &str,
        action: &str,
    ) -> Result<RouteResult, MoatError> {
        // Pre-PEP checks: payload size
        if let Some(max_bytes) = self.limits.max_payload_bytes {
            if message.payload.len() > max_bytes {
                let reason = format!(
                    "payload size {} exceeds limit {}",
                    message.payload.len(),
                    max_bytes
                );
                self.audit_log.append(AuditEventKind::PepDecision {
                    message_id: message.message_id,
                    sender_id: message.sender_id,
                    resource: resource.to_string(),
                    action: action.to_string(),
                    allowed: false,
                    stage_failed: Some("pre_pep_payload_size".into()),
                    reason: Some(reason.clone()),
                });
                return Ok(RouteResult {
                    allowed: false,
                    message_id: message.message_id,
                    alerts: vec![],
                    pre_pep_rejection: Some(reason),
                });
            }
        }

        // Pre-PEP checks: message age
        if let Some(max_age) = self.limits.max_message_age {
            let age = Utc::now() - message.timestamp;
            if age > max_age {
                let reason = format!(
                    "message timestamp {} is too old (age: {}s, max: {}s)",
                    message.timestamp,
                    age.num_seconds(),
                    max_age.num_seconds(),
                );
                self.audit_log.append(AuditEventKind::PepDecision {
                    message_id: message.message_id,
                    sender_id: message.sender_id,
                    resource: resource.to_string(),
                    action: action.to_string(),
                    allowed: false,
                    stage_failed: Some("pre_pep_message_age".into()),
                    reason: Some(reason.clone()),
                });
                return Ok(RouteResult {
                    allowed: false,
                    message_id: message.message_id,
                    alerts: vec![],
                    pre_pep_rejection: Some(reason),
                });
            }
        }

        // Pre-PEP checks: rate limiting
        if let Some(rate_max) = self.limits.rate_limit_max {
            let tracker = self.rate_trackers.entry(message.sender_id).or_default();
            if !tracker.record(Utc::now(), self.limits.rate_limit_window, rate_max) {
                let reason = format!(
                    "rate limit exceeded: {} messages in {}s window",
                    rate_max,
                    self.limits.rate_limit_window.num_seconds(),
                );
                self.audit_log.append(AuditEventKind::PepDecision {
                    message_id: message.message_id,
                    sender_id: message.sender_id,
                    resource: resource.to_string(),
                    action: action.to_string(),
                    allowed: false,
                    stage_failed: Some("pre_pep_rate_limit".into()),
                    reason: Some(reason.clone()),
                });
                return Ok(RouteResult {
                    allowed: false,
                    message_id: message.message_id,
                    alerts: vec![],
                    pre_pep_rejection: Some(reason),
                });
            }
        }

        // Pre-PEP checks: recipient exists
        if !self.registry.contains(&message.recipient_id) {
            let reason = format!("recipient {} not registered", message.recipient_id);
            self.audit_log.append(AuditEventKind::PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                resource: resource.to_string(),
                action: action.to_string(),
                allowed: false,
                stage_failed: Some("pre_pep_recipient_unknown".into()),
                reason: Some(reason.clone()),
            });
            return Ok(RouteResult {
                allowed: false,
                message_id: message.message_id,
                alerts: vec![],
                pre_pep_rejection: Some(reason),
            });
        }

        // Run PEP evaluation
        let decision = self.pep.evaluate(message, resource, action);

        // Log to audit
        self.audit_log.append(AuditEventKind::PepDecision {
            message_id: decision.message_id,
            sender_id: decision.sender_id,
            resource: resource.to_string(),
            action: action.to_string(),
            allowed: decision.allowed,
            stage_failed: decision.stage_failed.map(|s| s.to_string()),
            reason: decision.reason.clone(),
        });

        // Track via monitor (only if allowed -- failed messages don't count as actions)
        let alerts = if decision.allowed {
            self.monitor
                .record_action(message.sender_id, action, resource)
        } else {
            vec![]
        };

        // Log any alerts
        for alert in &alerts {
            self.audit_log.append(AuditEventKind::MonitorAlert {
                agent_id: alert.agent_id,
                alert_type: alert.alert_type.clone(),
                details: alert.details.clone(),
            });
        }

        Ok(RouteResult {
            allowed: decision.allowed,
            message_id: message.message_id,
            alerts,
            pre_pep_rejection: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use moat_core::{
        AgentKeypair, AuthenticatedMessage, CapabilityToken, PolicyBinding, ResourceLimits,
        ScopeEntry,
    };

    fn setup() -> (MessageRouter, AgentKeypair, AgentKeypair, PolicyBinding) {
        let policy = PolicyBinding::new("test-v1", b"test policy");
        let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();

        router.registry.register(sender.identity.clone()).unwrap();
        router
            .registry
            .register(recipient.identity.clone())
            .unwrap();
        router.pep.register_identity(sender.identity.clone());
        router.pep.register_identity(recipient.identity.clone());
        router.pep.add_trusted_root(sender.id());
        router.pep.add_trusted_root(recipient.id());

        (router, sender, recipient, policy)
    }

    fn make_msg(
        sender: &AgentKeypair,
        recipient_id: Uuid,
        policy: &PolicyBinding,
        seq: u64,
    ) -> AuthenticatedMessage {
        let mut cap =
            CapabilityToken::root(sender.id(), sender.id(), Utc::now() + Duration::hours(1));
        cap.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        cap.resource_limits = ResourceLimits::default();
        cap.sign(sender);

        AuthenticatedMessage::create(
            sender,
            recipient_id,
            b"test".to_vec(),
            cap,
            vec![],
            policy.clone(),
            seq,
        )
        .unwrap()
    }

    #[test]
    fn route_valid_message() {
        let (mut router, sender, recipient, policy) = setup();
        let msg = make_msg(&sender, recipient.id(), &policy, 1);
        let result = router.route(&msg, "tool://test", "execute").unwrap();
        assert!(result.allowed);
        assert!(result.pre_pep_rejection.is_none());
        assert_eq!(router.audit_log.len(), 1);
    }

    #[test]
    fn route_unauthorized_action() {
        let (mut router, sender, recipient, policy) = setup();
        let msg = make_msg(&sender, recipient.id(), &policy, 1);
        let result = router.route(&msg, "tool://test", "write").unwrap();
        assert!(!result.allowed);
        assert_eq!(router.audit_log.len(), 1);
    }

    #[test]
    fn audit_integrity_after_routing() {
        let (mut router, sender, recipient, policy) = setup();
        for seq in 1..=5 {
            let msg = make_msg(&sender, recipient.id(), &policy, seq);
            router.route(&msg, "tool://test", "execute").unwrap();
        }
        assert!(router.audit_log.verify_integrity().is_ok());
    }

    #[test]
    fn unknown_recipient_rejected() {
        let (mut router, sender, _recipient, policy) = setup();
        let unknown_recipient = Uuid::new_v4();
        let msg = make_msg(&sender, unknown_recipient, &policy, 1);
        let result = router.route(&msg, "tool://test", "execute").unwrap();
        assert!(!result.allowed);
        assert!(result
            .pre_pep_rejection
            .as_ref()
            .unwrap()
            .contains("not registered"));
    }

    #[test]
    fn oversized_payload_rejected() {
        let policy = PolicyBinding::new("test-v1", b"test policy");
        let limits = RouterLimits {
            max_payload_bytes: Some(10), // 10 bytes max
            ..Default::default()
        };
        let mut router =
            MessageRouter::with_limits(policy.clone(), MonitorThresholds::default(), limits);

        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();
        router.registry.register(sender.identity.clone()).unwrap();
        router
            .registry
            .register(recipient.identity.clone())
            .unwrap();
        router.pep.register_identity(sender.identity.clone());
        router.pep.add_trusted_root(sender.id());

        // Build a message with oversized payload
        let mut cap =
            CapabilityToken::root(sender.id(), sender.id(), Utc::now() + Duration::hours(1));
        cap.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        cap.sign(&sender);

        let msg = AuthenticatedMessage::create(
            &sender,
            recipient.id(),
            vec![0u8; 100], // 100 bytes > 10 byte limit
            cap,
            vec![],
            policy.clone(),
            1,
        )
        .unwrap();

        let result = router.route(&msg, "tool://test", "execute").unwrap();
        assert!(!result.allowed);
        assert!(result
            .pre_pep_rejection
            .as_ref()
            .unwrap()
            .contains("payload size"));
    }

    #[test]
    fn rate_limiting() {
        let policy = PolicyBinding::new("test-v1", b"test policy");
        let limits = RouterLimits {
            rate_limit_max: Some(2),
            rate_limit_window: Duration::minutes(1),
            ..Default::default()
        };
        let mut router =
            MessageRouter::with_limits(policy.clone(), MonitorThresholds::default(), limits);

        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();
        router.registry.register(sender.identity.clone()).unwrap();
        router
            .registry
            .register(recipient.identity.clone())
            .unwrap();
        router.pep.register_identity(sender.identity.clone());
        router.pep.register_identity(recipient.identity.clone());
        router.pep.add_trusted_root(sender.id());

        // First two messages succeed
        let msg1 = make_msg(&sender, recipient.id(), &policy, 1);
        let r1 = router.route(&msg1, "tool://a", "execute").unwrap();
        assert!(r1.allowed);

        let msg2 = make_msg(&sender, recipient.id(), &policy, 2);
        let r2 = router.route(&msg2, "tool://b", "execute").unwrap();
        assert!(r2.allowed);

        // Third message hits rate limit
        let msg3 = make_msg(&sender, recipient.id(), &policy, 3);
        let r3 = router.route(&msg3, "tool://c", "execute").unwrap();
        assert!(!r3.allowed);
        assert!(r3
            .pre_pep_rejection
            .as_ref()
            .unwrap()
            .contains("rate limit"));
    }
}
