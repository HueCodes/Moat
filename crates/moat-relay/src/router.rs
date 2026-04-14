//! Message router: routes authenticated messages through the PEP.
//!
//! The router receives messages, validates them through the PEP, records
//! the decision in the audit log, and tracks actions via the monitor.

use uuid::Uuid;

use moat_core::{AuthenticatedMessage, MoatError, PolicyBinding};
use moat_runtime::{
    AuditEventKind, AuditLog, MonitorThresholds, PolicyEnforcementPoint, RuntimeMonitor,
};

use crate::registry::AgentRegistry;

/// Outcome of routing a message.
#[derive(Debug)]
pub struct RouteResult {
    pub allowed: bool,
    pub message_id: Uuid,
    pub alerts: Vec<moat_runtime::monitor::MonitorAlert>,
}

/// The message router integrates registry, PEP, audit, and monitor.
pub struct MessageRouter {
    pub registry: AgentRegistry,
    pub pep: PolicyEnforcementPoint,
    pub audit_log: AuditLog,
    pub monitor: RuntimeMonitor,
}

impl MessageRouter {
    pub fn new(policy: PolicyBinding, thresholds: MonitorThresholds) -> Self {
        Self {
            registry: AgentRegistry::new(),
            pep: PolicyEnforcementPoint::new(policy),
            audit_log: AuditLog::new(),
            monitor: RuntimeMonitor::new(thresholds),
        }
    }

    /// Route a message: validate via PEP, log to audit, track via monitor.
    pub fn route(
        &mut self,
        message: &AuthenticatedMessage,
        resource: &str,
        action: &str,
    ) -> Result<RouteResult, MoatError> {
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

        router
            .registry
            .register(sender.identity.clone())
            .unwrap();
        router
            .registry
            .register(recipient.identity.clone())
            .unwrap();
        router.pep.register_identity(sender.identity.clone());
        router.pep.register_identity(recipient.identity.clone());

        (router, sender, recipient, policy)
    }

    fn make_msg(
        sender: &AgentKeypair,
        recipient_id: Uuid,
        policy: &PolicyBinding,
        seq: u64,
    ) -> AuthenticatedMessage {
        let mut cap = CapabilityToken::root(
            sender.id(),
            sender.id(),
            Utc::now() + Duration::hours(1),
        );
        cap.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        cap.resource_limits = ResourceLimits::default();

        AuthenticatedMessage::create(
            sender,
            recipient_id,
            b"test".to_vec(),
            cap,
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
}
