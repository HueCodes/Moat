//! Policy Enforcement Point (PEP) -- the three-stage verification pipeline.
//!
//! Every message entering the runtime passes through:
//! 1. Signature verification (is this really from the claimed sender?)
//! 2. Policy binding verification (was the right policy used?)
//! 3. Capability evaluation (is this action allowed by the token?)
//!
//! All three stages must pass. The PEP is deterministic: given the same
//! inputs it always produces the same result. No probabilistic filtering.

use std::collections::HashMap;
use uuid::Uuid;

use moat_core::{AgentIdentity, AuthenticatedMessage, PolicyBinding};

/// Result of PEP evaluation. Contains the decision and metadata for audit logging.
#[derive(Debug, Clone)]
pub struct PepDecision {
    pub message_id: Uuid,
    pub sender_id: Uuid,
    pub allowed: bool,
    pub stage_failed: Option<PepStage>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepStage {
    SignatureVerification,
    PolicyBinding,
    CapabilityEvaluation,
}

impl std::fmt::Display for PepStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PepStage::SignatureVerification => write!(f, "signature_verification"),
            PepStage::PolicyBinding => write!(f, "policy_binding"),
            PepStage::CapabilityEvaluation => write!(f, "capability_evaluation"),
        }
    }
}

/// The PEP tracks per-sender sequence numbers and the identity registry.
pub struct PolicyEnforcementPoint {
    /// Known agent identities, keyed by agent UUID.
    identities: HashMap<Uuid, AgentIdentity>,
    /// Last-seen sequence number per sender, for replay protection.
    sequence_numbers: HashMap<Uuid, u64>,
    /// The active policy binding that all messages must match.
    active_policy: PolicyBinding,
}

impl PolicyEnforcementPoint {
    pub fn new(active_policy: PolicyBinding) -> Self {
        Self {
            identities: HashMap::new(),
            sequence_numbers: HashMap::new(),
            active_policy,
        }
    }

    /// Register an agent identity so the PEP can verify its messages.
    pub fn register_identity(&mut self, identity: AgentIdentity) {
        tracing::info!(agent_id = %identity.id, name = %identity.name, "registered agent identity");
        self.identities.insert(identity.id, identity);
    }

    /// Run the full three-stage pipeline on an incoming message.
    /// Returns the resource and action that were requested (for audit) alongside the decision.
    pub fn evaluate(
        &mut self,
        message: &AuthenticatedMessage,
        resource: &str,
        action: &str,
    ) -> PepDecision {
        // Stage 1: Signature verification
        let sender_identity = match self.identities.get(&message.sender_id) {
            Some(id) => id,
            None => {
                return PepDecision {
                    message_id: message.message_id,
                    sender_id: message.sender_id,
                    allowed: false,
                    stage_failed: Some(PepStage::SignatureVerification),
                    reason: Some(format!("unknown sender: {}", message.sender_id)),
                };
            }
        };

        if let Err(e) = message.verify_signature(sender_identity) {
            return PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                allowed: false,
                stage_failed: Some(PepStage::SignatureVerification),
                reason: Some(e.to_string()),
            };
        }

        // Replay protection (between stages 1 and 2)
        let last_seq = self.sequence_numbers.get(&message.sender_id).copied().unwrap_or(0);
        if let Err(e) = message.verify_sequence(last_seq) {
            return PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                allowed: false,
                stage_failed: Some(PepStage::SignatureVerification),
                reason: Some(e.to_string()),
            };
        }

        // Stage 2: Policy binding verification
        if let Err(e) = message.verify_policy_binding(&self.active_policy) {
            return PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                allowed: false,
                stage_failed: Some(PepStage::PolicyBinding),
                reason: Some(e.to_string()),
            };
        }

        // Stage 3: Capability evaluation
        if let Err(e) = message.capability_token.is_action_allowed(resource, action) {
            return PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                allowed: false,
                stage_failed: Some(PepStage::CapabilityEvaluation),
                reason: Some(e.to_string()),
            };
        }

        // All stages passed -- update sequence tracker
        self.sequence_numbers.insert(message.sender_id, message.sequence_number);

        PepDecision {
            message_id: message.message_id,
            sender_id: message.sender_id,
            allowed: true,
            stage_failed: None,
            reason: None,
        }
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

    fn setup() -> (AgentKeypair, AgentKeypair, PolicyBinding, PolicyEnforcementPoint) {
        let policy = PolicyBinding::new("test-v1", b"test policy");
        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();
        let mut pep = PolicyEnforcementPoint::new(policy.clone());
        pep.register_identity(sender.identity.clone());
        pep.register_identity(recipient.identity.clone());
        (sender, recipient, policy, pep)
    }

    fn make_message(
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
            b"test payload".to_vec(),
            cap,
            policy.clone(),
            seq,
        )
        .unwrap()
    }

    #[test]
    fn full_pipeline_passes() {
        let (sender, recipient, policy, mut pep) = setup();
        let msg = make_message(&sender, recipient.id(), &policy, 1);
        let decision = pep.evaluate(&msg, "tool://review", "execute");
        assert!(decision.allowed);
    }

    #[test]
    fn unknown_sender_rejected() {
        let (_, recipient, policy, mut pep) = setup();
        let unknown = AgentKeypair::generate("unknown").unwrap();
        let msg = make_message(&unknown, recipient.id(), &policy, 1);
        let decision = pep.evaluate(&msg, "tool://review", "execute");
        assert!(!decision.allowed);
        assert_eq!(decision.stage_failed, Some(PepStage::SignatureVerification));
    }

    #[test]
    fn tampered_message_rejected() {
        let (sender, recipient, policy, mut pep) = setup();
        let mut msg = make_message(&sender, recipient.id(), &policy, 1);
        msg.payload = b"tampered".to_vec();
        let decision = pep.evaluate(&msg, "tool://review", "execute");
        assert!(!decision.allowed);
        assert_eq!(decision.stage_failed, Some(PepStage::SignatureVerification));
    }

    #[test]
    fn wrong_policy_rejected() {
        let (sender, recipient, _policy, mut pep) = setup();
        let wrong_policy = PolicyBinding::new("wrong-v1", b"wrong");
        let msg = make_message(&sender, recipient.id(), &wrong_policy, 1);
        let decision = pep.evaluate(&msg, "tool://review", "execute");
        assert!(!decision.allowed);
        assert_eq!(decision.stage_failed, Some(PepStage::PolicyBinding));
    }

    #[test]
    fn unauthorized_action_rejected() {
        let (sender, recipient, policy, mut pep) = setup();
        let msg = make_message(&sender, recipient.id(), &policy, 1);
        // Ask for an action not in the capability
        let decision = pep.evaluate(&msg, "tool://review", "write");
        assert!(!decision.allowed);
        assert_eq!(decision.stage_failed, Some(PepStage::CapabilityEvaluation));
    }

    #[test]
    fn replay_rejected() {
        let (sender, recipient, policy, mut pep) = setup();
        let msg1 = make_message(&sender, recipient.id(), &policy, 1);
        let decision1 = pep.evaluate(&msg1, "tool://review", "execute");
        assert!(decision1.allowed);

        let msg2 = make_message(&sender, recipient.id(), &policy, 1); // same seq
        let decision2 = pep.evaluate(&msg2, "tool://review", "execute");
        assert!(!decision2.allowed);
    }
}
