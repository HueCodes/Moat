//! Cryptographic Authenticated Messages (CAM).
//!
//! Every inter-agent invocation is wrapped in an `AuthenticatedMessage` that
//! cryptographically binds the sender, payload, capability token, and policy
//! binding. Sequence numbers provide replay protection per-sender.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::capability::CapabilityToken;
use crate::error::MoatError;
use crate::identity::{AgentIdentity, AgentKeypair};

/// The policy binding is a hash of the policy document that was evaluated
/// when the capability token was issued. Verification checks that the
/// binding matches the expected policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyBinding {
    /// SHA-256 hash of the policy document.
    pub policy_hash: Vec<u8>,
    /// Human-readable policy identifier, e.g. "default-v1".
    pub policy_id: String,
}

impl PolicyBinding {
    pub fn new(policy_id: impl Into<String>, policy_document: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(policy_document);
        Self {
            policy_hash: hasher.finalize().to_vec(),
            policy_id: policy_id.into(),
        }
    }
}

/// A fully authenticated message between agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedMessage {
    pub message_id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub payload: Vec<u8>,
    pub capability_token: CapabilityToken,
    pub policy_binding: PolicyBinding,
    /// Monotonically increasing per-sender. Used for replay detection.
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature over the canonical message bytes (everything except this field).
    pub signature: Vec<u8>,
}

/// The signable portion of a message (everything except the signature itself).
#[derive(Serialize)]
struct SignableMessage<'a> {
    message_id: Uuid,
    sender_id: Uuid,
    recipient_id: Uuid,
    payload: &'a [u8],
    capability_token: &'a CapabilityToken,
    policy_binding: &'a PolicyBinding,
    sequence_number: u64,
    timestamp: DateTime<Utc>,
}

impl AuthenticatedMessage {
    /// Create and sign a new authenticated message.
    pub fn create(
        sender: &AgentKeypair,
        recipient_id: Uuid,
        payload: Vec<u8>,
        capability_token: CapabilityToken,
        policy_binding: PolicyBinding,
        sequence_number: u64,
    ) -> Result<Self, MoatError> {
        let message_id = Uuid::new_v4();
        let timestamp = Utc::now();

        let signable = SignableMessage {
            message_id,
            sender_id: sender.id(),
            recipient_id,
            payload: &payload,
            capability_token: &capability_token,
            policy_binding: &policy_binding,
            sequence_number,
            timestamp,
        };

        let canonical = serde_json::to_vec(&signable)?;
        let signature = sender.sign(&canonical);

        Ok(Self {
            message_id,
            sender_id: sender.id(),
            recipient_id,
            payload,
            capability_token,
            policy_binding,
            sequence_number,
            timestamp,
            signature,
        })
    }

    /// Verify the message signature against the sender's public identity.
    /// This is stage 1 of the PEP three-stage pipeline.
    pub fn verify_signature(&self, sender_identity: &AgentIdentity) -> Result<(), MoatError> {
        let signable = SignableMessage {
            message_id: self.message_id,
            sender_id: self.sender_id,
            recipient_id: self.recipient_id,
            payload: &self.payload,
            capability_token: &self.capability_token,
            policy_binding: &self.policy_binding,
            sequence_number: self.sequence_number,
            timestamp: self.timestamp,
        };

        let canonical = serde_json::to_vec(&signable)?;
        sender_identity.verify(&canonical, &self.signature)
    }

    /// Verify the policy binding matches the expected policy.
    /// This is stage 2 of the PEP three-stage pipeline.
    pub fn verify_policy_binding(
        &self,
        expected_binding: &PolicyBinding,
    ) -> Result<(), MoatError> {
        if self.policy_binding != *expected_binding {
            return Err(MoatError::PolicyBindingMismatch {
                expected: expected_binding.policy_id.clone(),
                actual: self.policy_binding.policy_id.clone(),
            });
        }
        Ok(())
    }

    /// Check sequence number for replay protection.
    pub fn verify_sequence(&self, last_seen: u64) -> Result<(), MoatError> {
        if self.sequence_number <= last_seen {
            return Err(MoatError::ReplayDetected {
                got: self.sequence_number,
                last_seen,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ResourceLimits, ScopeEntry};
    use crate::identity::AgentKeypair;
    use chrono::Duration;

    fn test_setup() -> (AgentKeypair, AgentKeypair, CapabilityToken, PolicyBinding) {
        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();
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

        let policy = PolicyBinding::new("test-policy-v1", b"test policy document");
        (sender, recipient, cap, policy)
    }

    #[test]
    fn create_and_verify() {
        let (sender, recipient, cap, policy) = test_setup();
        let msg = AuthenticatedMessage::create(
            &sender,
            recipient.id(),
            b"hello".to_vec(),
            cap,
            policy.clone(),
            1,
        )
        .unwrap();

        assert!(msg.verify_signature(&sender.identity).is_ok());
        assert!(msg.verify_policy_binding(&policy).is_ok());
        assert!(msg.verify_sequence(0).is_ok());
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let (sender, recipient, cap, policy) = test_setup();
        let mut msg = AuthenticatedMessage::create(
            &sender,
            recipient.id(),
            b"hello".to_vec(),
            cap,
            policy,
            1,
        )
        .unwrap();

        msg.payload = b"tampered".to_vec();
        assert!(msg.verify_signature(&sender.identity).is_err());
    }

    #[test]
    fn wrong_policy_binding() {
        let (sender, recipient, cap, policy) = test_setup();
        let msg = AuthenticatedMessage::create(
            &sender,
            recipient.id(),
            b"hello".to_vec(),
            cap,
            policy,
            1,
        )
        .unwrap();

        let wrong_policy = PolicyBinding::new("wrong-policy", b"different document");
        assert!(msg.verify_policy_binding(&wrong_policy).is_err());
    }

    #[test]
    fn replay_detected() {
        let (sender, recipient, cap, policy) = test_setup();
        let msg = AuthenticatedMessage::create(
            &sender,
            recipient.id(),
            b"hello".to_vec(),
            cap,
            policy,
            5,
        )
        .unwrap();

        assert!(msg.verify_sequence(4).is_ok());
        assert!(msg.verify_sequence(5).is_err()); // equal
        assert!(msg.verify_sequence(6).is_err()); // past
    }
}
