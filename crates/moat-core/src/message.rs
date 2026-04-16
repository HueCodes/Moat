//! Cryptographic Authenticated Messages (CAM).
//!
//! Every inter-agent invocation is wrapped in an `AuthenticatedMessage` that
//! cryptographically binds the sender, payload, capability token, and policy
//! binding. Sequence numbers provide replay protection per-sender.
//!
//! The message signature covers a deterministic binary canonical form (not JSON),
//! so it is immune to serialization ordering changes.

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
    /// The delegation chain from root to the immediate parent of `capability_token`.
    /// Empty if `capability_token` is itself a root token.
    #[serde(default)]
    pub token_chain: Vec<CapabilityToken>,
    pub policy_binding: PolicyBinding,
    /// Monotonically increasing per-sender. Used for replay detection.
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature over the canonical message bytes (everything except this field).
    pub signature: Vec<u8>,
}

impl AuthenticatedMessage {
    /// Create and sign a new authenticated message.
    pub fn create(
        sender: &AgentKeypair,
        recipient_id: Uuid,
        payload: Vec<u8>,
        capability_token: CapabilityToken,
        token_chain: Vec<CapabilityToken>,
        policy_binding: PolicyBinding,
        sequence_number: u64,
    ) -> Result<Self, MoatError> {
        let message_id = Uuid::new_v4();
        let timestamp = Utc::now();

        let canonical = canonical_message_bytes(
            message_id,
            sender.id(),
            recipient_id,
            &payload,
            &capability_token,
            &token_chain,
            &policy_binding,
            sequence_number,
            timestamp,
        );
        let signature = sender.sign(&canonical);

        Ok(Self {
            message_id,
            sender_id: sender.id(),
            recipient_id,
            payload,
            capability_token,
            token_chain,
            policy_binding,
            sequence_number,
            timestamp,
            signature,
        })
    }

    /// Verify the message signature against the sender's public identity.
    /// This is stage 1 of the PEP three-stage pipeline.
    pub fn verify_signature(&self, sender_identity: &AgentIdentity) -> Result<(), MoatError> {
        let canonical = canonical_message_bytes(
            self.message_id,
            self.sender_id,
            self.recipient_id,
            &self.payload,
            &self.capability_token,
            &self.token_chain,
            &self.policy_binding,
            self.sequence_number,
            self.timestamp,
        );
        sender_identity.verify(&canonical, &self.signature)
    }

    /// Verify the policy binding matches the expected policy.
    /// This is stage 2 of the PEP three-stage pipeline.
    pub fn verify_policy_binding(&self, expected_binding: &PolicyBinding) -> Result<(), MoatError> {
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

/// Deterministic canonical bytes for message signing.
/// Uses fixed-size binary fields concatenated directly; payload is hashed.
#[allow(clippy::too_many_arguments)] // Canonical serialization needs all message fields; a wrapper struct would add indirection without benefit.
fn canonical_message_bytes(
    message_id: Uuid,
    sender_id: Uuid,
    recipient_id: Uuid,
    payload: &[u8],
    capability_token: &CapabilityToken,
    token_chain: &[CapabilityToken],
    policy_binding: &PolicyBinding,
    sequence_number: u64,
    timestamp: DateTime<Utc>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(message_id.as_bytes());
    buf.extend_from_slice(sender_id.as_bytes());
    buf.extend_from_slice(recipient_id.as_bytes());
    buf.extend_from_slice(&sha256_hash(payload));
    buf.extend_from_slice(capability_token.token_id.as_bytes());
    buf.extend_from_slice(&policy_binding.policy_hash);
    buf.extend_from_slice(policy_binding.policy_id.as_bytes());
    buf.extend_from_slice(&sequence_number.to_le_bytes());
    buf.extend_from_slice(&timestamp.timestamp().to_le_bytes());
    buf.extend_from_slice(&timestamp.timestamp_subsec_nanos().to_le_bytes());
    // Bind the token chain so it can't be swapped
    buf.extend_from_slice(&(token_chain.len() as u64).to_le_bytes());
    for token in token_chain {
        buf.extend_from_slice(token.token_id.as_bytes());
    }
    buf
}

/// SHA-256 hash of raw bytes.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
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
        let mut cap =
            CapabilityToken::root(sender.id(), sender.id(), Utc::now() + Duration::hours(1));
        cap.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        cap.resource_limits = ResourceLimits::default();
        cap.sign(&sender);

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
            vec![],
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
            vec![],
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
            vec![],
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
            vec![],
            policy,
            5,
        )
        .unwrap();

        assert!(msg.verify_sequence(4).is_ok());
        assert!(msg.verify_sequence(5).is_err()); // equal
        assert!(msg.verify_sequence(6).is_err()); // past
    }
}
