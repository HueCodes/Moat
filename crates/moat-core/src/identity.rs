//! Cryptographic identity for agents.
//!
//! Every entity in Moat gets a unique Ed25519 keypair. The `AgentIdentity`
//! binds a human-readable name and optional attestations to a verifiable
//! public key. Signing and verification are constant-time via ed25519-dalek.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::MoatError;

/// A key attestation binds a claim (e.g. "code_reviewer", "has_sbom:sha256:abc")
/// to the identity, signed by the attester.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub claim: String,
    pub attester_id: Uuid,
    pub issued_at: DateTime<Utc>,
}

/// The public-facing identity of an agent. Safe to share over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: Uuid,
    pub name: String,
    pub public_key: Vec<u8>,
    pub attestations: Vec<Attestation>,
    pub created_at: DateTime<Utc>,
}

/// Full keypair for an agent. The signing key MUST stay in-process;
/// only `AgentIdentity` (containing the public half) is transmitted.
pub struct AgentKeypair {
    pub identity: AgentIdentity,
    signing_key: SigningKey,
}

// Manual Debug impl to avoid leaking the signing key
impl std::fmt::Debug for AgentKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeypair")
            .field("identity", &self.identity)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl AgentKeypair {
    /// Generate a new agent identity with a fresh Ed25519 keypair.
    pub fn generate(name: impl Into<String>) -> Result<Self, MoatError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let identity = AgentIdentity {
            id: Uuid::new_v4(),
            name: name.into(),
            public_key: verifying_key.to_bytes().to_vec(),
            attestations: Vec::new(),
            created_at: Utc::now(),
        };

        Ok(Self {
            identity,
            signing_key,
        })
    }

    /// Sign arbitrary bytes. Returns the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    pub fn id(&self) -> Uuid {
        self.identity.id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl AgentIdentity {
    /// Verify a signature against this identity's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), MoatError> {
        let vk_bytes: [u8; 32] = self
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| MoatError::SignatureInvalid)?;

        let verifying_key =
            VerifyingKey::from_bytes(&vk_bytes).map_err(|_| MoatError::SignatureInvalid)?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| MoatError::SignatureInvalid)?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify(message, &signature)?;
        Ok(())
    }

    /// Add an attestation claim to this identity.
    pub fn add_attestation(&mut self, claim: String, attester_id: Uuid) {
        self.attestations.push(Attestation {
            claim,
            attester_id,
            issued_at: Utc::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let kp = AgentKeypair::generate("test-agent").unwrap();
        let msg = b"hello moat";
        let sig = kp.sign(msg);
        assert!(kp.identity.verify(msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let kp = AgentKeypair::generate("test-agent").unwrap();
        let sig = kp.sign(b"original");
        assert!(kp.identity.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = AgentKeypair::generate("agent-1").unwrap();
        let kp2 = AgentKeypair::generate("agent-2").unwrap();
        let sig = kp1.sign(b"hello");
        assert!(kp2.identity.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn debug_redacts_signing_key() {
        let kp = AgentKeypair::generate("test").unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("SigningKey"));
    }

    #[test]
    fn attestations() {
        let mut kp = AgentKeypair::generate("test").unwrap();
        let attester = Uuid::new_v4();
        kp.identity
            .add_attestation("code_reviewer".into(), attester);
        assert_eq!(kp.identity.attestations.len(), 1);
        assert_eq!(kp.identity.attestations[0].claim, "code_reviewer");
    }
}
