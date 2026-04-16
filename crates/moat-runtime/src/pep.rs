//! Policy Enforcement Point (PEP) -- the three-stage verification pipeline.
//!
//! Every message entering the runtime passes through:
//! 1. Signature verification (is this really from the claimed sender?)
//! 2. Policy binding verification (was the right policy used?)
//! 3. Capability evaluation (is the token chain valid and the action allowed?)
//!
//! Stage 3 now verifies the full cryptographic chain of capability tokens
//! back to a trusted root before checking permissions.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use moat_core::{AgentIdentity, AuthenticatedMessage, MoatError, PolicyBinding};

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

/// Serializable PEP state for persistence across restarts.
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct PepState {
    /// Last-seen sequence number per sender UUID.
    pub sequence_numbers: HashMap<Uuid, u64>,
}

impl PepState {
    /// Save state to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), MoatError> {
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)
            .map_err(|e| MoatError::Sandbox(format!("failed to save PEP state: {}", e)))?;
        Ok(())
    }

    /// Load state from a JSON file. Returns default state if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, MoatError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(path)
            .map_err(|e| MoatError::Sandbox(format!("failed to read PEP state: {}", e)))?;
        Ok(serde_json::from_slice(&data)?)
    }
}

/// The PEP tracks per-sender sequence numbers, the identity registry, and trusted roots.
pub struct PolicyEnforcementPoint {
    /// Known agent identities, keyed by agent UUID.
    identities: HashMap<Uuid, AgentIdentity>,
    /// Last-seen sequence number per sender, for replay protection.
    sequence_numbers: HashMap<Uuid, u64>,
    /// The active policy binding that all messages must match.
    active_policy: PolicyBinding,
    /// Agent IDs that are trusted as root token issuers.
    trusted_roots: HashSet<Uuid>,
    /// Optional path for persisting sequence state.
    state_path: Option<PathBuf>,
}

impl PolicyEnforcementPoint {
    pub fn new(active_policy: PolicyBinding) -> Self {
        Self {
            identities: HashMap::new(),
            sequence_numbers: HashMap::new(),
            active_policy,
            trusted_roots: HashSet::new(),
            state_path: None,
        }
    }

    /// Create a PEP with persistent state. Loads existing state from `state_path`
    /// if present, and persists sequence number updates after each successful evaluation.
    pub fn with_persistence(
        active_policy: PolicyBinding,
        state_path: PathBuf,
    ) -> Result<Self, MoatError> {
        let state = PepState::load(&state_path)?;
        Ok(Self {
            identities: HashMap::new(),
            sequence_numbers: state.sequence_numbers,
            active_policy,
            trusted_roots: HashSet::new(),
            state_path: Some(state_path),
        })
    }

    /// Register an agent identity so the PEP can verify its messages and token signatures.
    pub fn register_identity(&mut self, identity: AgentIdentity) {
        tracing::info!(agent_id = %identity.id, name = %identity.name, "registered agent identity");
        self.identities.insert(identity.id, identity);
    }

    /// Add an agent ID as a trusted root for capability token chains.
    pub fn add_trusted_root(&mut self, agent_id: Uuid) {
        tracing::info!(agent_id = %agent_id, "added trusted root");
        self.trusted_roots.insert(agent_id);
    }

    /// Persist current sequence state to disk (no-op if no state_path configured).
    fn persist_state(&self) -> Result<(), MoatError> {
        if let Some(ref path) = self.state_path {
            let state = PepState {
                sequence_numbers: self.sequence_numbers.clone(),
            };
            state.save(path)?;
        }
        Ok(())
    }

    /// Run the full three-stage pipeline on an incoming message.
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
        let last_seq = self
            .sequence_numbers
            .get(&message.sender_id)
            .copied()
            .unwrap_or(0);
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

        // Stage 3: Capability token chain verification + action check
        if let Err(e) = self.verify_token_chain(&message.capability_token, &message.token_chain) {
            return PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                allowed: false,
                stage_failed: Some(PepStage::CapabilityEvaluation),
                reason: Some(e.to_string()),
            };
        }

        if let Err(e) = message.capability_token.is_action_allowed(resource, action) {
            return PepDecision {
                message_id: message.message_id,
                sender_id: message.sender_id,
                allowed: false,
                stage_failed: Some(PepStage::CapabilityEvaluation),
                reason: Some(e.to_string()),
            };
        }

        // All stages passed -- update sequence tracker and persist
        self.sequence_numbers
            .insert(message.sender_id, message.sequence_number);
        if let Err(e) = self.persist_state() {
            tracing::error!(error = %e, "failed to persist PEP state");
        }

        PepDecision {
            message_id: message.message_id,
            sender_id: message.sender_id,
            allowed: true,
            stage_failed: None,
            reason: None,
        }
    }

    /// Verify the full capability token chain from root to leaf.
    fn verify_token_chain(
        &self,
        leaf: &moat_core::CapabilityToken,
        chain: &[moat_core::CapabilityToken],
    ) -> Result<(), MoatError> {
        if chain.is_empty() {
            // Leaf is a root token
            if leaf.parent_token_id.is_some() {
                return Err(MoatError::TokenChainInvalid(
                    "token has parent_token_id but no chain provided".into(),
                ));
            }
            if !self.trusted_roots.contains(&leaf.issuer_id) {
                return Err(MoatError::UntrustedTokenRoot(leaf.issuer_id));
            }
            let issuer_identity = self
                .identities
                .get(&leaf.issuer_id)
                .ok_or(MoatError::IdentityNotFound(leaf.issuer_id))?;
            leaf.verify_signature(issuer_identity)?;
            return Ok(());
        }

        // Verify chain[0] is a root
        let root = &chain[0];
        if root.parent_token_id.is_some() {
            return Err(MoatError::TokenChainInvalid(
                "first token in chain must be a root (no parent)".into(),
            ));
        }
        if !self.trusted_roots.contains(&root.issuer_id) {
            return Err(MoatError::UntrustedTokenRoot(root.issuer_id));
        }

        let root_identity = self
            .identities
            .get(&root.issuer_id)
            .ok_or(MoatError::IdentityNotFound(root.issuer_id))?;
        root.verify_signature(root_identity)?;

        for i in 1..chain.len() {
            let parent = &chain[i - 1];
            let child = &chain[i];

            if child.parent_token_id != Some(parent.token_id) {
                return Err(MoatError::TokenChainInvalid(format!(
                    "chain break at index {}: expected parent {}, got {:?}",
                    i, parent.token_id, child.parent_token_id,
                )));
            }

            let issuer_identity = self
                .identities
                .get(&child.issuer_id)
                .ok_or(MoatError::IdentityNotFound(child.issuer_id))?;
            child.verify_signature(issuer_identity)?;
        }

        // Verify leaf links to last chain token
        let last_chain = chain.last().expect("chain is non-empty");
        if leaf.parent_token_id != Some(last_chain.token_id) {
            return Err(MoatError::TokenChainInvalid(format!(
                "leaf parent {:?} doesn't match chain tail {}",
                leaf.parent_token_id, last_chain.token_id,
            )));
        }

        let leaf_issuer = self
            .identities
            .get(&leaf.issuer_id)
            .ok_or(MoatError::IdentityNotFound(leaf.issuer_id))?;
        leaf.verify_signature(leaf_issuer)?;

        Ok(())
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

    fn setup() -> (
        AgentKeypair,
        AgentKeypair,
        PolicyBinding,
        PolicyEnforcementPoint,
    ) {
        let policy = PolicyBinding::new("test-v1", b"test policy");
        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();
        let mut pep = PolicyEnforcementPoint::new(policy.clone());
        pep.register_identity(sender.identity.clone());
        pep.register_identity(recipient.identity.clone());
        pep.add_trusted_root(sender.id());
        pep.add_trusted_root(recipient.id());
        (sender, recipient, policy, pep)
    }

    fn make_message(
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
            b"test payload".to_vec(),
            cap,
            vec![],
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

        let msg2 = make_message(&sender, recipient.id(), &policy, 1);
        let decision2 = pep.evaluate(&msg2, "tool://review", "execute");
        assert!(!decision2.allowed);
    }

    #[test]
    fn untrusted_root_rejected() {
        let policy = PolicyBinding::new("test-v1", b"test policy");
        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();
        let mut pep = PolicyEnforcementPoint::new(policy.clone());
        pep.register_identity(sender.identity.clone());
        pep.register_identity(recipient.identity.clone());
        // Deliberately NOT adding sender as trusted root

        let msg = make_message(&sender, recipient.id(), &policy, 1);
        let decision = pep.evaluate(&msg, "tool://review", "execute");
        assert!(!decision.allowed);
        assert_eq!(decision.stage_failed, Some(PepStage::CapabilityEvaluation));
        assert!(decision.reason.as_ref().unwrap().contains("untrusted"));
    }

    #[test]
    fn delegated_token_chain_verified() {
        let (sender, recipient, policy, mut pep) = setup();

        let mut root_cap =
            CapabilityToken::root(sender.id(), sender.id(), Utc::now() + Duration::hours(1));
        root_cap.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        root_cap.resource_limits = ResourceLimits::default();
        root_cap.sign(&sender);

        let mut child_cap = root_cap
            .attenuate(
                recipient.id(),
                vec![ScopeEntry {
                    resource: "tool://review".into(),
                    actions: vec!["execute".into()],
                }],
                vec![],
                ResourceLimits::default(),
                10,
            )
            .unwrap();
        child_cap.sign(&sender);

        let msg = AuthenticatedMessage::create(
            &recipient,
            sender.id(),
            b"review result".to_vec(),
            child_cap,
            vec![root_cap],
            policy.clone(),
            1,
        )
        .unwrap();

        let decision = pep.evaluate(&msg, "tool://review", "execute");
        assert!(
            decision.allowed,
            "delegated token chain should pass: {:?}",
            decision.reason
        );
    }

    #[test]
    fn forged_token_rejected() {
        let (sender, recipient, policy, mut pep) = setup();

        let attacker = AgentKeypair::generate("attacker").unwrap();
        pep.register_identity(attacker.identity.clone());

        let mut forged_cap =
            CapabilityToken::root(sender.id(), attacker.id(), Utc::now() + Duration::hours(1));
        forged_cap.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["*".into()],
        }];
        forged_cap.sign(&attacker);

        let msg = AuthenticatedMessage::create(
            &attacker,
            recipient.id(),
            b"forged".to_vec(),
            forged_cap,
            vec![],
            policy.clone(),
            1,
        )
        .unwrap();

        let decision = pep.evaluate(&msg, "tool://anything", "execute");
        assert!(!decision.allowed, "forged token must be rejected");
    }

    #[test]
    fn persistent_state_survives_restart() {
        let dir = std::env::temp_dir().join(format!("moat-pep-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("pep_state.json");
        let policy = PolicyBinding::new("test-v1", b"test policy");

        let sender = AgentKeypair::generate("sender").unwrap();
        let recipient = AgentKeypair::generate("recipient").unwrap();

        // First PEP: process a message at seq=5
        {
            let mut pep =
                PolicyEnforcementPoint::with_persistence(policy.clone(), state_path.clone())
                    .unwrap();
            pep.register_identity(sender.identity.clone());
            pep.register_identity(recipient.identity.clone());
            pep.add_trusted_root(sender.id());

            let msg = make_message(&sender, recipient.id(), &policy, 5);
            let decision = pep.evaluate(&msg, "tool://test", "execute");
            assert!(decision.allowed);
        }

        // Second PEP: loaded from disk, should reject seq <= 5
        {
            let mut pep =
                PolicyEnforcementPoint::with_persistence(policy.clone(), state_path.clone())
                    .unwrap();
            pep.register_identity(sender.identity.clone());
            pep.register_identity(recipient.identity.clone());
            pep.add_trusted_root(sender.id());

            let msg_replay = make_message(&sender, recipient.id(), &policy, 3);
            let decision = pep.evaluate(&msg_replay, "tool://test", "execute");
            assert!(!decision.allowed, "replay after restart must be rejected");

            let msg_ok = make_message(&sender, recipient.id(), &policy, 6);
            let decision = pep.evaluate(&msg_ok, "tool://test", "execute");
            assert!(decision.allowed, "seq 6 should succeed after restart");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
