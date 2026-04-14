//! Capability tokens with monotonic attenuation and cryptographic signatures.
//!
//! A `CapabilityToken` encodes what an agent is allowed to do: which resources,
//! which actions, and under what constraints (CPU fuel, memory, network access).
//! Tokens form delegation chains where each child is strictly equal to or more
//! restrictive than its parent (monotonic restriction).
//!
//! Every token carries an Ed25519 signature from its issuer. The PEP verifies
//! the full signature chain back to a trusted root before granting access.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::MoatError;
use crate::identity::{AgentIdentity, AgentKeypair};

/// Resource constraints that limit sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceLimits {
    /// Maximum CPU fuel (wasmtime fuel units). None = unlimited.
    pub max_fuel: Option<u64>,
    /// Maximum memory in bytes. None = unlimited.
    pub max_memory_bytes: Option<u64>,
    /// Whether network access is permitted at all.
    pub network_allowed: bool,
    /// Allowed network hosts (only checked if network_allowed is true).
    /// Empty = all hosts allowed when network_allowed is true.
    pub allowed_hosts: Vec<String>,
    /// Allowed filesystem paths (read-only). Empty = no fs access.
    pub allowed_fs_read: Vec<String>,
    /// Allowed filesystem paths (read-write). Empty = no write access.
    pub allowed_fs_write: Vec<String>,
}

impl Default for ResourceLimits {
    /// Default is maximally restrictive: no network, no filesystem, no fuel limit.
    fn default() -> Self {
        Self {
            max_fuel: None,
            max_memory_bytes: None,
            network_allowed: false,
            allowed_hosts: Vec::new(),
            allowed_fs_read: Vec::new(),
            allowed_fs_write: Vec::new(),
        }
    }
}

/// A single scope entry: a resource pattern paired with allowed actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeEntry {
    /// Resource pattern, e.g. "file:///tmp/*" or "tool://code_review".
    /// Supports trailing wildcard `*`.
    pub resource: String,
    /// Allowed actions on this resource, e.g. ["read", "execute"].
    pub actions: Vec<String>,
}

/// The capability token that travels with authenticated messages.
/// Forms a chain via `parent_token_id` for delegation tracking.
/// Must be signed by its `issuer_id` before use; the PEP rejects unsigned tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: Uuid,
    pub issuer_id: Uuid,
    pub subject_id: Uuid,
    pub parent_token_id: Option<Uuid>,
    pub delegation_depth: u32,

    /// Positive grants: what the subject IS allowed to do.
    pub allowed: Vec<ScopeEntry>,
    /// Negative grants: what the subject is explicitly DENIED.
    /// Denials override allows (deny takes precedence).
    pub denied: Vec<ScopeEntry>,

    pub resource_limits: ResourceLimits,

    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    /// Ed25519 signature over the canonical token bytes (all fields except this one).
    /// Empty for unsigned tokens, which will fail PEP verification.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl CapabilityToken {
    /// Create a root capability token (no parent). Returns unsigned; call `sign()` next.
    pub fn root(issuer_id: Uuid, subject_id: Uuid, expires_at: DateTime<Utc>) -> Self {
        Self {
            token_id: Uuid::new_v4(),
            issuer_id,
            subject_id,
            parent_token_id: None,
            delegation_depth: 0,
            allowed: Vec::new(),
            denied: Vec::new(),
            resource_limits: ResourceLimits::default(),
            issued_at: Utc::now(),
            expires_at,
            signature: Vec::new(),
        }
    }

    /// Sign this token with the issuer's keypair. Must be called before use.
    pub fn sign(&mut self, keypair: &AgentKeypair) {
        let bytes = self.canonical_bytes();
        self.signature = keypair.sign(&bytes);
    }

    /// Verify this token's signature against the claimed issuer's identity.
    pub fn verify_signature(&self, issuer_identity: &AgentIdentity) -> Result<(), MoatError> {
        if self.signature.is_empty() {
            return Err(MoatError::TokenSignatureInvalid);
        }
        let bytes = self.canonical_bytes();
        issuer_identity.verify(&bytes, &self.signature)
    }

    /// Derive a child token with attenuated (equal or more restrictive) permissions.
    /// The parent must be signed (non-empty signature). Returns an unsigned child;
    /// the caller must sign it with the delegator's keypair.
    ///
    /// Enforces the three monotonic restriction theorems:
    /// 1. Child cannot add resources/actions not in parent's allowed set
    /// 2. Child inherits all parent denials (denials are additive)
    /// 3. Child resource limits can only tighten (lower fuel, less memory, fewer hosts)
    pub fn attenuate(
        &self,
        new_subject_id: Uuid,
        allowed: Vec<ScopeEntry>,
        additional_denied: Vec<ScopeEntry>,
        resource_limits: ResourceLimits,
        max_depth: u32,
    ) -> Result<CapabilityToken, MoatError> {
        // Parent must be signed before attenuating
        if self.signature.is_empty() {
            return Err(MoatError::TokenSignatureInvalid);
        }

        let new_depth = self.delegation_depth + 1;
        if new_depth > max_depth {
            return Err(MoatError::DelegationDepthExceeded {
                depth: new_depth,
                max: max_depth,
            });
        }

        // Theorem 1: child allowed must be subset of parent allowed
        for child_entry in &allowed {
            if !self.scope_is_subset_of_allowed(child_entry) {
                return Err(MoatError::AttenuationViolation);
            }
        }

        // Theorem 3: resource limits can only tighten
        self.validate_limits_tighten(&resource_limits)?;

        // Theorem 2: inherit all parent denials, add new ones
        let mut merged_denied = self.denied.clone();
        merged_denied.extend(additional_denied);

        Ok(CapabilityToken {
            token_id: Uuid::new_v4(),
            issuer_id: self.subject_id, // delegator becomes issuer
            subject_id: new_subject_id,
            parent_token_id: Some(self.token_id),
            delegation_depth: new_depth,
            allowed,
            denied: merged_denied,
            resource_limits,
            issued_at: Utc::now(),
            expires_at: self.expires_at, // child cannot outlive parent
            signature: Vec::new(),       // unsigned until caller signs
        })
    }

    /// Check whether a specific action on a resource is permitted by this token.
    pub fn is_action_allowed(&self, resource: &str, action: &str) -> Result<(), MoatError> {
        // Check expiry
        if Utc::now() > self.expires_at {
            return Err(MoatError::CapabilityExpired(self.expires_at));
        }

        // Denials checked first (deny overrides allow)
        for denied in &self.denied {
            if resource_matches(&denied.resource, resource)
                && denied.actions.iter().any(|a| a == action || a == "*")
            {
                return Err(MoatError::ActionDenied {
                    resource: resource.to_string(),
                    action: action.to_string(),
                });
            }
        }

        // Check positive grants
        for entry in &self.allowed {
            if resource_matches(&entry.resource, resource)
                && entry.actions.iter().any(|a| a == action || a == "*")
            {
                return Ok(());
            }
        }

        Err(MoatError::ActionDenied {
            resource: resource.to_string(),
            action: action.to_string(),
        })
    }

    /// Deterministic canonical bytes for signing. Covers all fields except `signature`.
    /// Uses a hand-built binary format: fixed-size fields concatenated directly,
    /// variable-size fields (allowed, denied, limits) hashed individually.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(self.token_id.as_bytes());
        buf.extend_from_slice(self.issuer_id.as_bytes());
        buf.extend_from_slice(self.subject_id.as_bytes());
        match self.parent_token_id {
            Some(pid) => buf.extend_from_slice(pid.as_bytes()),
            None => buf.extend_from_slice(&[0u8; 16]),
        }
        buf.extend_from_slice(&self.delegation_depth.to_le_bytes());

        // Hash complex sub-structures for determinism
        buf.extend_from_slice(&sha256_json(&self.allowed));
        buf.extend_from_slice(&sha256_json(&self.denied));
        buf.extend_from_slice(&sha256_json(&self.resource_limits));

        buf.extend_from_slice(&self.issued_at.timestamp().to_le_bytes());
        buf.extend_from_slice(&self.issued_at.timestamp_subsec_nanos().to_le_bytes());
        buf.extend_from_slice(&self.expires_at.timestamp().to_le_bytes());
        buf.extend_from_slice(&self.expires_at.timestamp_subsec_nanos().to_le_bytes());
        buf
    }

    fn scope_is_subset_of_allowed(&self, child_entry: &ScopeEntry) -> bool {
        // Each child resource+action must be covered by at least one parent entry
        for child_action in &child_entry.actions {
            let covered = self.allowed.iter().any(|parent_entry| {
                resource_pattern_subset(&child_entry.resource, &parent_entry.resource)
                    && parent_entry
                        .actions
                        .iter()
                        .any(|a| a == child_action || a == "*")
            });
            if !covered {
                return false;
            }
        }
        true
    }

    fn validate_limits_tighten(&self, child: &ResourceLimits) -> Result<(), MoatError> {
        // Fuel: child must be <= parent (or parent is None/unlimited)
        if let Some(parent_fuel) = self.resource_limits.max_fuel {
            match child.max_fuel {
                None => return Err(MoatError::AttenuationViolation), // child can't be unlimited if parent isn't
                Some(cf) if cf > parent_fuel => return Err(MoatError::AttenuationViolation),
                _ => {}
            }
        }

        // Memory: same logic
        if let Some(parent_mem) = self.resource_limits.max_memory_bytes {
            match child.max_memory_bytes {
                None => return Err(MoatError::AttenuationViolation),
                Some(cm) if cm > parent_mem => return Err(MoatError::AttenuationViolation),
                _ => {}
            }
        }

        // Network: can only go from allowed -> denied, not the reverse
        if !self.resource_limits.network_allowed && child.network_allowed {
            return Err(MoatError::AttenuationViolation);
        }

        // Hosts: child hosts must be subset of parent hosts (if parent has restrictions)
        if !self.resource_limits.allowed_hosts.is_empty() {
            for host in &child.allowed_hosts {
                if !self.resource_limits.allowed_hosts.contains(host) {
                    return Err(MoatError::AttenuationViolation);
                }
            }
        }

        Ok(())
    }
}

/// SHA-256 hash of JSON-serialized value. Used for sub-structure canonicalization.
fn sha256_json<T: Serialize>(value: &T) -> [u8; 32] {
    let json = serde_json::to_vec(value).expect("serializable type must serialize");
    sha256_hash(&json)
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

/// Check if a concrete resource matches a pattern (supports trailing `*` wildcard).
fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        resource.starts_with(prefix)
    } else {
        pattern == resource
    }
}

/// Check if child_pattern is a subset of parent_pattern.
/// "tool://review" is a subset of "tool://*", but not vice versa.
fn resource_pattern_subset(child: &str, parent: &str) -> bool {
    if parent == "*" {
        return true;
    }
    if let Some(parent_prefix) = parent.strip_suffix('*') {
        // Child must be within parent's prefix
        if let Some(child_prefix) = child.strip_suffix('*') {
            child_prefix.starts_with(parent_prefix)
        } else {
            child.starts_with(parent_prefix)
        }
    } else {
        // Parent is exact, child must be exact match
        child == parent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn future(hours: i64) -> DateTime<Utc> {
        Utc::now() + Duration::hours(hours)
    }

    fn root_token() -> (AgentKeypair, CapabilityToken) {
        let kp = AgentKeypair::generate("root-issuer").unwrap();
        let mut token = CapabilityToken::root(kp.id(), Uuid::new_v4(), future(1));
        token.allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into(), "read".into()],
        }];
        token.resource_limits = ResourceLimits {
            max_fuel: Some(1_000_000),
            max_memory_bytes: Some(64 * 1024 * 1024),
            network_allowed: true,
            allowed_hosts: vec!["api.example.com".into()],
            allowed_fs_read: vec!["/tmp".into()],
            allowed_fs_write: vec![],
        };
        token.sign(&kp);
        (kp, token)
    }

    #[test]
    fn action_allowed() {
        let (_kp, token) = root_token();
        assert!(token.is_action_allowed("tool://review", "execute").is_ok());
    }

    #[test]
    fn action_denied_not_in_scope() {
        let (_kp, token) = root_token();
        assert!(token.is_action_allowed("file:///etc/passwd", "read").is_err());
    }

    #[test]
    fn explicit_denial_overrides_allow() {
        let (kp, mut token) = root_token();
        token.denied.push(ScopeEntry {
            resource: "tool://dangerous".into(),
            actions: vec!["execute".into()],
        });
        // Re-sign after modification
        token.sign(&kp);
        assert!(token
            .is_action_allowed("tool://dangerous", "execute")
            .is_err());
        assert!(token.is_action_allowed("tool://safe", "execute").is_ok());
    }

    #[test]
    fn attenuate_narrows_scope() {
        let (kp, parent) = root_token();
        let child_subject = Uuid::new_v4();
        let mut child = parent
            .attenuate(
                child_subject,
                vec![ScopeEntry {
                    resource: "tool://review".into(),
                    actions: vec!["execute".into()],
                }],
                vec![],
                ResourceLimits {
                    max_fuel: Some(500_000),
                    max_memory_bytes: Some(32 * 1024 * 1024),
                    network_allowed: true,
                    allowed_hosts: vec!["api.example.com".into()],
                    ..Default::default()
                },
                10,
            )
            .unwrap();
        child.sign(&kp);

        assert!(child.is_action_allowed("tool://review", "execute").is_ok());
        assert!(child
            .is_action_allowed("tool://deploy", "execute")
            .is_err());
    }

    #[test]
    fn attenuate_cannot_broaden() {
        let (_kp, parent) = root_token();
        let result = parent.attenuate(
            Uuid::new_v4(),
            vec![ScopeEntry {
                resource: "file://*".into(),
                actions: vec!["read".into()],
            }],
            vec![],
            ResourceLimits::default(),
            10,
        );
        assert!(matches!(result, Err(MoatError::AttenuationViolation)));
    }

    #[test]
    fn attenuate_cannot_increase_fuel() {
        let (_kp, parent) = root_token();
        let result = parent.attenuate(
            Uuid::new_v4(),
            vec![],
            vec![],
            ResourceLimits {
                max_fuel: Some(2_000_000),
                ..Default::default()
            },
            10,
        );
        assert!(matches!(result, Err(MoatError::AttenuationViolation)));
    }

    #[test]
    fn attenuate_cannot_enable_network_if_parent_denies() {
        let (kp, mut parent) = root_token();
        parent.resource_limits.network_allowed = false;
        parent.sign(&kp);
        let result = parent.attenuate(
            Uuid::new_v4(),
            vec![],
            vec![],
            ResourceLimits {
                network_allowed: true,
                ..Default::default()
            },
            10,
        );
        assert!(matches!(result, Err(MoatError::AttenuationViolation)));
    }

    #[test]
    fn denials_are_additive_through_chain() {
        let (kp, parent) = root_token();
        let child_kp = AgentKeypair::generate("child").unwrap();
        let mut child = parent
            .attenuate(
                child_kp.id(),
                vec![ScopeEntry {
                    resource: "tool://*".into(),
                    actions: vec!["execute".into()],
                }],
                vec![ScopeEntry {
                    resource: "tool://dangerous".into(),
                    actions: vec!["execute".into()],
                }],
                ResourceLimits {
                    max_fuel: Some(500_000),
                    max_memory_bytes: Some(32 * 1024 * 1024),
                    ..Default::default()
                },
                10,
            )
            .unwrap();
        child.sign(&kp);

        // Now grandchild adds another denial
        let mut grandchild = child
            .attenuate(
                Uuid::new_v4(),
                vec![ScopeEntry {
                    resource: "tool://*".into(),
                    actions: vec!["execute".into()],
                }],
                vec![ScopeEntry {
                    resource: "tool://also_bad".into(),
                    actions: vec!["execute".into()],
                }],
                ResourceLimits {
                    max_fuel: Some(250_000),
                    max_memory_bytes: Some(16 * 1024 * 1024),
                    ..Default::default()
                },
                10,
            )
            .unwrap();
        grandchild.sign(&child_kp);

        // Grandchild inherits parent's denial AND has its own
        assert!(grandchild
            .is_action_allowed("tool://dangerous", "execute")
            .is_err());
        assert!(grandchild
            .is_action_allowed("tool://also_bad", "execute")
            .is_err());
        assert!(grandchild
            .is_action_allowed("tool://safe", "execute")
            .is_ok());
    }

    #[test]
    fn depth_limit_enforced() {
        let (kp, parent) = root_token();
        let limits = ResourceLimits {
            max_fuel: Some(500_000),
            max_memory_bytes: Some(32 * 1024 * 1024),
            ..Default::default()
        };
        let allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        let mut child = parent
            .attenuate(Uuid::new_v4(), allowed.clone(), vec![], limits.clone(), 2)
            .unwrap();
        child.sign(&kp);
        assert_eq!(child.delegation_depth, 1);

        let child_kp = AgentKeypair::generate("child").unwrap();
        let mut grandchild = child
            .attenuate(Uuid::new_v4(), allowed.clone(), vec![], limits.clone(), 2)
            .unwrap();
        grandchild.sign(&child_kp);
        assert_eq!(grandchild.delegation_depth, 2);

        let result = grandchild.attenuate(Uuid::new_v4(), allowed, vec![], limits, 2);
        assert!(matches!(
            result,
            Err(MoatError::DelegationDepthExceeded { .. })
        ));
    }

    #[test]
    fn expired_token_denied() {
        let (kp, mut token) = root_token();
        token.expires_at = Utc::now() - Duration::hours(1);
        token.sign(&kp);
        assert!(matches!(
            token.is_action_allowed("tool://x", "execute"),
            Err(MoatError::CapabilityExpired(_))
        ));
    }

    #[test]
    fn sign_and_verify() {
        let (kp, token) = root_token();
        assert!(token.verify_signature(&kp.identity).is_ok());
    }

    #[test]
    fn unsigned_token_fails_verification() {
        let kp = AgentKeypair::generate("issuer").unwrap();
        let token = CapabilityToken::root(kp.id(), Uuid::new_v4(), future(1));
        assert!(matches!(
            token.verify_signature(&kp.identity),
            Err(MoatError::TokenSignatureInvalid)
        ));
    }

    #[test]
    fn modified_after_signing_fails() {
        let (kp, mut token) = root_token();
        // Tamper with the token after signing
        token.allowed.push(ScopeEntry {
            resource: "file://*".into(),
            actions: vec!["write".into()],
        });
        assert!(token.verify_signature(&kp.identity).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (_kp, token) = root_token();
        let other_kp = AgentKeypair::generate("other").unwrap();
        assert!(token.verify_signature(&other_kp.identity).is_err());
    }

    #[test]
    fn attenuate_unsigned_parent_fails() {
        let token = CapabilityToken::root(Uuid::new_v4(), Uuid::new_v4(), future(1));
        let result = token.attenuate(
            Uuid::new_v4(),
            vec![],
            vec![],
            ResourceLimits::default(),
            10,
        );
        assert!(matches!(result, Err(MoatError::TokenSignatureInvalid)));
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let (_, token) = root_token();
        let b1 = token.canonical_bytes();
        let b2 = token.canonical_bytes();
        assert_eq!(b1, b2);
    }
}
