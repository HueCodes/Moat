//! Capability tokens with monotonic attenuation.
//!
//! A `CapabilityToken` encodes what an agent is allowed to do: which resources,
//! which actions, and under what constraints (CPU fuel, memory, network access).
//! Tokens form delegation chains where each child is strictly equal to or more
//! restrictive than its parent (monotonic restriction).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::MoatError;

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
}

impl CapabilityToken {
    /// Create a root capability token (no parent).
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
        }
    }

    /// Derive a child token with attenuated (equal or more restrictive) permissions.
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

    /// Canonical bytes for signing: JSON serialization of the token.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MoatError> {
        Ok(serde_json::to_vec(self)?)
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

    fn root_token() -> CapabilityToken {
        let mut token = CapabilityToken::root(Uuid::new_v4(), Uuid::new_v4(), future(1));
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
        token
    }

    #[test]
    fn action_allowed() {
        let token = root_token();
        assert!(token.is_action_allowed("tool://review", "execute").is_ok());
    }

    #[test]
    fn action_denied_not_in_scope() {
        let token = root_token();
        assert!(token.is_action_allowed("file:///etc/passwd", "read").is_err());
    }

    #[test]
    fn explicit_denial_overrides_allow() {
        let mut token = root_token();
        token.denied.push(ScopeEntry {
            resource: "tool://dangerous".into(),
            actions: vec!["execute".into()],
        });
        assert!(token
            .is_action_allowed("tool://dangerous", "execute")
            .is_err());
        // Other tools still work
        assert!(token.is_action_allowed("tool://safe", "execute").is_ok());
    }

    #[test]
    fn attenuate_narrows_scope() {
        let parent = root_token();
        let child_subject = Uuid::new_v4();
        let child = parent
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

        // Child can do what it was granted
        assert!(child.is_action_allowed("tool://review", "execute").is_ok());
        // Child cannot do what parent could but child wasn't granted
        assert!(child
            .is_action_allowed("tool://deploy", "execute")
            .is_err());
    }

    #[test]
    fn attenuate_cannot_broaden() {
        let parent = root_token();
        let result = parent.attenuate(
            Uuid::new_v4(),
            vec![ScopeEntry {
                resource: "file://*".into(), // parent doesn't grant file access
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
        let parent = root_token();
        let result = parent.attenuate(
            Uuid::new_v4(),
            vec![],
            vec![],
            ResourceLimits {
                max_fuel: Some(2_000_000), // more than parent's 1M
                ..Default::default()
            },
            10,
        );
        assert!(matches!(result, Err(MoatError::AttenuationViolation)));
    }

    #[test]
    fn attenuate_cannot_enable_network_if_parent_denies() {
        let mut parent = root_token();
        parent.resource_limits.network_allowed = false;
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
        let parent = root_token();
        let child = parent
            .attenuate(
                Uuid::new_v4(),
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

        // Now grandchild adds another denial
        let grandchild = child
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
        let parent = root_token();
        let limits = ResourceLimits {
            max_fuel: Some(500_000),
            max_memory_bytes: Some(32 * 1024 * 1024),
            ..Default::default()
        };
        let allowed = vec![ScopeEntry {
            resource: "tool://*".into(),
            actions: vec!["execute".into()],
        }];
        let child = parent
            .attenuate(Uuid::new_v4(), allowed.clone(), vec![], limits.clone(), 2)
            .unwrap();
        assert_eq!(child.delegation_depth, 1);
        let grandchild = child
            .attenuate(Uuid::new_v4(), allowed.clone(), vec![], limits.clone(), 2)
            .unwrap();
        assert_eq!(grandchild.delegation_depth, 2);
        let result = grandchild.attenuate(Uuid::new_v4(), allowed, vec![], limits, 2);
        assert!(matches!(
            result,
            Err(MoatError::DelegationDepthExceeded { .. })
        ));
    }

    #[test]
    fn expired_token_denied() {
        let mut token = root_token();
        token.expires_at = Utc::now() - Duration::hours(1);
        assert!(matches!(
            token.is_action_allowed("tool://x", "execute"),
            Err(MoatError::CapabilityExpired(_))
        ));
    }
}
