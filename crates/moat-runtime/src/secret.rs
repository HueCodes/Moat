//! Secret proxy: handle-based secret management.
//!
//! Agents never see raw secret values. Instead, they receive opaque `SecretHandle`s
//! that the runtime resolves at the point of use (e.g., injecting an API key
//! into an outgoing HTTP header). This prevents secrets from leaking into agent
//! memory, logs, or cross-agent messages.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use moat_core::MoatError;

/// An opaque handle that refers to a secret stored in the proxy.
/// The agent can pass this around but cannot extract the raw value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretHandle {
    pub name: String,
}

impl SecretHandle {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// An HTTP header injection instruction: the runtime replaces the handle
/// with the real secret value when making the actual request.
#[derive(Debug, Clone)]
pub struct HeaderInjection {
    pub header_name: String,
    pub secret_value: String,
}

/// The secret proxy holds secrets and controls which agents can resolve which handles.
pub struct SecretProxy {
    /// Secret storage: handle name -> raw value.
    secrets: HashMap<String, String>,
    /// Access control: handle name -> set of agent UUIDs that may resolve it.
    access: HashMap<String, HashSet<Uuid>>,
}

impl SecretProxy {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            access: HashMap::new(),
        }
    }

    /// Store a secret and grant access to specific agents.
    /// Returns a handle the agents can use to reference it.
    pub fn store(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        allowed_agents: Vec<Uuid>,
    ) -> SecretHandle {
        let name = name.into();
        self.secrets.insert(name.clone(), value.into());
        self.access
            .insert(name.clone(), allowed_agents.into_iter().collect());
        SecretHandle::new(name)
    }

    /// Resolve a handle to an HTTP header injection for a specific agent.
    /// Fails if the agent is not authorized or the handle doesn't exist.
    pub fn resolve_for_header(
        &self,
        handle: &SecretHandle,
        agent_id: Uuid,
        header_name: impl Into<String>,
    ) -> Result<HeaderInjection, MoatError> {
        let value = self.resolve(handle, agent_id)?;
        Ok(HeaderInjection {
            header_name: header_name.into(),
            secret_value: value,
        })
    }

    /// Internal resolution: checks access then returns the raw value.
    /// Only the runtime layer should call this -- never exposed to agents.
    fn resolve(&self, handle: &SecretHandle, agent_id: Uuid) -> Result<String, MoatError> {
        // Check the handle exists
        let value = self
            .secrets
            .get(&handle.name)
            .ok_or_else(|| MoatError::SecretHandleNotFound(handle.name.clone()))?;

        // Check agent is authorized
        let allowed = self
            .access
            .get(&handle.name)
            .ok_or_else(|| MoatError::SecretHandleNotFound(handle.name.clone()))?;

        if !allowed.contains(&agent_id) {
            return Err(MoatError::SecretAccessDenied {
                agent_id,
                handle: handle.name.clone(),
            });
        }

        Ok(value.clone())
    }

    /// Revoke an agent's access to a specific secret.
    pub fn revoke(&mut self, handle: &SecretHandle, agent_id: Uuid) {
        if let Some(agents) = self.access.get_mut(&handle.name) {
            agents.remove(&agent_id);
        }
    }

    /// Remove a secret entirely.
    pub fn remove(&mut self, handle: &SecretHandle) {
        self.secrets.remove(&handle.name);
        self.access.remove(&handle.name);
    }
}

impl Default for SecretProxy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_resolve() {
        let agent_a = Uuid::new_v4();
        let mut proxy = SecretProxy::new();
        let handle = proxy.store("api_key", "sk-12345", vec![agent_a]);

        let injection = proxy
            .resolve_for_header(&handle, agent_a, "Authorization")
            .unwrap();
        assert_eq!(injection.header_name, "Authorization");
        assert_eq!(injection.secret_value, "sk-12345");
    }

    #[test]
    fn unauthorized_agent_denied() {
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let mut proxy = SecretProxy::new();
        let handle = proxy.store("api_key", "sk-12345", vec![agent_a]);

        let result = proxy.resolve_for_header(&handle, agent_b, "Authorization");
        assert!(matches!(result, Err(MoatError::SecretAccessDenied { .. })));
    }

    #[test]
    fn nonexistent_handle() {
        let proxy = SecretProxy::new();
        let handle = SecretHandle::new("nonexistent");
        let result = proxy.resolve_for_header(&handle, Uuid::new_v4(), "X-Key");
        assert!(matches!(
            result,
            Err(MoatError::SecretHandleNotFound(_))
        ));
    }

    #[test]
    fn revoke_access() {
        let agent = Uuid::new_v4();
        let mut proxy = SecretProxy::new();
        let handle = proxy.store("key", "val", vec![agent]);

        assert!(proxy.resolve_for_header(&handle, agent, "X").is_ok());
        proxy.revoke(&handle, agent);
        assert!(matches!(
            proxy.resolve_for_header(&handle, agent, "X"),
            Err(MoatError::SecretAccessDenied { .. })
        ));
    }

    #[test]
    fn remove_secret() {
        let agent = Uuid::new_v4();
        let mut proxy = SecretProxy::new();
        let handle = proxy.store("key", "val", vec![agent]);

        proxy.remove(&handle);
        assert!(matches!(
            proxy.resolve_for_header(&handle, agent, "X"),
            Err(MoatError::SecretHandleNotFound(_))
        ));
    }
}
