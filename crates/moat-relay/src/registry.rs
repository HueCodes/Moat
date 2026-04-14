//! Agent registry: tracks registered agents and their identities.

use std::collections::HashMap;
use uuid::Uuid;

use moat_core::{AgentIdentity, MoatError};

/// Central registry of agent identities.
pub struct AgentRegistry {
    agents: HashMap<Uuid, AgentIdentity>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    /// Register an agent. Returns error if the ID is already registered.
    pub fn register(&mut self, identity: AgentIdentity) -> Result<(), MoatError> {
        let id = identity.id;
        if self.agents.contains_key(&id) {
            // Idempotent: re-registration of same ID is a no-op
            tracing::warn!(agent_id = %id, "agent already registered, skipping");
            return Ok(());
        }
        tracing::info!(agent_id = %id, name = %identity.name, "registered agent");
        self.agents.insert(id, identity);
        Ok(())
    }

    pub fn get(&self, id: &Uuid) -> Result<&AgentIdentity, MoatError> {
        self.agents.get(id).ok_or(MoatError::IdentityNotFound(*id))
    }

    pub fn contains(&self, id: &Uuid) -> bool {
        self.agents.contains_key(id)
    }

    pub fn list(&self) -> Vec<&AgentIdentity> {
        self.agents.values().collect()
    }

    pub fn remove(&mut self, id: &Uuid) -> Option<AgentIdentity> {
        self.agents.remove(id)
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moat_core::AgentKeypair;

    #[test]
    fn register_and_lookup() {
        let kp = AgentKeypair::generate("test").unwrap();
        let mut reg = AgentRegistry::new();
        reg.register(kp.identity.clone()).unwrap();
        assert!(reg.contains(&kp.id()));
        assert!(reg.get(&kp.id()).is_ok());
    }

    #[test]
    fn unknown_agent() {
        let reg = AgentRegistry::new();
        let result = reg.get(&Uuid::new_v4());
        assert!(matches!(result, Err(MoatError::IdentityNotFound(_))));
    }

    #[test]
    fn idempotent_registration() {
        let kp = AgentKeypair::generate("test").unwrap();
        let mut reg = AgentRegistry::new();
        reg.register(kp.identity.clone()).unwrap();
        reg.register(kp.identity.clone()).unwrap(); // no error
        assert_eq!(reg.list().len(), 1);
    }
}
