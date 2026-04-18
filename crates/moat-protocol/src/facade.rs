//! High-level [`Moat`] facade.
//!
//! Wraps [`MessageRouter`] with an ergonomic builder so typical setup — register
//! agents, add trusted roots, wire optional persistence — takes a few chained
//! calls instead of a dozen lines of plumbing. The underlying router is still
//! reachable via [`Moat::router`] / [`Moat::router_mut`] for power-user needs.

use std::path::PathBuf;

use uuid::Uuid;

use moat_core::{AgentIdentity, AuthenticatedMessage, MoatError, PolicyBinding};
use moat_relay::router::{RouteResult, RouterLimits};
use moat_relay::MessageRouter;
use moat_runtime::monitor::MonitorAlert;
use moat_runtime::{AuditLog, MonitorThresholds, PolicyEnforcementPoint, RuntimeMonitor};

/// High-level facade around [`MessageRouter`].
///
/// Construct via [`Moat::builder`]. For direct access to the underlying router
/// (custom monitor configuration, registry inspection, etc.), use
/// [`Moat::router`] and [`Moat::router_mut`].
pub struct Moat {
    router: MessageRouter,
}

impl Moat {
    /// Start building a new Moat runtime.
    pub fn builder() -> MoatBuilder {
        MoatBuilder::default()
    }

    /// Register an agent identity with both the registry and the PEP in one call.
    pub fn register_agent(&mut self, identity: AgentIdentity) -> Result<(), MoatError> {
        self.router.registry.register(identity.clone())?;
        self.router.pep.register_identity(identity);
        Ok(())
    }

    /// Mark an agent as a trusted capability-token issuing root.
    ///
    /// Capability chains presented to the PEP must terminate at one of these
    /// roots, otherwise the message is rejected at stage 3.
    pub fn trust_root(&mut self, agent_id: Uuid) {
        self.router.pep.add_trusted_root(agent_id);
    }

    /// Route an authenticated message through the PEP.
    ///
    /// On success the router has: verified the message signature, checked replay
    /// protection, verified the policy binding, walked the capability-token chain
    /// back to a trusted root, recorded the decision in the audit log, and
    /// updated the runtime monitor.
    pub fn route(
        &mut self,
        message: &AuthenticatedMessage,
        resource: &str,
        action: &str,
    ) -> Result<RouteResult, MoatError> {
        self.router.route(message, resource, action)
    }

    /// Borrow the audit log (for `verify_integrity`, iteration, export).
    pub fn audit_log(&self) -> &AuditLog {
        &self.router.audit_log
    }

    /// Borrow the runtime monitor (for snapshot, alert inspection).
    pub fn monitor(&self) -> &RuntimeMonitor {
        &self.router.monitor
    }

    /// Recent monitor alerts emitted during routing (most recent last).
    pub fn alerts(&self) -> &[MonitorAlert] {
        self.router.monitor.alerts()
    }

    /// Borrow the underlying [`MessageRouter`] — escape hatch for advanced use.
    pub fn router(&self) -> &MessageRouter {
        &self.router
    }

    /// Mutably borrow the underlying [`MessageRouter`] — escape hatch for advanced use.
    pub fn router_mut(&mut self) -> &mut MessageRouter {
        &mut self.router
    }
}

/// Builder for [`Moat`].
///
/// All fields are optional except at least one trusted root if you plan to
/// route capability-bearing messages (the PEP will otherwise reject every
/// message at stage 3 for lack of a verifiable chain endpoint).
#[derive(Default)]
pub struct MoatBuilder {
    policy: Option<PolicyBinding>,
    thresholds: Option<MonitorThresholds>,
    limits: Option<RouterLimits>,
    agents: Vec<AgentIdentity>,
    trusted_roots: Vec<Uuid>,
    audit_path: Option<PathBuf>,
    pep_state_path: Option<PathBuf>,
}

impl MoatBuilder {
    /// Set the active policy binding. If unset, a default `moat-default-v1`
    /// binding is used.
    pub fn policy(mut self, policy: PolicyBinding) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set monitor thresholds (action counts, cost caps, etc.).
    pub fn monitor_thresholds(mut self, thresholds: MonitorThresholds) -> Self {
        self.thresholds = Some(thresholds);
        self
    }

    /// Set router-level limits (payload size, message age, rate limiting).
    pub fn router_limits(mut self, limits: RouterLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Register an agent identity. Adds to both the registry and the PEP.
    pub fn agent(mut self, identity: AgentIdentity) -> Self {
        self.agents.push(identity);
        self
    }

    /// Register multiple agent identities at once.
    pub fn agents<I: IntoIterator<Item = AgentIdentity>>(mut self, identities: I) -> Self {
        self.agents.extend(identities);
        self
    }

    /// Mark an agent as a trusted capability-token root.
    pub fn trust_root(mut self, agent_id: Uuid) -> Self {
        self.trusted_roots.push(agent_id);
        self
    }

    /// Persist the audit log to `path` (JSONL, fsync on append).
    pub fn persist_audit_to(mut self, path: PathBuf) -> Self {
        self.audit_path = Some(path);
        self
    }

    /// Persist PEP sequence-number state to `path`.
    pub fn persist_pep_state_to(mut self, path: PathBuf) -> Self {
        self.pep_state_path = Some(path);
        self
    }

    /// Finalize and construct the [`Moat`] runtime.
    pub fn build(self) -> Result<Moat, MoatError> {
        let policy = self
            .policy
            .unwrap_or_else(|| PolicyBinding::new("moat-default-v1", b"moat default policy"));
        let thresholds = self.thresholds.unwrap_or_default();
        let limits = self.limits.unwrap_or_default();

        let mut router = MessageRouter::with_limits(policy.clone(), thresholds, limits);

        if let Some(path) = self.audit_path {
            router.audit_log = AuditLog::with_persistence(path)?;
        }
        if let Some(path) = self.pep_state_path {
            router.pep = PolicyEnforcementPoint::with_persistence(policy, path)?;
        }

        for identity in self.agents {
            router.registry.register(identity.clone())?;
            router.pep.register_identity(identity);
        }
        for root in self.trusted_roots {
            router.pep.add_trusted_root(root);
        }

        Ok(Moat { router })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use moat_core::{AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry};

    fn self_issued_root(issuer: &AgentKeypair) -> CapabilityToken {
        let mut token = CapabilityToken::root(
            issuer.id(),
            issuer.id(),
            Utc::now() + Duration::hours(1),
        );
        token.allowed = vec![ScopeEntry {
            resource: "tool://analyze".into(),
            actions: vec!["read".into(), "execute".into()],
        }];
        token.sign(issuer);
        token
    }

    #[test]
    fn builder_registers_agents_and_roots() {
        let coord = AgentKeypair::generate("coord").unwrap();
        let worker = AgentKeypair::generate("worker").unwrap();

        let moat = Moat::builder()
            .agent(coord.identity.clone())
            .agent(worker.identity.clone())
            .trust_root(coord.id())
            .build()
            .unwrap();

        assert!(moat.router().registry.contains(&coord.id()));
        assert!(moat.router().registry.contains(&worker.id()));
    }

    #[test]
    fn end_to_end_route_via_facade() {
        let coord = AgentKeypair::generate("coord").unwrap();
        let worker = AgentKeypair::generate("worker").unwrap();

        let policy = PolicyBinding::new("test-v1", b"test policy");
        let mut moat = Moat::builder()
            .policy(policy.clone())
            .agent(coord.identity.clone())
            .agent(worker.identity.clone())
            .trust_root(coord.id())
            .build()
            .unwrap();

        let root_token = self_issued_root(&coord);

        // Worker cannot broaden — attenuate to read-only with tighter fuel.
        let mut worker_token = root_token
            .attenuate(
                worker.id(),
                vec![ScopeEntry {
                    resource: "tool://analyze".into(),
                    actions: vec!["read".into()],
                }],
                vec![],
                ResourceLimits::default(),
                10,
            )
            .unwrap();
        worker_token.sign(&coord);

        let msg = AuthenticatedMessage::create(
            &worker,
            coord.id(),
            b"analysis done".to_vec(),
            worker_token,
            vec![root_token],
            policy,
            1,
        )
        .unwrap();

        let result = moat.route(&msg, "tool://analyze", "read").unwrap();
        assert!(result.allowed, "expected allow, got {:?}", result);
    }

    #[test]
    fn escape_hatch_router_mut_still_works() {
        let coord = AgentKeypair::generate("coord").unwrap();
        let mut moat = Moat::builder().agent(coord.identity.clone()).build().unwrap();
        // Power user can still tweak monitor thresholds post-build.
        moat.router_mut()
            .monitor
            .update_thresholds(MonitorThresholds::default());
    }
}
