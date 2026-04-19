//! # Moat — the missing security layer for AI agents
//!
//! Moat is a cryptographically enforced, sandboxed runtime for agent-to-agent
//! communication. Think *mTLS for AI agents*: every agent has an Ed25519 identity,
//! every message is signed, every capability is attenuated monotonically across
//! delegation boundaries, and every action is recorded in a tamper-evident audit log.
//!
//! This crate is the **recommended entry point**. It re-exports the types from
//! [`moat_core`], [`moat_runtime`], and [`moat_relay`], and provides a high-level
//! [`Moat`] facade that hides most of the wiring for common cases.
//!
//! ## Quickstart
//!
//! ```no_run
//! use moat_protocol::{AgentKeypair, CapabilityToken, Moat, ResourceLimits, ScopeEntry};
//! use chrono::{Duration, Utc};
//!
//! # fn main() -> Result<(), moat_protocol::MoatError> {
//! let coordinator = AgentKeypair::generate("coordinator")?;
//! let worker      = AgentKeypair::generate("worker")?;
//!
//! // One call to build the whole runtime: registry, PEP, audit log, monitor.
//! let mut moat = Moat::builder()
//!     .agent(coordinator.identity.clone())
//!     .agent(worker.identity.clone())
//!     .trust_root(coordinator.id())
//!     .build()?;
//!
//! // Issue a signed token, attenuate it for the worker.
//! let mut root = CapabilityToken::root(
//!     coordinator.id(), coordinator.id(), Utc::now() + Duration::hours(1),
//! );
//! root.allowed = vec![ScopeEntry {
//!     resource: "tool://analyze".into(),
//!     actions:  vec!["read".into(), "execute".into()],
//! }];
//! root.sign(&coordinator);
//!
//! let mut worker_token = root.attenuate(
//!     worker.id(),
//!     vec![ScopeEntry { resource: "tool://analyze".into(), actions: vec!["read".into()] }],
//!     vec![],
//!     ResourceLimits::default(),
//!     10,
//! )?;
//! worker_token.sign(&coordinator);
//! # Ok(())
//! # }
//! ```
//!
//! For full routing and verification see the `orchestrated_pipeline` example in
//! the `moat-relay` crate.

mod facade;

pub use facade::{Moat, MoatBuilder};

pub use moat_core::{
    AgentIdentity, AgentKeypair, AuthenticatedMessage, CapabilityToken, MoatError, PolicyBinding,
    ResourceLimits, ScopeEntry,
};

pub use moat_runtime::monitor::MonitorAlert;
pub use moat_runtime::{
    ActionPattern, AgentState, AuditEventKind, AuditLog, MonitorSnapshot, MonitorThresholds,
    PepDecision, PepStage, PepState, PolicyEnforcementPoint, RuntimeMonitor, Sandbox,
    SandboxConfig, SandboxResult, SecretHandle, SecretProxy, WindowConfig,
};

pub use moat_relay::router::{RouteResult, RouterLimits};
pub use moat_relay::{AgentRegistry, MessageRouter};
