//! moat-runtime: Sandbox runtime for Moat agents.
//!
//! Provides the Policy Enforcement Point (PEP), Wasm sandbox execution,
//! secret proxy, runtime monitor, and tamper-evident audit log.

pub mod audit;
pub mod monitor;
pub mod pep;
pub mod sandbox;
pub mod secret;

pub use audit::{AuditEventKind, AuditLog};
pub use monitor::{
    ActionPattern, AgentState, MonitorSnapshot, MonitorThresholds, RuntimeMonitor, WindowConfig,
};
pub use pep::{PepDecision, PepStage, PepState, PolicyEnforcementPoint};
pub use sandbox::{Sandbox, SandboxConfig, SandboxResult};
pub use secret::{SecretHandle, SecretProxy};
