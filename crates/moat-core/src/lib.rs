//! moat-core: Core types for the Moat agent sandbox protocol.
//!
//! Provides cryptographic identity, capability tokens with monotonic attenuation,
//! authenticated messages (CAM), and the policy/error types that all other Moat
//! crates build on.

pub mod capability;
pub mod error;
pub mod identity;
pub mod message;

pub use capability::{CapabilityToken, ResourceLimits, ScopeEntry};
pub use error::MoatError;
pub use identity::{AgentIdentity, AgentKeypair};
pub use message::{AuthenticatedMessage, PolicyBinding};
