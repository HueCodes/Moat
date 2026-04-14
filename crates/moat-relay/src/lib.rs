//! moat-relay: Agent registry, message routing, and discovery.
//!
//! The relay is the central coordination point where agents register their
//! identities and capabilities. Messages between agents are routed through
//! the relay, which delegates to the PEP for authorization.

pub mod registry;
pub mod router;

pub use registry::AgentRegistry;
pub use router::MessageRouter;
