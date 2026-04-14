//! Error types for the Moat protocol.
//!
//! All errors are non-exhaustive to allow adding variants without breaking changes.
//! Crypto-related errors intentionally avoid leaking internal state.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MoatError {
    // --- Identity & Crypto ---
    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("identity not found: {0}")]
    IdentityNotFound(Uuid),

    #[error("keypair generation failed: {0}")]
    KeyGeneration(String),

    // --- Capability ---
    #[error("capability token expired at {0}")]
    CapabilityExpired(chrono::DateTime<chrono::Utc>),

    #[error("action '{action}' denied on resource '{resource}'")]
    ActionDenied { resource: String, action: String },

    #[error("attenuation violation: child cannot broaden parent scope")]
    AttenuationViolation,

    #[error("capability chain depth {depth} exceeds maximum {max}")]
    DelegationDepthExceeded { depth: u32, max: u32 },

    // --- Policy ---
    #[error("policy binding verification failed: expected {expected}, got {actual}")]
    PolicyBindingMismatch { expected: String, actual: String },

    #[error("policy evaluation denied: {reason}")]
    PolicyDenied { reason: String },

    // --- Message ---
    #[error("replay detected: sequence {got} is not greater than {last_seen}")]
    ReplayDetected { got: u64, last_seen: u64 },

    #[error("message expired at {0}")]
    MessageExpired(chrono::DateTime<chrono::Utc>),

    // --- Secret ---
    #[error("secret handle not found: {0}")]
    SecretHandleNotFound(String),

    #[error("secret access denied for agent {agent_id} on handle {handle}")]
    SecretAccessDenied { agent_id: Uuid, handle: String },

    // --- Monitor ---
    #[error("resource limit exceeded: {resource} (limit: {limit}, current: {current})")]
    ResourceLimitExceeded {
        resource: String,
        limit: u64,
        current: u64,
    },

    #[error("trajectory alert: {0}")]
    TrajectoryAlert(String),

    // --- Audit ---
    #[error("audit chain integrity violated at entry {index}")]
    AuditChainBroken { index: u64 },

    // --- Serialization ---
    #[error("serialization error: {0}")]
    Serialization(String),

    // --- Sandbox ---
    #[error("sandbox error: {0}")]
    Sandbox(String),
}

impl From<serde_json::Error> for MoatError {
    fn from(e: serde_json::Error) -> Self {
        MoatError::Serialization(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for MoatError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        // Intentionally discard details to avoid leaking crypto internals
        MoatError::SignatureInvalid
    }
}
