//! WebAssembly bindings for Moat core types.
//!
//! Exposed surface (JS names via `wasm-bindgen`):
//! - `generateKeypair(name)` — create a fresh Ed25519 identity
//! - `rootToken(signingKeyHex, subjectId, allowedScope, expiresSecs)` — sign a root capability
//! - `attenuate(parentTokenJson, signerKeyHex, subjectId, allowedScope)` — sign a narrower child
//! - `verifyTokenSignature(tokenJson, identityJson)` — verify issuer signature
//! - `verifyMessage(messageJson, identityJson)` — verify CAM sender signature
//!
//! Inputs/outputs are JSON strings. That keeps the TS API portable across Node,
//! browsers, and bundlers without serde-wasm-bindgen ceremony. All errors are
//! surfaced as JS `Error` instances with a human-readable message.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use moat_core::{
    AgentIdentity, AgentKeypair, AuthenticatedMessage, CapabilityToken, ResourceLimits, ScopeEntry,
};

/// Install a panic hook that routes Rust panics to `console.error`.
///
/// Call once at JS startup — optional but strongly recommended.
#[wasm_bindgen(js_name = installPanicHook)]
pub fn install_panic_hook() {
    #[cfg(all(target_arch = "wasm32", feature = "console_error_panic_hook"))]
    console_error_panic_hook::set_once();
}

fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    JsError::new(&e.to_string()).into()
}

#[derive(Serialize)]
struct KeypairOut {
    id: String,
    name: String,
    public_key_hex: String,
    signing_key_hex: String,
}

/// Generate a new Ed25519 keypair.
///
/// Returns a JSON string `{ id, name, public_key_hex, signing_key_hex }`.
/// The `signing_key_hex` is the 32-byte seed; treat it as a secret.
#[wasm_bindgen(js_name = generateKeypair)]
pub fn generate_keypair(name: &str) -> Result<String, JsValue> {
    let kp = AgentKeypair::generate(name).map_err(to_js_error)?;
    let out = KeypairOut {
        id: kp.id().to_string(),
        name: kp.identity.name.clone(),
        public_key_hex: hex(&kp.identity.public_key),
        signing_key_hex: hex(&kp.signing_key_bytes()),
    };
    serde_json::to_string(&out).map_err(to_js_error)
}

#[derive(Deserialize)]
struct ScopeIn {
    resource: String,
    actions: Vec<String>,
}

/// Sign a new root capability token.
///
/// `signing_key_hex` must be the 32-byte seed returned by `generateKeypair`.
/// `allowed_json` is a JSON array of `{ resource, actions }` entries.
#[wasm_bindgen(js_name = rootToken)]
pub fn root_token(
    signing_key_hex: &str,
    name: &str,
    subject_id: &str,
    allowed_json: &str,
    expires_secs_from_now: f64,
) -> Result<String, JsValue> {
    let kp = keypair_from_hex(signing_key_hex, name)?;
    let subject = parse_uuid(subject_id)?;
    let allowed = parse_scope(allowed_json)?;
    let expires_at = utc_from_secs(expires_secs_from_now);

    let mut token = CapabilityToken::root(kp.id(), subject, expires_at);
    token.allowed = allowed;
    token.sign(&kp);
    serde_json::to_string(&token).map_err(to_js_error)
}

/// Attenuate an existing token and sign with the delegator's key.
///
/// The delegator must be the `subject_id` of the parent token; otherwise the
/// signature won't validate. The PEP enforces monotonic restriction regardless
/// of what the caller passes here — this function will also reject broadening
/// at construction time via `attenuate`'s own checks.
#[wasm_bindgen(js_name = attenuateToken)]
pub fn attenuate_token(
    parent_json: &str,
    signer_key_hex: &str,
    signer_name: &str,
    subject_id: &str,
    allowed_json: &str,
    max_depth: u32,
) -> Result<String, JsValue> {
    let parent: CapabilityToken = serde_json::from_str(parent_json).map_err(to_js_error)?;
    let signer = keypair_from_hex(signer_key_hex, signer_name)?;
    let subject = parse_uuid(subject_id)?;
    let allowed = parse_scope(allowed_json)?;

    let mut child = parent
        .attenuate(
            subject,
            allowed,
            vec![],
            parent.resource_limits.clone(),
            max_depth,
        )
        .map_err(to_js_error)?;
    child.sign(&signer);
    serde_json::to_string(&child).map_err(to_js_error)
}

#[derive(Deserialize)]
struct IdentityIn {
    id: String,
    name: String,
    public_key_hex: String,
}

/// Verify a capability token's issuer signature against an identity.
///
/// Returns `true` on success, `false` if signature doesn't match. Throws if
/// the input JSON is malformed.
#[wasm_bindgen(js_name = verifyTokenSignature)]
pub fn verify_token_signature(token_json: &str, identity_json: &str) -> Result<bool, JsValue> {
    let token: CapabilityToken = serde_json::from_str(token_json).map_err(to_js_error)?;
    let identity = identity_from_json(identity_json)?;
    Ok(token.verify_signature(&identity).is_ok())
}

/// Verify an authenticated message's sender signature.
#[wasm_bindgen(js_name = verifyMessage)]
pub fn verify_message(message_json: &str, identity_json: &str) -> Result<bool, JsValue> {
    let msg: AuthenticatedMessage = serde_json::from_str(message_json).map_err(to_js_error)?;
    let identity = identity_from_json(identity_json)?;
    Ok(msg.verify_signature(&identity).is_ok())
}

/// Return the free resource-limit defaults as JSON for TS callers.
#[wasm_bindgen(js_name = defaultResourceLimits)]
pub fn default_resource_limits() -> Result<String, JsValue> {
    serde_json::to_string(&ResourceLimits::default()).map_err(to_js_error)
}

// ---- helpers ----

fn parse_uuid(s: &str) -> Result<uuid::Uuid, JsValue> {
    uuid::Uuid::parse_str(s).map_err(to_js_error)
}

fn parse_scope(json: &str) -> Result<Vec<ScopeEntry>, JsValue> {
    let entries: Vec<ScopeIn> = serde_json::from_str(json).map_err(to_js_error)?;
    Ok(entries
        .into_iter()
        .map(|e| ScopeEntry {
            resource: e.resource,
            actions: e.actions,
        })
        .collect())
}

fn utc_from_secs(secs_from_now: f64) -> DateTime<Utc> {
    Utc::now() + Duration::milliseconds((secs_from_now * 1000.0) as i64)
}

fn keypair_from_hex(signing_key_hex: &str, name: &str) -> Result<AgentKeypair, JsValue> {
    let bytes = unhex(signing_key_hex)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("signing key must be 32 bytes (64 hex chars)"))?;
    let signing = SigningKey::from_bytes(&arr);
    let verifying = signing.verifying_key();
    let identity = AgentIdentity {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        public_key: verifying.to_bytes().to_vec(),
        attestations: Vec::new(),
        created_at: Utc::now(),
    };
    // NB: id is regenerated here because we don't round-trip it through signing_key_hex.
    // For workflows that must preserve id, round-trip via the full keypair JSON instead.
    Ok(AgentKeypair::from_parts(identity, signing))
}

fn identity_from_json(json: &str) -> Result<AgentIdentity, JsValue> {
    let v: IdentityIn = serde_json::from_str(json).map_err(to_js_error)?;
    Ok(AgentIdentity {
        id: parse_uuid(&v.id)?,
        name: v.name,
        public_key: unhex(&v.public_key_hex)?,
        attestations: Vec::new(),
        created_at: Utc::now(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, JsValue> {
    if !s.len().is_multiple_of(2) {
        return Err(JsError::new("hex string must have even length").into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_js_error)
}
