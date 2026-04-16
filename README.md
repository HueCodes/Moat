# Moat Protocol

Cryptographically enforced, sandboxed agent-to-agent communication runtime in Rust.

Zero-trust from the ground up: every agent has an Ed25519 identity, every message is signed, every action is authorized via capability tokens with monotonic attenuation, and every decision is audit-logged in a tamper-evident SHA-256 hash chain.

## Why Moat?

Multi-agent systems are powerful but dangerous. A misbehaving agent can poison another's memory, escalate its own privileges, or drift from its original intent through a sequence of individually-reasonable actions. Moat treats every agent as untrusted by default and enforces security at the runtime level — not through prompts or conventions.

**Moat defends against five documented attack classes:**

| Attack | Defense |
|---|---|
| **Skill Poisoning** — malicious plugins replacing legitimate tools | Cryptographic identity verification at registration |
| **Indirect Prompt Injection** — external content hijacking control flow | Strict data/control plane separation via Wasm sandbox |
| **Memory Poisoning** — fabricated rules injected into persistent memory | Cross-sandbox state transfers treated as untrusted input |
| **Intent Drift** — individually reasonable actions escalating into unauthorized behavior | Runtime monitor tracking cumulative action trajectories |
| **Privilege Escalation** — incremental assembly of dangerous operations | OS-level confinement via Wasm sandbox + capability attenuation |

## Architecture

```
Agent A ──AuthenticatedMessage──> MessageRouter ──> Agent B
                                      │
                            PolicyEnforcementPoint
                            ├─ Stage 1: Signature verification + replay protection
                            ├─ Stage 2: Policy binding verification
                            └─ Stage 3: Capability token evaluation + chain walk
                                      │
                            AuditLog (SHA-256 hash chain)
                            RuntimeMonitor (FSM + sliding windows)
                            SecretProxy (handle-based injection)
                            Sandbox (Wasmtime + WASI)
```

### Crate map

| Crate | Purpose |
|---|---|
| [`moat-core`](crates/moat-core) | Identity, capability tokens, messages, errors (pure types, no IO) |
| [`moat-runtime`](crates/moat-runtime) | PEP, Wasm sandbox, audit log, runtime monitor, secret proxy |
| [`moat-relay`](crates/moat-relay) | Agent registry, message router, integration tests |
| [`moat-cli`](crates/moat-cli) | CLI tool (`moat identity`, `moat token`, `moat audit`) |

## Quick start

```bash
# Clone and build
git clone https://github.com/moat-protocol/moat.git
cd moat
cargo build --workspace

# Run the test suite (83 tests)
cargo test --workspace

# Try an example
cargo run --example orchestrated_pipeline -p moat-relay
```

### Create an agent identity and issue a scoped token

```rust
use chrono::{Duration, Utc};
use moat_core::{
    AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry,
};

// Every agent gets an Ed25519 keypair
let coordinator = AgentKeypair::generate("coordinator").unwrap();
let worker = AgentKeypair::generate("worker").unwrap();

// Coordinator creates a root token with broad permissions
let mut root_token = CapabilityToken::root(
    coordinator.id(),
    coordinator.id(),
    Utc::now() + Duration::hours(1),
);
root_token.allowed = vec![ScopeEntry {
    resource: "tool://analyze".into(),
    actions: vec!["read".into(), "execute".into()],
}];
root_token.sign(&coordinator);

// Attenuate: worker gets read-only access, less fuel, less memory.
// Attenuation is monotonic — scope can only narrow, never widen.
let mut worker_token = root_token.attenuate(
    worker.id(),
    vec![ScopeEntry {
        resource: "tool://analyze".into(),
        actions: vec!["read".into()],  // no "execute"
    }],
    vec![],  // no additional denials
    ResourceLimits {
        max_fuel: Some(1_000_000),
        max_memory_bytes: Some(32 * 1024 * 1024),
        ..Default::default()
    },
    10,  // max delegation depth
).unwrap();
worker_token.sign(&coordinator);
```

### Send an authenticated message through the relay

```rust
use moat_core::{AuthenticatedMessage, PolicyBinding};
use moat_relay::MessageRouter;
use moat_runtime::MonitorThresholds;

let policy = PolicyBinding::new("v1", b"policy document");
let mut router = MessageRouter::new(policy.clone(), MonitorThresholds::default());

// Register agents and trust the coordinator
router.registry.register(coordinator.identity.clone()).unwrap();
router.registry.register(worker.identity.clone()).unwrap();
router.pep.register_identity(coordinator.identity.clone());
router.pep.register_identity(worker.identity.clone());
router.pep.add_trusted_root(coordinator.id());

// Worker sends a signed message
let msg = AuthenticatedMessage::create(
    &worker,
    coordinator.id(),
    b"analysis complete".to_vec(),
    worker_token.clone(),
    vec![root_token.clone()],  // token chain for verification
    policy.clone(),
    1,  // sequence number
).unwrap();

// Route through PEP — signature, policy, and capability are all verified
let decision = router.route(&msg, "tool://analyze", "read").unwrap();
assert!(decision.allowed);
```

## CLI

```bash
# Generate a new agent identity
moat identity generate --name my-agent

# Show identity details
moat identity show --name my-agent

# Create a capability token
moat token create --issuer my-agent --subject worker \
    --resource "tool://analyze" --actions read,execute \
    --max-fuel 1000000 --expires-in 1h

# Attenuate an existing token (narrow scope)
moat token attenuate --token <token-file> \
    --subject sub-worker --resource "tool://analyze" --actions read

# Verify token signature chain
moat token verify --token <token-file>

# Verify audit log integrity
moat audit verify --path audit.jsonl
```

## Security model

Moat's security rests on three invariants:

1. **Capability tokens are always signed.** Unsigned tokens are rejected. Token delegation chains are verified back to trusted roots.
2. **Attenuation is monotonic.** A child token's scope is always a subset of its parent's. Denials are additive. Resource limits can only tighten.
3. **The audit log is tamper-evident.** Every PEP decision, sandbox action, and secret resolution is recorded in a SHA-256 hash chain. Modifying any entry breaks all subsequent hashes.

Additional guarantees:
- **Replay protection**: per-sender monotonic sequence numbers
- **Secret isolation**: agents receive opaque handles; the runtime injects values at the point of use
- **Sandbox default-deny**: no filesystem or network access unless explicitly granted by capability token
- **Pure-Rust stack**: no C bindings, no OpenSSL, no ring — auditable all the way down

See [`spec/PROTOCOL.md`](spec/PROTOCOL.md) for the formal protocol specification and threat model.

## Dependencies

All pure Rust:

| Category | Crates |
|---|---|
| Crypto | `ed25519-dalek` 2, `sha2` 0.10, `rand` 0.8 |
| Sandbox | `wasmtime` 29, `wasmtime-wasi` 29, `cap-std` 3 |
| Serialization | `serde` 1, `serde_json` 1 |
| Async | `tokio` 1 |
| Errors | `thiserror` 2 |
| Observability | `tracing` 0.1 |
| CLI | `clap` 4 |

## Known limitations (MVP)

- Wildcard matching is prefix-only (`tool://*` matches `tool://anything`, not `tool://*/read`)
- WASI Preview2 network APIs not yet available — `network_allowed` flag is documented but not enforced
- Single-process relay (no multi-node federation)
- MAPL policy language not yet implemented (policies are Rust structs)
- No web UI/dashboard

## Contributing

```bash
# The full gate — run before every commit
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

[Apache-2.0](LICENSE)
