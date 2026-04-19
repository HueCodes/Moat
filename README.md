# Moat

Moat is a security runtime for AI agent frameworks (MCP, LangChain, CrewAI) that adds cryptographic identity, capability-bound authorization, sandboxed execution, and tamper-evident auditing to multi-agent systems. Each agent has an Ed25519 keypair, every message is signed and replay-protected, every capability delegation is monotonically attenuated, every untrusted action runs in a Wasm sandbox, and every decision is appended to a SHA-256 hash chain.

## Features

* **Ed25519 Identity**: Per-agent keypairs with deterministic IDs derived from public keys
* **Capability Tokens**: Signed, expiring, scoped grants with monotonic attenuation enforced by construction
* **Three-Stage PEP**: Signature and replay verification, policy binding, capability evaluation, in that order
* **Wasm Sandbox**: `wasmtime` + WASI Preview1 with fuel limits, memory caps, default-deny filesystem and network
* **Audit Log**: Append-only SHA-256 hash chain with optional JSONL persistence
* **Runtime Monitor**: FSM transitions, sliding-window rate tracking, cross-agent pattern detection
* **Secret Proxy**: Per-agent ACLs, opaque handles, point-of-use injection, revocable at runtime
* **Replay Protection**: Per-sender monotonic sequence numbers, persisted across restarts
* **Router**: Rate limiting, payload size caps, timestamp expiry, recipient existence checks
* **Pure Rust**: No C bindings, no OpenSSL, no ring; the primitive stack is auditable
* **WebAssembly Bindings**: TypeScript and JavaScript API via `wasm-bindgen`, published as `@moat/core`

## Security Model

Three invariants enforced by construction:

| Invariant | Mechanism |
|-----------|-----------|
| Capability tokens are always signed | Unsigned tokens rejected; chains verified back to a trusted root |
| Attenuation is monotonic | Children narrow scope only; denials are additive; resource limits only tighten |
| Audit log is tamper-evident | SHA-256 hash chain breaks on any retroactive mutation |

### Attack Coverage

| Attack Class | Defense |
|--------------|---------|
| Skill poisoning (malicious plugins replacing legitimate tools) | Signed identity at registration; PEP rejects unknown issuers |
| Indirect prompt injection (external content hijacking control flow) | Wasm sandbox enforces strict data and control plane separation |
| Memory poisoning (fabricated rules injected across sessions) | Cross-sandbox state treated as untrusted input |
| Intent drift (benign actions escalating over time) | Runtime monitor tracks cumulative trajectories and FSM transitions |
| Privilege escalation (incremental assembly of dangerous ops) | OS-level confinement plus monotonic capability attenuation |

Grounded in the threat model from Authenticated Workflows (Rajagopalan and Rao, 2026), Taming OpenClaw (Deng et al., 2026), AgentGuard (Koohestani, ASE 2025), and NVIDIA 2026 agent security guidance.

## Performance

Measured on Apple M2, release mode, `criterion` benches (`cargo bench -p moat-core`):

| Operation | Time | Throughput |
|-----------|------|------------|
| `CapabilityToken::sign` | 14.4 µs | ~69k/s |
| `CapabilityToken::verify_signature` | 32.4 µs | ~31k/s |
| `CapabilityToken::is_action_allowed` | 40 ns | ~25M/s |
| `AuthenticatedMessage::create` (256 B payload) | 14.2 µs | ~70k/s |
| `AuthenticatedMessage::verify_signature` (256 B payload) | 31.5 µs | ~32k/s |

A single core handles roughly 30,000 authenticated messages per second end-to-end before any business logic runs. Ed25519 verification dominates; canonical-bytes SHA-256 prehash and UUID copies are noise.

## Installation

### Prerequisites
* Rust toolchain (1.75+)

### Build
```bash
git clone https://github.com/HueCodes/Moat.git
cd Moat
cargo build --workspace
cargo test --workspace
```

86 tests across 6 crates.

## Usage

### CLI

```bash
# Generate an agent identity
moat identity generate --name alice

# Issue a root capability
moat token create --issuer alice --subject bob \
  --resource "tool://analyze" --actions read,execute \
  --max-fuel 1000000 --expires-in 1h

# Attenuate a delegation
moat token attenuate --token bob.token --subject carol \
  --resource "tool://analyze" --actions read

# Verify a token chain
moat token verify --token carol.token

# Verify an audit log
moat audit verify --path audit.jsonl

# Run the scripted multi-agent demo
moat demo
```

### Library (Rust)

```rust
use chrono::{Duration, Utc};
use moat_core::{AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry};

let coordinator = AgentKeypair::generate("coordinator")?;
let worker      = AgentKeypair::generate("worker")?;

// Root token: coordinator grants itself broad rights.
let mut root = CapabilityToken::root(
    coordinator.id(), coordinator.id(), Utc::now() + Duration::hours(1),
);
root.allowed = vec![ScopeEntry {
    resource: "tool://analyze".into(),
    actions:  vec!["read".into(), "execute".into()],
}];
root.sign(&coordinator);

// Delegate a narrower slice to the worker. Broadening returns an error.
let mut worker_tok = root.attenuate(
    worker.id(),
    vec![ScopeEntry { resource: "tool://analyze".into(), actions: vec!["read".into()] }],
    vec![],
    ResourceLimits { max_fuel: Some(1_000_000), ..Default::default() },
    10,
)?;
worker_tok.sign(&coordinator);
```

Full routing, PEP verification, and audit-log integration in `crates/moat-relay/examples/orchestrated_pipeline.rs`.

### TypeScript / JavaScript

```ts
import * as moat from '@moat/core';

const alice = JSON.parse(moat.generateKeypair('alice'));
const root  = moat.rootToken(
  alice.signing_key_hex, alice.name, alice.id,
  JSON.stringify([{ resource: 'tool://analyze', actions: ['read'] }]),
  3600,
);
// Broadening scope throws; monotonic attenuation is enforced in the Rust core.
```

See `crates/moat-wasm` for the full TS API and build instructions.

## Architecture

```
┌─────────┐   signed + capability-bound msg   ┌─────────┐
│ Agent A │ ────────────────────────────────> │ Agent B │
└─────────┘                                   └─────────┘
                       │
              ┌────────▼────────┐
              │       PEP       │  1. signature + replay
              │  (3-stage gate) │  2. policy binding
              └────────┬────────┘  3. capability + chain walk
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
  AuditLog       RuntimeMonitor    Wasm Sandbox
 (hash chain)   (FSM + windows)    (default-deny)
```

### Crates

| Crate | Purpose |
|-------|---------|
| `moat` | Entry point; high-level builder that hides PEP, registry, and router plumbing |
| `moat-core` | Identity, capability tokens, messages, errors; pure types, no IO |
| `moat-runtime` | PEP, Wasm sandbox, audit log, runtime monitor, secret proxy |
| `moat-relay` | Agent registry, message router, integration tests |
| `moat-cli` | `moat identity`, `moat token`, `moat audit`, `moat demo` |
| `moat-wasm` | WebAssembly bindings for Node and browser, published as `@moat/core` |

### Dependencies

| Category | Crates |
|----------|--------|
| Crypto | `ed25519-dalek` 2, `sha2` 0.10, `rand` 0.8 |
| Sandbox | `wasmtime` 29, `wasmtime-wasi` 29, `cap-std` 3 |
| Serialization | `serde` 1, `serde_json` 1 |
| Async | `tokio` 1 |
| Errors | `thiserror` 2 |
| Observability | `tracing` 0.1 |
| CLI | `clap` 4 |

## Status

MVP implementation. Implemented and tested:

* Ed25519 identity, signing, verification (`ed25519-dalek`)
* Signed capability tokens with monotonic attenuation and chain verification
* Three-stage PEP (signature and replay, policy binding, capability evaluation)
* Wasm sandbox via `wasmtime` + WASI Preview1 with fuel, memory, and filesystem pre-opens
* Append-only audit log with SHA-256 hash chain plus optional JSONL persistence
* Runtime monitor: FSM transitions, sliding-window rates, pattern detection
* Secret proxy with per-agent ACLs, revocation, HTTP header injection
* Router with rate limiting, payload size caps, timestamp expiry, recipient existence checks

Known limitations:

* Wildcard resource matching is prefix-only (`tool://*` matches `tool://anything` but not `tool://*/read`)
* WASI Preview2 network APIs are not yet stable; the `network_allowed` flag is enforced as default-deny via WASI defaults but there is no allowlist enforcement for egress yet
* Single-process relay (no multi-node federation)
* No MAPL parser (policies expressed as Rust structs, not a DSL)
* No web dashboard yet
* Attestations are structurally present but not deeply integrated into PEP evaluation

## Spec

Full protocol specification and threat model in `spec/PROTOCOL.md`.

## Contributing

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must be green before a PR lands.

## License

Apache-2.0. See `LICENSE` for details.
