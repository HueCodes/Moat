# Moat

**The missing security layer for MCP, LangChain, and CrewAI.**
_mTLS for AI agents, in Rust._

Agent frameworks today have no security boundary between agents. When Agent A delegates to Agent B, B inherits ambient access to everything A can reach — no attenuation, no audit trail, no enforcement. Moat fixes that at the runtime level: every agent has an Ed25519 identity, every message is signed, every capability is attenuated on delegation, every action is audit-logged in a tamper-evident hash chain, and every untrusted execution happens inside a Wasm sandbox.

```
┌─────────┐   signed + capability-bound msg   ┌─────────┐
│ Agent A │ ─────────────────────────────────▶│ Agent B │
└─────────┘                                   └─────────┘
                      │
              ┌───────▼────────┐
              │      PEP       │  1. signature + replay
              │ (3-stage gate) │  2. policy binding
              └───────┬────────┘  3. capability + chain walk
                      │
      ┌───────────────┼────────────────┐
      ▼               ▼                ▼
 AuditLog       RuntimeMonitor    Wasm Sandbox
 (hash chain)   (FSM + windows)   (default-deny)
```

## Why this exists

A misbehaving or compromised agent can poison another's memory, escalate its own privileges, or drift from its intent through a sequence of individually-reasonable actions. Prompt-layer guardrails don't stop any of that. Moat treats every agent as untrusted by default and enforces security cryptographically.

| Attack class | Moat's defense |
|---|---|
| **Skill poisoning** — malicious plugins replacing legitimate tools | Signed identity at registration; PEP rejects unknown issuers |
| **Indirect prompt injection** — external content hijacking control flow | Wasm sandbox with strict data/control plane separation |
| **Memory poisoning** — fabricated rules injected across sessions | Cross-sandbox state treated as untrusted input |
| **Intent drift** — benign-looking actions escalating over time | Runtime monitor tracks cumulative trajectories and FSM transitions |
| **Privilege escalation** — incremental assembly of dangerous ops | OS-level confinement + monotonic capability attenuation |

Grounded in the threat model from [Authenticated Workflows (Rajagopalan & Rao, 2026)](https://arxiv.org/abs/2602.10465), [Taming OpenClaw (Deng et al., 2026)](https://arxiv.org/abs/2603.11619), [AgentGuard (Koohestani, 2025 — ASE '25)](https://arxiv.org/abs/2509.23864), and NVIDIA's 2026 agent security guidance.

## Quick start

```bash
git clone https://github.com/HueCodes/Moat.git
cd moat
cargo build --workspace
cargo test --workspace          # 83 tests
cargo run -p moat-cli -- demo   # scripted 3-agent scenario
```

### Issue a capability, attenuate it, verify a message

```rust
use chrono::{Duration, Utc};
use moat_core::{AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry};

let coordinator = AgentKeypair::generate("coordinator")?;
let worker      = AgentKeypair::generate("worker")?;

// Root token: coordinator grants itself broad rights
let mut root = CapabilityToken::root(
    coordinator.id(), coordinator.id(), Utc::now() + Duration::hours(1),
);
root.allowed = vec![ScopeEntry {
    resource: "tool://analyze".into(),
    actions:  vec!["read".into(), "execute".into()],
}];
root.sign(&coordinator);

// Delegate a narrower slice to the worker — monotonic attenuation.
// Trying to *broaden* scope here returns an error at compile-of-intent.
let mut worker_tok = root.attenuate(
    worker.id(),
    vec![ScopeEntry { resource: "tool://analyze".into(), actions: vec!["read".into()] }],
    vec![],
    ResourceLimits { max_fuel: Some(1_000_000), ..Default::default() },
    10,
)?;
worker_tok.sign(&coordinator);
```

Full routing, PEP verification, and audit-log integration is in [`examples/orchestrated_pipeline`](crates/moat-relay/examples/orchestrated_pipeline.rs).

## Crates

| Crate | Purpose |
|---|---|
| [`moat`](crates/moat) | **Entry point.** High-level `Moat` builder that hides PEP/registry/router plumbing; re-exports everything else. |
| [`moat-core`](crates/moat-core) | Identity, capability tokens, messages, errors — pure types, no IO |
| [`moat-runtime`](crates/moat-runtime) | PEP, Wasm sandbox, audit log, runtime monitor, secret proxy |
| [`moat-relay`](crates/moat-relay) | Agent registry, message router, integration tests |
| [`moat-cli`](crates/moat-cli) | `moat identity`, `moat token`, `moat audit`, `moat demo` |
| [`moat-wasm`](crates/moat-wasm) | WebAssembly bindings for Node / browser — published as [`@moat/core`](crates/moat-wasm/README.md) on npm |

## TypeScript / JavaScript

Moat's core primitives are also available from JS via WebAssembly:

```ts
import * as moat from '@moat/core';
const alice = JSON.parse(moat.generateKeypair('alice'));
const root  = moat.rootToken(
  alice.signing_key_hex, alice.name, alice.id,
  JSON.stringify([{ resource: 'tool://analyze', actions: ['read'] }]),
  3600,
);
// Broadening throws — monotonic attenuation is enforced in Rust.
```

See [`crates/moat-wasm`](crates/moat-wasm) for the full TS/JS API and build instructions.

## CLI

```bash
moat identity generate --name alice
moat token create --issuer alice --subject bob \
  --resource "tool://analyze" --actions read,execute \
  --max-fuel 1000000 --expires-in 1h
moat token attenuate --token bob.token --subject carol \
  --resource "tool://analyze" --actions read
moat token verify --token carol.token
moat audit verify --path audit.jsonl
moat demo                       # runs the multi-agent delegation scenario
```

## Security model

Three invariants, none negotiable:

1. **Capability tokens are always signed.** Unsigned tokens are rejected. Delegation chains are verified back to a trusted root.
2. **Attenuation is monotonic.** A child's scope is a subset of its parent's; denials are additive; resource limits only tighten. Proven by construction in `CapabilityToken::attenuate`.
3. **Audit log is tamper-evident.** Every PEP decision, sandbox action, secret resolution, and monitor alert is appended to a SHA-256 hash chain. Any retroactive mutation breaks all subsequent hashes.

Plus:

- **Replay protection** via per-sender monotonic sequence numbers, persisted across restarts
- **Secret isolation** — agents hold opaque handles; the runtime injects values at point-of-use
- **Sandbox default-deny** — no filesystem or network unless explicitly granted by a capability token
- **Pure-Rust stack** — no C bindings, no OpenSSL, no ring; auditable all the way down

Formal specification and threat model: [`spec/PROTOCOL.md`](spec/PROTOCOL.md).

## Status & limitations

This is an MVP. It is honest about what it does and doesn't do.

**Implemented and tested:**
- Ed25519 identity, signing, verification (`ed25519-dalek`)
- Signed capability tokens with monotonic attenuation + chain verification
- Three-stage PEP (signature + replay, policy binding, capability evaluation)
- Wasm sandbox via `wasmtime` + WASI Preview1 with fuel, memory, and filesystem pre-opens
- Append-only audit log with SHA-256 hash chain + optional JSONL persistence
- Runtime monitor: FSM transitions, sliding-window rates, pattern detection
- Secret proxy with per-agent ACLs, revocation, HTTP header injection
- Router: rate limiting, payload size caps, timestamp expiry, recipient existence checks

**Known limitations:**
- Wildcard resource matching is **prefix-only** (`tool://*` matches `tool://anything` but not `tool://*/read`)
- **WASI Preview2 network APIs are not yet stable** — the `network_allowed` flag is enforced as default-deny via WASI defaults but there is no allowlist enforcement for egress yet
- **Single-process relay** — no multi-node federation
- **No MAPL parser** — policies are expressed as Rust structs, not a DSL
- **No web dashboard** yet
- Attestations are structurally present but not deeply integrated into PEP evaluation

Contributions and scrutiny welcome. File an issue if you spot something.

## Performance

Measured on an Apple M2, release mode, `criterion` bench suite (`cargo bench -p moat-core`):

| Operation | Time | Throughput |
|---|---|---|
| `CapabilityToken::sign` | 14.4 µs | ~69 k/s |
| `CapabilityToken::verify_signature` | 32.4 µs | ~31 k/s |
| `CapabilityToken::is_action_allowed` | 40 ns | ~25 M/s |
| `AuthenticatedMessage::create` (256 B payload) | 14.2 µs | ~70 k/s |
| `AuthenticatedMessage::verify_signature` (256 B payload) | 31.5 µs | ~32 k/s |

Verification is the PEP's hot path — in round numbers, a single core handles **~30,000 authenticated messages per second** end-to-end before any business logic runs. Ed25519 verify dominates; the canonical-bytes SHA-256 prehash and UUID copies are noise.

## Dependencies

All pure Rust.

| Category | Crates |
|---|---|
| Crypto | `ed25519-dalek` 2, `sha2` 0.10, `rand` 0.8 |
| Sandbox | `wasmtime` 29, `wasmtime-wasi` 29, `cap-std` 3 |
| Serialization | `serde` 1, `serde_json` 1 |
| Async | `tokio` 1 |
| Errors | `thiserror` 2 |
| Observability | `tracing` 0.1 |
| CLI | `clap` 4 |

## Contributing

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must be green before a PR lands.

## License

[Apache-2.0](LICENSE).
