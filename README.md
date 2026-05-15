# Moat

Moat is a Rust security runtime for multi-agent AI systems. An agent gets an Ed25519 identity at registration. Any action it takes has to ride on a capability token signed by someone with the authority to grant it, and that token can only ever be narrower than the one it was derived from. Untrusted code runs under a `wasmtime` sandbox with fuel and filesystem limits taken straight from the token. Every decision the policy engine makes is appended to a hash chain you can later verify was never edited.

The design is three invariants the type system and the policy enforcement point hold for you, not three features you opt into:

- **Capability tokens are always signed.** Unsigned tokens are rejected and chains are walked back to a trusted root.
- **Delegation only narrows.** A child token can drop scope and tighten resource limits, never widen them. Asking for more returns `AttenuationViolation`.
- **The audit log is tamper-evident.** Each decision is a link in a SHA-256 hash chain, so any retroactive edit fails verification.

The three-stage PEP, the runtime monitor, and the secret proxy all exist to uphold those three.

## Quickstart

```bash
git clone https://github.com/HueCodes/Moat.git
cd Moat
cargo test --workspace            # 95 tests across 6 crates
cargo run -p moat-cli -- demo     # scripted multi-agent walkthrough
```

```rust
use chrono::{Duration, Utc};
use moat_core::{AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry};

let coordinator = AgentKeypair::generate("coordinator")?;
let worker = AgentKeypair::generate("worker")?;

let mut root = CapabilityToken::root(
    coordinator.id(), coordinator.id(), Utc::now() + Duration::hours(1),
);
root.allowed = vec![ScopeEntry {
    resource: "tool://analyze".into(),
    actions: vec!["read".into(), "execute".into()],
}];
root.sign(&coordinator);

// Hand the worker a strictly narrower slice. Asking for more is an error.
let mut worker_tok = root.attenuate(
    worker.id(),
    vec![ScopeEntry { resource: "tool://analyze".into(), actions: vec!["read".into()] }],
    vec![],
    ResourceLimits { max_fuel: Some(1_000_000), ..Default::default() },
    10,
)?;
worker_tok.sign(&coordinator);
```

TypeScript bindings (`@moat/core`, via `wasm-bindgen`) are in `crates/moat-wasm`. A full PEP + routing + audit run is in `crates/moat-relay/examples/orchestrated_pipeline.rs`.

## Performance

Apple M2, release build, `cargo bench -p moat-core`:

| Operation | Time |
|-----------|------|
| Token sign | 14.4 µs |
| Token verify | 32.4 µs |
| `is_action_allowed` | 40 ns |
| Authenticated message create (256 B) | 14.2 µs |
| Authenticated message verify (256 B) | 31.5 µs |

About 30k fully authenticated messages per second per core before any business logic runs. Ed25519 verification dominates; the SHA-256 prehash and UUID copies are noise. The primitive stack is pure Rust (`ed25519-dalek`, `sha2`, `rand`) with no OpenSSL or ring, so it audits end to end.

## What works, what doesn't

Implemented and tested: Ed25519 identity, signed capability tokens with monotonic attenuation and chain verification, the three-stage PEP, Wasm sandboxing via `wasmtime` + WASI Preview 1 (fuel, memory, filesystem pre-opens), the append-only audit chain with optional JSONL persistence, the FSM and rate-window runtime monitor, the handle-based secret proxy, agent revocation (revoking an issuer transitively kills every token it signed, persisted across restarts), and filesystem attenuation (a child cannot reach a path its parent did not grant, and sandbox pre-opens are derived from the token).

Not done yet:

- WASI Preview 2 network APIs are not stable, so egress is default-deny but there is no per-host allowlist enforcement.
- Single-process relay; no multi-node federation.
- Policies are Rust structs, not a DSL with a parser.
- Wildcard resource matching is prefix-only.
- Attestations exist in the types but are not deeply wired into PEP evaluation.

The threat model targets the documented agent attack classes: skill poisoning, indirect prompt injection, memory poisoning, intent drift, and incremental privilege escalation. `spec/PROTOCOL.md` maps each one to its defense.

## Layout

| Crate | What's in it |
|-------|--------------|
| `moat` | High-level builder; hides PEP, registry, and router |
| `moat-core` | Identity, tokens, messages; pure types, no IO |
| `moat-runtime` | PEP, Wasm sandbox, audit log, monitor, secret proxy |
| `moat-relay` | Registry, router, integration tests |
| `moat-cli` | `moat identity` / `token` / `audit` / `demo` |
| `moat-wasm` | WebAssembly bindings (`@moat/core`) |

## License

Apache-2.0.
