# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **moat-runtime**: Agent revocation in the PEP (`revoke`, `unrevoke`, `is_revoked`). Revoked senders are rejected at stage 1; any token chain whose issuer set intersects the revocation list is rejected at stage 3, so revoking a manager transitively invalidates every token they signed without enumeration. Persisted alongside sequence-number state.
- **moat-core**: Filesystem path subset check in `CapabilityToken::attenuate` — child `allowed_fs_read` / `allowed_fs_write` paths must be equal to or under one of the parent's paths. Path-component aware (`/tmp/foo` is not within `/tmp/foobar`).
- **moat-protocol**: `Moat::{revoke_agent, unrevoke_agent, is_revoked}` and `MoatBuilder::revoke` for managing revocations through the facade.
- **moat-core**: New `MoatError::AgentRevoked(Uuid)` variant.
- New `examples/sandbox_fs_attenuation` showing capability tokens, attenuation rejection, and WASI preopens composing end-to-end.

## [0.1.0] - 2026-04-15

### Added

- **moat-core**: Ed25519 agent identity (`AgentKeypair`, `AgentIdentity`) with signing key redacted from Debug
- **moat-core**: Capability tokens with scoped permissions, resource limits, and monotonic attenuation
- **moat-core**: Authenticated messages (CAM) with deterministic canonical serialization and replay protection
- **moat-core**: 20-variant typed error enum via `thiserror`
- **moat-runtime**: Three-stage Policy Enforcement Point (signature, policy binding, capability evaluation)
- **moat-runtime**: Wasm sandbox via Wasmtime with fuel metering, memory limits, and WASI filesystem pre-opens
- **moat-runtime**: Tamper-evident audit log with SHA-256 hash chain and optional file-backed persistence
- **moat-runtime**: Runtime monitor with per-agent FSM state tracking, sliding window rate analysis, and suspicious pattern detection
- **moat-runtime**: Handle-based secret proxy with per-agent ACLs and revocation support
- **moat-relay**: Agent registry with identity registration and lookup
- **moat-relay**: Message router integrating PEP, audit log, and runtime monitor
- **moat-cli**: CLI for identity generation, token management, and audit verification
- Orchestrated pipeline example demonstrating multi-agent delegation with capability attenuation
- Ping-pong example demonstrating basic two-agent communication
- Secret injection example demonstrating handle-based secret management
- Protocol specification (`spec/PROTOCOL.md`)
