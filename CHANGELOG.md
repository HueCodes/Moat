# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
