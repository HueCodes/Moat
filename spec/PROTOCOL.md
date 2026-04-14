# Moat Protocol Specification v0.1

## Overview

Moat is a runtime that provides cryptographically enforced, sandboxed agent-to-agent communication. Every agent gets a unique Ed25519 identity. Every message is signed and verified. Every action is authorized through capability tokens. Every decision is audit-logged in a tamper-evident hash chain.

## Threat Model

Moat defends against five attack classes documented in the academic literature:

1. **Skill Poisoning** (Taming OpenClaw): Malicious plugins replacing legitimate tools. Defense: cryptographic identity verification at registration, attestation-based trust.
2. **Indirect Prompt Injection**: External content hijacking control flow. Defense: strict data/control plane separation via sandbox isolation.
3. **Memory Poisoning**: Fabricated rules injected into persistent memory. Defense: cross-sandbox state transfers treated as untrusted input.
4. **Intent Drift**: Individually reasonable actions escalating into unauthorized behavior. Defense: runtime monitor tracking cumulative action trajectories.
5. **Privilege Escalation**: Incremental assembly of dangerous operations. Defense: OS-level confinement via Wasm sandbox + capability attenuation.

## Architecture

```
Agent A                    Moat Runtime                    Agent B
   |                           |                              |
   |-- AuthenticatedMessage -->|                              |
   |                     [1. Verify Signature]                |
   |                     [2. Verify Policy Binding]           |
   |                     [3. Evaluate Capability]             |
   |                     [4. Log to Audit Chain]              |
   |                     [5. Track via Monitor]               |
   |                           |-- AuthenticatedMessage ----->|
   |                           |                              |
```

### Components

- **AgentIdentity**: Ed25519 keypair + attestations. Public key transmitted; signing key stays in-process.
- **CapabilityToken**: Scoped permissions with resource patterns, action lists, and resource limits. Forms delegation chains with monotonic attenuation.
- **AuthenticatedMessage (CAM)**: Cryptographically binds sender, payload, capability token, and policy binding. Includes sequence numbers for replay protection.
- **PolicyEnforcementPoint (PEP)**: Three-stage verification pipeline: (1) signature, (2) policy binding, (3) capability evaluation. Deterministic -- same inputs always produce same result.
- **Sandbox**: Wasm execution via wasmtime with fuel metering, memory limits, and restricted filesystem/network access derived from capability tokens.
- **SecretProxy**: Handle-based secret management. Agents receive opaque handles; the runtime injects real values at the point of use (e.g., HTTP headers).
- **RuntimeMonitor**: Tracks action counts, duration, resource consumption, and cumulative cost per agent. Emits alerts when thresholds are crossed.
- **AuditLog**: Append-only with SHA-256 hash chain. Every PEP decision, sandbox action, and secret resolution is recorded. Tamper-evident.

## Capability Attenuation

Capability tokens form delegation chains satisfying three theorems:

1. **Monotonic Restriction**: A child token's allowed scope must be a subset of its parent's.
2. **Transitive Denial**: All parent denials are inherited by children. Denials are additive through the chain.
3. **No Privilege Escalation**: Resource limits (fuel, memory, network, filesystem) can only tighten, never loosen.

Attempting to broaden scope, remove a denial, or increase a resource limit returns `AttenuationViolation`.

## Message Format

```
AuthenticatedMessage {
    message_id:       UUID v4
    sender_id:        UUID (matches AgentIdentity.id)
    recipient_id:     UUID
    payload:          bytes
    capability_token: CapabilityToken
    policy_binding:   PolicyBinding { policy_hash: SHA-256, policy_id: string }
    sequence_number:  u64 (monotonically increasing per sender)
    timestamp:        DateTime<Utc>
    signature:        Ed25519 signature over canonical JSON of all fields except signature
}
```

## PEP Pipeline

Stage 1 - **Signature Verification**: Look up sender identity, verify Ed25519 signature over canonical message bytes, check sequence number for replay.

Stage 2 - **Policy Binding Verification**: Confirm the message's policy_binding matches the runtime's active policy (hash comparison).

Stage 3 - **Capability Evaluation**: Check denials first (deny overrides allow), then check positive grants. Resource patterns support trailing wildcard (`*`).

All three stages must pass. Failure at any stage is logged to the audit chain with the failing stage identified.

## Secret Management

Agents never see raw secret values. The flow:

1. Operator stores secret in `SecretProxy` with access control list (set of agent UUIDs).
2. Agent receives a `SecretHandle` (opaque name reference).
3. When the agent needs the secret (e.g., for an API call), the runtime resolves the handle and injects the value into the outgoing request.
4. Access can be revoked per-agent. Secrets can be removed entirely.

## Audit Chain

Each entry contains:
- Index, timestamp, event details
- `previous_hash`: SHA-256 of the previous entry (genesis uses 32 zero bytes)
- `entry_hash`: SHA-256 of (index || timestamp || event || previous_hash)

Verification walks the chain and recomputes each hash. Any modification breaks all subsequent entries.

## Dependencies

Pure-Rust only: ed25519-dalek, sha2, wasmtime, wasmtime-wasi, cap-std, serde, serde_json, tokio, tracing, thiserror, uuid, chrono. No ring, no openssl, no protobuf.

## Status

MVP implementation. Not yet implemented: MAPL policy language parser, multi-node relay, Wasm compilation toolchain, MDP-based probabilistic assurance, web UI.
