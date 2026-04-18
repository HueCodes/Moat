# @moat/core

WebAssembly bindings for [Moat](https://github.com/HueCodes/Moat) — the missing security layer for AI agents. Call the Moat cryptographic primitives (signed identities, capability tokens with monotonic attenuation, authenticated-message verification) from TypeScript or JavaScript in Node or the browser.

> This is the thin JS face of a Rust runtime. If you want full PEP + audit-log + Wasm-sandbox enforcement, run the [`moat` Rust crate](https://crates.io/crates/moat) as a sidecar. `@moat/core` is for in-process token issuance, attenuation, and verification.

## Install

```bash
npm i @moat/core
```

## Quickstart

```ts
import * as moat from '@moat/core';
moat.installPanicHook(); // optional, routes Rust panics to console.error

// Generate two agents
const alice = JSON.parse(moat.generateKeypair('alice'));
const bob   = JSON.parse(moat.generateKeypair('bob'));

// Alice mints a root token
const root = moat.rootToken(
  alice.signing_key_hex,
  alice.name,
  alice.id,
  JSON.stringify([{ resource: 'tool://analyze', actions: ['read', 'execute'] }]),
  3600, // expires in 1h
);

// Attenuate to Bob: read-only. Monotonic restriction enforced in Rust —
// asking for ['delete'] here throws.
const bobToken = moat.attenuateToken(
  root,
  alice.signing_key_hex,
  alice.name,
  bob.id,
  JSON.stringify([{ resource: 'tool://analyze', actions: ['read'] }]),
  10,
);

// Verify
const aliceIdentity = JSON.stringify({
  id: alice.id, name: alice.name, public_key_hex: alice.public_key_hex
});
console.log(moat.verifyTokenSignature(bobToken, aliceIdentity)); // true
```

## API

| Function | Purpose |
|---|---|
| `installPanicHook()` | Route Rust panics to `console.error`. Call once. |
| `generateKeypair(name)` | Fresh Ed25519 keypair → JSON `{ id, name, public_key_hex, signing_key_hex }` |
| `rootToken(signingKeyHex, name, subjectId, allowedJson, expiresSecs)` | Sign a root capability token |
| `attenuateToken(parentJson, signerKeyHex, signerName, subjectId, allowedJson, maxDepth)` | Sign a narrower child token; throws on broadening attempts |
| `verifyTokenSignature(tokenJson, identityJson)` | Check issuer signature; returns boolean |
| `verifyMessage(messageJson, identityJson)` | Check CAM sender signature; returns boolean |
| `defaultResourceLimits()` | Default `ResourceLimits` as JSON |

## Building from source

```bash
# One-time
cargo install wasm-pack

# Node target (default)
npm run build

# Browser / bundler targets
npm run build:web
npm run build:bundler

# Smoke test the Node build
npm run smoke
```

The build emits `pkg/moat_wasm.{js,d.ts,wasm}` for consumption by any JS runtime.

## Security note

The Rust side enforces monotonic attenuation *at construction time*. `@moat/core` cannot grant more permission than the caller's parent token carries — broadening attempts throw before a signature is ever produced. Verification is constant-time (handled by [`ed25519-dalek`](https://docs.rs/ed25519-dalek)). Signing keys are 32-byte seeds; treat the hex strings returned by `generateKeypair` as secrets.

## License

Apache-2.0.
