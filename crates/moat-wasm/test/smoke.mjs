// Smoke test for @moat/core.
// Run with: npm run build && npm run smoke
//
// Exercises the full user-facing API: keypair generation, root token,
// attenuation, signature verification, and rejection of forged tokens.

import * as moat from '../pkg/moat_wasm.js';

moat.installPanicHook();

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  console.log('  ok:', msg);
}

console.log('Moat WASM smoke test');

// 1. Generate two agents
const alice = JSON.parse(moat.generateKeypair('alice'));
const bob = JSON.parse(moat.generateKeypair('bob'));
assert(alice.id && alice.signing_key_hex.length === 64, 'alice keypair shape');
assert(bob.id && bob.signing_key_hex.length === 64, 'bob keypair shape');

// 2. Alice signs a root token granting read + execute on tool://analyze
const rootTokenJson = moat.rootToken(
  alice.signing_key_hex,
  alice.name,
  alice.id,
  JSON.stringify([{ resource: 'tool://analyze', actions: ['read', 'execute'] }]),
  3600, // expires in 1h
);
assert(JSON.parse(rootTokenJson).signature.length > 0, 'root token is signed');

// 3. Verify root token against Alice's identity
const aliceIdentity = JSON.stringify({
  id: alice.id,
  name: alice.name,
  public_key_hex: alice.public_key_hex,
});
assert(
  moat.verifyTokenSignature(rootTokenJson, aliceIdentity),
  'root token verifies against alice'
);

// 4. Tampered token fails verification
const tampered = JSON.parse(rootTokenJson);
tampered.allowed[0].actions.push('delete'); // broaden after signing
assert(
  !moat.verifyTokenSignature(JSON.stringify(tampered), aliceIdentity),
  'tampered token rejected'
);

// 5. Attenuate: Bob gets read-only
const bobTokenJson = moat.attenuateToken(
  rootTokenJson,
  alice.signing_key_hex,
  alice.name,
  bob.id,
  JSON.stringify([{ resource: 'tool://analyze', actions: ['read'] }]),
  10,
);
assert(
  moat.verifyTokenSignature(bobTokenJson, aliceIdentity),
  'attenuated token signed by alice verifies'
);

// 6. Attempt to broaden: bob asks for delete — must fail
let broadeningFailed = false;
try {
  moat.attenuateToken(
    rootTokenJson,
    alice.signing_key_hex,
    alice.name,
    bob.id,
    JSON.stringify([{ resource: 'tool://analyze', actions: ['delete'] }]),
    10,
  );
} catch (_) {
  broadeningFailed = true;
}
assert(broadeningFailed, 'broadening attempt rejected at attenuation time');

console.log('\nAll smoke tests passed.');
