/**
 * WASM integration test — verifies Rust crypto works in Node.js
 */

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(__dirname, '../../wasm');

// Load WASM module in Node.js (no bundler)
const wasmBuffer = readFileSync(join(wasmDir, 'stvor_crypto_bg.wasm'));
const {
  default: init,
  WasmKeyPair, WasmSession,
  wasm_ec_sign, wasm_ec_verify, wasm_hkdf, wasm_x3dh,
  wasm_mlkem_keygen, wasm_mlkem_encaps, wasm_mlkem_decaps,
  wasm_hybrid_initiate, wasm_hybrid_respond,
  wasm_hybrid_session_initiate, wasm_hybrid_session_respond,
} = await import(join(wasmDir, 'stvor_crypto.js'));

await init(wasmBuffer);

// ─── Test helpers ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e: unknown) {
    console.error(`  ✗ ${name}: ${(e as Error).message}`);
    failed++;
  }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

function fromB64url(s: string): Uint8Array {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

// ─── Tests ────────────────────────────────────────────────────────────────────

console.log('\n@stvor/web3 WASM tests\n');

await test('WasmKeyPair.generate() produces 65-byte public key', () => {
  const kp = new WasmKeyPair();
  const pub = fromB64url(kp.public_key);
  assert(pub.length === 65, `Expected 65, got ${pub.length}`);
  assert(pub[0] === 0x04, `Expected 0x04, got ${pub[0]}`);
  const priv = fromB64url(kp.private_key);
  assert(priv.length === 32, `Expected 32, got ${priv.length}`);
});

await test('WasmKeyPair.from_private_key() restores public key', () => {
  const kp = new WasmKeyPair();
  const restored = WasmKeyPair.from_private_key(kp.private_key);
  assert(kp.public_key === restored.public_key, 'Public key must match after restore');
});

await test('wasm_hkdf is deterministic', () => {
  const ikm = btoa('test-ikm').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const salt = btoa('test-salt').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const a = wasm_hkdf(ikm, salt, 'test', 32);
  const b = wasm_hkdf(ikm, salt, 'test', 32);
  assert(a === b, 'HKDF must be deterministic');
});

await test('wasm_ec_sign + wasm_ec_verify round-trip', () => {
  const kp = new WasmKeyPair();
  const data = new TextEncoder().encode('stvor web3 test');
  const sig = wasm_ec_sign(data, kp);
  const ok = wasm_ec_verify(data, sig, kp.public_key);
  assert(ok, 'Signature must verify');
});

await test('wasm_ec_verify rejects wrong data', () => {
  const kp = new WasmKeyPair();
  const sig = wasm_ec_sign(new TextEncoder().encode('hello'), kp);
  const ok = wasm_ec_verify(new TextEncoder().encode('hellx'), sig, kp.public_key);
  assert(!ok, 'Must reject wrong data');
});

await test('wasm_x3dh produces same key for both parties', () => {
  const aliceIK = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK = new WasmKeyPair();
  const bobSPK = new WasmKeyPair();

  const skAlice = wasm_x3dh(aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key);
  const skBob   = wasm_x3dh(bobIK, bobSPK, aliceIK.public_key, aliceSPK.public_key);

  assert(skAlice === skBob, `X3DH keys must match: ${skAlice} vs ${skBob}`);
});

await test('WasmSession: alice encrypts, bob decrypts', () => {
  const aliceIK = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK = new WasmKeyPair();
  const bobSPK = new WasmKeyPair();

  const alice = WasmSession.establish(aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key);
  const bob   = WasmSession.establish(bobIK, bobSPK, aliceIK.public_key, aliceSPK.public_key);

  const plaintext = new TextEncoder().encode('Hello TON!');
  const blob = alice.encrypt(plaintext);
  const decrypted = bob.decrypt(blob);

  assert(
    plaintext.every((b, i) => b === decrypted[i]),
    'Decrypted must match plaintext',
  );
});

await test('WasmSession: bidirectional 5 rounds', () => {
  const aliceIK = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK = new WasmKeyPair();
  const bobSPK = new WasmKeyPair();

  const alice = WasmSession.establish(aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key);
  const bob   = WasmSession.establish(bobIK, bobSPK, aliceIK.public_key, aliceSPK.public_key);

  for (let i = 0; i < 5; i++) {
    const msg = new TextEncoder().encode(`round-${i}`);
    const enc = alice.encrypt(msg);
    const dec = bob.decrypt(enc);
    assert(msg.every((b, j) => b === dec[j]), `Round ${i} A→B failed`);

    const reply = new TextEncoder().encode(`reply-${i}`);
    const encR = bob.encrypt(reply);
    const decR = alice.decrypt(encR);
    assert(reply.every((b, j) => b === decR[j]), `Round ${i} B→A failed`);
  }
});

await test('WasmSession: serialise and restore', () => {
  const aliceIK = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK = new WasmKeyPair();
  const bobSPK = new WasmKeyPair();

  const alice = WasmSession.establish(aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key);
  const bob   = WasmSession.establish(bobIK, bobSPK, aliceIK.public_key, aliceSPK.public_key);

  const enc1 = alice.encrypt(new TextEncoder().encode('init'));
  bob.decrypt(enc1);

  // Restore Bob's session from JSON
  const json = bob.to_json();
  const bobRestored = WasmSession.from_json(json);

  const msg2 = new TextEncoder().encode('after restore');
  const enc2 = alice.encrypt(msg2);
  const dec2 = bobRestored.decrypt(enc2);

  assert(msg2.every((b, i) => b === dec2[i]), 'Must decrypt after session restore');
});

// ─── ML-KEM-768 tests ─────────────────────────────────────────────────────────

await test('wasm_mlkem_keygen: correct key sizes', () => {
  const kp = JSON.parse(wasm_mlkem_keygen());
  const ek = fromB64url(kp.ek);
  const dk = fromB64url(kp.dk);
  assert(ek.length === 1184, `EK must be 1184 bytes, got ${ek.length}`);
  assert(dk.length === 64,   `DK seed must be 64 bytes, got ${dk.length}`);
});

await test('wasm_mlkem_encaps/decaps: shared secrets match', () => {
  const kp  = JSON.parse(wasm_mlkem_keygen());
  const enc = JSON.parse(wasm_mlkem_encaps(kp.ek));
  const ss  = wasm_mlkem_decaps(kp.dk, enc.ct);
  assert(enc.ss === ss, 'ML-KEM shared secrets must match');
});

await test('wasm_mlkem_decaps: wrong key gives different secret', () => {
  const kp1 = JSON.parse(wasm_mlkem_keygen());
  const kp2 = JSON.parse(wasm_mlkem_keygen());
  const enc = JSON.parse(wasm_mlkem_encaps(kp1.ek));
  const ss_wrong = wasm_mlkem_decaps(kp2.dk, enc.ct);
  assert(enc.ss !== ss_wrong, 'Wrong DK must not reproduce shared secret');
});

await test('wasm_mlkem: tampered CT gives different secret', () => {
  const kp = JSON.parse(wasm_mlkem_keygen());
  const enc = JSON.parse(wasm_mlkem_encaps(kp.ek));

  // Flip first byte of CT
  const ctBytes = fromB64url(enc.ct);
  ctBytes[0] ^= 0xff;
  const tamperedCt = btoa(String.fromCharCode(...ctBytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const ss_tampered = wasm_mlkem_decaps(kp.dk, tamperedCt);
  assert(enc.ss !== ss_tampered, 'Tampered CT must produce different secret');
});

// ─── Hybrid X3DH + ML-KEM-768 tests ──────────────────────────────────────────

await test('wasm_hybrid_initiate/respond: shared secrets match', () => {
  const aliceIK  = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK    = new WasmKeyPair();
  const bobSPK   = new WasmKeyPair();
  const bobPqc   = JSON.parse(wasm_mlkem_keygen());

  const init = JSON.parse(wasm_hybrid_initiate(
    aliceIK, aliceSPK,
    bobIK.public_key, bobSPK.public_key,
    bobPqc.ek,
  ));

  const respSk = wasm_hybrid_respond(
    bobIK, bobSPK,
    aliceIK.public_key, aliceSPK.public_key,
    bobPqc.dk,
    init.mlkem_ct,
  );

  assert(init.shared_key === respSk, 'Hybrid X3DH shared secrets must match');
});

await test('wasm_hybrid: differs from classical X3DH', () => {
  const aliceIK  = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK    = new WasmKeyPair();
  const bobSPK   = new WasmKeyPair();
  const bobPqc   = JSON.parse(wasm_mlkem_keygen());

  const classical = wasm_x3dh(aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key);
  const hybrid    = JSON.parse(wasm_hybrid_initiate(
    aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key, bobPqc.ek,
  ));

  assert(classical !== hybrid.shared_key, 'Hybrid key must differ from classical X3DH');
});

await test('wasm_hybrid_session: full E2EE roundtrip', () => {
  const aliceIK  = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK    = new WasmKeyPair();
  const bobSPK   = new WasmKeyPair();
  const bobPqc   = JSON.parse(wasm_mlkem_keygen());

  // Alice creates hybrid session
  const initResult = JSON.parse(wasm_hybrid_session_initiate(
    aliceIK, aliceSPK,
    bobIK.public_key, bobSPK.public_key,
    bobPqc.ek,
  ));
  const alice = WasmSession.from_json(initResult.session_json);

  // Bob creates hybrid session with Alice's ML-KEM CT
  const bob = wasm_hybrid_session_respond(
    bobIK, bobSPK,
    aliceIK.public_key, aliceSPK.public_key,
    bobPqc.dk,
    initResult.mlkem_ct,
  );

  // Alice sends, Bob receives
  const msg = new TextEncoder().encode('Quantum-safe gm from TON!');
  const enc = alice.encrypt(msg);
  const dec = bob.decrypt(enc);
  assert(msg.every((b, i) => b === dec[i]), 'Hybrid session message must decrypt correctly');

  // Bob replies
  const reply = new TextEncoder().encode('Hybrid PQC works!');
  const encR = bob.encrypt(reply);
  const decR = alice.decrypt(encR);
  assert(reply.every((b, i) => b === decR[i]), 'Hybrid session reply must decrypt correctly');
});

await test('wasm_hybrid_session: 5 bidirectional rounds', () => {
  const aliceIK  = new WasmKeyPair();
  const aliceSPK = new WasmKeyPair();
  const bobIK    = new WasmKeyPair();
  const bobSPK   = new WasmKeyPair();
  const bobPqc   = JSON.parse(wasm_mlkem_keygen());

  const initResult = JSON.parse(wasm_hybrid_session_initiate(
    aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key, bobPqc.ek,
  ));
  const alice = WasmSession.from_json(initResult.session_json);
  const bob   = wasm_hybrid_session_respond(
    bobIK, bobSPK, aliceIK.public_key, aliceSPK.public_key, bobPqc.dk, initResult.mlkem_ct,
  );

  for (let i = 0; i < 5; i++) {
    const msg   = new TextEncoder().encode(`pqc-round-${i}`);
    const enc   = alice.encrypt(msg);
    const dec   = bob.decrypt(enc);
    assert(msg.every((b, j) => b === dec[j]), `Round ${i} A→B failed`);

    const reply = new TextEncoder().encode(`pqc-reply-${i}`);
    const encR  = bob.encrypt(reply);
    const decR  = alice.decrypt(encR);
    assert(reply.every((b, j) => b === decR[j]), `Round ${i} B→A failed`);
  }
});

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
