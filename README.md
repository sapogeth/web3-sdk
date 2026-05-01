# @stvor/web3

**Post-quantum end-to-end encryption for TON Web3.**

The first E2EE library built for Web3 that is resistant to quantum computers — today.

**Documentation:** [pqc.stvor.xyz](https://pqc.stvor.xyz)

```
npm install @stvor/web3
```

[![Tests](https://img.shields.io/badge/tests-53%2F53-brightgreen)](https://github.com/stvor/web3)
[![NIST FIPS 203](https://img.shields.io/badge/NIST%20FIPS%20203-ML--KEM--768-blue)](https://csrc.nist.gov/pubs/fips/203/final)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://npmjs.com/@stvor/web3)
[![TON](https://img.shields.io/badge/network-TON-0088cc)](https://ton.org)

---

## Why

Every message sent today can be stored and decrypted later by a quantum computer. This is called a **"Store Now, Decrypt Later"** attack. It is happening now.

`@stvor/web3` uses **ML-KEM-768** (NIST FIPS 203, finalized 2024) combined with classical **P-256 X3DH** in a hybrid scheme. Breaking the encryption requires breaking **both** — which no computer, classical or quantum, can do simultaneously.

## Features

- **Hybrid post-quantum X3DH** — ML-KEM-768 + P-256, HKDF-combined
- **Double Ratchet** — forward secrecy and break-in recovery (Signal Protocol)
- **TON wallet identity** — `userId = wallet address`. No accounts, no passwords
- **On-chain key registry** — public keys stored in a FunC smart contract
- **TON Storage delivery** — encrypted messages stored off-chain, decentralised
- **Zero dependencies** — 0 npm runtime dependencies. WASM crypto core (270 KB)
- **NIST verified** — 53 official ACVTS test vectors (ECDH, ECDSA, AES-GCM, HKDF)

## Crypto stack

```
Identity:    TON wallet address (signed with Ed25519)
Key exchange: Hybrid X3DH
               ├── P-256 ECDH       (classical, NIST)
               └── ML-KEM-768       (post-quantum, NIST FIPS 203)
               └── HKDF-SHA256 combine → shared secret
Sessions:    Double Ratchet (Signal Protocol)
Encryption:  AES-256-GCM
Signing:     ECDSA P-256 / SHA-256
Implementation: Rust → WASM (270 KB, zero C dependencies)
```

---

## Quick start

```ts
import { StvorWeb3 } from '@stvor/web3';
import initWasm from '@stvor/web3/wasm';

// 1. Load WASM crypto engine
const wasm = await initWasm();

// 2. Connect with TON wallet (TonConnect)
const alice = await StvorWeb3.connect({
  provider: tonConnectProvider,       // TonConnect wallet
  contractAddress: 'EQD...',          // stvor_registry on TON testnet
  tonApiUrl: 'https://testnet.toncenter.com/api/v2',
  wasm,
});

// 3. Listen for incoming messages
alice.onMessage(msg => {
  console.log(`From ${msg.from}:`, msg.data);
});

// 4. Send a post-quantum encrypted message
await alice.send('0:bob_address...', {
  text: 'Hello, quantum-safe Web3!'
});

// 5. Disconnect when done
await alice.disconnect();
```

---

## Installation

```bash
npm install @stvor/web3
```

**Requirements:** Browser or Node.js ≥ 18 with Web Crypto API and WebAssembly support (available everywhere since 2022).

---

## API reference

### `StvorWeb3.connect(config)`

Creates a client connected to the TON network.

```ts
const client = await StvorWeb3.connect({
  provider: TonConnectProvider,   // TON Connect wallet provider
  contractAddress: string,        // stvor_registry contract address
  tonApiUrl: string,              // TonCenter API endpoint
  wasm: WasmModule,               // initialized WASM module
  tonApiKey?: string,             // optional TonCenter API key
  pollIntervalMs?: number,        // message poll interval (default: 5000)
  pqc?: boolean,                  // enable hybrid PQC (default: true)
});
```

### `client.send(to, data)`

Sends a post-quantum encrypted message to a TON wallet address.

```ts
await client.send('0:recipient_address...', {
  text: 'Hello!',
  // any JSON-serializable data
});
```

### `client.onMessage(handler)`

Registers a handler for incoming messages. Returns an unsubscribe function.

```ts
const unsub = client.onMessage(msg => {
  console.log(msg.from);       // TON address
  console.log(msg.data);       // decrypted payload
  console.log(msg.timestamp);  // Date
  console.log(msg.id);         // message ID
});

// Later:
unsub();
```

### `client.address`

The TON wallet address of this client.

```ts
console.log(client.address); // "0:abc123..."
```

### `client.chain`

Network: `'mainnet'` or `'testnet'`.

### `client.disconnect()`

Stops polling and clears session state.

---

## Low-level WASM API

For advanced use cases, the Rust crypto primitives are directly accessible:

```ts
import initWasm, {
  WasmKeyPair,
  WasmSession,
  wasm_mlkem_keygen,
  wasm_mlkem_encaps,
  wasm_mlkem_decaps,
  wasm_hybrid_initiate,
  wasm_hybrid_respond,
  wasm_ec_sign,
  wasm_ec_verify,
  wasm_hkdf,
} from '@stvor/web3/wasm';

const wasm = await initWasm();

// ML-KEM-768 key generation
const { ek, dk } = JSON.parse(wasm_mlkem_keygen());
// ek = 1184-byte encapsulation key (base64url)
// dk = 64-byte decapsulation key seed (base64url)

// Encapsulate shared secret
const { ct, ss } = JSON.parse(wasm_mlkem_encaps(ek));

// Decapsulate
const ss2 = wasm_mlkem_decaps(dk, ct);
// ss === ss2

// Hybrid X3DH session
const aliceIK  = new WasmKeyPair();
const aliceSPK = new WasmKeyPair();
const bobIK    = new WasmKeyPair();
const bobSPK   = new WasmKeyPair();
const bobPqc   = JSON.parse(wasm_mlkem_keygen());

// Alice initiates
const { session_json, mlkem_ct } = JSON.parse(
  wasm_hybrid_session_initiate(aliceIK, aliceSPK, bobIK.public_key, bobSPK.public_key, bobPqc.ek)
);
const alice = WasmSession.from_json(session_json);

// Bob responds
const bob = wasm_hybrid_session_respond(
  bobIK, bobSPK, aliceIK.public_key, aliceSPK.public_key, bobPqc.dk, mlkem_ct
);

// Encrypted messaging
const ct2 = alice.encrypt(new TextEncoder().encode('gm'));
const pt  = bob.decrypt(ct2);
// new TextDecoder().decode(pt) === 'gm'
```

---

## Smart contract

The `stvor_registry` FunC contract stores public keys on-chain and tracks message bag IDs.

**Testnet address:** `EQD...` *(deploy with `node contracts/deploy.mjs`)*

**ABI:**

| Method | Type | Description |
|--------|------|-------------|
| `register_keys` | internal | Store IK + SPK + SIG + ML-KEM EK |
| `store_message` | internal | Record a TON Storage bag ID |
| `delete_message` | internal | Remove a bag ID (recipient only) |
| `get_keys(addr)` | get-method | Read public keys for an address |
| `get_messages(addr)` | get-method | List pending message bag IDs |
| `get_message_count(addr)` | get-method | Count pending messages |

---

## Security

### Hybrid PQC scheme

```
shared_key = HKDF-SHA256(
  ikm  = ecdh_sk ‖ mlkem_ss,
  salt = 0x00...00,
  info = "STVOR-HYBRID-v1"
)
```

This is secure if **either** ECDH (P-256) or ML-KEM-768 is secure. An attacker must break both simultaneously — impossible with any known classical or quantum algorithm.

### NIST ACVTS verification

All cryptographic primitives are verified against official NIST test vectors:

| Algorithm | Standard | Vectors |
|-----------|----------|---------|
| P-256 ECDH | NIST KAS ECC CDH | 25 |
| ECDSA P-256/SHA-256 | NIST FIPS 186-3 SigVer | 15 |
| AES-256-GCM | NIST SP 800-38D | 21 |
| HKDF-SHA256 | RFC 5869 (NIST SP 800-56C) | 3 |

### Forward secrecy

The Double Ratchet protocol ensures that compromising a session key does not expose past messages. Each message uses a fresh symmetric key derived from the ratchet chain.

### Key zeroization

All private key material is zeroed from memory after use via the `zeroize` crate.

---

## Comparison

| | **@stvor/web3** | XMTP | Waku | Signal (libsignal) |
|---|---|---|---|---|
| Post-quantum (ML-KEM-768) | ✅ | ❌ | ❌ | ❌ |
| TON wallet identity | ✅ | ❌ | ❌ | ❌ |
| Double Ratchet | ✅ | ✅ | ❌ | ✅ |
| On-chain key registry | ✅ | ❌ | ❌ | ❌ |
| Zero npm dependencies | ✅ | ❌ | ❌ | ❌ |
| NIST ACVTS verified | ✅ | ❌ | ❌ | ✅ |
| Rust WASM crypto core | ✅ | ❌ | ❌ | ✅ |

---

## Project structure

```
stvor-web3/
├── crypto-core/          Rust crypto engine
│   └── src/
│       ├── crypto.rs     P-256 ECDH/ECDSA, AES-256-GCM, HKDF, HMAC
│       ├── pqc.rs        ML-KEM-768 (NIST FIPS 203)
│       ├── ratchet.rs    X3DH + Double Ratchet session
│       ├── wasm.rs       WASM bindings (wasm-bindgen)
│       └── nist_tests.rs NIST ACVTS test vectors
│
├── sdk/
│   ├── wasm/             Compiled WASM + TypeScript types (270 KB)
│   └── src/
│       ├── wallet.ts     TON wallet → E2EE identity derivation
│       ├── ton-storage.ts TON Storage + contract client
│       ├── stvor.ts      Main client (StvorWeb3)
│       └── index.ts      Public API exports
│
└── contracts/
    ├── stvor_registry.fc FunC smart contract
    ├── StvorRegistry.ts  TypeScript wrapper
    └── deploy.mjs        Testnet deployment script
```

---

## Deploy contract (testnet)

```bash
cd contracts
npm install

# Set your wallet mnemonic
export STVOR_MNEMONIC="word1 word2 ... word24"

# Deploy to TON testnet
node deploy.mjs

# Output:
# Contract address: EQD...
# ✓ Deployed successfully!
```

Get testnet TON from [@testgiver_ton_bot](https://t.me/testgiver_ton_bot).

---

## Contributing

```bash
# Run all tests (53 total)
cd crypto-core && cargo test        # 28 Rust tests (incl. NIST vectors)
cd sdk && node --experimental-wasm-modules --import tsx/esm src/__tests__/wasm.test.ts  # 17 WASM tests
cd contracts && node --import tsx/esm tests/registry.test.ts  # 8 contract tests

# Rebuild WASM after Rust changes
cd crypto-core && wasm-pack build --target web --out-dir ../sdk/wasm
```

---

## License

MIT — [stvor.xyz](https://stvor.xyz)

---

**Docs:** [pqc.stvor.xyz](https://pqc.stvor.xyz) · **npm:** [@stvor/web3](https://npmjs.com/@stvor/web3) · **TON:** testnet
