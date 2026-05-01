/**
 * STVOR Web3 — TON Wallet Identity
 *
 * Derives deterministic E2EE identity from a TON wallet signature.
 * userId = TON wallet address (raw "0:hex" format)
 *
 * Flow:
 *  1. signData("STVOR-IDENTITY-v1:<address>") via TON Connect
 *  2. HKDF(signature) → seeds for IK, SPK, and ML-KEM keys
 *  3. IK + SPK = P-256 keypairs (X3DH + Double Ratchet)
 *  4. ML-KEM-768 keypair for post-quantum hybrid X3DH
 */

import type { WasmKeyPair } from '../wasm/stvor_crypto.js';

// ─── TON Connect provider interface ──────────────────────────────────────────
// Minimal subset — no @tonconnect/sdk dependency needed

export interface TonConnectProvider {
  account: {
    address: string;      // Raw TON address: "0:abc..."
    chain: '-239' | '-3'; // -239 mainnet, -3 testnet
    publicKey?: string;   // hex-encoded Ed25519 wallet pubkey
  };
  /** Sign arbitrary data payload (TON Connect v2 signData) */
  signData(payload: { cell: string }): Promise<{ signature: string; timestamp: number }>;
  /** Sign and submit a TON transaction, returns signed BOC */
  signTransaction(to: string, bodyHex: string, valueGrams: string): Promise<string>;
}

// ─── Identity ─────────────────────────────────────────────────────────────────

export interface WalletIdentity {
  address: string;
  chain: 'mainnet' | 'testnet';
  /** P-256 identity keypair (X3DH) */
  identityKeyPair: WasmKeyPair;
  /** P-256 signed pre-key (X3DH) */
  signedPreKeyPair: WasmKeyPair;
  /** ECDSA signature of SPK public key by IK */
  signedPreKeySignature: Uint8Array;
  /** ML-KEM-768 encapsulation key (1184 bytes, base64url) — publish on-chain */
  mlkemEncapKey: string | null;
  /** ML-KEM-768 decapsulation key seed (64 bytes, base64url) — keep private */
  mlkemDecapKey: string | null;
}

// ─── Derive identity from TON wallet ─────────────────────────────────────────

export async function connectWithTON(
  provider: TonConnectProvider,
  wasm: typeof import('../wasm/stvor_crypto.js'),
  pqc = true,
): Promise<WalletIdentity> {
  const { address, chain } = provider.account;
  const message = `STVOR-IDENTITY-v1:${address.toLowerCase()}`;
  const msgBytes = new TextEncoder().encode(message);
  const msgB64 = btoa(String.fromCharCode(...msgBytes));

  const { signature } = await provider.signData({ cell: msgB64 });
  const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));

  return deriveIdentity(address, chain, sigBytes, wasm, pqc);
}

// ─── Key derivation ───────────────────────────────────────────────────────────

async function deriveIdentity(
  address: string,
  chain: string,
  sig: Uint8Array,
  wasm: typeof import('../wasm/stvor_crypto.js'),
  pqc: boolean,
): Promise<WalletIdentity> {
  const sigB64  = toB64url(sig);
  const saltB64 = toB64url(new TextEncoder().encode('stvor-identity-salt'));

  const ikSeedB64  = wasm.wasm_hkdf(sigB64, saltB64, 'IK', 32);
  const spkSeedB64 = wasm.wasm_hkdf(sigB64, saltB64, 'SPK', 32);

  const identityKeyPair  = wasm.WasmKeyPair.from_private_key(ikSeedB64);
  const signedPreKeyPair = wasm.WasmKeyPair.from_private_key(spkSeedB64);

  const spkPubBytes = fromB64url(signedPreKeyPair.public_key);
  const signedPreKeySignature = fromB64url(wasm.wasm_ec_sign(spkPubBytes, identityKeyPair));

  // ML-KEM-768 keypair — derived deterministically if pqc enabled
  let mlkemEncapKey: string | null = null;
  let mlkemDecapKey: string | null = null;

  if (pqc) {
    // Generate fresh ML-KEM keypair (not derivable from sig — must be stored securely)
    const pqcKp = JSON.parse(wasm.wasm_mlkem_keygen()) as { ek: string; dk: string };
    mlkemEncapKey = pqcKp.ek;
    mlkemDecapKey = pqcKp.dk;
  }

  return {
    address,
    chain: chain === '-239' ? 'mainnet' : 'testnet',
    identityKeyPair,
    signedPreKeyPair,
    signedPreKeySignature,
    mlkemEncapKey,
    mlkemDecapKey,
  };
}

// ─── Base64url helpers ────────────────────────────────────────────────────────

export function toB64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(s: string): Uint8Array {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
