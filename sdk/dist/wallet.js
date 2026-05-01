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
// ─── Derive identity from TON wallet ─────────────────────────────────────────
export async function connectWithTON(provider, wasm, pqc = true) {
    const { address, chain } = provider.account;
    const message = `STVOR-IDENTITY-v1:${address.toLowerCase()}`;
    const msgBytes = new TextEncoder().encode(message);
    const msgB64 = btoa(String.fromCharCode(...msgBytes));
    const { signature } = await provider.signData({ cell: msgB64 });
    const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    return deriveIdentity(address, chain, sigBytes, wasm, pqc);
}
// ─── Key derivation ───────────────────────────────────────────────────────────
async function deriveIdentity(address, chain, sig, wasm, pqc) {
    const sigB64 = toB64url(sig);
    const saltB64 = toB64url(new TextEncoder().encode('stvor-identity-salt'));
    const ikSeedB64 = wasm.wasm_hkdf(sigB64, saltB64, 'IK', 32);
    const spkSeedB64 = wasm.wasm_hkdf(sigB64, saltB64, 'SPK', 32);
    const identityKeyPair = wasm.WasmKeyPair.from_private_key(ikSeedB64);
    const signedPreKeyPair = wasm.WasmKeyPair.from_private_key(spkSeedB64);
    const spkPubBytes = fromB64url(signedPreKeyPair.public_key);
    const signedPreKeySignature = fromB64url(wasm.wasm_ec_sign(spkPubBytes, identityKeyPair));
    // ML-KEM-768 keypair — derived deterministically if pqc enabled
    let mlkemEncapKey = null;
    let mlkemDecapKey = null;
    if (pqc) {
        // Generate fresh ML-KEM keypair (not derivable from sig — must be stored securely)
        const pqcKp = JSON.parse(wasm.wasm_mlkem_keygen());
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
export function toB64url(bytes) {
    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64url(s) {
    return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
