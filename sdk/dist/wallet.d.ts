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
export interface TonConnectProvider {
    account: {
        address: string;
        chain: '-239' | '-3';
        publicKey?: string;
    };
    /** Sign arbitrary data payload (TON Connect v2 signData) */
    signData(payload: {
        cell: string;
    }): Promise<{
        signature: string;
        timestamp: number;
    }>;
    /** Sign and submit a TON transaction, returns signed BOC */
    signTransaction(to: string, bodyHex: string, valueGrams: string): Promise<string>;
}
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
export declare function connectWithTON(provider: TonConnectProvider, wasm: typeof import('../wasm/stvor_crypto.js'), pqc?: boolean): Promise<WalletIdentity>;
export declare function toB64url(bytes: Uint8Array): string;
export declare function fromB64url(s: string): Uint8Array;
//# sourceMappingURL=wallet.d.ts.map