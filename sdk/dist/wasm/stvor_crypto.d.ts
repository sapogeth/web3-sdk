/* tslint:disable */
/* eslint-disable */

/**
 * AA identity container exposed to JS
 */
export class WasmAaIdentity {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Derive AA identity from a wallet signature.
     *
     * chain_type: "evm" | "ton"
     * Returns WasmAaIdentity with all keys derived.
     */
    static derive(address: string, chain_id: string, chain_type: string, signature_b64: string): WasmAaIdentity;
    /**
     * Establish hybrid X3DH session from this AA identity.
     * Returns JSON: { session_json, mlkem_ct }
     */
    establish_session_with(peer_ik_b64: string, peer_spk_b64: string, peer_mlkem_ek_b64: string): string;
    /**
     * Respond to a hybrid X3DH session from a peer.
     * Returns WasmSession ready to use.
     */
    respond_to_session(peer_ik_b64: string, peer_spk_b64: string, mlkem_ct_b64: string): WasmSession;
    /**
     * Verify the SPK signature — returns true if valid
     */
    verify_spk(): boolean;
    /**
     * Wallet address
     */
    readonly address: string;
    /**
     * Chain type: "evm" or "ton"
     */
    readonly chain_type: string;
    /**
     * P-256 identity public key (base64url, 65 bytes)
     */
    readonly identity_key: string;
    /**
     * ML-KEM-768 encapsulation key (base64url, 1184 bytes)
     */
    readonly mlkem_ek: string;
    /**
     * P-256 signed pre-key public (base64url, 65 bytes)
     */
    readonly signed_pre_key: string;
    /**
     * ECDSA signature of SPK by IK (base64url, DER)
     */
    readonly spk_signature: string;
}

export class WasmKeyPair {
    free(): void;
    [Symbol.dispose](): void;
    static from_private_key(priv_b64: string): WasmKeyPair;
    constructor();
    readonly private_key: string;
    readonly public_key: string;
}

export class WasmSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypt base64url-encoded blob → plaintext bytes
     */
    decrypt(blob_b64: string): Uint8Array;
    /**
     * Encrypt plaintext bytes → base64url-encoded ciphertext+header blob
     */
    encrypt(plaintext: Uint8Array): string;
    /**
     * Establish an E2EE session from wallet identity.
     * my_ik, my_spk: WasmKeyPair
     * peer_ik_b64, peer_spk_b64: base64url-encoded 65-byte public keys
     */
    static establish(my_ik: WasmKeyPair, my_spk: WasmKeyPair, peer_ik_b64: string, peer_spk_b64: string): WasmSession;
    /**
     * Restore session from JSON string
     */
    static from_json(json: string): WasmSession;
    /**
     * Serialize session state to JSON string
     */
    to_json(): string;
}

/**
 * Create a UserOperation binding — proves E2EE session belongs to this AA op.
 * Returns JSON: { user_op_hash, identity_sig, session_commitment }
 */
export function wasm_aa_bind_userop(user_op_hash_hex: string, identity: WasmAaIdentity, session_root_b64: string): string;

/**
 * Derive AA identity — shorthand function (no class needed)
 * Returns JSON: { ik, spk, spk_sig, mlkem_ek, address, chain_type }
 */
export function wasm_aa_derive(address: string, chain_id: string, chain_type: string, signature_b64: string): string;

/**
 * Sign a TON v5 extension body with AA identity.
 * Returns JSON: { body_hex, identity_sig, wallet_address }
 */
export function wasm_aa_sign_ton_extension(wallet_address: string, body_hex: string, identity: WasmAaIdentity): string;

/**
 * Verify a TON v5 extension signature.
 */
export function wasm_aa_verify_ton_extension(ext_json: string, identity_ik_b64: string): boolean;

/**
 * Verify a UserOperation binding.
 */
export function wasm_aa_verify_userop(binding_json: string, identity_ik_b64: string, session_root_b64: string): boolean;

/**
 * ECDSA sign: returns base64url DER signature
 */
export function wasm_ec_sign(data: Uint8Array, key_pair: WasmKeyPair): string;

/**
 * ECDSA verify: public_key_b64 is base64url 65-byte uncompressed P-256
 */
export function wasm_ec_verify(data: Uint8Array, sig_b64: string, public_key_b64: string): boolean;

/**
 * HKDF-SHA256
 */
export function wasm_hkdf(ikm_b64: string, salt_b64: string, info: string, len: number): string;

/**
 * Hybrid X3DH initiator: returns JSON { shared_key: base64url, mlkem_ct: base64url }
 * Send mlkem_ct to the responder in the handshake payload.
 */
export function wasm_hybrid_initiate(my_ik: WasmKeyPair, my_spk: WasmKeyPair, peer_ik_b64: string, peer_spk_b64: string, peer_mlkem_ek_b64: string): string;

/**
 * Hybrid X3DH responder: returns base64url-encoded 32-byte shared key.
 */
export function wasm_hybrid_respond(my_ik: WasmKeyPair, my_spk: WasmKeyPair, peer_ik_b64: string, peer_spk_b64: string, my_mlkem_dk_b64: string, mlkem_ct_b64: string): string;

/**
 * Hybrid session establish — initiator side.
 * Returns JSON: { session_json: string, mlkem_ct: base64url }
 */
export function wasm_hybrid_session_initiate(my_ik: WasmKeyPair, my_spk: WasmKeyPair, peer_ik_b64: string, peer_spk_b64: string, peer_mlkem_ek_b64: string): string;

/**
 * Hybrid session establish — responder side. Returns WasmSession.
 */
export function wasm_hybrid_session_respond(my_ik: WasmKeyPair, my_spk: WasmKeyPair, peer_ik_b64: string, peer_spk_b64: string, my_mlkem_dk_b64: string, mlkem_ct_b64: string): WasmSession;

/**
 * ML-KEM-768 decapsulate. Returns base64url-encoded 32-byte shared secret.
 */
export function wasm_mlkem_decaps(dk_b64: string, ct_b64: string): string;

/**
 * ML-KEM-768 encapsulate. Returns JSON: { ct: base64url, ss: base64url }
 */
export function wasm_mlkem_encaps(ek_b64: string): string;

/**
 * ML-KEM-768 key pair. Returns JSON: { ek: base64url, dk: base64url }
 */
export function wasm_mlkem_keygen(): string;

/**
 * X3DH shared key derivation (classical)
 */
export function wasm_x3dh(my_ik: WasmKeyPair, my_spk: WasmKeyPair, peer_ik_b64: string, peer_spk_b64: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmaaidentity_free: (a: number, b: number) => void;
    readonly __wbg_wasmkeypair_free: (a: number, b: number) => void;
    readonly __wbg_wasmsession_free: (a: number, b: number) => void;
    readonly wasm_aa_bind_userop: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasm_aa_derive: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly wasm_aa_sign_ton_extension: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasm_aa_verify_ton_extension: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasm_aa_verify_userop: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasm_ec_sign: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasm_ec_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasm_hkdf: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasm_hybrid_initiate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly wasm_hybrid_respond: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly wasm_hybrid_session_initiate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly wasm_hybrid_session_respond: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly wasm_mlkem_decaps: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_mlkem_encaps: (a: number, b: number) => [number, number, number, number];
    readonly wasm_mlkem_keygen: () => [number, number, number, number];
    readonly wasm_x3dh: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasmaaidentity_address: (a: number) => [number, number];
    readonly wasmaaidentity_chain_type: (a: number) => [number, number];
    readonly wasmaaidentity_derive: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasmaaidentity_establish_session_with: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmaaidentity_identity_key: (a: number) => [number, number];
    readonly wasmaaidentity_mlkem_ek: (a: number) => [number, number];
    readonly wasmaaidentity_respond_to_session: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wasmaaidentity_signed_pre_key: (a: number) => [number, number];
    readonly wasmaaidentity_spk_signature: (a: number) => [number, number];
    readonly wasmaaidentity_verify_spk: (a: number) => [number, number, number];
    readonly wasmkeypair_from_private_key: (a: number, b: number) => [number, number, number];
    readonly wasmkeypair_generate: () => number;
    readonly wasmkeypair_private_key: (a: number) => [number, number];
    readonly wasmkeypair_public_key: (a: number) => [number, number];
    readonly wasmsession_decrypt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmsession_encrypt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmsession_establish: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasmsession_from_json: (a: number, b: number) => [number, number, number];
    readonly wasmsession_to_json: (a: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
