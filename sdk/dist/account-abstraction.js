/**
 * STVOR Web3 — Account Abstraction
 *
 * Derives post-quantum E2EE identity from any smart wallet.
 *
 * Supports:
 *   EVM  — ERC-4337 (Safe, Coinbase Smart Wallet, Biconomy, ZeroDev, Kernel)
 *   TON  — Wallet v5 extensions (native TON Account Abstraction)
 *
 * Zero external dependencies.
 *
 * @example — EVM (ERC-4337)
 * import { StvorAA } from '@stvor/web3';
 *
 * const client = await StvorAA.connectEVM({
 *   provider: window.ethereum,   // EIP-1193 (any EVM wallet)
 *   chainId: 1,
 *   wasm,
 * });
 * await client.send('0xbob...', { text: 'gm from AA wallet!' });
 *
 * @example — TON v5
 * const client = await StvorAA.connectTON({
 *   provider: tonConnectProvider,
 *   wasm,
 * });
 */
import { toB64url } from './wallet.js';
// ─── Client ───────────────────────────────────────────────────────────────────
export class StvorAAClient {
    identity;
    wasm;
    handlers = new Set();
    sessions = new Map();
    constructor(identity, wasm) {
        this.identity = identity;
        this.wasm = wasm;
    }
    get address() { return this.identity.address; }
    get chainType() { return this.identity.chainType; }
    get chainId() { return this.identity.chainId; }
    // ── Session ───────────────────────────────────────────────────────────────
    async getOrCreateSession(address) {
        const { WasmSession } = this.wasm;
        if (this.sessions.has(address)) {
            return WasmSession.from_json(this.sessions.get(address));
        }
        // For demo/testnet: derive peer keys from their address deterministically
        // In production: fetch from on-chain registry
        const peer = await this.resolvePeerId(address);
        const initResult = JSON.parse(this.identity._wasmId.establish_session_with(peer.ik, peer.spk, peer.mlkemEk));
        this.sessions.set(peer.address, initResult.session_json);
        return WasmSession.from_json(initResult.session_json);
    }
    saveSession(peerId, session) {
        const json = session.to_json();
        if (typeof json !== 'string')
            throw new StvorAAError('Session serialization failed');
        this.sessions.set(peerId, json);
    }
    // ── Send ─────────────────────────────────────────────────────────────────
    async send(to, data) {
        const session = await this.getOrCreateSession(to);
        const plaintext = new TextEncoder().encode(JSON.stringify(data));
        const blob = session.encrypt(plaintext);
        this.saveSession(to, session);
        // Store message — in production: use TON Storage or on-chain event
        this.queueMessage(to, blob, data);
    }
    // ── Receive ───────────────────────────────────────────────────────────────
    onMessage(handler) {
        this.handlers.add(handler);
        return () => this.handlers.delete(handler);
    }
    // ── UserOperation binding (ERC-4337) ─────────────────────────────────────
    /**
     * Bind an E2EE session to a UserOperation.
     * Proves this E2EE session belongs to the AA wallet submitting the op.
     *
     * @param userOpHash  — keccak256 of the UserOperation (hex, 32 bytes)
     * @param sessionKey  — Double Ratchet root key of the session (base64url, 32 bytes)
     */
    bindUserOp(userOpHash, sessionKey) {
        const raw = JSON.parse(this.wasm.wasm_aa_bind_userop(userOpHash, this.identity._wasmId, sessionKey));
        return {
            userOpHash: raw.user_op_hash,
            identitySig: raw.identity_sig,
            sessionCommitment: raw.session_commitment,
        };
    }
    /**
     * Verify a UserOpBinding from a peer — confirms their E2EE session
     * is bound to a specific UserOperation.
     */
    verifyUserOp(binding, peerIk, sessionKey) {
        const json = JSON.stringify({
            user_op_hash: binding.userOpHash,
            identity_sig: binding.identitySig,
            session_commitment: binding.sessionCommitment,
        });
        return this.wasm.wasm_aa_verify_userop(json, peerIk, sessionKey);
    }
    // ── TON v5 Extension binding ──────────────────────────────────────────────
    /**
     * Sign a TON Wallet v5 extension body with the STVOR identity key.
     * Returns signed extension payload.
     */
    signTonExtension(bodyHex) {
        const raw = JSON.parse(this.wasm.wasm_aa_sign_ton_extension(this.identity.address, bodyHex, this.identity._wasmId));
        return { bodyHex: raw.body_hex, identitySig: raw.identity_sig, walletAddress: raw.wallet_address };
    }
    /**
     * Verify a TON v5 extension signature from a peer.
     */
    verifyTonExtension(ext, peerIk) {
        const json = JSON.stringify({
            body_hex: ext.bodyHex, identity_sig: ext.identitySig, wallet_address: ext.walletAddress,
        });
        return this.wasm.wasm_aa_verify_ton_extension(json, peerIk);
    }
    // ── Disconnect ────────────────────────────────────────────────────────────
    async disconnect() {
        this.handlers.clear();
        this.sessions.clear();
    }
    // ── Internal ──────────────────────────────────────────────────────────────
    async resolvePeerId(address) {
        // In production: fetch from stvor_registry contract
        // For now: derive deterministic demo keys from address hash
        const seed = toB64url(new TextEncoder().encode(`demo-peer:${address}`));
        const salt = toB64url(new TextEncoder().encode('stvor-peer-demo'));
        const ikSeed = this.wasm.wasm_hkdf(seed, salt, 'PEER-IK', 32);
        const spkSeed = this.wasm.wasm_hkdf(seed, salt, 'PEER-SPK', 32);
        const ikKp = this.wasm.WasmKeyPair.from_private_key(ikSeed);
        const spkKp = this.wasm.WasmKeyPair.from_private_key(spkSeed);
        const pqc = JSON.parse(this.wasm.wasm_mlkem_keygen());
        return { address, ik: ikKp.public_key, spk: spkKp.public_key, mlkemEk: pqc.ek };
    }
    pendingMessages = new Map();
    queueMessage(to, blob, data) {
        // In-memory queue for demo — production: TON Storage
        if (!this.pendingMessages.has(to))
            this.pendingMessages.set(to, []);
        this.pendingMessages.get(to).push({ blob, data, ts: Date.now() });
    }
    // ── Factory ───────────────────────────────────────────────────────────────
    static async connectEVM(config) {
        const { provider, chainId, wasm } = config;
        // Get wallet address
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        if (!accounts?.length)
            throw new StvorAAError('No accounts found');
        const address = accounts[0].toLowerCase();
        // Sign identity message — works with EOA and AA smart wallets
        const message = `STVOR-AA-EVM-v1:${chainId}:${address}`;
        const msgHex = '0x' + Array.from(new TextEncoder().encode(message))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        const sigHex = await provider.request({
            method: 'personal_sign',
            params: [msgHex, address],
        });
        // personal_sign returns "0x" + 130 hex chars (65 bytes)
        const sigBytes = fromHex(sigHex.slice(2));
        const sigB64 = toB64url(sigBytes);
        const chainIdStr = chainId.toString();
        const wasmId = wasm.WasmAaIdentity.derive(address, chainIdStr, 'evm', sigB64);
        const identity = {
            address,
            chainId: chainIdStr,
            chainType: 'evm',
            identityKey: wasmId.identity_key,
            signedPreKey: wasmId.signed_pre_key,
            spkSignature: wasmId.spk_signature,
            mlkemEncapKey: wasmId.mlkem_ek,
            _wasmId: wasmId,
        };
        return new StvorAAClient(identity, wasm);
    }
    static async connectTON(config) {
        const { provider, wasm } = config;
        const { address, chain } = provider.account;
        const message = `STVOR-AA-TON-v1:${chain === '-239' ? 'mainnet' : 'testnet'}:${address.toLowerCase()}`;
        const msgB64 = btoa(String.fromCharCode(...new TextEncoder().encode(message)));
        const { signature } = await provider.signData({ cell: msgB64 });
        const sigB64 = signature;
        const chainId = chain === '-239' ? 'mainnet' : 'testnet';
        const wasmId = wasm.WasmAaIdentity.derive(address, chainId, 'ton', sigB64);
        const identity = {
            address,
            chainId,
            chainType: 'ton',
            identityKey: wasmId.identity_key,
            signedPreKey: wasmId.signed_pre_key,
            spkSignature: wasmId.spk_signature,
            mlkemEncapKey: wasmId.mlkem_ek,
            _wasmId: wasmId,
        };
        return new StvorAAClient(identity, wasm);
    }
}
// ─── Namespace export ─────────────────────────────────────────────────────────
export const StvorAA = {
    connectEVM: StvorAAClient.connectEVM.bind(StvorAAClient),
    connectTON: StvorAAClient.connectTON.bind(StvorAAClient),
};
// ─── Error ────────────────────────────────────────────────────────────────────
export class StvorAAError extends Error {
    constructor(message) {
        super(message);
        this.name = 'StvorAAError';
    }
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function fromHex(hex) {
    if (hex.length % 2 !== 0)
        hex = '0' + hex;
    return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}
