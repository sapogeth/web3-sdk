/**
 * STVOR Web3 — Main Client
 *
 * Fully decentralised E2EE on TON:
 *  - Identity    = TON wallet address
 *  - Crypto      = Hybrid X3DH (P-256 + ML-KEM-768) + Double Ratchet + AES-256-GCM
 *  - Key storage = TON smart contract (on-chain, trustless)
 *  - Messages    = TON Storage (decentralised, off-chain)
 *
 * @example
 * import { StvorWeb3 } from '@stvor/web3';
 * import initWasm from '@stvor/web3/wasm';
 *
 * const wasm = await initWasm();
 *
 * const alice = await StvorWeb3.connect({
 *   provider: tonConnectProvider,
 *   contractAddress: 'EQD...',
 *   tonApiUrl: 'https://testnet.toncenter.com/api/v2',
 *   wasm,
 * });
 *
 * alice.onMessage(msg => console.log(msg.from, msg.data));
 * await alice.send('0:bob_address...', { text: 'gm from TON!' });
 * await alice.disconnect();
 */
import { connectWithTON, toB64url, fromB64url } from './wallet.js';
import { TonStorageClient } from './ton-storage.js';
// ─── Client ───────────────────────────────────────────────────────────────────
export class StvorWeb3Client {
    identity;
    storage;
    wasm;
    pollIntervalMs;
    handlers = new Set();
    sessions = new Map();
    pollTimer = null;
    alive = true;
    pqc;
    constructor(identity, storage, wasm, pollIntervalMs, pqc) {
        this.identity = identity;
        this.storage = storage;
        this.wasm = wasm;
        this.pollIntervalMs = pollIntervalMs;
        this.pqc = pqc;
    }
    get address() { return this.identity.address; }
    get chain() { return this.identity.chain; }
    // ── Session ───────────────────────────────────────────────────────────────
    async getOrCreateSession(peerId) {
        const { WasmSession, wasm_ec_verify, wasm_hybrid_session_initiate } = this.wasm;
        if (this.sessions.has(peerId)) {
            return WasmSession.from_json(this.sessions.get(peerId).json);
        }
        const peerKeys = await this.storage.fetchKeys(peerId);
        // Verify peer's SPK signature
        const spkPubBytes = fromB64url(peerKeys.signedPreKey);
        const spkSigBytes = fromB64url(peerKeys.signedPreKeySignature);
        if (!wasm_ec_verify(spkPubBytes, toB64url(spkSigBytes), peerKeys.identityKey)) {
            throw new StvorWeb3Error(`Invalid SPK signature for ${peerId}`);
        }
        let session;
        let isHybrid = false;
        if (this.pqc && peerKeys.mlkemEncapKey) {
            // Hybrid X3DH: P-256 + ML-KEM-768
            const initResult = JSON.parse(wasm_hybrid_session_initiate(this.identity.identityKeyPair, this.identity.signedPreKeyPair, peerKeys.identityKey, peerKeys.signedPreKey, peerKeys.mlkemEncapKey));
            session = WasmSession.from_json(initResult.session_json);
            isHybrid = true;
            // Store the mlkem_ct so the responder can complete handshake
            // In production: send mlkem_ct to peer via a handshake message
            // For now we store it in a special metadata field
            await this.storage.storeMessage(peerId, {
                from: this.identity.address,
                ciphertext: JSON.stringify({ __handshake__: true, mlkem_ct: initResult.mlkem_ct }),
                timestamp: Date.now(),
            });
        }
        else {
            // Classical X3DH fallback
            session = WasmSession.establish(this.identity.identityKeyPair, this.identity.signedPreKeyPair, peerKeys.identityKey, peerKeys.signedPreKey);
        }
        this.saveSession(peerId, session, isHybrid);
        return session;
    }
    saveSession(peerId, session, hybrid) {
        const result = session.to_json();
        if (typeof result !== 'string')
            throw new StvorWeb3Error('Session serialization failed');
        this.sessions.set(peerId, { json: result, hybrid });
    }
    // ── Send ─────────────────────────────────────────────────────────────────
    async send(to, data) {
        const session = await this.getOrCreateSession(to);
        const plaintext = new TextEncoder().encode(JSON.stringify(data));
        const ciphertextB64 = session.encrypt(plaintext);
        this.saveSession(to, session, this.sessions.get(to)?.hybrid ?? false);
        await this.storage.storeMessage(to, {
            from: this.identity.address,
            ciphertext: ciphertextB64,
            timestamp: Date.now(),
        });
    }
    // ── Receive ───────────────────────────────────────────────────────────────
    onMessage(handler) {
        this.handlers.add(handler);
        return () => this.handlers.delete(handler);
    }
    async poll() {
        if (!this.alive)
            return;
        try {
            const messages = await this.storage.fetchMessages(this.identity.address);
            for (const msg of messages) {
                await this.processIncoming(msg);
                // Note: deletion requires signed tx — skip in polling, expire server-side
            }
        }
        catch {
            // ignore transient network errors
        }
        finally {
            if (this.alive) {
                this.pollTimer = setTimeout(() => this.poll(), this.pollIntervalMs);
            }
        }
    }
    async processIncoming(raw) {
        const { wasm_hybrid_session_respond } = this.wasm;
        // Check if this is a hybrid handshake initiation
        try {
            const meta = JSON.parse(raw.ciphertext);
            if (meta.__handshake__ && meta.mlkem_ct && this.identity.mlkemDecapKey) {
                const peerKeys = await this.storage.fetchKeys(raw.from);
                const session = wasm_hybrid_session_respond(this.identity.identityKeyPair, this.identity.signedPreKeyPair, peerKeys.identityKey, peerKeys.signedPreKey, this.identity.mlkemDecapKey, meta.mlkem_ct);
                this.saveSession(raw.from, session, true);
                return;
            }
        }
        catch {
            // Not a handshake message — proceed as normal
        }
        const session = await this.getOrCreateSession(raw.from);
        let plaintext;
        try {
            plaintext = session.decrypt(raw.ciphertext);
        }
        catch {
            return; // drop undecryptable messages silently
        }
        this.saveSession(raw.from, session, this.sessions.get(raw.from)?.hybrid ?? false);
        let data;
        try {
            data = JSON.parse(new TextDecoder().decode(plaintext));
        }
        catch {
            data = new TextDecoder().decode(plaintext);
        }
        const msg = { from: raw.from, data, timestamp: new Date(raw.timestamp), id: raw.id };
        for (const h of this.handlers)
            await h(msg);
    }
    // ── Disconnect ────────────────────────────────────────────────────────────
    async disconnect() {
        this.alive = false;
        if (this.pollTimer)
            clearTimeout(this.pollTimer);
        this.handlers.clear();
        this.sessions.clear();
    }
    // ── Factory ───────────────────────────────────────────────────────────────
    static async connect(config) {
        const pqc = config.pqc ?? true;
        const identity = await connectWithTON(config.provider, config.wasm, pqc);
        const storage = new TonStorageClient({
            tonApiUrl: config.tonApiUrl,
            contractAddress: config.contractAddress,
            apiKey: config.tonApiKey,
        });
        const mlkemEncapKey = identity.mlkemEncapKey ?? '';
        // Build register_keys transaction body and sign via TonConnect
        const regBody = storage.buildRegisterKeysBody({
            identityKey: identity.identityKeyPair.public_key,
            signedPreKey: identity.signedPreKeyPair.public_key,
            signedPreKeySignature: toB64url(identity.signedPreKeySignature),
            mlkemEncapKey,
        });
        const signedBoc = await config.provider.signTransaction(config.contractAddress, regBody, '20000000');
        await storage.registerKeys({
            address: identity.address,
            identityKey: identity.identityKeyPair.public_key,
            signedPreKey: identity.signedPreKeyPair.public_key,
            signedPreKeySignature: toB64url(identity.signedPreKeySignature),
            mlkemEncapKey,
        }, signedBoc);
        const client = new StvorWeb3Client(identity, storage, config.wasm, config.pollIntervalMs ?? 5_000, pqc);
        client.poll();
        return client;
    }
}
export const StvorWeb3 = {
    connect: StvorWeb3Client.connect.bind(StvorWeb3Client),
};
export class StvorWeb3Error extends Error {
    constructor(message) {
        super(message);
        this.name = 'StvorWeb3Error';
    }
}
