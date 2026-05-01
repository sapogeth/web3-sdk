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
type WasmModule = typeof import('../wasm/stvor_crypto.js');
export interface EIP1193Provider {
    request(args: {
        method: string;
        params?: unknown[];
    }): Promise<unknown>;
}
export interface TonAAProvider {
    account: {
        address: string;
        chain: '-239' | '-3';
    };
    signData(payload: {
        cell: string;
    }): Promise<{
        signature: string;
        timestamp: number;
    }>;
    signTransaction(to: string, bodyHex: string, value: string): Promise<string>;
}
export interface AAIdentity {
    address: string;
    chainId: string;
    chainType: 'evm' | 'ton';
    /** P-256 IK public key (base64url, 65 bytes) */
    identityKey: string;
    /** P-256 SPK public key (base64url, 65 bytes) */
    signedPreKey: string;
    /** ECDSA signature of SPK by IK (base64url) */
    spkSignature: string;
    /** ML-KEM-768 encapsulation key (base64url, 1184 bytes) */
    mlkemEncapKey: string;
    /** WASM identity object */
    _wasmId: import('../wasm/stvor_crypto.js').WasmAaIdentity;
}
export interface UserOpBinding {
    userOpHash: string;
    identitySig: string;
    sessionCommitment: string;
}
export interface StvorAAConfigEVM {
    provider: EIP1193Provider;
    chainId: number;
    wasm: WasmModule;
    pollIntervalMs?: number;
}
export interface StvorAAConfigTON {
    provider: TonAAProvider;
    contractAddress?: string;
    tonApiUrl?: string;
    wasm: WasmModule;
    pollIntervalMs?: number;
}
export interface AAMessage {
    from: string;
    data: unknown;
    timestamp: Date;
    id: string;
}
export type AAMessageHandler = (msg: AAMessage) => void | Promise<void>;
export declare class StvorAAClient {
    readonly identity: AAIdentity;
    private readonly wasm;
    private readonly handlers;
    private readonly sessions;
    private constructor();
    get address(): string;
    get chainType(): 'evm' | 'ton';
    get chainId(): string;
    private getOrCreateSession;
    private saveSession;
    send(to: string, data: unknown): Promise<void>;
    onMessage(handler: AAMessageHandler): () => void;
    /**
     * Bind an E2EE session to a UserOperation.
     * Proves this E2EE session belongs to the AA wallet submitting the op.
     *
     * @param userOpHash  — keccak256 of the UserOperation (hex, 32 bytes)
     * @param sessionKey  — Double Ratchet root key of the session (base64url, 32 bytes)
     */
    bindUserOp(userOpHash: string, sessionKey: string): UserOpBinding;
    /**
     * Verify a UserOpBinding from a peer — confirms their E2EE session
     * is bound to a specific UserOperation.
     */
    verifyUserOp(binding: UserOpBinding, peerIk: string, sessionKey: string): boolean;
    /**
     * Sign a TON Wallet v5 extension body with the STVOR identity key.
     * Returns signed extension payload.
     */
    signTonExtension(bodyHex: string): {
        bodyHex: string;
        identitySig: string;
        walletAddress: string;
    };
    /**
     * Verify a TON v5 extension signature from a peer.
     */
    verifyTonExtension(ext: {
        bodyHex: string;
        identitySig: string;
        walletAddress: string;
    }, peerIk: string): boolean;
    disconnect(): Promise<void>;
    private resolvePeerId;
    private pendingMessages;
    private queueMessage;
    static connectEVM(config: StvorAAConfigEVM): Promise<StvorAAClient>;
    static connectTON(config: StvorAAConfigTON): Promise<StvorAAClient>;
}
export declare const StvorAA: {
    connectEVM: typeof StvorAAClient.connectEVM;
    connectTON: typeof StvorAAClient.connectTON;
};
export declare class StvorAAError extends Error {
    constructor(message: string);
}
export {};
//# sourceMappingURL=account-abstraction.d.ts.map