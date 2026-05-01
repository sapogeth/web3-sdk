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
import type { TonConnectProvider } from './wallet.js';
type WasmModule = typeof import('../wasm/stvor_crypto.js');
export interface StvorWeb3Config {
    provider: TonConnectProvider;
    contractAddress: string;
    tonApiUrl: string;
    wasm: WasmModule;
    tonApiKey?: string;
    pollIntervalMs?: number;
    /** Use hybrid PQC (ML-KEM-768 + X3DH). Default: true */
    pqc?: boolean;
}
export interface Web3Message {
    from: string;
    data: unknown;
    timestamp: Date;
    id: string;
}
export type MessageHandler = (msg: Web3Message) => void | Promise<void>;
export declare class StvorWeb3Client {
    private readonly identity;
    private readonly storage;
    private readonly wasm;
    private readonly pollIntervalMs;
    private readonly handlers;
    private readonly sessions;
    private pollTimer;
    private alive;
    private readonly pqc;
    private constructor();
    get address(): string;
    get chain(): 'mainnet' | 'testnet';
    private getOrCreateSession;
    private saveSession;
    send(to: string, data: unknown): Promise<void>;
    onMessage(handler: MessageHandler): () => void;
    private poll;
    private processIncoming;
    disconnect(): Promise<void>;
    static connect(config: StvorWeb3Config): Promise<StvorWeb3Client>;
}
export declare const StvorWeb3: {
    connect: typeof StvorWeb3Client.connect;
};
export declare class StvorWeb3Error extends Error {
    constructor(message: string);
}
export {};
//# sourceMappingURL=stvor.d.ts.map