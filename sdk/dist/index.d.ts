/**
 * @stvor/web3 — Decentralised post-quantum E2EE on TON. Zero external dependencies.
 *
 * Crypto stack:
 *   P-256 X3DH + ML-KEM-768 (NIST FIPS 203) + Double Ratchet + AES-256-GCM
 *   Implemented in Rust, compiled to WASM. NIST ACVTS verified (53 vectors).
 *
 * @example
 * import { StvorWeb3 } from '@stvor/web3';
 * import initWasm from '@stvor/web3/wasm';
 *
 * const wasm = await initWasm();
 *
 * const alice = await StvorWeb3.connect({
 *   provider: tonConnectProvider,   // TonConnect wallet
 *   contractAddress: 'EQD...',      // stvor_registry on TON testnet
 *   tonApiUrl: 'https://testnet.toncenter.com/api/v2',
 *   wasm,
 * });
 *
 * alice.onMessage(msg => console.log(msg.from, msg.data));
 * await alice.send('0:bob...', { text: 'Quantum-safe gm!' });
 * await alice.disconnect();
 */
export { StvorWeb3, StvorWeb3Client, StvorWeb3Error } from './stvor.js';
export type { StvorWeb3Config, Web3Message, MessageHandler } from './stvor.js';
export { connectWithTON, toB64url, fromB64url } from './wallet.js';
export type { TonConnectProvider, WalletIdentity } from './wallet.js';
export { TonStorageClient, TonStorageError } from './ton-storage.js';
export type { PublicKeys, StoredMessage } from './ton-storage.js';
export { StvorAA, StvorAAClient, StvorAAError } from './account-abstraction.js';
export type { AAIdentity, AAMessage, AAMessageHandler, EIP1193Provider, TonAAProvider, StvorAAConfigEVM, StvorAAConfigTON, UserOpBinding, } from './account-abstraction.js';
//# sourceMappingURL=index.d.ts.map