/**
 * STVOR Web3 — TON Storage + Registry client
 *
 * Key registry:  stvor_registry.fc smart contract (on-chain, trustless)
 * Message relay: TonCenter HTTP API v2 + TON Storage (decentralised)
 *
 * Zero external dependencies — uses only native fetch + Web Crypto API.
 *
 * ## Status
 *
 * This module provides the complete API surface for on-chain key registration
 * and off-chain message delivery. Some parts require a deployed contract:
 *
 * - `registerKeys` / `deleteMessage` — require a signed BOC from TonConnect.
 *   Call `buildRegisterKeysBody()` to get the cell body, sign it via TonConnect,
 *   then pass the signed BOC here.
 *
 * - `fetchKeys` — reads from the deployed stvor_registry contract via TonCenter
 *   HTTP API. Requires `contractAddress` to point to a live deployment.
 *   Contract source: `contracts/stvor_registry.fc`. Deploy: `node contracts/deploy.mjs`.
 *
 * - `fetchMessages` / `storeMessage` — use TON Storage (off-chain).
 *   TON Storage availability depends on the network (testnet support is limited).
 *   The `parseMsgMetaDict` function parses TonCenter v2 stack responses; the exact
 *   JSON shape varies by TonCenter version — test against your target API endpoint.
 *
 * - Cell builder (`buildRegisterKeysBody` etc.) — minimal pure-JS implementation
 *   sufficient for the stvor_registry ABI. For complex contracts use @ton/core.
 *
 * ## Contract deployment
 *
 * ```bash
 * export STVOR_MNEMONIC="word1 word2 ... word24"
 * node contracts/deploy.mjs
 * # → prints deployed contract address
 * ```
 */
export interface PublicKeys {
    identityKey: string;
    signedPreKey: string;
    signedPreKeySignature: string;
    mlkemEncapKey: string;
    address: string;
}
export interface StoredMessage {
    id: string;
    from: string;
    ciphertext: string;
    timestamp: number;
}
export declare class TonStorageClient {
    private readonly apiUrl;
    private readonly contractAddress;
    private readonly apiKey;
    constructor(opts: {
        tonApiUrl: string;
        contractAddress: string;
        apiKey?: string;
    });
    registerKeys(_keys: PublicKeys, signedBoc: string): Promise<void>;
    fetchKeys(address: string): Promise<PublicKeys>;
    storeMessage(to: string, msg: Omit<StoredMessage, 'id'>): Promise<string>;
    fetchMessages(address: string): Promise<StoredMessage[]>;
    deleteMessage(_address: string, _messageId: string, signedBoc: string): Promise<void>;
    buildRegisterKeysBody(keys: Omit<PublicKeys, 'address'>): string;
    buildStoreMessageBody(toAddress: string, bagId: string): string;
    buildDeleteMessageBody(bagId: string): string;
    private runGetMethod;
    private sendBoc;
    private downloadBag;
    private fetch;
}
export declare class TonStorageError extends Error {
    readonly status: number;
    constructor(message: string, status: number);
}
//# sourceMappingURL=ton-storage.d.ts.map