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

type WasmModule = typeof import('../wasm/stvor_crypto.js');

// ─── EIP-1193 provider (EVM) ──────────────────────────────────────────────────

export interface EIP1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

// ─── TON Connect provider (subset) ───────────────────────────────────────────

export interface TonAAProvider {
  account: {
    address: string;
    chain: '-239' | '-3';
  };
  signData(payload: { cell: string }): Promise<{ signature: string; timestamp: number }>;
  signTransaction(to: string, bodyHex: string, value: string): Promise<string>;
}

// ─── AA Identity ─────────────────────────────────────────────────────────────

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

// ─── UserOperation binding ────────────────────────────────────────────────────

export interface UserOpBinding {
  userOpHash: string;
  identitySig: string;
  sessionCommitment: string;
}

// ─── Config ───────────────────────────────────────────────────────────────────

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

// ─── Message ──────────────────────────────────────────────────────────────────

export interface AAMessage {
  from: string;
  data: unknown;
  timestamp: Date;
  id: string;
}

export type AAMessageHandler = (msg: AAMessage) => void | Promise<void>;

// ─── Client ───────────────────────────────────────────────────────────────────

export class StvorAAClient {
  private readonly handlers = new Set<AAMessageHandler>();
  private readonly sessions = new Map<string, string>();

  private constructor(
    readonly identity: AAIdentity,
    private readonly wasm: WasmModule,
  ) {}

  get address(): string { return this.identity.address; }
  get chainType(): 'evm' | 'ton' { return this.identity.chainType; }
  get chainId(): string { return this.identity.chainId; }

  // ── Session ───────────────────────────────────────────────────────────────

  private async getOrCreateSession(address: string): Promise<import('../wasm/stvor_crypto.js').WasmSession> {
    const { WasmSession } = this.wasm;

    if (this.sessions.has(address)) {
      return WasmSession.from_json(this.sessions.get(address)!);
    }

    // For demo/testnet: derive peer keys from their address deterministically
    // In production: fetch from on-chain registry
    const peer = await this.resolvePeerId(address);

    const initResult = JSON.parse(
      this.identity._wasmId.establish_session_with(
        peer.ik, peer.spk, peer.mlkemEk,
      )
    ) as { session_json: string; mlkem_ct: string };

    this.sessions.set(peer.address, initResult.session_json);
    return WasmSession.from_json(initResult.session_json);
  }

  private saveSession(peerId: string, session: import('../wasm/stvor_crypto.js').WasmSession): void {
    const json = session.to_json();
    if (typeof json !== 'string') throw new StvorAAError('Session serialization failed');
    this.sessions.set(peerId, json);
  }

  // ── Send ─────────────────────────────────────────────────────────────────

  async send(to: string, data: unknown): Promise<void> {
    const session = await this.getOrCreateSession(to);
    const plaintext = new TextEncoder().encode(JSON.stringify(data));
    const blob = session.encrypt(plaintext);
    this.saveSession(to, session);

    // Store message — in production: use TON Storage or on-chain event
    this.queueMessage(to, blob, data);
  }

  // ── Receive ───────────────────────────────────────────────────────────────

  onMessage(handler: AAMessageHandler): () => void {
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
  bindUserOp(userOpHash: string, sessionKey: string): UserOpBinding {
    const raw = JSON.parse(
      this.wasm.wasm_aa_bind_userop(userOpHash, this.identity._wasmId, sessionKey)
    ) as { user_op_hash: string; identity_sig: string; session_commitment: string };
    return {
      userOpHash:        raw.user_op_hash,
      identitySig:       raw.identity_sig,
      sessionCommitment: raw.session_commitment,
    };
  }

  /**
   * Verify a UserOpBinding from a peer — confirms their E2EE session
   * is bound to a specific UserOperation.
   */
  verifyUserOp(binding: UserOpBinding, peerIk: string, sessionKey: string): boolean {
    const json = JSON.stringify({
      user_op_hash:       binding.userOpHash,
      identity_sig:       binding.identitySig,
      session_commitment: binding.sessionCommitment,
    });
    return this.wasm.wasm_aa_verify_userop(json, peerIk, sessionKey);
  }

  // ── TON v5 Extension binding ──────────────────────────────────────────────

  /**
   * Sign a TON Wallet v5 extension body with the STVOR identity key.
   * Returns signed extension payload.
   */
  signTonExtension(bodyHex: string): { bodyHex: string; identitySig: string; walletAddress: string } {
    const raw = JSON.parse(
      this.wasm.wasm_aa_sign_ton_extension(this.identity.address, bodyHex, this.identity._wasmId)
    ) as { body_hex: string; identity_sig: string; wallet_address: string };
    return { bodyHex: raw.body_hex, identitySig: raw.identity_sig, walletAddress: raw.wallet_address };
  }

  /**
   * Verify a TON v5 extension signature from a peer.
   */
  verifyTonExtension(ext: { bodyHex: string; identitySig: string; walletAddress: string }, peerIk: string): boolean {
    const json = JSON.stringify({
      body_hex: ext.bodyHex, identity_sig: ext.identitySig, wallet_address: ext.walletAddress,
    });
    return this.wasm.wasm_aa_verify_ton_extension(json, peerIk);
  }

  // ── Disconnect ────────────────────────────────────────────────────────────

  async disconnect(): Promise<void> {
    this.handlers.clear();
    this.sessions.clear();
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private async resolvePeerId(address: string): Promise<{ address: string; ik: string; spk: string; mlkemEk: string }> {
    // In production: fetch from stvor_registry contract
    // For now: derive deterministic demo keys from address hash
    const seed = toB64url(new TextEncoder().encode(`demo-peer:${address}`));
    const salt = toB64url(new TextEncoder().encode('stvor-peer-demo'));
    const ikSeed  = this.wasm.wasm_hkdf(seed, salt, 'PEER-IK', 32);
    const spkSeed = this.wasm.wasm_hkdf(seed, salt, 'PEER-SPK', 32);
    const ikKp    = this.wasm.WasmKeyPair.from_private_key(ikSeed);
    const spkKp   = this.wasm.WasmKeyPair.from_private_key(spkSeed);
    const pqc     = JSON.parse(this.wasm.wasm_mlkem_keygen()) as { ek: string };
    return { address, ik: ikKp.public_key, spk: spkKp.public_key, mlkemEk: pqc.ek };
  }

  private pendingMessages = new Map<string, Array<{ blob: string; data: unknown; ts: number }>>();

  private queueMessage(to: string, blob: string, data: unknown): void {
    // In-memory queue for demo — production: TON Storage
    if (!this.pendingMessages.has(to)) this.pendingMessages.set(to, []);
    this.pendingMessages.get(to)!.push({ blob, data, ts: Date.now() });
  }

  // ── Factory ───────────────────────────────────────────────────────────────

  static async connectEVM(config: StvorAAConfigEVM): Promise<StvorAAClient> {
    const { provider, chainId, wasm } = config;

    // Get wallet address
    const accounts = await provider.request({ method: 'eth_requestAccounts' }) as string[];
    if (!accounts?.length) throw new StvorAAError('No accounts found');
    const address = accounts[0].toLowerCase();

    // Sign identity message — works with EOA and AA smart wallets
    const message    = `STVOR-AA-EVM-v1:${chainId}:${address}`;
    const msgHex     = '0x' + Array.from(new TextEncoder().encode(message))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const sigHex     = await provider.request({
      method: 'personal_sign',
      params: [msgHex, address],
    }) as string;

    // personal_sign returns "0x" + 130 hex chars (65 bytes)
    const sigBytes   = fromHex(sigHex.slice(2));
    const sigB64     = toB64url(sigBytes);
    const chainIdStr = chainId.toString();

    const wasmId = wasm.WasmAaIdentity.derive(address, chainIdStr, 'evm', sigB64);

    const identity: AAIdentity = {
      address,
      chainId: chainIdStr,
      chainType: 'evm',
      identityKey:   wasmId.identity_key,
      signedPreKey:  wasmId.signed_pre_key,
      spkSignature:  wasmId.spk_signature,
      mlkemEncapKey: wasmId.mlkem_ek,
      _wasmId:       wasmId,
    };

    return new StvorAAClient(identity, wasm);
  }

  static async connectTON(config: StvorAAConfigTON): Promise<StvorAAClient> {
    const { provider, wasm } = config;
    const { address, chain } = provider.account;

    const message = `STVOR-AA-TON-v1:${chain === '-239' ? 'mainnet' : 'testnet'}:${address.toLowerCase()}`;
    const msgB64  = btoa(String.fromCharCode(...new TextEncoder().encode(message)));

    const { signature } = await provider.signData({ cell: msgB64 });
    const sigB64        = signature;
    const chainId       = chain === '-239' ? 'mainnet' : 'testnet';

    const wasmId = wasm.WasmAaIdentity.derive(address, chainId, 'ton', sigB64);

    const identity: AAIdentity = {
      address,
      chainId,
      chainType: 'ton',
      identityKey:   wasmId.identity_key,
      signedPreKey:  wasmId.signed_pre_key,
      spkSignature:  wasmId.spk_signature,
      mlkemEncapKey: wasmId.mlkem_ek,
      _wasmId:       wasmId,
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
  constructor(message: string) {
    super(message);
    this.name = 'StvorAAError';
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return new Uint8Array(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
}
