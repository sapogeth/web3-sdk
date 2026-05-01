/**
 * STVOR Registry — TypeScript wrapper
 *
 * Sends transactions to the stvor_registry.fc contract
 * and reads state via TON HTTP API.
 * Used by @stvor/web3 SDK instead of TonStorageClient.
 */

import {
  TonClient,
  WalletContractV4,
  internal,
  toNano,
  Address,
  beginCell,
  Cell,
  Dictionary,
} from '@ton/ton';
import type { KeyPair } from '@ton/crypto';

// ─── Op codes (must match FunC contract) ─────────────────────────────────────

const OP_REGISTER_KEYS  = 0x1001;
const OP_STORE_MESSAGE  = 0x1002;
const OP_DELETE_MESSAGE = 0x1003;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RegistryKeys {
  identityKey: Buffer;           // 65 bytes uncompressed P-256
  signedPreKey: Buffer;          // 65 bytes
  signedPreKeySignature: Buffer; // ECDSA DER signature, padded to 64 bytes
}

export interface MessageMeta {
  bagId: bigint;
  from: Address;
  timestamp: number;
}

// ─── Contract wrapper ─────────────────────────────────────────────────────────

export class StvorRegistry {
  private readonly client: TonClient;
  private readonly contractAddress: Address;

  constructor(opts: { endpoint: string; contractAddress: string }) {
    this.client = new TonClient({ endpoint: opts.endpoint });
    this.contractAddress = Address.parse(opts.contractAddress);
  }

  // ── Write ops (send transactions) ─────────────────────────────────────────

  async registerKeys(
    wallet: WalletContractV4,
    keyPair: KeyPair,
    keys: RegistryKeys,
  ): Promise<void> {
    // IK/SPK are 65 bytes = 520 bits
    // Signature padded to 64 bytes = 512 bits
    const sig64 = Buffer.alloc(64);
    keys.signedPreKeySignature.copy(sig64, 0, 0, Math.min(64, keys.signedPreKeySignature.length));

    // Each key in its own ref cell — TON cell limit is 1023 bits
    const ikCell  = beginCell().storeBuffer(keys.identityKey).endCell();
    const spkCell = beginCell().storeBuffer(keys.signedPreKey).endCell();
    const sigCell = beginCell().storeBuffer(sig64).endCell();

    const body = beginCell()
      .storeUint(OP_REGISTER_KEYS, 32)
      .storeUint(0, 64)
      .storeRef(ikCell)
      .storeRef(spkCell)
      .storeRef(sigCell)
      .endCell();

    await this.sendTx(wallet, keyPair, body, '0.02');
  }

  async storeMessage(
    wallet: WalletContractV4,
    keyPair: KeyPair,
    to: Address,
    bagId: bigint,
  ): Promise<void> {
    const body = beginCell()
      .storeUint(OP_STORE_MESSAGE, 32)
      .storeUint(0, 64)
      .storeAddress(to)
      .storeUint(bagId, 256)
      .endCell();

    await this.sendTx(wallet, keyPair, body, '0.01');
  }

  async deleteMessage(
    wallet: WalletContractV4,
    keyPair: KeyPair,
    bagId: bigint,
  ): Promise<void> {
    const body = beginCell()
      .storeUint(OP_DELETE_MESSAGE, 32)
      .storeUint(0, 64)
      .storeUint(bagId, 256)
      .endCell();

    await this.sendTx(wallet, keyPair, body, '0.01');
  }

  // ── Read ops (get methods) ─────────────────────────────────────────────────

  async getKeys(address: Address): Promise<RegistryKeys | null> {
    try {
      const result = await this.client.runMethod(this.contractAddress, 'get_keys', [
        { type: 'int', value: BigInt('0x' + address.hash.toString('hex')) },
      ]);

      const ik  = result.stack.readBuffer();   // 65 bytes
      const spk = result.stack.readBuffer();   // 65 bytes
      const sig = result.stack.readBuffer();   // 64 bytes
      // ts = result.stack.readNumber();

      return { identityKey: ik, signedPreKey: spk, signedPreKeySignature: sig };
    } catch {
      return null; // 404 = not registered
    }
  }

  async getMessageCount(address: Address): Promise<number> {
    const result = await this.client.runMethod(this.contractAddress, 'get_message_count', [
      { type: 'int', value: BigInt('0x' + address.hash.toString('hex')) },
    ]);
    return result.stack.readNumber();
  }

  async getMessages(address: Address): Promise<MessageMeta[]> {
    const result = await this.client.runMethod(this.contractAddress, 'get_messages', [
      { type: 'int', value: BigInt('0x' + address.hash.toString('hex')) },
    ]);

    const dictCell = result.stack.readCellOpt();
    if (!dictCell) return [];

    const messages: MessageMeta[] = [];
    const dict = Dictionary.loadDirect(
      Dictionary.Keys.BigUint(256),
      Dictionary.Values.Cell(),
      dictCell,
    );

    for (const [bagId, metaCell] of dict) {
      const cs = metaCell.beginParse();
      const from = cs.loadAddress();
      const timestamp = Number(cs.loadUintBig(64));
      messages.push({ bagId, from, timestamp });
    }
    return messages;
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private async sendTx(
    wallet: WalletContractV4,
    keyPair: KeyPair,
    body: Cell,
    value: string,
  ): Promise<void> {
    const walletContract = this.client.open(wallet);
    const seqno = await walletContract.getSeqno();

    await walletContract.sendTransfer({
      secretKey: keyPair.secretKey,
      seqno,
      messages: [
        internal({
          to: this.contractAddress,
          value: toNano(value),
          body,
          bounce: true,
        }),
      ],
    });
  }
}
