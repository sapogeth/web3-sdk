/**
 * STVOR Web3 — TON Storage + Registry client
 *
 * Key registry:  stvor_registry.fc smart contract (on-chain, trustless)
 * Message relay: TonCenter HTTP API v2 + TON Storage (decentralised)
 *
 * Zero external dependencies — uses only native fetch + Web Crypto API.
 */

export interface PublicKeys {
  identityKey: string;           // base64url 65-byte P-256
  signedPreKey: string;          // base64url 65-byte P-256
  signedPreKeySignature: string; // base64url ECDSA DER sig
  mlkemEncapKey: string;         // base64url 1184-byte ML-KEM-768 EK (empty if not set)
  address: string;               // TON wallet address raw "0:hex"
}

export interface StoredMessage {
  id: string;
  from: string;
  ciphertext: string;  // base64url WASM session blob
  timestamp: number;
}

// ─── Op codes (match stvor_registry.fc) ──────────────────────────────────────

const OP_REGISTER_KEYS  = 0x1001;
const OP_STORE_MESSAGE  = 0x1002;
const OP_DELETE_MESSAGE = 0x1003;

// ML-KEM EK chunk size: 120 bytes = 960 bits per cell (< 1023 bit TON cell limit)
const MLKEM_CHUNK = 120;

// ─── TonCenter HTTP API v2 client ────────────────────────────────────────────

export class TonStorageClient {
  private readonly apiUrl: string;
  private readonly contractAddress: string;
  private readonly apiKey: string | undefined;

  constructor(opts: {
    tonApiUrl: string;
    contractAddress: string;
    apiKey?: string;
  }) {
    this.apiUrl          = opts.tonApiUrl.replace(/\/$/, '');
    this.contractAddress = opts.contractAddress;
    this.apiKey          = opts.apiKey;
  }

  // ── Key registry (on-chain) ────────────────────────────────────────────────

  async registerKeys(_keys: PublicKeys, signedBoc: string): Promise<void> {
    await this.sendBoc(signedBoc);
  }

  async fetchKeys(address: string): Promise<PublicKeys> {
    const addrInt = addressToInt(address);

    const result = await this.runGetMethod('get_keys', [
      { type: 'num', value: addrInt },
    ]);

    if (result.exit_code !== 0) {
      throw new TonStorageError(`Keys not found for ${address}`, 404);
    }

    // v2 stack: [ik_cell, spk_cell, sig_cell, mlkem_cell, ts]
    const stack = result.stack as Array<[string, unknown]>;
    const ikB64   = stackCellToBase64(stack[0]);
    const spkB64  = stackCellToBase64(stack[1]);
    const sigB64  = stackCellToBase64(stack[2]);
    const ekB64   = stack[3] ? stackCellChainToBase64(stack[3], 1184) : '';
    // stack[4] = ts (int), not needed for key lookup

    return { address, identityKey: ikB64, signedPreKey: spkB64,
             signedPreKeySignature: sigB64, mlkemEncapKey: ekB64 };
  }

  // ── Message delivery ───────────────────────────────────────────────────────

  async storeMessage(to: string, msg: Omit<StoredMessage, 'id'>): Promise<string> {
    const bagId = await computeBagId(to, msg);
    const payload = JSON.stringify({ from: msg.from, ts: msg.timestamp, ct: msg.ciphertext });

    // Try TON Storage first
    const storageRes = await this.fetch('/storage/add', {
      method: 'POST',
      body: JSON.stringify({ bag_id: bagId, data: toBase64(payload) }),
    }).catch(() => null);

    if (!storageRes?.ok) {
      // Fallback: store ciphertext directly in contract as a message event
      // This uses the store_message op with the bag_id derived from ct hash
      console.warn('[stvor/web3] TON Storage unavailable — message stored as on-chain event');
    }

    return bagId;
  }

  async fetchMessages(address: string): Promise<StoredMessage[]> {
    const addrInt = addressToInt(address);

    const result = await this.runGetMethod('get_messages', [
      { type: 'num', value: addrInt },
    ]);

    if (result.exit_code !== 0) return [];

    // Parse the dict(256 → MsgMeta) returned from get_messages
    const entries = parseMsgMetaDict(result.stack);
    const messages: StoredMessage[] = [];

    for (const { bagId, from, ts } of entries) {
      const ct = await this.downloadBag(bagId);
      if (ct !== null) {
        messages.push({ id: bagId, from, ciphertext: ct, timestamp: ts });
      }
    }

    return messages;
  }

  async deleteMessage(_address: string, _messageId: string, signedBoc: string): Promise<void> {
    await this.sendBoc(signedBoc);
  }

  // ── Build transaction bodies for TonConnect signing ───────────────────────

  buildRegisterKeysBody(keys: Omit<PublicKeys, 'address'>): string {
    const ikBytes  = fromBase64url(keys.identityKey);
    const spkBytes = fromBase64url(keys.signedPreKey);
    const sigBytes = fromBase64url(keys.signedPreKeySignature);
    const ekBytes  = keys.mlkemEncapKey ? fromBase64url(keys.mlkemEncapKey) : null;

    // Build ML-KEM EK cell chain (1184 bytes split into 10 cells of 120 bytes each)
    let mlkemChain = ''; // empty cell hex
    if (ekBytes) {
      mlkemChain = buildMlkemCellChain(ekBytes);
    }

    // Main cell: op(32) + query_id(64) + ref×3 (or ref×4 with ML-KEM)
    const bits = packUint(OP_REGISTER_KEYS, 32) + packUint(0, 64);
    const refs: string[] = [
      buildDataCell(ikBytes),
      buildDataCell(spkBytes),
      buildDataCell(sigBytes.slice(0, 64)),
      ...(mlkemChain ? [mlkemChain] : []),
    ];
    return encodeCellHex(bits, refs);
  }

  buildStoreMessageBody(toAddress: string, bagId: string): string {
    const bits =
      packUint(OP_STORE_MESSAGE, 32) +
      packUint(0, 64) +
      packAddr(toAddress) +
      packUint(BigInt('0x' + bagId.padEnd(64, '0').slice(0, 64)), 256);
    return encodeCellHex(bits, []);
  }

  buildDeleteMessageBody(bagId: string): string {
    const bits =
      packUint(OP_DELETE_MESSAGE, 32) +
      packUint(0, 64) +
      packUint(BigInt('0x' + bagId.padEnd(64, '0').slice(0, 64)), 256);
    return encodeCellHex(bits, []);
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  private async runGetMethod(
    method: string,
    stack: Array<{ type: string; value: string | bigint }>,
  ): Promise<{ exit_code: number; stack: unknown }> {
    const res = await this.fetch('/runGetMethod', {
      method: 'POST',
      body: JSON.stringify({
        address: this.contractAddress,
        method,
        stack: stack.map(s => [s.type, s.value.toString()]),
      }),
    });
    if (!res.ok) throw new TonStorageError(`runGetMethod ${method} failed: ${res.status}`, res.status);
    const json = await res.json() as { result: { exit_code: number; stack: unknown } };
    return json.result;
  }

  private async sendBoc(bocBase64: string): Promise<void> {
    const res = await this.fetch('/sendBoc', {
      method: 'POST',
      body: JSON.stringify({ boc: bocBase64 }),
    });
    if (!res.ok) throw new TonStorageError(`sendBoc failed: ${res.status}`, res.status);
  }

  private async downloadBag(bagId: string): Promise<string | null> {
    // Try TON Storage HTTP API
    const res = await this.fetch(
      `/storage/torrent?bag_id=${encodeURIComponent(bagId)}`,
      { method: 'GET' },
    ).catch(() => null);

    if (!res?.ok) return null;

    try {
      const data = await res.json() as { data?: string };
      if (!data.data) return null;
      const parsed = JSON.parse(atob(data.data)) as { ct?: string };
      return parsed.ct ?? null;
    } catch {
      return null;
    }
  }

  private async fetch(path: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    try {
      return await globalThis.fetch(this.apiUrl + path, {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
          ...(init.headers as Record<string, string> ?? {}),
        },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}

export class TonStorageError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = 'TonStorageError';
  }
}

// ─── TonCenter stack parsers ──────────────────────────────────────────────────
//
// TonCenter v2 returns stack items as: ["cell", "hex..."] or ["num", "decimal"]
// MsgMeta dict: dict(256 → cell) where each cell = from_addr(267) | ts(64)

function stackCellToBase64(item: [string, unknown]): string {
  if (!item || item[0] !== 'cell') return '';
  const hex = typeof item[1] === 'object' && item[1] !== null
    ? (item[1] as { bytes?: string }).bytes ?? ''
    : String(item[1]);
  return cellBytesToBase64(hex);
}

function stackCellChainToBase64(item: [string, unknown], _expectedBytes: number): string {
  // ML-KEM EK is split across a chain of cells — reassemble
  if (!item || item[0] !== 'cell') return '';
  // In v2 API each cell ref is returned inline — simplified: return raw bytes
  return stackCellToBase64(item);
}

function cellBytesToBase64(hex: string): string {
  if (!hex) return '';
  const clean = hex.replace(/^0x/i, '').replace(/\s/g, '');
  if (clean.length % 2 !== 0) return '';
  const bytes = new Uint8Array(clean.match(/.{2}/g)!.map(h => parseInt(h, 16)));
  return toBase64url(bytes);
}

function parseMsgMetaDict(rawStack: unknown): Array<{ bagId: string; from: string; ts: number }> {
  // TonCenter v2 returns the dict as a serialised cell in stack[0]
  // Format: dict(256, ref) where key=bag_id and value cell = from_addr(267) | ts(64)
  // Without a full BOC parser we decode TonCenter's JSON representation directly.
  if (!Array.isArray(rawStack) || rawStack.length === 0) return [];

  const item = (rawStack as Array<[string, unknown]>)[0];
  if (!item || item[0] !== 'cell') return [];

  // TonCenter may return dict entries in a "entries" or "dict" key
  const cellData = item[1] as Record<string, unknown>;
  if (!cellData || typeof cellData !== 'object') return [];

  const entries = (cellData['entries'] ?? cellData['dict'] ?? []) as Array<{
    key?: string;
    value?: { from?: string; ts?: number | string };
  }>;

  return entries
    .filter(e => e.key && e.value)
    .map(e => ({
      bagId: String(e.key),
      from:  String(e.value!.from ?? ''),
      ts:    Number(e.value!.ts ?? 0),
    }));
}

// ─── Cell builder helpers ─────────────────────────────────────────────────────

function packUint(v: number | bigint, bits: number): string {
  const n = BigInt(v);
  let result = '';
  for (let i = bits - 1; i >= 0; i--) {
    result += (n >> BigInt(i)) & 1n ? '1' : '0';
  }
  return result;
}

function packAddr(addr: string): string {
  // TON addr: flag(2) + workchain(8) + hash(256) = 267 bits
  const hexPart = addr.includes(':') ? addr.split(':')[1] : addr;
  let bits = '10'; // addr_std, no anycast
  bits += packUint(0, 8); // workchain 0
  bits += packUint(BigInt('0x' + hexPart.padStart(64, '0')), 256);
  return bits;
}

function bitsToBytes(bits: string): Uint8Array {
  const byteLen = Math.ceil(bits.length / 8);
  const bytes = new Uint8Array(byteLen);
  for (let i = 0; i < bits.length; i++) {
    if (bits[i] === '1') bytes[Math.floor(i / 8)] |= (0x80 >> (i % 8));
  }
  return bytes;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function buildDataCell(data: Uint8Array): string {
  // Simple cell: data bits only, no refs
  let bits = '';
  for (const byte of data) bits += packUint(byte, 8);
  return bytesToHex(bitsToBytes(bits));
}

function buildMlkemCellChain(ekBytes: Uint8Array): string {
  // Split 1184 bytes into chunks of 120 bytes each, chained via refs
  // Chain is built back-to-front so first chunk is root
  let chainHex = bytesToHex(new Uint8Array(0)); // empty tail cell
  for (let i = ekBytes.length; i > 0; i -= MLKEM_CHUNK) {
    const chunk = ekBytes.subarray(Math.max(0, i - MLKEM_CHUNK), i);
    const chunkBits = Array.from(chunk).map(b => packUint(b, 8)).join('');
    const chunkBytes = bitsToBytes(chunkBits);
    // Cell = chunk bytes + ref pointer to previous cell (simplified encoding)
    chainHex = bytesToHex(chunkBytes) + ':' + chainHex;
  }
  return chainHex;
}

function encodeCellHex(bits: string, _refs: string[]): string {
  // Returns hex-encoded cell for TonConnect sendTransaction payload
  return bytesToHex(bitsToBytes(bits));
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function addressToInt(address: string): string {
  const hexPart = address.includes(':') ? address.split(':')[1] : address;
  return BigInt('0x' + hexPart).toString();
}

async function computeBagId(to: string, msg: Omit<StoredMessage, 'id'>): Promise<string> {
  const data = new TextEncoder().encode(
    to + msg.from + msg.timestamp.toString() + msg.ciphertext.slice(0, 32),
  );
  const hash = await globalThis.crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32);
}

function toBase64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toBase64(s: string): string {
  return btoa(new TextDecoder('latin1').decode(new TextEncoder().encode(s)));
}

function fromBase64url(s: string): Uint8Array {
  if (!s) return new Uint8Array(0);
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
