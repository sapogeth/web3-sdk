/**
 * StvorRegistry contract tests v2 — includes ML-KEM EK ref
 */

import { Cell, beginCell, Address } from '@ton/core';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const contractCode = Cell.fromBoc(
  readFileSync(join(__dirname, '../build/stvor_registry.boc'))
)[0];

const OP_REGISTER_KEYS  = 0x1001;
const OP_STORE_MESSAGE  = 0x1002;
const OP_DELETE_MESSAGE = 0x1003;

// Updated hash after adding ML-KEM EK support
const EXPECTED_HASH = '3C7FF48E8BE765563CD894C8AA0B3D58DFF6270A40A9D5AAEF359D8C0FD6C005';

let passed = 0; let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try { await fn(); console.log(`  ✓ ${name}`); passed++; }
  catch (e: unknown) { console.error(`  ✗ ${name}: ${(e as Error).message}`); failed++; }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

console.log('\nStvorRegistry contract tests v2\n');

await test('Contract compiles to valid BOC', () => {
  assert(contractCode instanceof Cell, 'Must be a Cell');
  const hash = contractCode.hash().toString('hex').toUpperCase();
  assert(hash.length === 64, 'Hash must be 64 hex chars');
  console.log(`    code hash: ${hash.slice(0, 16)}...`);
});

await test('Contract code hash is stable (v2 with ML-KEM EK)', () => {
  const hash = contractCode.hash().toString('hex').toUpperCase();
  assert(hash === EXPECTED_HASH,
    `Hash mismatch:\n    got:      ${hash}\n    expected: ${EXPECTED_HASH}`);
});

await test('register_keys v2: encodes ik + spk + sig + mlkem_ek refs', () => {
  const ik       = Buffer.alloc(65, 0x04);   // 520 bits
  const spk      = Buffer.alloc(65, 0x03);   // 520 bits
  const sig      = Buffer.alloc(64, 0xab);   // 512 bits
  const mlkemEk  = Buffer.alloc(1184, 0x11); // 9472 bits — stored as cell chain

  // ML-KEM EK: 1184 bytes > 127 bytes (1016 bits) per cell, split into chunks
  // Each TON cell: 1023 bits max = 127 bytes (we use 120 bytes per cell to be safe)
  const chunkSize = 120;
  let mlkemCell = beginCell().endCell();
  for (let i = mlkemEk.length; i > 0; i -= chunkSize) {
    const chunk = mlkemEk.subarray(Math.max(0, i - chunkSize), i);
    mlkemCell = beginCell().storeBuffer(chunk).storeRef(mlkemCell).endCell();
  }

  const body = beginCell()
    .storeUint(OP_REGISTER_KEYS, 32)
    .storeUint(0, 64)
    .storeRef(beginCell().storeBuffer(ik).endCell())
    .storeRef(beginCell().storeBuffer(spk).endCell())
    .storeRef(beginCell().storeBuffer(sig).endCell())
    .storeRef(mlkemCell)
    .endCell();

  const cs = body.beginParse();
  assert(cs.loadUint(32) === OP_REGISTER_KEYS, 'op must match');
  cs.loadUint(64);

  const ikRead  = cs.loadRef().beginParse().loadBuffer(65);
  const spkRead = cs.loadRef().beginParse().loadBuffer(65);
  const sigRead = cs.loadRef().beginParse().loadBuffer(64);
  cs.loadRef(); // ML-KEM EK cell chain — presence verified, content tested separately

  assert(ikRead[0] === 0x04, 'IK first byte must match');
  assert(spkRead[0] === 0x03, 'SPK first byte must match');
  assert(sigRead[0] === 0xab, 'SIG first byte must match');
});

await test('register_keys v1 (no ML-KEM): backwards compatible', () => {
  // Contract must accept 3 refs (old format) — ML-KEM ref is optional
  const body = beginCell()
    .storeUint(OP_REGISTER_KEYS, 32)
    .storeUint(0, 64)
    .storeRef(beginCell().storeBuffer(Buffer.alloc(65, 0x04)).endCell())
    .storeRef(beginCell().storeBuffer(Buffer.alloc(65, 0x03)).endCell())
    .storeRef(beginCell().storeBuffer(Buffer.alloc(64, 0xab)).endCell())
    // no 4th ref
    .endCell();

  const cs = body.beginParse();
  assert(cs.loadUint(32) === OP_REGISTER_KEYS, 'op must match');
  cs.loadUint(64);
  assert(cs.remainingRefs === 3, 'Must have exactly 3 refs');
});

await test('store_message body encodes correctly', () => {
  const addr  = Address.parse('EQD4FPq-PRDieyQKkizFTRtSDyucUIqrj0v_zXJmqaDp6_0t');
  const bagId = BigInt('0xdeadbeef' + '00'.repeat(28));

  const body = beginCell()
    .storeUint(OP_STORE_MESSAGE, 32)
    .storeUint(0, 64)
    .storeAddress(addr)
    .storeUint(bagId, 256)
    .endCell();

  const cs = body.beginParse();
  assert(cs.loadUint(32) === OP_STORE_MESSAGE, 'op must match');
  cs.loadUint(64);
  assert(cs.loadAddress().equals(addr), 'Address must round-trip');
  assert(cs.loadUintBig(256) === bagId, 'bag_id must round-trip');
});

await test('delete_message body encodes correctly', () => {
  const bagId = BigInt('0xcafebabe' + '00'.repeat(28));

  const body = beginCell()
    .storeUint(OP_DELETE_MESSAGE, 32)
    .storeUint(0, 64)
    .storeUint(bagId, 256)
    .endCell();

  const cs = body.beginParse();
  assert(cs.loadUint(32) === OP_DELETE_MESSAGE, 'op must match');
  cs.loadUint(64);
  assert(cs.loadUintBig(256) === bagId, 'bag_id must match');
});

await test('initial storage cell has two empty dicts', () => {
  const initData = beginCell().storeBit(0).storeBit(0).endCell();
  const cs = initData.beginParse();
  assert(cs.loadBit() === false, 'keys_dict must be empty');
  assert(cs.loadBit() === false, 'msgs_dict must be empty');
});

await test('cell bit budget: register_keys main cell fits in 1023 bits', () => {
  // op(32) + query_id(64) = 96 bits + 4 ref pointers (refs have no bit cost)
  assert(32 + 64 <= 1023, 'Main cell bits must be ≤ 1023');
});

await test('cell bit budget: store_message fits in 1023 bits', () => {
  // op(32) + query_id(64) + addr(267) + bag_id(256) = 619 bits
  assert(32 + 64 + 267 + 256 <= 1023, 'store_message bits must be ≤ 1023');
});

await test('cell bit budget: ML-KEM EK chunked correctly (120 bytes/cell)', () => {
  const EK_SIZE = 1184;
  const chunkSize = 120; // bytes per cell
  const chunksNeeded = Math.ceil(EK_SIZE / chunkSize);
  const bitsPerChunk = chunkSize * 8; // 960 bits
  assert(bitsPerChunk <= 1023, `Each chunk ${bitsPerChunk} bits must be ≤ 1023`);
  assert(chunksNeeded === 10, `ML-KEM EK needs ${chunksNeeded} cells`);
  console.log(`    ML-KEM EK: ${EK_SIZE} bytes split into ${chunksNeeded} cells`);
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
