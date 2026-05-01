/**
 * Deploy stvor_registry to TON testnet
 * Usage: node deploy.mjs
 *
 * Reads mnemonic from STVOR_MNEMONIC env variable (24 words, space-separated).
 * Contract address is deterministic from code + init data.
 */

import { TonClient, WalletContractV4, internal, toNano } from '@ton/ton';
import { mnemonicToPrivateKey } from '@ton/crypto';
import { Cell, beginCell, contractAddress } from '@ton/core';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const TESTNET_API = 'https://testnet.toncenter.com/api/v2';
const MAINNET_API = 'https://toncenter.com/api/v2';

const isTestnet = process.argv[2] !== 'mainnet';
const apiUrl = isTestnet ? TESTNET_API : MAINNET_API;
const networkName = isTestnet ? 'testnet' : 'mainnet';

async function deploy() {
  const mnemonic = process.env.STVOR_MNEMONIC;
  if (!mnemonic) {
    console.error('Set STVOR_MNEMONIC env variable (24 words)');
    process.exit(1);
  }

  const words = mnemonic.trim().split(/\s+/);
  const keyPair = await mnemonicToPrivateKey(words);

  const client = new TonClient({ endpoint: apiUrl });
  const wallet = WalletContractV4.create({ workchain: 0, publicKey: keyPair.publicKey });
  const walletContract = client.open(wallet);

  const balance = await walletContract.getBalance();
  console.log(`Deploying from: ${wallet.address.toString()}`);
  console.log(`Balance: ${Number(balance) / 1e9} TON`);

  if (balance < toNano('0.1')) {
    console.error(`Insufficient balance. Get test TON at https://t.me/testgiver_ton_bot`);
    process.exit(1);
  }

  // Load compiled BOC
  const bocBytes = readFileSync(join(__dirname, 'build/stvor_registry.boc'));
  const code = Cell.fromBoc(bocBytes)[0];

  // Initial storage: two empty dicts
  const initData = beginCell()
    .storeDict(null)   // keys_dict
    .storeDict(null)   // msgs_dict
    .endCell();

  const init = { code, data: initData };
  const contractAddr = contractAddress(0, init);

  console.log(`\nContract address: ${contractAddr.toString()}`);
  console.log(`Network: ${networkName}`);

  // Check if already deployed
  const state = await client.getContractState(contractAddr);
  if (state.state === 'active') {
    console.log('\n✓ Contract already deployed');
    return contractAddr.toString();
  }

  // Deploy
  const seqno = await walletContract.getSeqno();
  await walletContract.sendTransfer({
    secretKey: keyPair.secretKey,
    seqno,
    messages: [
      internal({
        to: contractAddr,
        value: toNano('0.05'),
        init,
        bounce: false,
      }),
    ],
  });

  console.log('\n⏳ Waiting for deploy...');
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 3000));
    const s = await client.getContractState(contractAddr);
    if (s.state === 'active') {
      console.log('✓ Deployed successfully!');
      console.log(`\nContract address: ${contractAddr.toString()}`);
      console.log(`\nAdd to your config:\n  contractAddress: '${contractAddr.toString()}'`);
      return contractAddr.toString();
    }
    process.stdout.write('.');
  }
  console.error('\nTimeout waiting for deploy');
  process.exit(1);
}

deploy().catch(console.error);
