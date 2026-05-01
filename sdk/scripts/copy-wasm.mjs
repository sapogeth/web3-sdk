// Copies WASM crypto files into dist/wasm/ so they ship in the npm package.
import { cpSync, mkdirSync, rmSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const src  = join(__dirname, '../wasm');
const dest = join(__dirname, '../dist/wasm');

mkdirSync(dest, { recursive: true });

// Copy only the files we need — skip package.json and .gitignore
const files = [
  'stvor_crypto.js',
  'stvor_crypto.d.ts',
  'stvor_crypto_bg.wasm',
  'stvor_crypto_bg.wasm.d.ts',
];
for (const file of files) {
  cpSync(join(src, file), join(dest, file));
}

// Remove .gitignore that wasm-pack generates with "*" — it blocks npm pack
const gitignore = join(dest, '.gitignore');
if (existsSync(gitignore)) rmSync(gitignore);

console.log('✓ Copied wasm/ → dist/wasm/');
