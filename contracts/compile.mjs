import { compileFunc } from '@ton-community/func-js';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const result = await compileFunc({
  targets: ['stvor_registry.fc'],
  sources: (path) => readFileSync(join(__dirname, path)).toString(),
});

if (result.status === 'error') {
  console.error('Compilation failed:\n' + result.message);
  process.exit(1);
}

mkdirSync(join(__dirname, 'build'), { recursive: true });

const bocHex = result.codeBoc;
writeFileSync(join(__dirname, 'build/stvor_registry.boc'), Buffer.from(bocHex, 'base64'));
writeFileSync(join(__dirname, 'build/stvor_registry.boc.b64'), bocHex);

console.log('✓ Compiled: build/stvor_registry.boc');
console.log('  Cell hash:', result.codeHashHex ?? '(no hash)');
