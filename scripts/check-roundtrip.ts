import { decryptOracle, encryptToyHiAE } from '../src/hiae';

const key = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
const nonce = Uint8Array.from(Array.from({ length: 16 }, (_, i) => 0xa0 + i));
const pt = new TextEncoder().encode('ModelBreach');
const ad = new TextEncoder().encode('aad');

const { ciphertext, tag } = encryptToyHiAE(key, nonce, pt, ad);
const out = decryptOracle(key, nonce, ciphertext, ad, tag);

const ok = out.valid === true && out.plaintext !== null && new TextDecoder().decode(out.plaintext) === 'ModelBreach';
if (!ok) {
  throw new Error('Toy HiAE round-trip gate failed');
}

console.log('roundtrip-ok');
