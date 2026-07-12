import { describe, expect, it } from 'vitest';
import { decryptOracle, encryptToyHiAE, initToyHiAE, updateFunction, CONST0, CONST1 } from './hiae';
import { aesl, aeslInv } from './aesl';
import { xorBytes } from './bytes';

const randKey = () => { const k = new Uint8Array(32); crypto.getRandomValues(k); return k; };
const randNonce = () => { const n = new Uint8Array(16); crypto.getRandomValues(n); return n; };

describe('Toy HiAE AEAD', () => {
  it('decrypt(encrypt(pt)) == pt with the correct tag (real ciphertext round-trip)', () => {
    for (let t = 0; t < 50; t++) {
      const key = randKey();
      const nonce = randNonce();
      const len = 1 + Math.floor(Math.random() * 48);
      const pt = new Uint8Array(len);
      crypto.getRandomValues(pt);
      const ad = new TextEncoder().encode('ad-' + t);

      const { ciphertext, tag } = encryptToyHiAE(key, nonce, pt, ad);
      const out = decryptOracle(key, nonce, ciphertext, ad, tag);
      expect(out.valid).toBe(true);
      expect(out.plaintext).not.toBeNull();
      expect(Array.from(out.plaintext!.subarray(0, len))).toEqual(Array.from(pt));
    }
  });

  it('rejects a forged tag (authentication holds)', () => {
    const key = randKey();
    const nonce = randNonce();
    const pt = new TextEncoder().encode('authentic message');
    const ad = new Uint8Array(0);
    const { ciphertext, tag } = encryptToyHiAE(key, nonce, pt, ad);

    const badTag = new Uint8Array(tag);
    badTag[0] ^= 0x01;
    expect(decryptOracle(key, nonce, ciphertext, ad, badTag).valid).toBe(false);
  });

  it('rejects a flipped ciphertext bit under the honest tag', () => {
    const key = randKey();
    const nonce = randNonce();
    const pt = new Uint8Array(32);
    crypto.getRandomValues(pt);
    const ad = new Uint8Array(0);
    const { ciphertext, tag } = encryptToyHiAE(key, nonce, pt, ad);

    const tampered = new Uint8Array(ciphertext);
    tampered[3] ^= 0x80;
    expect(decryptOracle(key, nonce, tampered, ad, tag).valid).toBe(false);
  });

  it('a random-tag forgery is (overwhelmingly) rejected', () => {
    const key = randKey();
    const nonce = randNonce();
    const { ciphertext } = encryptToyHiAE(key, nonce, new Uint8Array(16), new Uint8Array(0));
    let accepted = 0;
    for (let t = 0; t < 64; t++) {
      const tag = new Uint8Array(16);
      crypto.getRandomValues(tag);
      if (decryptOracle(key, nonce, ciphertext, new Uint8Array(0), tag).valid) accepted++;
    }
    expect(accepted).toBe(0);
  });

  it('updateFunction is invertible, so init can be undone to expose the key', () => {
    // This is exactly the property the attack relies on: given the full post-init
    // state, the 8 update rounds and the init mixing are reversible back to the key.
    const invUpdate = (next: { blocks: [Uint8Array, Uint8Array, Uint8Array, Uint8Array] }, X: Uint8Array) => {
      const s1 = new Uint8Array(next.blocks[0]);
      const s3 = new Uint8Array(next.blocks[2]);
      const s2 = xorBytes(next.blocks[1], X);
      const t = xorBytes(xorBytes(next.blocks[3], aesl(s3)), X);
      const s0 = xorBytes(aeslInv(t), s1);
      return { blocks: [s0, s1, s2, s3] as [Uint8Array, Uint8Array, Uint8Array, Uint8Array] };
    };

    const key = randKey();
    const nonce = randNonce();
    let st = initToyHiAE(key, nonce);
    for (let i = 7; i >= 0; i--) st = invUpdate(st, i % 2 === 0 ? CONST0 : CONST1);

    const k0 = key.subarray(0, 16), k1 = key.subarray(16, 32);
    expect(Array.from(st.blocks[0])).toEqual(Array.from(xorBytes(k0, CONST0)));
    expect(Array.from(st.blocks[1])).toEqual(Array.from(xorBytes(k1, CONST1)));
  });

  it('updateFunction forward matches its definition', () => {
    const s: { blocks: [Uint8Array, Uint8Array, Uint8Array, Uint8Array] } = {
      blocks: [randNonce(), randNonce(), randNonce(), randNonce()],
    };
    const X = randNonce();
    const n = updateFunction(s, X);
    expect(Array.from(n.blocks[0])).toEqual(Array.from(s.blocks[1]));
    expect(Array.from(n.blocks[1])).toEqual(Array.from(xorBytes(s.blocks[2], X)));
    expect(Array.from(n.blocks[2])).toEqual(Array.from(s.blocks[3]));
  });
});
