import { describe, expect, it } from 'vitest';
import { deriveToyKey, TOY_AD, TOY_NONCE, TOY_SEED_SPACE } from './toykey';
import { encryptToyHiAE } from './hiae';
import { toHex } from './bytes';

describe('Disclosed toy keyspace', () => {
  it('is a public, deterministic function of the seed', () => {
    expect(toHex(deriveToyKey(0x1234))).toBe(toHex(deriveToyKey(0x1234)));
    expect(deriveToyKey(0x1234).length).toBe(32);
  });

  it('derives distinct keys for distinct seeds (so recovery is well-defined)', () => {
    const seen = new Set<string>();
    for (let s = 0; s < TOY_SEED_SPACE; s++) seen.add(toHex(deriveToyKey(s)));
    expect(seen.size).toBe(TOY_SEED_SPACE);
  }, 30000);

  it('every seed yields a distinct keystream block under the fixed nonce — the '
    + 'guess-and-determine truly lands on a UNIQUE seed', () => {
    const seen = new Set<string>();
    for (let s = 0; s < TOY_SEED_SPACE; s++) {
      const ct = encryptToyHiAE(deriveToyKey(s), TOY_NONCE, new Uint8Array(16), TOY_AD).ciphertext;
      seen.add(toHex(ct.subarray(0, 16)));
    }
    expect(seen.size).toBe(TOY_SEED_SPACE);
  }, 30000);

  it('does not leak the seed as plaintext bytes of the key', () => {
    // The KDF is AESL-diffused, so key bytes should not simply echo the seed.
    let echoes = 0;
    for (let s = 0; s < 256; s++) {
      const k = deriveToyKey(s);
      if (k[0] === (s & 0xff)) echoes++;
    }
    expect(echoes).toBeLessThan(8); // ~1 expected by chance, never systematic
  });
});
