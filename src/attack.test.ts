import { describe, expect, it } from 'vitest';
import { runModelBreachAttack, evaluateKeyEquation, evaluateByteEquation } from './attack';
import { decryptOracle, encryptToyHiAE } from './hiae';
import { deriveToyKey, TOY_AD, TOY_NONCE, TOY_SEED_SPACE } from './toykey';
import { aesl, aeslInv } from './aesl';
import { xorBytes } from './bytes';

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * Build a BLACK-BOX oracle pair over a secret seed. The oracles expose only the
 * AEAD interface — no `__toyKey`, no seed. If the attack recovers the key it can
 * only be from observed encryption/decryption behaviour.
 */
function blackBoxOracles(secretSeed: number) {
  const key = deriveToyKey(secretSeed);
  let leaked = false;
  const enc = async (pt: Uint8Array) => {
    // Guard: assert nobody smuggles the key out through the function object.
    if ((enc as unknown as Record<string, unknown>).__toyKey !== undefined) leaked = true;
    const out = encryptToyHiAE(key, TOY_NONCE, pt, TOY_AD);
    return { ct: out.ciphertext, tag: out.tag };
  };
  const dec = async (ct: Uint8Array, tag: Uint8Array) => {
    const out = decryptOracle(key, TOY_NONCE, ct, TOY_AD, tag);
    return { valid: out.valid, pt: out.plaintext };
  };
  return { key, enc, dec, leaked: () => leaked };
}

describe('End-to-end toy key recovery is genuinely computed from oracle output', () => {
  const ctx = {
    nonce: TOY_NONCE,
    ad: TOY_AD,
    encryptLocal: (k: Uint8Array, n: Uint8Array, pt: Uint8Array, ad: Uint8Array) =>
      encryptToyHiAE(k, n, pt, ad),
  };

  it('recovers the exact key from a black-box oracle (no metadata channel)', async () => {
    const secretSeed = 0xBEEF & (TOY_SEED_SPACE - 1);
    const bb = blackBoxOracles(secretSeed);

    const res = await runModelBreachAttack(bb.enc, bb.dec, () => {}, ctx);

    expect(bb.leaked()).toBe(false);
    expect(res.recoveredSeed).toBe(secretSeed);
    expect(eq(res.recoveredKey, bb.key)).toBe(true);
  });

  it('recovered key is derived, not accidentally equal: it must forge a valid tag', async () => {
    const secretSeed = 0x1234 & (TOY_SEED_SPACE - 1);
    const bb = blackBoxOracles(secretSeed);
    const res = await runModelBreachAttack(bb.enc, bb.dec, () => {}, ctx);

    // Independently confirm the recovered key forges an accepted ciphertext.
    const msg = new TextEncoder().encode('independent forgery check');
    const forged = encryptToyHiAE(res.recoveredKey, TOY_NONCE, msg, TOY_AD);
    const out = decryptOracle(bb.key, TOY_NONCE, forged.ciphertext, TOY_AD, forged.tag);
    expect(out.valid).toBe(true);
  });

  it('records observe → guess-determine → forge steps', async () => {
    const bb = blackBoxOracles(0x00ff);
    const res = await runModelBreachAttack(bb.enc, bb.dec, () => {}, ctx);
    const phases = res.steps.map((s) => s.phase);
    expect(phases).toContain('observe');
    expect(phases).toContain('guess-determine');
    expect(phases).toContain('forge');
    const gd = res.steps.find((s) => s.phase === 'guess-determine')!;
    expect(gd.candidatesBefore).toBe(TOY_SEED_SPACE);
    expect(gd.candidatesAfter).toBe(1);
  });

  it('fails honestly if the target key is OUTSIDE the disclosed toy keyspace', async () => {
    // A full random key cannot be produced by any toy seed, so the honest attack
    // must throw rather than silently "succeed" (this is what a metadata-read
    // shortcut would have hidden).
    const randomKey = new Uint8Array(32);
    crypto.getRandomValues(randomKey);
    const enc = async (pt: Uint8Array) => {
      const o = encryptToyHiAE(randomKey, TOY_NONCE, pt, TOY_AD);
      return { ct: o.ciphertext, tag: o.tag };
    };
    const dec = async (ct: Uint8Array, tag: Uint8Array) => {
      const o = decryptOracle(randomKey, TOY_NONCE, ct, TOY_AD, tag);
      return { valid: o.valid, pt: o.plaintext };
    };
    await expect(runModelBreachAttack(enc, dec, () => {}, ctx)).rejects.toThrow();
  }, 20000);
});

describe('MITM key equation and byte equation (paper Section 4.1–4.2 math)', () => {
  it('evaluateKeyEquation holds for a construction that satisfies it and fails otherwise', () => {
    const rand = () => { const b = new Uint8Array(16); crypto.getRandomValues(b); return b; };
    const K0 = rand(), U0 = rand(), U2 = rand(), U3 = rand(), U9 = rand(), U17 = rand();
    // Solve U1 to satisfy the equation exactly.
    const right = xorBytes(
      xorBytes(aeslInv(xorBytes(aesl(xorBytes(K0, U2)), U3)), aeslInv(xorBytes(K0, U9))),
      U17,
    );
    const U1 = xorBytes(aesl(xorBytes(K0, U0)), right);
    expect(evaluateKeyEquation(K0, U0, U1, U2, U3, U9, U17)).toBe(true);

    const U1bad = new Uint8Array(U1);
    U1bad[0] ^= 0x01;
    expect(evaluateKeyEquation(K0, U0, U1bad, U2, U3, U9, U17)).toBe(false);
  });

  it('evaluateByteEquation is a total predicate over its byte inputs', () => {
    const rand = () => { const b = new Uint8Array(16); crypto.getRandomValues(b); return b; };
    // Just exercise it across all 16 byte positions without throwing.
    for (let t = 0; t < 16; t++) {
      const r = evaluateByteEquation(t, rand(), rand(), rand(), rand(), rand(), rand());
      expect(typeof r).toBe('boolean');
    }
  });
});
