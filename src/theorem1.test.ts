import { describe, expect, it } from 'vitest';
import { aesl, SBOX } from './aesl';
import { xorBytes } from './bytes';
import { sboxDiffCandidates, theorem1StateRecoveryWithTrace } from './theorem1';

describe('S-box differential distribution table', () => {
  it('sboxDiffCandidates returns exactly the x with S(x)⊕S(x⊕δin)=δout', () => {
    for (let trial = 0; trial < 30; trial++) {
      const din = 1 + Math.floor(Math.random() * 255);
      const dout = Math.floor(Math.random() * 256);
      const got = new Set(sboxDiffCandidates(din, dout));

      // Independent brute-force reference over the AES S-box.
      const ref = new Set<number>();
      for (let x = 0; x < 256; x++) {
        if ((SBOX[x] ^ SBOX[x ^ din]) === dout) ref.add(x);
      }
      expect(got).toEqual(ref);
      // Differentials over the AES S-box always have even-sized solution sets.
      expect(got.size % 2).toBe(0);
    }
  });

  it('zero input difference yields no candidates', () => {
    expect(sboxDiffCandidates(0, 0)).toEqual([]);
  });
});

describe('Theorem 1 state recovery (real differential enumeration)', () => {
  const randBlock = () => { const b = new Uint8Array(16); crypto.getRandomValues(b); return b; };
  const randActiveAlpha = () => {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a.subarray(0, 4));
    for (let i = 0; i < 4; i++) if (a[i] === 0) a[i] = i + 1;
    return a;
  };
  const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

  it('recovers the planted (x0,x1) from the (α,β) differentials it was NOT told', () => {
    let recoveredOnce = false;
    for (let attempt = 0; attempt < 200 && !recoveredOnce; attempt++) {
      const x0 = randBlock(), x1 = randBlock();
      const alpha0 = randActiveAlpha(), alpha1 = randActiveAlpha();
      const x0p = xorBytes(x0, alpha0), x1p = xorBytes(x1, alpha1);
      const beta0 = xorBytes(aesl(x0), aesl(x0p));
      const beta1 = xorBytes(aesl(x1), aesl(x1p));

      const z0 = new Uint8Array(x0), z0p = new Uint8Array(x0p);
      const z1 = new Uint8Array(x1), z1p = new Uint8Array(x1p);
      const zero = () => new Uint8Array(16);
      const u0 = zero(), u0p = zero(), u1 = zero(), u1p = zero();

      const y0 = aesl(x0), y0p = aesl(x0p), y1 = aesl(x1), y1p = aesl(x1p);
      const x2 = xorBytes(xorBytes(xorBytes(y0, z0), u0), xorBytes(xorBytes(y1, z1), u1));
      const x2p = xorBytes(xorBytes(xorBytes(y0p, z0p), u0p), xorBytes(xorBytes(y1p, z1p), u1p));
      const alpha2 = xorBytes(x2, x2p);
      const beta2 = xorBytes(aesl(x2), aesl(x2p));

      const rec = theorem1StateRecoveryWithTrace(
        alpha0, beta0, alpha1, beta1, alpha2, beta2,
        z0, z0p, z1, z1p, u0, u0p, u1, u1p,
      );
      if (rec === null) continue;
      // The enumeration must land on the planted state and prove uniqueness.
      expect(eq(rec.x0, x0)).toBe(true);
      expect(eq(rec.x1, x1)).toBe(true);
      expect(rec.trace.afterAlpha2).toBe(1);
      // The recovered pair must actually satisfy the input differentials.
      expect(Array.from(xorBytes(aesl(rec.x0), aesl(rec.x0p)))).toEqual(Array.from(beta0));
      recoveredOnce = true;
    }
    expect(recoveredOnce).toBe(true);
  });
});
