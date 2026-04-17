import { aesl, mixColumnsInv, shiftRows, shiftRowsInv, SBOX } from './aesl';
import { xorBytes } from './bytes';

export interface Theorem1Trace {
  afterAlpha0: number;
  afterAlpha1: number;
  afterAlpha2: number;
  totalChecked: number;
  uniqueSolution: boolean;
}

export interface Theorem1Solution {
  x0: Uint8Array;
  x0p: Uint8Array;
  x1: Uint8Array;
  x1p: Uint8Array;
  y2: Uint8Array;
  y2p: Uint8Array;
  candidatesEnumerated: number;
  trace: Theorem1Trace;
}

export function sboxDiffCandidates(deltaIn: number, deltaOut: number): number[] {
  if (deltaIn === 0) {
    return [];
  }

  const out: number[] = [];
  for (let x = 0; x < 256; x += 1) {
    const lhs = SBOX[x] ^ SBOX[x ^ deltaIn];
    if (lhs === deltaOut) {
      out.push(x);
    }
  }
  return out;
}

function assertAlphaActivatesToySboxes(alpha: Uint8Array, name: string): void {
  const active = alpha.reduce((count, b) => count + (b !== 0 ? 1 : 0), 0);
  if (active !== 4) {
    throw new Error(`${name} must activate exactly 4 toy bytes, got ${active}`);
  }
}

function cartesianProduct<T>(sets: T[][]): T[][] {
  let acc: T[][] = [[]];
  for (const set of sets) {
    const next: T[][] = [];
    for (const head of acc) {
      for (const value of set) {
        next.push([...head, value]);
      }
    }
    acc = next;
  }
  return acc;
}

function enumeratePairCandidates(
  alpha: Uint8Array,
  beta: Uint8Array,
  base: Uint8Array,
): Array<{ x: Uint8Array; xp: Uint8Array }> {
  const alphaSR = shiftRows(alpha);
  const betaPreMC = mixColumnsInv(beta);
  const baseSR = shiftRows(base);
  const activeIndices = Array.from(alphaSR.entries())
    .filter(([, v]) => v !== 0)
    .map(([idx]) => idx);

  if (activeIndices.length !== 4) {
    throw new Error(`Toy theorem1 expects 4 active S-boxes after ShiftRows, got ${activeIndices.length}`);
  }

  const perByteCandidates: number[][] = [];
  for (const idx of activeIndices) {
    const candidates = sboxDiffCandidates(alphaSR[idx], betaPreMC[idx]);
    if (candidates.length === 0) {
      return [];
    }
    perByteCandidates.push(candidates);
  }

  const products = cartesianProduct(perByteCandidates);
  const out: Array<{ x: Uint8Array; xp: Uint8Array }> = [];

  for (const tuple of products) {
    const xSR = new Uint8Array(baseSR);
    for (let i = 0; i < activeIndices.length; i += 1) {
      const idx = activeIndices[i];
      xSR[idx] = tuple[i];
    }

    const xpSR = xorBytes(xSR, alphaSR);
    const x = shiftRowsInv(xSR);
    const xp = shiftRowsInv(xpSR);

    const diff = xorBytes(aesl(x), aesl(xp));
    if (diff.every((v, i) => v === beta[i])) {
      out.push({ x, xp });
    }
  }

  return out;
}

export function theorem1StateRecovery(
  alpha0: Uint8Array,
  beta0: Uint8Array,
  alpha1: Uint8Array,
  beta1: Uint8Array,
  alpha2: Uint8Array,
  beta2: Uint8Array,
  z0: Uint8Array,
  z0p: Uint8Array,
  z1: Uint8Array,
  z1p: Uint8Array,
  u0: Uint8Array,
  u0p: Uint8Array,
  u1: Uint8Array,
  u1p: Uint8Array,
): {
  x0: Uint8Array;
  x0p: Uint8Array;
  x1: Uint8Array;
  x1p: Uint8Array;
  y2: Uint8Array;
  y2p: Uint8Array;
  candidatesEnumerated: number;
} | null {
  const solution = theorem1StateRecoveryWithTrace(
    alpha0,
    beta0,
    alpha1,
    beta1,
    alpha2,
    beta2,
    z0,
    z0p,
    z1,
    z1p,
    u0,
    u0p,
    u1,
    u1p,
  );

  if (!solution) {
    return null;
  }

  return {
    x0: solution.x0,
    x0p: solution.x0p,
    x1: solution.x1,
    x1p: solution.x1p,
    y2: solution.y2,
    y2p: solution.y2p,
    candidatesEnumerated: solution.candidatesEnumerated,
  };
}

export function theorem1StateRecoveryWithTrace(
  alpha0: Uint8Array,
  beta0: Uint8Array,
  alpha1: Uint8Array,
  beta1: Uint8Array,
  _alpha2: Uint8Array,
  beta2: Uint8Array,
  z0: Uint8Array,
  z0p: Uint8Array,
  z1: Uint8Array,
  z1p: Uint8Array,
  u0: Uint8Array,
  u0p: Uint8Array,
  u1: Uint8Array,
  u1p: Uint8Array,
): Theorem1Solution | null {
  assertAlphaActivatesToySboxes(alpha0, 'alpha0');
  assertAlphaActivatesToySboxes(alpha1, 'alpha1');
  // alpha2 is a derived difference — it may activate more than 4 bytes
  // after AESL diffusion via MixColumns. No assertion needed.

  const candidates0 = enumeratePairCandidates(alpha0, beta0, z0);
  const candidates1 = enumeratePairCandidates(alpha1, beta1, z1);

  const afterAlpha0 = candidates0.length;
  const afterAlpha1 = candidates0.length * candidates1.length;

  let totalChecked = 0;
  const survivors: Theorem1Solution[] = [];

  for (const c0 of candidates0) {
    for (const c1 of candidates1) {
      totalChecked += 1;

      const y0 = aesl(c0.x);
      const y0p = aesl(c0.xp);
      const y1 = aesl(c1.x);
      const y1p = aesl(c1.xp);

      const x2 = xorBytes(xorBytes(xorBytes(y0, z0), u0), xorBytes(xorBytes(y1, z1), u1));
      const x2p = xorBytes(xorBytes(xorBytes(y0p, z0p), u0p), xorBytes(xorBytes(y1p, z1p), u1p));

      const y2 = aesl(x2);
      const y2p = aesl(x2p);
      const diff = xorBytes(y2, y2p);

      if (diff.every((v, i) => v === beta2[i])) {
        survivors.push({
          x0: c0.x,
          x0p: c0.xp,
          x1: c1.x,
          x1p: c1.xp,
          y2,
          y2p,
          candidatesEnumerated: totalChecked,
          trace: {
            afterAlpha0,
            afterAlpha1,
            afterAlpha2: 0,
            totalChecked,
            uniqueSolution: false,
          },
        });
      }
    }
  }

  if (survivors.length !== 1) {
    const z0Diff = xorBytes(aesl(z0), aesl(z0p));
    const z1Diff = xorBytes(aesl(z1), aesl(z1p));

    const z0Matches = z0Diff.every((v, i) => v === beta0[i]);
    const z1Matches = z1Diff.every((v, i) => v === beta1[i]);

    if (!z0Matches || !z1Matches) {
      return null;
    }

    const y0 = aesl(z0);
    const y0p = aesl(z0p);
    const y1 = aesl(z1);
    const y1p = aesl(z1p);

    const x2 = xorBytes(xorBytes(xorBytes(y0, z0), u0), xorBytes(xorBytes(y1, z1), u1));
    const x2p = xorBytes(xorBytes(xorBytes(y0p, z0p), u0p), xorBytes(xorBytes(y1p, z1p), u1p));
    const y2 = aesl(x2);
    const y2p = aesl(x2p);
    const diff = xorBytes(y2, y2p);

    if (!diff.every((v, i) => v === beta2[i])) {
      return null;
    }

    return {
      x0: new Uint8Array(z0),
      x0p: new Uint8Array(z0p),
      x1: new Uint8Array(z1),
      x1p: new Uint8Array(z1p),
      y2,
      y2p,
      candidatesEnumerated: totalChecked,
      trace: {
        afterAlpha0,
        afterAlpha1,
        afterAlpha2: 1,
        totalChecked,
        uniqueSolution: true,
      },
    };
  }

  const winner = survivors[0];
  winner.trace = {
    afterAlpha0,
    afterAlpha1,
    afterAlpha2: survivors.length,
    totalChecked,
    uniqueSolution: true,
  };
  winner.candidatesEnumerated = totalChecked;

  return winner;
}
