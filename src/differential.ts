/**
 * A seeded AESL differential-consistency illustration.
 *
 * The page used to describe ePrint 2025/1203's meet-in-the-middle differential
 * step in prose ("the browser never runs this algorithm") while the browser ran
 * an unrelated exhaustive seed search. The machinery was in the repo and unit
 * tested, but a learner could not run it or see a number come out of it.
 *
 * This module runs the differential step for real and MEASURES it:
 *
 *   1. Plant a random state pair (x, x ⊕ α) with α active in four bytes, and
 *      compute β = AESL(x) ⊕ AESL(x ⊕ α) — a real AESL evaluation, not a chosen
 *      characteristic.
 *   2. Ask what α alone says: nothing. Every one of the 256 values per active
 *      byte is possible, so the space over the active bytes is 256⁴ = 2³².
 *   3. Ask what (α, β) together say: each active S-box now has to satisfy
 *      S(x) ⊕ S(x ⊕ δin) = δout, which the AES DDT answers with 0, 2 or 4
 *      values. The product of those counts is the surviving space — measured
 *      on this run's differential, not quoted.
 *   4. Verify that the planted fixture's four active bytes occur among those
 *      candidates. This is a consistency check, not unknown-state recovery:
 *      the twelve inactive bytes are supplied by the fixture.
 *
 * SCALE, PLAINLY: this is ONE AESL call with four active S-boxes. The paper
 * chains this step across HiAE's 2048-bit state, which is where 2^209 comes
 * from; that chaining is not executed here, and this module does not claim it.
 */

import { aesl, shiftRows } from './aesl';
import { xorBytes } from './bytes';
import { activeSboxConstraints, type SboxConstraint } from './theorem1';

export interface DifferentialStepResult {
  /** The input difference actually used (4 active bytes). */
  alpha: Uint8Array;
  /** β = AESL(x) ⊕ AESL(x ⊕ α), computed from the real round function. */
  beta: Uint8Array;
  /** Per-active-S-box constraints solved from the DDT. */
  constraints: SboxConstraint[];
  /** Number of active S-boxes (4 for this toy differential). */
  activeSboxes: number;
  /** 256^activeSboxes — the space over the active bytes knowing α only. */
  naiveSpace: number;
  /** Product of the per-S-box candidate counts — what (α, β) leaves. */
  survivingSpace: number;
  /** log2 of the two above, and of the measured reduction. */
  naiveBits: number;
  survivingBits: number;
  reductionBits: number;
  /** Active-byte combinations admitted by the four DDT constraints. */
  candidatesEnumerated: number;
  /** Does the known fixture occur among those active-byte candidates? */
  fixtureConsistent: boolean;
  /** Wall-clock milliseconds for the DDT consistency calculation. */
  elapsedMs: number;
}

function randomBlock(): Uint8Array {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return b;
}

/** A difference with exactly four non-zero bytes (positions 0–3 pre-ShiftRows). */
function randomActiveAlpha(): Uint8Array {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a.subarray(0, 4));
  for (let i = 0; i < 4; i += 1) if (a[i] === 0) a[i] = i + 1;
  return a;
}

/**
 * Build one observed AESL differential and enumerate its active-byte DDT
 * candidates. The planted pair generates and validates the fixture; this does
 * not recover an unknown full state.
 */
export function runDifferentialStep(): DifferentialStepResult {
  const x0 = randomBlock();
  const alpha0 = randomActiveAlpha();
  const x0p = xorBytes(x0, alpha0);

  // Real AESL evaluations — β is observed, never chosen.
  const beta0 = xorBytes(aesl(x0), aesl(x0p));

  const constraints = activeSboxConstraints(alpha0, beta0);
  const activeSboxes = constraints.length;
  const naiveSpace = Math.pow(256, activeSboxes);
  const survivingSpace = constraints.reduce((n, c) => n * c.candidates.length, 1);

  const started = performance.now();
  const fixtureShifted = shiftRows(x0);
  const fixtureConsistent = constraints.every((c) => c.candidates.includes(fixtureShifted[c.index]));
  const elapsedMs = performance.now() - started;

  return {
    alpha: alpha0,
    beta: beta0,
    constraints,
    activeSboxes,
    naiveSpace,
    survivingSpace,
    naiveBits: Math.log2(naiveSpace),
    survivingBits: Math.log2(Math.max(1, survivingSpace)),
    reductionBits: Math.log2(naiveSpace) - Math.log2(Math.max(1, survivingSpace)),
    candidatesEnumerated: survivingSpace,
    fixtureConsistent,
    elapsedMs,
  };
}

export interface DdtCensus {
  /** Non-zero input differences considered (255). */
  inputDifferences: number;
  /** (δin, δout) pairs considered (255 × 256). */
  pairs: number;
  /** How many pairs admit exactly 0 / 2 / 4 solutions. */
  withZero: number;
  withTwo: number;
  withFour: number;
  /** Total solutions across all pairs. */
  totalSolutions: number;
  /** totalSolutions / pairs — the expected survivors per active S-box. */
  meanSolutionsPerPair: number;
  /** Expected candidates conditioned on observing a possible output difference. */
  meanSolutionsObserved: number;
  /** The largest solution count seen (4 for the AES S-box). */
  maxSolutions: number;
}

/**
 * Census the AES S-box difference distribution table by building it. This is the
 * structural reason the differential step pays: knowing δout collapses each
 * active byte from 256 possibilities to one on average. Computed by counting,
 * not quoted from the literature.
 */
export function ddtCensus(sbox: Uint8Array): DdtCensus {
  let withZero = 0;
  let withTwo = 0;
  let withFour = 0;
  let totalSolutions = 0;
  let observedCandidateTotal = 0;
  let maxSolutions = 0;

  const row = new Uint16Array(256);
  for (let din = 1; din < 256; din += 1) {
    row.fill(0);
    for (let x = 0; x < 256; x += 1) {
      row[sbox[x] ^ sbox[x ^ din]] += 1;
    }
    for (let dout = 0; dout < 256; dout += 1) {
      const n = row[dout];
      totalSolutions += n;
      observedCandidateTotal += n * n;
      if (n > maxSolutions) maxSolutions = n;
      if (n === 0) withZero += 1;
      else if (n === 2) withTwo += 1;
      else if (n === 4) withFour += 1;
    }
  }

  const pairs = 255 * 256;
  return {
    inputDifferences: 255,
    pairs,
    withZero,
    withTwo,
    withFour,
    totalSolutions,
    meanSolutionsPerPair: totalSolutions / pairs,
    meanSolutionsObserved: observedCandidateTotal / totalSolutions,
    maxSolutions,
  };
}
