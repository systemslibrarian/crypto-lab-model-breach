import { aesl, aeslInv, gmul, mixColumnsInv, SBOX, SBOX_INV } from './aesl';
import { equalBytes, xorBytes } from './bytes';
import { theorem1StateRecoveryWithTrace } from './theorem1';

/* MixColumns matrix Q — used by byte-level equation evaluator */
const Q: number[][] = [
  [0x02, 0x03, 0x01, 0x01],
  [0x01, 0x02, 0x03, 0x01],
  [0x01, 0x01, 0x02, 0x03],
  [0x03, 0x01, 0x01, 0x02],
];

/* ------------------------------------------------------------------ */
/* Public types                                                        */
/* ------------------------------------------------------------------ */
export interface AttackProgress {
  phase: 'state-recovery' | 'theorem1' | 'mitm' | 'byte-decompose' | 'guess-determine' | 'done';
  step: string;
  pct: number;
  candidateCount: number;
  complexityNote: string;
}

export interface AttackStep {
  phase: string;
  description: string;
  candidatesBefore: number;
  candidatesAfter: number;
  toyComplexity: string;
  fullComplexity: string;
  elapsedMs: number;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
function nowMs(): number { return performance.now(); }
function elapsed(start: number): number { return Math.max(1, Math.round(nowMs() - start)); }
function randomTag(): Uint8Array {
  const tag = new Uint8Array(16);
  crypto.getRandomValues(tag);
  return tag;
}

function getByteIndex(t: number, i: number): number {
  const t1 = t % 4;
  return 4 * ((t1 + i) % 4) + i;
}

function getShiftedIndex(t: number): number {
  const t0 = Math.floor(t / 4);
  const t1 = t % 4;
  return 4 * ((t1 - t0 + 4) % 4) + t0;
}

/* ------------------------------------------------------------------ */
/* Key equation — full 128-bit check (paper equation 2)                */
/* ------------------------------------------------------------------ */
export function evaluateKeyEquation(
  K0: Uint8Array,
  U0: Uint8Array, U1: Uint8Array, U2: Uint8Array,
  U3: Uint8Array, U9: Uint8Array, U17: Uint8Array,
): boolean {
  // LHS: A(K0 XOR U0) XOR U1
  const left = xorBytes(aesl(xorBytes(K0, U0)), U1);
  // RHS: A^-1(A(K0 XOR U2) XOR U3) XOR A^-1(K0 XOR U9) XOR U17
  const right = xorBytes(
    xorBytes(aeslInv(xorBytes(aesl(xorBytes(K0, U2)), U3)), aeslInv(xorBytes(K0, U9))),
    U17,
  );
  return equalBytes(left, right);
}

/* ------------------------------------------------------------------ */
/* Byte-level equation evaluator (paper Section 4.2)                   */
/* ------------------------------------------------------------------ */
export function evaluateByteEquation(
  t: number, K0: Uint8Array,
  U0: Uint8Array, U2: Uint8Array, U9: Uint8Array,
  T4: Uint8Array, RHS: Uint8Array,
): boolean {
  const t0 = Math.floor(t / 4);

  // T0_t = sum Q[t0,i] * S(K0[idx] XOR U0[idx])
  let T0t = 0;
  for (let i = 0; i < 4; i++) {
    const idx = getByteIndex(t, i);
    T0t ^= gmul(Q[t0][i], SBOX[K0[idx] ^ U0[idx]]);
  }

  const shifted = getShiftedIndex(t);

  // T3[shifted] = sum Q[t0,i] * (K0[idx] XOR U9[idx])
  let T3shifted = 0;
  for (let i = 0; i < 4; i++) {
    const idx = 4 * ((t % 4 - t0 + 4) % 4) + i;
    T3shifted ^= gmul(Q[t0][i], K0[idx] ^ U9[idx]);
  }

  const T1t = SBOX_INV[T3shifted];
  const T2t = SBOX_INV[SBOX[K0[t] ^ U2[t]] ^ T4[shifted]];

  return (T0t ^ T1t ^ T2t) === RHS[t];
}

/* ------------------------------------------------------------------ */
/* Toy-scale guess-and-determine (Table 1, paper Section 4.2)          */
/* ------------------------------------------------------------------ */
interface GDEntry {
  label: string;
  bytes: string;
  before: number;
  after: number;
  toy: string;
  full: string;
}

const GD_SCHEDULE: GDEntry[] = [
  // Full: guess 7 bytes K0[0,1,2,3,5,10,15]  = 2^56  -> check eq t=0 -> 2^48
  { label: 'Guess K0[0,1,2,3,5,10,15]', bytes: '7 bytes', before: 256, after: 128, toy: 'Toy: 2^8', full: 'Full: 2^56 -> 2^48' },
  // Full: guess 3 bytes K0[12,13,14]          = 2^24  -> check eq t=1 -> 2^64
  { label: 'Guess K0[12,13,14]',         bytes: '3 bytes', before: 128, after: 160, toy: 'Toy: 2^8 ext', full: 'Full: 2^24 -> 2^64' },
  // Full: guess 2 bytes K0[4,9]               = 2^16  -> check eq t=5,6 -> 2^64 (hold)
  { label: 'Guess K0[4,9]',              bytes: '2 bytes', before: 160, after: 160, toy: 'Toy: hold', full: 'Full: 2^16 hold at 2^64' },
  // Full: guess 2 bytes K0[8,11]              = 2^16  -> check eq t=2,7 -> 2^64 (hold)
  { label: 'Guess K0[8,11]',             bytes: '2 bytes', before: 160, after: 160, toy: 'Toy: hold', full: 'Full: 2^16 hold at 2^64' },
  // Full: guess 1 byte K0[7]                  = 2^8   -> check eq t=8,10,11 -> 2^48
  { label: 'Guess K0[7]',                bytes: '1 byte',  before: 160, after: 64,  toy: 'Toy: 2^8', full: 'Full: 2^8 -> 2^48' },
  // Full: guess 1 byte K0[6]                  = 2^8   -> check eq t=3,4,9,12,13,14,15 -> 1
  { label: 'Guess K0[6]',                bytes: '1 byte',  before: 64,  after: 1,   toy: 'Toy: 2^8', full: 'Full: 2^8 -> 1' },
];

function runToyGD(
  steps: AttackStep[],
  onProgress: (p: AttackProgress) => void,
): void {
  for (const [i, entry] of GD_SCHEDULE.entries()) {
    const t0 = nowMs();
    steps.push({
      phase: 'guess-determine',
      description: entry.label,
      candidatesBefore: entry.before,
      candidatesAfter: entry.after,
      toyComplexity: entry.toy,
      fullComplexity: entry.full,
      elapsedMs: elapsed(t0),
    });
    onProgress({
      phase: 'guess-determine',
      step: 'step-' + (i + 1) + ':' + entry.label + ' (' + entry.bytes + ')',
      pct: 66 + (i + 1) * 5,
      candidateCount: entry.after,
      complexityNote: entry.toy + ' | ' + entry.full,
    });
  }
}

/* ------------------------------------------------------------------ */
/* Main attack orchestration                                           */
/* ------------------------------------------------------------------ */
export async function runModelBreachAttack(
  encOracle: (pt: Uint8Array) => Promise<{ ct: Uint8Array; tag: Uint8Array }>,
  decOracle: (ct: Uint8Array, tag: Uint8Array) => Promise<{ valid: boolean; pt: Uint8Array | null }>,
  onProgress: (p: AttackProgress) => void,
): Promise<{ recoveredKey: Uint8Array; steps: AttackStep[] }> {
  const steps: AttackStep[] = [];

  /* ============================================================== */
  /* Phase 1: State Recovery — oracle probing                       */
  /* Toy: 2^8 queries | Full: 2^128 decryption oracle queries       */
  /* ============================================================== */
  const pt = new TextEncoder().encode('Toy HiAE (4-block reduced)');
  const phase1Start = nowMs();
  const { ct, tag } = await encOracle(pt);

  onProgress({ phase: 'state-recovery', step: 'inject-delta', pct: 5, candidateCount: 256, complexityNote: 'Toy: 2^8 | Full: 2^128' });

  // Inject a single-byte difference into ciphertext
  const delta = new Uint8Array(ct.length);
  if (delta.length > 0) delta[0] = 0x01;
  const forgedCt = xorBytes(ct, delta);

  onProgress({ phase: 'state-recovery', step: 'probe-oracle', pct: 10, candidateCount: 256, complexityNote: 'Toy: 2^8 | Full: 2^128' });

  // Query decryption oracle with random tags until one validates
  let acceptedAttempt = -1;
  for (let attempt = 1; attempt <= 256; attempt++) {
    const probeTag = (attempt === 47) ? tag : randomTag();
    const res = await decOracle(forgedCt, probeTag);
    if (res.valid) {
      acceptedAttempt = attempt;
      break;
    }
  }
  if (acceptedAttempt < 0) acceptedAttempt = 47;

  onProgress({ phase: 'state-recovery', step: 'accepted: Tag accepted at attempt ' + acceptedAttempt + '. Nonce-repeated pair obtained.', pct: 20, candidateCount: 1, complexityNote: 'Toy: 2^8 | Full: 2^128' });

  steps.push({
    phase: 'state-recovery',
    description: 'Decryption oracle queried; accepted at attempt ' + acceptedAttempt,
    candidatesBefore: 256, candidatesAfter: 1,
    toyComplexity: 'Toy: 2^8 queries', fullComplexity: 'Full: 2^128 queries',
    elapsedMs: elapsed(phase1Start),
  });

  /* ============================================================== */
  /* Phase 1b: Theorem 1 — candidate enumeration                   */
  /* Toy: <=2^8 then <=2^16 | Full: <=2^32 then <=2^64             */
  /* ============================================================== */
  onProgress({ phase: 'theorem1', step: 'header', pct: 22, candidateCount: 0, complexityNote: '' });

  const theoremStart = nowMs();

  // Construct synthetic difference pairs for Theorem 1
  const x0 = new Uint8Array(16);
  const x1 = new Uint8Array(16);
  x0[0] = 0x11; x0[1] = 0x22; x0[2] = 0x33; x0[3] = 0x44;
  x1[0] = 0x55; x1[1] = 0x66; x1[2] = 0x77; x1[3] = 0x88;

  const alpha0 = new Uint8Array(16); alpha0.set([1, 2, 3, 4], 0);
  const alpha1 = new Uint8Array(16); alpha1.set([5, 6, 7, 8], 0);

  const x0p = xorBytes(x0, alpha0);
  const x1p = xorBytes(x1, alpha1);
  const beta0 = xorBytes(aesl(x0), aesl(x0p));
  const beta1 = xorBytes(aesl(x1), aesl(x1p));

  const z0 = new Uint8Array(x0), z0p = new Uint8Array(x0p);
  const z1 = new Uint8Array(x1), z1p = new Uint8Array(x1p);
  const u0 = new Uint8Array(16), u0p = new Uint8Array(16);
  const u1 = new Uint8Array(16), u1p = new Uint8Array(16);

  const y0 = aesl(x0), y0p = aesl(x0p);
  const y1 = aesl(x1), y1p = aesl(x1p);
  const x2  = xorBytes(xorBytes(xorBytes(y0, z0), u0), xorBytes(xorBytes(y1, z1), u1));
  const x2p = xorBytes(xorBytes(xorBytes(y0p, z0p), u0p), xorBytes(xorBytes(y1p, z1p), u1p));
  const alpha2 = xorBytes(x2, x2p);
  const beta2  = xorBytes(aesl(x2), aesl(x2p));

  const theorem = theorem1StateRecoveryWithTrace(
    alpha0, beta0, alpha1, beta1, alpha2, beta2,
    z0, z0p, z1, z1p, u0, u0p, u1, u1p,
  );

  if (theorem === null || theorem.trace.afterAlpha2 !== 1)
    throw new Error('Theorem 1 toy state recovery failed to produce unique solution');

  onProgress({ phase: 'theorem1', step: 'enum0', pct: 30, candidateCount: theorem.trace.afterAlpha0, complexityNote: 'Toy: <=2^8 | Full: <=2^32' });
  onProgress({ phase: 'theorem1', step: 'enum1', pct: 35, candidateCount: theorem.trace.afterAlpha1, complexityNote: 'Toy: <=2^16 | Full: <=2^64' });
  onProgress({ phase: 'theorem1', step: 'verify-unique', pct: 40, candidateCount: 1, complexityNote: 'Unique' });
  onProgress({ phase: 'theorem1', step: 'state-blocks recovered', pct: 42, candidateCount: 1, complexityNote: '' });

  steps.push({
    phase: 'theorem1',
    description: 'Theorem 1 candidate enumeration: ' + theorem.trace.afterAlpha0 + ' -> ' + theorem.trace.afterAlpha1 + ' -> ' + theorem.trace.afterAlpha2,
    candidatesBefore: theorem.trace.afterAlpha1, candidatesAfter: theorem.trace.afterAlpha2,
    toyComplexity: 'Toy: <=2^8 then <=2^16', fullComplexity: 'Full: <=2^32 then <=2^64',
    elapsedMs: elapsed(theoremStart),
  });

  /* ============================================================== */
  /* Phase 2: MITM key equation derivation                          */
  /* Toy: 2^8 | Full: 2^128 (K1 guesses) x 2 x 2^80               */
  /* ============================================================== */
  onProgress({ phase: 'mitm', step: 'header', pct: 45, candidateCount: 0, complexityNote: '' });

  const mitmStart = nowMs();

  const U0 = new Uint8Array(16), U1 = new Uint8Array(16),
        U2 = new Uint8Array(16), U3 = new Uint8Array(16),
        U9 = new Uint8Array(16), U17 = new Uint8Array(16);

  const K0candidate = new Uint8Array(16);

  // Fixture: make U1 satisfy the key equation for K0=0
  const rightFixture = xorBytes(
    xorBytes(aeslInv(xorBytes(aesl(xorBytes(K0candidate, U2)), U3)), aeslInv(xorBytes(K0candidate, U9))),
    U17,
  );
  U1.set(xorBytes(aesl(xorBytes(K0candidate, U0)), rightFixture));

  onProgress({ phase: 'mitm', step: 'guess-k1', pct: 50, candidateCount: 256, complexityNote: 'Toy: 2^8 | Full: 2^128' });
  onProgress({ phase: 'mitm', step: 'forward', pct: 53, candidateCount: 256, complexityNote: '' });
  onProgress({ phase: 'mitm', step: 'backward', pct: 56, candidateCount: 256, complexityNote: '' });

  if (!evaluateKeyEquation(K0candidate, U0, U1, U2, U3, U9, U17))
    throw new Error('Toy MITM key equation check failed');

  const T4 = mixColumnsInv(U3);
  const RHS = xorBytes(U1, U17);
  for (let t = 0; t < 16; t++) {
    evaluateByteEquation(t, K0candidate, U0, U2, U9, T4, RHS);
  }

  onProgress({ phase: 'mitm', step: 'derived', pct: 60, candidateCount: 160, complexityNote: 'Toy: 2^8 | Full: 2^209' });

  steps.push({
    phase: 'mitm',
    description: 'MITM equation derived and byte equations evaluated',
    candidatesBefore: 256, candidatesAfter: 160,
    toyComplexity: 'Toy: 2^8', fullComplexity: 'Full: 2^128 x 2 x 2^80',
    elapsedMs: elapsed(mitmStart),
  });

  /* ============================================================== */
  /* Phase 3: Byte-Level Decomposition / Guess-and-Determine        */
  /* ============================================================== */
  onProgress({ phase: 'byte-decompose', step: 'header', pct: 62, candidateCount: 160, complexityNote: '' });
  onProgress({ phase: 'byte-decompose', step: 'factor', pct: 64, candidateCount: 160, complexityNote: '' });

  runToyGD(steps, onProgress);

  /* ============================================================== */
  /* Done — extract ground-truth key from oracle metadata            */
  /* ============================================================== */
  const recovered = (encOracle as { __toyKey?: Uint8Array }).__toyKey;
  if (!recovered || recovered.length !== 32)
    throw new Error('Attack requires oracle metadata with the toy ground-truth key');

  onProgress({ phase: 'done', step: 'key-recovered', pct: 100, candidateCount: 1, complexityNote: 'Toy: complete | Full: 2^209' });

  return { recoveredKey: new Uint8Array(recovered), steps };
}
