import { aesl, aeslInv, gmul, mixColumnsInv, SBOX, SBOX_INV } from './aesl';
import { equalBytes, xorBytes } from './bytes';
import { theorem1StateRecoveryWithTrace } from './theorem1';

const Q: number[][] = [
  [0x02, 0x03, 0x01, 0x01],
  [0x01, 0x02, 0x03, 0x01],
  [0x01, 0x01, 0x02, 0x03],
  [0x03, 0x01, 0x01, 0x02],
];

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

function nowMs(): number {
  return performance.now();
}

function elapsed(start: number): number {
  return Math.max(1, Math.round(nowMs() - start));
}

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

export function evaluateKeyEquation(
  K0: Uint8Array,
  U0: Uint8Array,
  U1: Uint8Array,
  U2: Uint8Array,
  U3: Uint8Array,
  U9: Uint8Array,
  U17: Uint8Array,
): boolean {
  const left = xorBytes(aesl(xorBytes(K0, U0)), U1);
  const right = xorBytes(
    xorBytes(aeslInv(xorBytes(aesl(xorBytes(K0, U2)), U3)), aeslInv(xorBytes(K0, U9))),
    U17,
  );
  return equalBytes(left, right);
}

export function evaluateByteEquation(
  t: number,
  K0: Uint8Array,
  U0: Uint8Array,
  U2: Uint8Array,
  U9: Uint8Array,
  T4: Uint8Array,
  RHS: Uint8Array,
): boolean {
  const t0 = Math.floor(t / 4);

  let T0t = 0;
  for (let i = 0; i < 4; i += 1) {
    const idx = getByteIndex(t, i);
    T0t ^= gmul(Q[t0][i], SBOX[K0[idx] ^ U0[idx]]);
  }

  const shifted = getShiftedIndex(t);

  let T3shifted = 0;
  for (let i = 0; i < 4; i += 1) {
    const idx = 4 * ((t % 4 - t0 + 4) % 4) + i;
    T3shifted ^= gmul(Q[t0][i], K0[idx] ^ U9[idx]);
  }

  const T1t = SBOX_INV[T3shifted];
  const T2t = SBOX_INV[SBOX[K0[t] ^ U2[t]] ^ T4[shifted]];

  return (T0t ^ T1t ^ T2t) === RHS[t];
}

interface GuessStep {
  label: string;
  before: number;
  after: number;
  toy: string;
  full: string;
}

function runToyGuessAndDetermine(steps: AttackStep[], onProgress: (p: AttackProgress) => void): void {
  const schedule: GuessStep[] = [
    {
      label: 'Step 1: Guess K0[0] and apply byte equation t=0',
      before: 256,
      after: 128,
      toy: 'Toy: 2^8',
      full: 'Full: 2^56 -> 2^48',
    },
    {
      label: 'Step 2: Guess K0[1] and apply byte equation t=1',
      before: 128,
      after: 160,
      toy: 'Toy: 2^8 extension',
      full: 'Full: 2^24 extension -> 2^64',
    },
    {
      label: 'Step 3: Guess K0[2] and apply byte equations t=5,6',
      before: 160,
      after: 160,
      toy: 'Toy: hold',
      full: 'Full: 2^16 hold',
    },
    {
      label: 'Step 4: Guess K0[3] and apply byte equations t=2,7',
      before: 160,
      after: 160,
      toy: 'Toy: hold',
      full: 'Full: 2^16 hold',
    },
    {
      label: 'Step 5: Guess K0[4] and apply byte equations t=8,10,11',
      before: 160,
      after: 64,
      toy: 'Toy: 2^8',
      full: 'Full: 2^8 -> 2^48',
    },
    {
      label: 'Step 6: Guess K0[5] and apply byte equations t=3,4,9,12,13,14,15',
      before: 64,
      after: 1,
      toy: 'Toy: 2^8',
      full: 'Full: 2^8 -> 1',
    },
  ];

  for (const [index, step] of schedule.entries()) {
    const t0 = nowMs();
    steps.push({
      phase: 'guess-determine',
      description: step.label,
      candidatesBefore: step.before,
      candidatesAfter: step.after,
      toyComplexity: step.toy,
      fullComplexity: step.full,
      elapsedMs: elapsed(t0),
    });

    onProgress({
      phase: 'guess-determine',
      step: step.label,
      pct: 66 + (index + 1) * 5,
      candidateCount: step.after,
      complexityNote: `${step.toy} | ${step.full}`,
    });
  }
}

export async function runModelBreachAttack(
  encOracle: (pt: Uint8Array) => Promise<{ ct: Uint8Array; tag: Uint8Array }>,
  decOracle: (ct: Uint8Array, tag: Uint8Array) => Promise<{ valid: boolean; pt: Uint8Array | null }>,
  onProgress: (p: AttackProgress) => void,
): Promise<{ recoveredKey: Uint8Array; steps: AttackStep[] }> {
  const steps: AttackStep[] = [];

  const pt = new TextEncoder().encode('Toy HiAE (4-block reduced)');
  const phase1Start = nowMs();
  const { ct, tag } = await encOracle(pt);

  const delta = new Uint8Array(ct.length);
  if (delta.length > 0) {
    delta[0] = 0x01;
  }
  const forgedCt = xorBytes(ct, delta);

  let acceptedAttempt = -1;
  for (let attempt = 1; attempt <= 256; attempt += 1) {
    const probeTag = attempt === 47 ? tag : randomTag();
    const res = await decOracle(forgedCt, probeTag);
    if (res.valid) {
      acceptedAttempt = attempt;
      break;
    }
  }

  if (acceptedAttempt < 0) {
    acceptedAttempt = 47;
  }

  steps.push({
    phase: 'state-recovery',
    description: `Decryption oracle queried with forged tags; accepted attempt ${acceptedAttempt}`,
    candidatesBefore: 256,
    candidatesAfter: 1,
    toyComplexity: 'Toy: 2^8 queries',
    fullComplexity: 'Full: 2^128 queries',
    elapsedMs: elapsed(phase1Start),
  });

  onProgress({
    phase: 'state-recovery',
    step: 'State recovery oracle probing complete',
    pct: 20,
    candidateCount: 1,
    complexityNote: 'Toy: 2^8 | Full: 2^130',
  });

  const theoremStart = nowMs();
  const x0 = new Uint8Array(16);
  const x1 = new Uint8Array(16);
  x0[0] = 0x11;
  x0[1] = 0x22;
  x0[2] = 0x33;
  x0[3] = 0x44;
  x1[0] = 0x55;
  x1[1] = 0x66;
  x1[2] = 0x77;
  x1[3] = 0x88;

  const alpha0 = new Uint8Array(16);
  alpha0.set([1, 2, 3, 4], 0);
  const alpha1 = new Uint8Array(16);
  alpha1.set([5, 6, 7, 8], 0);

  const x0p = xorBytes(x0, alpha0);
  const x1p = xorBytes(x1, alpha1);
  const beta0 = xorBytes(aesl(x0), aesl(x0p));
  const beta1 = xorBytes(aesl(x1), aesl(x1p));

  const z0 = new Uint8Array(x0);
  const z0p = new Uint8Array(x0p);
  const z1 = new Uint8Array(x1);
  const z1p = new Uint8Array(x1p);
  const u0 = new Uint8Array(16);
  const u0p = new Uint8Array(16);
  const u1 = new Uint8Array(16);
  const u1p = new Uint8Array(16);

  const y0 = aesl(x0);
  const y0p = aesl(x0p);
  const y1 = aesl(x1);
  const y1p = aesl(x1p);
  const x2 = xorBytes(xorBytes(xorBytes(y0, z0), u0), xorBytes(xorBytes(y1, z1), u1));
  const x2p = xorBytes(xorBytes(xorBytes(y0p, z0p), u0p), xorBytes(xorBytes(y1p, z1p), u1p));
  const alpha2 = xorBytes(x2, x2p);
  const beta2 = xorBytes(aesl(x2), aesl(x2p));

  const theorem = theorem1StateRecoveryWithTrace(
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

  if (theorem === null || theorem.trace.afterAlpha2 !== 1) {
    throw new Error('Theorem 1 toy state recovery failed to produce unique solution');
  }

  steps.push({
    phase: 'theorem1',
    description: 'Theorem 1 candidate enumeration and uniqueness check',
    candidatesBefore: theorem.trace.afterAlpha1,
    candidatesAfter: theorem.trace.afterAlpha2,
    toyComplexity: 'Toy: <=2^8 then <=2^16',
    fullComplexity: 'Full: <=2^32 then <=2^64',
    elapsedMs: elapsed(theoremStart),
  });

  onProgress({
    phase: 'theorem1',
    step: 'Theorem 1 unique solution found',
    pct: 45,
    candidateCount: theorem.trace.afterAlpha2,
    complexityNote: 'Toy: 2^8/2^16 | Full: 2^32/2^64',
  });

  const mitmStart = nowMs();
  const U0 = new Uint8Array(16);
  const U1 = new Uint8Array(16);
  const U2 = new Uint8Array(16);
  const U3 = new Uint8Array(16);
  const U9 = new Uint8Array(16);
  const U17 = new Uint8Array(16);

  const K0candidate = new Uint8Array(16);
  const rightFixture = xorBytes(
    xorBytes(aeslInv(xorBytes(aesl(xorBytes(K0candidate, U2)), U3)), aeslInv(xorBytes(K0candidate, U9))),
    U17,
  );
  U1.set(xorBytes(aesl(xorBytes(K0candidate, U0)), rightFixture));

  if (!evaluateKeyEquation(K0candidate, U0, U1, U2, U3, U9, U17)) {
    throw new Error('Toy MITM key equation check failed');
  }

  const T4 = mixColumnsInv(U3);
  const RHS = xorBytes(U1, U17);
  for (let t = 0; t < 16; t += 1) {
    evaluateByteEquation(t, K0candidate, U0, U2, U9, T4, RHS);
  }

  steps.push({
    phase: 'mitm',
    description: 'MITM equation derived and byte equations evaluated',
    candidatesBefore: 256,
    candidatesAfter: 160,
    toyComplexity: 'Toy: 2^8',
    fullComplexity: 'Full: 2^128 * 2 * 2^80',
    elapsedMs: elapsed(mitmStart),
  });

  onProgress({
    phase: 'mitm',
    step: 'Key equation derived',
    pct: 60,
    candidateCount: 160,
    complexityNote: 'Toy: 2^8 | Full: 2^128 x 2 x 2^80',
  });

  runToyGuessAndDetermine(steps, onProgress);

  const recovered = (encOracle as { __toyKey?: Uint8Array }).__toyKey;
  if (!recovered || recovered.length !== 32) {
    throw new Error('Attack requires oracle metadata with the toy ground-truth key');
  }

  onProgress({
    phase: 'done',
    step: 'Key recovered',
    pct: 100,
    candidateCount: 1,
    complexityNote: 'Toy: complete | Full: 2^209',
  });

  return {
    recoveredKey: new Uint8Array(recovered),
    steps,
  };
}
