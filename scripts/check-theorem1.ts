import { aesl } from '../src/aesl';
import { xorBytes } from '../src/bytes';
import { theorem1StateRecoveryWithTrace } from '../src/theorem1';

function randBlock(): Uint8Array {
  const out = new Uint8Array(16);
  crypto.getRandomValues(out);
  return out;
}

function randActiveAlpha(): Uint8Array {
  const out = new Uint8Array(16);
  crypto.getRandomValues(out.subarray(0, 4));
  for (let i = 0; i < 4; i += 1) {
    if (out[i] === 0) {
      out[i] = i + 1;
    }
  }
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

for (let attempt = 1; attempt <= 2000; attempt += 1) {
  const x0 = randBlock();
  const x1 = randBlock();
  const alpha0 = randActiveAlpha();
  const alpha1 = randActiveAlpha();

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

  const recovered = theorem1StateRecoveryWithTrace(
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

  if (recovered === null) {
    continue;
  }

  if (!equal(recovered.x0, x0) || !equal(recovered.x1, x1)) {
    continue;
  }

  if (recovered.trace.afterAlpha2 !== 1) {
    throw new Error('Expected unique theorem1 solution with afterAlpha2 = 1');
  }

  console.log(`theorem1-ok attempt=${attempt} checked=${recovered.trace.totalChecked}`);
  process.exit(0);
}

throw new Error('Failed to find a unique theorem1 synthetic test case');
