import { aesl } from './aesl';
import { xorBytes } from './bytes';

/**
 * Toy key derivation for the live browser attack.
 *
 * The end-to-end demo has to actually RECOVER the key from observed oracle
 * output — not read it out of a side channel. Recovering a full random 256-bit
 * HiAE key is the 2^209 research result the demo is *about*; it is not
 * browser-runnable. So the live simulation draws its key from an honestly
 * disclosed, reduced keyspace: a public function of a `TOY_SEED_BITS`-bit seed.
 *
 * This is the one and only place the "toy scale" of the demo lives. The attack
 * in `attack.ts` brute-forces this seed space using the encryption oracle's
 * keystream as the distinguisher, derives the candidate key with this same
 * public function, and verifies it. Nothing reads the ground-truth key.
 *
 * The derivation is deliberately nonlinear (built from the real AES round
 * function AESL) so the derived key bytes look random and the recovery has to
 * genuinely match oracle output rather than read seed bytes back out of the key.
 */
export const TOY_SEED_BITS = 16;
export const TOY_SEED_SPACE = 1 << TOY_SEED_BITS;

/** Derive a 32-byte key deterministically from a `TOY_SEED_BITS`-bit seed. */
export function deriveToyKey(seed: number): Uint8Array {
  const s = seed & (TOY_SEED_SPACE - 1);

  // Two diversified 16-byte blocks, each an AESL image of a seed-dependent input.
  const inA = new Uint8Array(16);
  inA[0] = s & 0xff;
  inA[1] = (s >>> 8) & 0xff;
  inA[2] = 0x9e;
  inA[3] = 0x37;
  inA[15] = 0x01;

  const inB = new Uint8Array(16);
  inB[0] = (s >>> 8) & 0xff;
  inB[1] = s & 0xff;
  inB[2] = 0xc2;
  inB[3] = 0x8d;
  inB[15] = 0x02;

  const blockA = aesl(inA);
  const blockB = aesl(xorBytes(inB, blockA));

  const key = new Uint8Array(32);
  key.set(blockA, 0);
  key.set(blockB, 16);
  return key;
}

/**
 * The fixed nonce/AD the live attack uses. Nonce-respecting: the attack issues
 * exactly one encryption query per seen instance under this nonce, so no nonce
 * is ever reused across two different plaintexts — the standard-model rule is
 * honoured, which is precisely why the *extended* (decryption-oracle) model is
 * the interesting one.
 */
export const TOY_NONCE = new Uint8Array([
  0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2d, 0x62, 0x72,
  0x65, 0x61, 0x63, 0x68, 0x2d, 0x6e, 0x30, 0x31,
]);

export const TOY_AD = new Uint8Array([0x74, 0x6f, 0x79, 0x2d, 0x61, 0x64]); // "toy-ad"
