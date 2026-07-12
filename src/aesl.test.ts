import { describe, expect, it } from 'vitest';
import {
  aesl, aeslInv, gmul, mixColumns, mixColumnsInv,
  shiftRows, shiftRowsInv, subBytes, subBytesInv, SBOX, SBOX_INV, xtime,
} from './aesl';

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (s: string): Uint8Array =>
  Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));

describe('AESL is the real AES round function (SubBytes ∘ ShiftRows ∘ MixColumns, no round key)', () => {
  // FIPS-197 Appendix B worked example, round 1. The state entering round 1
  // (after AddRoundKey) is column-major:
  const roundInput = fromHex('193de3bea0f4e22b9ac68d2ae9f84808');

  it('SubBytes matches FIPS-197 round-1 vector', () => {
    expect(hex(subBytes(roundInput))).toBe('d42711aee0bf98f1b8b45de51e415230');
  });

  it('ShiftRows matches FIPS-197 round-1 vector', () => {
    expect(hex(shiftRows(subBytes(roundInput)))).toBe('d4bf5d30e0b452aeb84111f11e2798e5');
  });

  it('MixColumns matches FIPS-197 round-1 vector', () => {
    expect(hex(mixColumns(shiftRows(subBytes(roundInput))))).toBe('046681e5e0cb199a48f8d37a2806264c');
  });

  it('aesl composes SubBytes∘ShiftRows∘MixColumns to the FIPS round output', () => {
    expect(hex(aesl(roundInput))).toBe('046681e5e0cb199a48f8d37a2806264c');
  });

  it('S-box is a permutation and matches known FIPS entries', () => {
    expect(SBOX[0x00]).toBe(0x63);
    expect(SBOX[0x53]).toBe(0xed);
    expect(SBOX[0xff]).toBe(0x16);
    const seen = new Set(SBOX);
    expect(seen.size).toBe(256);
  });

  it('S-box and inverse S-box are true inverses', () => {
    for (let x = 0; x < 256; x++) {
      expect(SBOX_INV[SBOX[x]]).toBe(x);
      expect(SBOX[SBOX_INV[x]]).toBe(x);
    }
  });

  it('GF(2^8) multiply: xtime and gmul match reference values', () => {
    expect(xtime(0x57)).toBe(0xae);
    expect(gmul(0x57, 0x13)).toBe(0xfe); // FIPS-197 §4.2 worked example
    expect(gmul(0x02, 0x80)).toBe(0x1b); // reduction case
    expect(gmul(0x01, 0xab)).toBe(0xab);
  });
});

describe('AESL layer inverses round-trip', () => {
  const block = fromHex('00112233445566778899aabbccddeeff');

  it('subBytesInv ∘ subBytes = identity', () => {
    expect(hex(subBytesInv(subBytes(block)))).toBe(hex(block));
  });
  it('shiftRowsInv ∘ shiftRows = identity', () => {
    expect(hex(shiftRowsInv(shiftRows(block)))).toBe(hex(block));
  });
  it('mixColumnsInv ∘ mixColumns = identity', () => {
    expect(hex(mixColumnsInv(mixColumns(block)))).toBe(hex(block));
  });
  it('aeslInv ∘ aesl = identity for many random blocks', () => {
    for (let t = 0; t < 200; t++) {
      const b = new Uint8Array(16);
      crypto.getRandomValues(b);
      expect(hex(aeslInv(aesl(b)))).toBe(hex(b));
    }
  });
});
