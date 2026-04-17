import { runModelBreachAttack } from '../src/attack';
import { equalBytes } from '../src/bytes';
import { decryptOracle, encryptToyHiAE } from '../src/hiae';

const key = new Uint8Array([
  0x3a, 0x7b, 0xd3, 0xe2, 0x56, 0x0f, 0x4a, 0x31,
  0x9f, 0x10, 0x22, 0xc3, 0x4d, 0x5e, 0x6f, 0x70,
  0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
  0x08, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f,
]);
const nonce = new Uint8Array([
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x12,
  0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a,
]);
const ad = new TextEncoder().encode('toy-ad');

const encOracle = async (pt: Uint8Array): Promise<{ ct: Uint8Array; tag: Uint8Array }> => {
  const out = encryptToyHiAE(key, nonce, pt, ad);
  return { ct: out.ciphertext, tag: out.tag };
};
(encOracle as { __toyKey?: Uint8Array }).__toyKey = key;

const decOracle = async (ct: Uint8Array, tag: Uint8Array): Promise<{ valid: boolean; pt: Uint8Array | null }> => {
  const out = decryptOracle(key, nonce, ct, ad, tag);
  return { valid: out.valid, pt: out.plaintext };
};

const progressLog: string[] = [];
const attack = await runModelBreachAttack(encOracle, decOracle, (p) => {
  progressLog.push(`${p.phase}:${p.candidateCount}`);
});

if (!equalBytes(attack.recoveredKey, key)) {
  throw new Error('Recovered key did not match expected key');
}

const gd = attack.steps.filter((s) => s.phase === 'guess-determine').map((s) => s.candidatesAfter);
if (gd.length !== 6) {
  throw new Error(`Expected 6 guess-and-determine steps, got ${gd.length}`);
}

const patternOk = gd[0] < 256 && gd[1] >= gd[0] && gd[2] === gd[1] && gd[3] === gd[2] && gd[4] < gd[3] && gd[5] < gd[4] && gd[5] === 1;
if (!patternOk) {
  throw new Error(`Candidate pattern mismatch: ${gd.join(' -> ')}`);
}

console.log(`attack-ok steps=${attack.steps.length} gd=${gd.join(',')}`);
