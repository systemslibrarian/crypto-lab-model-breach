import { aesl } from './aesl';
import { assertLength, concatBytes, equalBytes, splitBlocks, xorBytes } from './bytes';

const CONST0 = new Uint8Array([
  0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
]);

const CONST1 = new Uint8Array([
  0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
  0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8,
]);

export interface ToyState {
  blocks: [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
}

function cloneState(state: ToyState): ToyState {
  return {
    blocks: [
      new Uint8Array(state.blocks[0]),
      new Uint8Array(state.blocks[1]),
      new Uint8Array(state.blocks[2]),
      new Uint8Array(state.blocks[3]),
    ],
  };
}

export function updateFunction(state: ToyState, X: Uint8Array): ToyState {
  assertLength(X, 16, 'X');
  const [s0, s1, s2, s3] = state.blocks;

  const next0 = new Uint8Array(s1);
  const next1 = xorBytes(s2, X);
  const next2 = new Uint8Array(s3);
  const next3 = xorBytes(xorBytes(aesl(xorBytes(s0, s1)), aesl(s3)), X);

  return { blocks: [next0, next1, next2, next3] };
}

function absorbData(state: ToyState, data: Uint8Array): ToyState {
  let cur = cloneState(state);
  const blocks = splitBlocks(data);
  for (const block of blocks) {
    cur = updateFunction(cur, block);
  }
  return cur;
}

export function initToyHiAE(key: Uint8Array, nonce: Uint8Array): ToyState {
  assertLength(key, 32, 'key');
  assertLength(nonce, 16, 'nonce');

  const k0 = key.subarray(0, 16);
  const k1 = key.subarray(16, 32);

  let state: ToyState = {
    blocks: [
      xorBytes(k0, CONST0),
      xorBytes(k1, CONST1),
      xorBytes(nonce, CONST0),
      aesl(xorBytes(k0, nonce)),
    ],
  };

  for (let i = 0; i < 8; i += 1) {
    state = updateFunction(state, i % 2 === 0 ? CONST0 : CONST1);
  }

  return state;
}

export function encryptToyHiAE(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  let state = absorbData(initToyHiAE(key, nonce), ad);

  const ciphertextBlocks: Uint8Array[] = [];
  let offset = 0;
  const blocks = splitBlocks(plaintext);

  for (const block of blocks) {
    const stream = aesl(xorBytes(state.blocks[0], state.blocks[2]));
    const ctBlock = xorBytes(block, stream);
    state = updateFunction(state, block);

    const chunkLen = Math.min(16, plaintext.length - offset);
    if (chunkLen > 0) {
      ciphertextBlocks.push(ctBlock.subarray(0, chunkLen));
    }
    offset += 16;
  }

  const folded = xorBytes(
    xorBytes(state.blocks[0], state.blocks[1]),
    xorBytes(state.blocks[2], state.blocks[3]),
  );
  const tag = aesl(folded);

  return {
    ciphertext: concatBytes(ciphertextBlocks),
    tag,
  };
}

export function decryptOracle(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  ad: Uint8Array,
  tag: Uint8Array,
): { valid: boolean; plaintext: Uint8Array | null } {
  assertLength(tag, 16, 'tag');
  let state = absorbData(initToyHiAE(key, nonce), ad);

  const plaintextBlocks: Uint8Array[] = [];
  let offset = 0;
  const blocks = splitBlocks(ciphertext);

  for (const block of blocks) {
    const stream = aesl(xorBytes(state.blocks[0], state.blocks[2]));
    const ptBlock = xorBytes(block, stream);
    state = updateFunction(state, ptBlock);

    const chunkLen = Math.min(16, ciphertext.length - offset);
    if (chunkLen > 0) {
      plaintextBlocks.push(ptBlock.subarray(0, chunkLen));
    }
    offset += 16;
  }

  const folded = xorBytes(
    xorBytes(state.blocks[0], state.blocks[1]),
    xorBytes(state.blocks[2], state.blocks[3]),
  );
  const expectedTag = aesl(folded);

  // This explicit reject path is the attack surface: adversaries can keep querying invalid tags.
  if (!equalBytes(expectedTag, tag)) {
    return { valid: false, plaintext: null };
  }

  return {
    valid: true,
    plaintext: concatBytes(plaintextBlocks),
  };
}

export { CONST0, CONST1 };
