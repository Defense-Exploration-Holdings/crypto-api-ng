// crypto-api-ng:facade
'use strict';

/*
 * BLAKE3 in plain JavaScript: the engine used when WebAssembly is not
 * available, and the reference the wasm engine is tested against. See
 * src/hasher/blake3.mjs for how it is used.
 *
 * Engine interface (shared with src/wasm/blake3.mjs):
 *   update(state, init, message, nchunks)  hash the first `nchunks` whole chunks of
 *                                          `message` into the tree
 *   finalize(state, init, tail, bytes)     the first `bytes` output bytes of the hash that ends
 *                                          with `tail` (the last chunk)
 *
 * `init` is `{key: number[8], flags}`: the key words and the flags every compression
 * carries (0, KEYED_HASH or DERIVE_KEY_MATERIAL). `state.chunks` counts the chunks in
 * the tree and `state.stack` holds the chaining values of the finished subtrees, eight
 * int32 each, the oldest first (popcount(chunks) entries).
 */

export const BLOCK = 64;
export const CHUNK = 1024;

export const CHUNK_START = 1;
export const CHUNK_END = 2;
export const PARENT = 4;
export const ROOT = 8;
export const KEYED_HASH = 16;
export const DERIVE_KEY_CONTEXT = 32;
export const DERIVE_KEY_MATERIAL = 64;

export const IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
].map((w) => w | 0);

const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const TWO32 = 4294967296;

// Message word order of each of the 7 rounds.
const SCHEDULE = [];
(function () {
  let s = [];
  for (let i = 0; i < 16; i++) {
    s.push(i);
  }
  for (let r = 0; r < 7; r++) {
    SCHEDULE.push(s);
    s = PERM.map((p) => s[p]);
  }
})();

const v = new Int32Array(16);
const m = new Int32Array(16);

function g(a, b, c, d, x, y) {
  let va = (v[a] + v[b] + x) | 0;
  let vd = v[d] ^ va;
  vd = (vd >>> 16) | (vd << 16);
  let vc = (v[c] + vd) | 0;
  let vb = v[b] ^ vc;
  vb = (vb >>> 12) | (vb << 20);
  va = (va + vb + y) | 0;
  vd ^= va;
  vd = (vd >>> 8) | (vd << 24);
  vc = (vc + vd) | 0;
  vb ^= vc;
  vb = (vb >>> 7) | (vb << 25);
  v[a] = va;
  v[b] = vb;
  v[c] = vc;
  v[d] = vd;
}

/**
 * The compression function. The 16 output words are left in `v`, already
 * combined (`v[0..8]` is the new chaining value).
 *
 * @param {ArrayLike<number>} cv - eight int32 chaining value words
 * @param {number} counter
 * @param {number} len - bytes of the block
 * @param {number} flags
 */
function compress(cv, counter, len, flags) {
  for (let i = 0; i < 8; i++) {
    v[i] = cv[i];
    v[i + 8] = i < 4 ? IV[i] : 0;
  }
  v[12] = counter % TWO32;
  v[13] = Math.floor(counter / TWO32);
  v[14] = len;
  v[15] = flags;
  for (let r = 0; r < 7; r++) {
    const s = SCHEDULE[r];
    g(0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) {
    v[i] ^= v[i + 8];
    v[i + 8] ^= cv[i];
  }
}

/** Load the words of `message[pos, pos + len)` into `m`, zero padded to a block. */
function load(message, pos, len) {
  const e = pos + len;
  for (let i = 0; i < 16; i++) {
    const p = pos + 4 * i;
    m[i] = (p < e ? message.charCodeAt(p) : 0) |
      ((p + 1 < e ? message.charCodeAt(p + 1) : 0) << 8) |
      ((p + 2 < e ? message.charCodeAt(p + 2) : 0) << 16) |
      ((p + 3 < e ? message.charCodeAt(p + 3) : 0) << 24);
  }
}

/**
 * Everything but the last compression of the chunk `message[pos, pos + len)`
 * (0..1024 bytes). The last compression is returned as parameters, because it
 * becomes the root output when the chunk is the whole tree.
 */
function chunkEnd(init, message, pos, len, counter) {
  let cv = init.key.slice();
  let first = CHUNK_START;
  let done = 0;
  while (len - done > BLOCK) {
    load(message, pos + done, BLOCK);
    compress(cv, counter, BLOCK, init.flags | first);
    cv = Array.prototype.slice.call(v, 0, 8);
    first = 0;
    done += BLOCK;
  }
  load(message, pos + done, len - done);
  return {
    cv: cv, block: Array.prototype.slice.call(m), blockLen: len - done,
    flags: init.flags | first | CHUNK_END, counter: counter
  };
}

function chainingValue(end) {
  m.set(end.block);
  compress(end.cv, end.counter, end.blockLen, end.flags);
  return Array.prototype.slice.call(v, 0, 8);
}

function parentEnd(init, left, right) {
  return {
    cv: init.key.slice(), block: left.concat(right), blockLen: BLOCK,
    flags: init.flags | PARENT, counter: 0
  };
}

/** Number of one bits in `n` (a non-negative integer below 2^53). */
function popcount(n) {
  let c = 0;
  while (n > 0) {
    c += n % 2;
    n = Math.floor(n / 2);
  }
  return c;
}

export default {
  name: 'js',

  update(state, init, message, nchunks) {
    for (let i = 0; i < nchunks; i++) {
      let cv = chainingValue(chunkEnd(init, message, i * CHUNK, CHUNK, state.chunks));
      state.chunks += 1;
      // One parent for every trailing zero bit of the chunk count.
      let total = state.chunks;
      let depth = popcount(state.chunks - 1);
      while (total % 2 === 0) {
        depth -= 1;
        cv = chainingValue(parentEnd(init, state.stack.slice(8 * depth, 8 * depth + 8), cv));
        total /= 2;
      }
      state.stack.length = 8 * depth;
      state.stack.push.apply(state.stack, cv);
    }
  },

  finalize(state, init, tail, bytes) {
    let end = chunkEnd(init, tail, 0, tail.length, state.chunks);
    for (let depth = popcount(state.chunks); depth > 0; depth--) {
      end = parentEnd(init, state.stack.slice(8 * depth - 8, 8 * depth), chainingValue(end));
    }
    m.set(end.block);
    let out = '';
    for (let counter = 0; out.length < bytes; counter++) {
      compress(end.cv, counter, end.blockLen, end.flags | ROOT);
      for (let i = 0; i < 16; i++) {
        const w = v[i];
        out += String.fromCharCode(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
      }
    }
    return out.substr(0, bytes);
  }
};
