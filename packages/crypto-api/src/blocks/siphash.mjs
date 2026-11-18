// crypto-api-ng:facade
'use strict';

/*
 * SipHash-2-4 and SipHash-1-3 in plain JavaScript: the engines used when WebAssembly is not
 * available, and the reference the wasm engines are tested against. See src/blocks/base.mjs for
 * how they are used and src/hash/siphash.zig for the algorithm.
 *
 * Engine interface (shared with src/wasm/blocks.mjs):
 *   blocks(state, message, start, end)  process the whole 8-byte words message[start, end)
 *   final(state, tail)                  the 8-byte result (least significant byte first) of the last word `tail`
 *
 * `state.hash` is v0, v1, v2, v3 as 64-bit words, low half first (eight int32). `state.counter`
 * is the number of bytes processed so far.
 */

import {r, add, rotl, word, le32} from "./u64.mjs";
import {ownOption, defineOption, toBinaryString} from "../tools/input.mjs";

/**
 * Copy the `key` option (required, 16 bytes) into `out` as a binary string.
 *
 * @ignore
 */
export function normalizeKey(name, options, out) {
  const given = ownOption(options, 'key');
  if (given === undefined) {
    throw new TypeError(name + ': the key option is required (16 bytes)');
  }
  const key = toBinaryString(given, name + ': key');
  if (key.length !== 16) {
    throw new RangeError(name + ': key must be 16 bytes, got ' + key.length);
  }
  defineOption(out, 'key', key);
}

/** The initial `state.hash` for a 16-byte key (a binary string). */
export function iv(key) {
  const k0l = word(key, 0);
  const k0h = word(key, 4);
  const k1l = word(key, 8);
  const k1h = word(key, 12);
  return [
    k0l ^ 0x70736575, k0h ^ 0x736f6d65,
    k1l ^ 0x6e646f6d, k1h ^ 0x646f7261,
    k0l ^ 0x6e657261, k0h ^ 0x6c796765,
    k1l ^ 0x79746573, k1h ^ 0x74656462
  ];
}

function round(v) {
  add(v[0], v[1], v[2], v[3]);
  v[0] = r.lo;
  v[1] = r.hi;
  rotl(v[2], v[3], 13);
  v[2] = r.lo ^ v[0];
  v[3] = r.hi ^ v[1];
  rotl(v[0], v[1], 32);
  v[0] = r.lo;
  v[1] = r.hi;
  add(v[4], v[5], v[6], v[7]);
  v[4] = r.lo;
  v[5] = r.hi;
  rotl(v[6], v[7], 16);
  v[6] = r.lo ^ v[4];
  v[7] = r.hi ^ v[5];
  add(v[0], v[1], v[6], v[7]);
  v[0] = r.lo;
  v[1] = r.hi;
  rotl(v[6], v[7], 21);
  v[6] = r.lo ^ v[0];
  v[7] = r.hi ^ v[1];
  add(v[4], v[5], v[2], v[3]);
  v[4] = r.lo;
  v[5] = r.hi;
  rotl(v[2], v[3], 17);
  v[2] = r.lo ^ v[4];
  v[3] = r.hi ^ v[5];
  rotl(v[4], v[5], 32);
  v[4] = r.lo;
  v[5] = r.hi;
}

function compress(v, c, lo, hi) {
  v[6] ^= lo;
  v[7] ^= hi;
  for (let i = 0; i < c; i++) {
    round(v);
  }
  v[0] ^= lo;
  v[1] ^= hi;
}

function engine(c, d) {
  return {
    name: 'js',

    blocks(state, message, start, end) {
      const v = state.hash;
      for (let p = start; p < end; p += 8) {
        compress(v, c, word(message, p), word(message, p + 4));
      }
      state.counter += end - start;
    },

    final(state, tail) {
      const v = state.hash.slice(0, 8);
      let pos = 0;
      if (tail.length === 8) {
        compress(v, c, word(tail, 0), word(tail, 4));
        pos = 8;
      }
      const total = state.counter + tail.length;
      let lo = 0;
      let hi = (total % 256) << 24;
      for (let i = 0; pos + i < tail.length; i++) {
        const b = tail.charCodeAt(pos + i);
        if (i < 4) {
          lo |= b << (8 * i);
        } else {
          hi |= b << (8 * (i - 4));
        }
      }
      compress(v, c, lo, hi);
      v[4] ^= 0xff;
      for (let i = 0; i < d; i++) {
        round(v);
      }
      return le32(v[0] ^ v[2] ^ v[4] ^ v[6]) + le32(v[1] ^ v[3] ^ v[5] ^ v[7]);
    }
  };
}

export const siphash24 = engine(2, 4);
export const siphash13 = engine(1, 3);
