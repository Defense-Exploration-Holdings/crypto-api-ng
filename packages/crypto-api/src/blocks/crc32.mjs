// crypto-api-ng:facade
'use strict';

/*
 * CRC-32 (IEEE 802.3) and CRC-32C (Castagnoli) in plain JavaScript: the engines used when
 * WebAssembly is not available, and the reference the wasm engines are tested against. See
 * src/blocks/base.mjs for how they are used and src/hash/crc32.zig for the algorithm.
 *
 * Engine interface (shared with src/wasm/blocks.mjs):
 *   blocks(state, message, start, end)  process the whole blocks message[start, end)
 *   final(state, tail)                  the 4-byte checksum of the last block `tail`
 *
 * `state.hash` holds the running register as one int32 (it starts as 0xFFFFFFFF; the
 * checksum is its complement), `state.counter` the number of bytes processed so far.
 */

export const BLOCK = 64;
/** The initial register. */
export const IV = [-1];

function makeTable(poly) {
  const t = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? (c >>> 1) ^ poly : c >>> 1;
    }
    t[i] = c;
  }
  return t;
}

function engine(poly) {
  let table = null;

  function run(crc, message, start, end) {
    const t = table || (table = makeTable(poly));
    let c = crc;
    for (let i = start; i < end; i++) {
      c = t[(c ^ message.charCodeAt(i)) & 255] ^ (c >>> 8);
    }
    return c;
  }

  return {
    name: 'js',

    blocks(state, message, start, end) {
      state.hash[0] = run(state.hash[0], message, start, end);
      state.counter += end - start;
    },

    final(state, tail) {
      const c = ~run(state.hash[0], tail, 0, tail.length);
      return String.fromCharCode((c >>> 24) & 0xff, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff);
    }
  };
}

export const crc32 = engine(0xEDB88320 | 0);
export const crc32c = engine(0x82F63B78 | 0);
