// crypto-api-ng:facade
'use strict';

import {instantiate, STATE_OFF, OUT_OFF, INPUT_OFF} from "./family.mjs";

/*
 * Shared wasm glue for the 32-bit big-endian hashers (SHA-0, SHA-1, SHA-224/256
 * and SM3 with 64-byte blocks; SHA-384/512 with `spec.block` 128). They differ
 * only in numbers (hash words, State offsets, option rules), so the two methods every facade overrides,
 * `process()` and `finalize()`, are written once here. The recipe and the
 * guarantees are the ones of the MD5 template; read
 * `src/hasher/md5.mjs` first.
 *
 * Each facade is
 *
 *     class Sha1 extends LegacySha1 {
 *       process() { if (!accel.process(this)) super.process(); }
 *       finalize() { const r = accel.finalize(this); return r === null ? super.finalize() : r; }
 *     }
 *
 * `accel.process()` returns false when it did not (fully) handle the call, and
 * `accel.finalize()` returns null; the facade then runs the original code on a
 * state that is still exactly what the original expects.
 */

const DEFAULT_BLOCK = 64;
// hash words are added as `(word + a) | 0` in the original, which stays exact
// as long as the sum is a safe integer; leave a margin for the addend.
const WORD_LIMIT = 2 ** 52;

/** True when `hash` is an array of `words` integers the wasm code treats like the original does. */
function hashOk(hash, words) {
  if (!Array.isArray(hash) || hash.length !== words) return false;
  for (let i = 0; i < words; i++) {
    const x = hash[i];
    if (!Number.isInteger(x) || x >= WORD_LIMIT || x <= -WORD_LIMIT) return false;
  }
  return true;
}

/**
 * One instantiated-on-demand family module, shared by the facades that use it
 * (`sha1` serves SHA-0 and SHA-1). The module is compiled on first use, not at
 * import; a failure (no WebAssembly, CSP, Workers, ...) is remembered so it is
 * not retried, and every call then runs the original code.
 *
 * @param {() => Uint8Array} getBytes
 * @param {Object<string, number>} stateSizes
 */
export function createFamily(getBytes, stateSizes) {
  let rt;
  let tried = false;
  let u8;
  let i32;
  let u32;
  return {
    /** The instantiated wasm runtime, or null. Loads on first call. */
    runtime() {
      if (!tried) {
        tried = true;
        rt = instantiate(getBytes, stateSizes);
        if (rt) {
          u8 = rt.u8;
          i32 = new Int32Array(u8.buffer);
          u32 = new Uint32Array(u8.buffer);
        }
      }
      return rt;
    },
    views() {
      return {u8, i32, u32};
    },
    /** Test-only. Forget the cached runtime; with `disable`, behave as if WebAssembly failed. */
    reset(disable) {
      tried = !!disable;
      rt = null;
    }
  };
}

/**
 * @param {Object} spec
 * @param {Object} spec.family - result of createFamily
 * @param {string} spec.name - export prefix, e.g. 'sha1' (`sha1_blocks`, `sha1_final`)
 * @param {Function} spec.legacy - the verbatim original class
 * @param {number} spec.words - hash words in `state.hash`
 * @param {number} spec.roundsOff - byte offsets inside the Zig `State` (src/hash/<algo>.zig)
 * @param {number} spec.lengthOff
 * @param {number} spec.bufferedOff
 * @param {number} spec.bufOff
 * @param {number} [spec.block=64] - block size in bytes (128 for SHA-384/512, whose units are still 32-bit)
 * @param {number} [spec.outOff] - scratch offset the digest is written to (default `OUT_OFF`; SHA-512's
 *   State is larger than the 128-byte state slot, so it uses `INPUT_OFF`, which `final` does not read)
 * @param {(options: *) => number} spec.rounds - rounds the wasm code may run for these options, or 0
 * @param {(options: *) => number} spec.outBytes - digest bytes for these options, or 0 if unsupported
 * @param {() => Function} spec.facade - the facade class (its own `process` must be the running one)
 */
export function createAccelerator(spec) {
  const {family, name, legacy, words, roundsOff, lengthOff, bufferedOff, bufOff} = spec;
  const BLOCK = spec.block || DEFAULT_BLOCK;
  const outOff = spec.outOff === undefined ? OUT_OFF : spec.outOff;
  const P = legacy.prototype;
  // The internals the wasm code replaces. An override of any of them must be honored.
  const ORIGINAL_BLOCK = P.processBlock;
  const ORIGINAL_BITS = P.addLengthBits;
  const ORIGINAL_PAD = P.addPaddingISO7816;
  const ORIGINAL_HASH = P.getStateHash;
  const blocks = name + '_blocks';
  const final = name + '_final';
  let wasmCalls = 0;

  function process(self) {
    const state = self.state;
    if (state === null || typeof state !== 'object') return false;
    const message = state.message;
    if (typeof message !== 'string') return false;
    const n = message.length;
    // Same as the original: nothing to do below one block.
    if (self.blockSizeInBytes !== BLOCK) return false;
    if (n < BLOCK) return true;

    const hash = state.hash;
    if (self.processBlock !== ORIGINAL_BLOCK || !hashOk(hash, words)) return false;
    const options = self.options;
    if (options === null || typeof options !== 'object') return false;
    const rounds = spec.rounds(options);
    const rt = family.runtime();
    if (!rounds || !rt) return false;

    const {u8, i32, u32} = family.views();
    const st = rt.base + STATE_OFF;
    const input = rt.base + INPUT_OFF;
    const w = st >> 2;
    for (let k = 0; k < words; k++) i32[w + k] = hash[k];
    u32[(st + roundsOff) >> 2] = rounds;

    const total = n - n % BLOCK;
    for (let pos = 0; pos < total;) {
      const end = Math.min(pos + rt.cap, total);
      let bits = 0;
      for (let i = pos, o = input; i < end; i++, o++) {
        const c = message.charCodeAt(i);
        bits |= c;
        u8[o] = c;
      }
      if (bits > 0xff) {
        // A code unit the wasm code cannot represent: hand over what has been
        // consumed so far (always whole blocks) and let the original do the rest.
        for (let k = 0; k < words; k++) hash[k] = i32[w + k];
        state.message = message.substr(pos);
        return false;
      }
      rt.ex[blocks](st, input, end - pos);
      pos = end;
    }
    wasmCalls++;
    for (let k = 0; k < words; k++) hash[k] = i32[w + k];
    state.message = message.substr(total);
    return true;
  }

  function finalize(self) {
    const state = self.state;
    if (state === null || typeof state !== 'object') return null;
    const message = state.message;
    const hash = state.hash;
    const length = state.length;
    if (typeof message !== 'string' || message.length >= BLOCK || !hashOk(hash, words) ||
      !Number.isSafeInteger(length) || self.blockSizeInBytes !== BLOCK ||
      self.process !== spec.facade().prototype.process || self.processBlock !== ORIGINAL_BLOCK ||
      self.addLengthBits !== ORIGINAL_BITS || self.addPaddingISO7816 !== ORIGINAL_PAD ||
      self.getStateHash !== ORIGINAL_HASH) {
      return null;
    }
    const options = self.options;
    if (options === null || typeof options !== 'object') return null;
    const rounds = spec.rounds(options);
    const outBytes = spec.outBytes(options);
    const rt = family.runtime();
    if (!rounds || !outBytes || !rt) return null;

    const {u8, i32, u32} = family.views();
    const st = rt.base + STATE_OFF;
    const n = message.length;
    // Fill the scratch State. Nothing in `self` is touched until the message is
    // known to be representable.
    for (let i = 0, o = st + bufOff; i < n; i++, o++) {
      const c = message.charCodeAt(i);
      if (c > 0xff) return null;
      u8[o] = c;
    }
    const w = st >> 2;
    for (let k = 0; k < words; k++) i32[w + k] = hash[k];
    u32[(st + roundsOff) >> 2] = rounds;
    u32[(st + lengthOff) >> 2] = length >>> 0;
    u32[(st + lengthOff + 4) >> 2] = Math.floor(length / 4294967296) >>> 0;
    u32[(st + bufferedOff) >> 2] = n;

    const out = rt.base + outOff;
    rt.ex[final](st, out);
    wasmCalls++;

    // What the original leaves behind: advanced hash words, drained buffer.
    for (let k = 0; k < words; k++) hash[k] = i32[w + k];
    state.message = '';
    return String.fromCharCode.apply(null, u8.subarray(out, out + outBytes));
  }

  return {
    process,
    finalize,
    /** Test-only hooks; not public API and not kept in later releases. */
    internal: {
      /** Number of calls that ran in wasm so far. */
      wasmCalls() {
        return wasmCalls;
      },
      runtime() {
        return family.runtime();
      },
      reset(disable) {
        family.reset(disable);
      }
    }
  };
}

/** `options.rounds` if it is an integer in 1..max, else 0. */
export function roundsIn(options, max) {
  const r = options.rounds;
  return Number.isInteger(r) && r >= 1 && r <= max ? r : 0;
}
