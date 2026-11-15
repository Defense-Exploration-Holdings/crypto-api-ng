// crypto-api-ng:facade
'use strict';

import LegacyMd5 from "../../legacy/hasher/md5.mjs";
import {wasmBytes} from "../../wasm/md.mjs";
import {instantiate, wipe, STATE_OFF, OUT_OFF, INPUT_OFF} from "../wasm/family.mjs";

/*
 * MD5 with the compression and padding done in wasm, and everything else left
 * to the original JavaScript. This file is the template for every other
 * algorithm.
 *
 * The facade extends the verbatim crypto-api 0.8.5 class and overrides only
 * `process()` and `finalize()`. `this.state` stays the original plain object
 * ({message, length, hash}), so `update()`, `reset()`, `getState()`,
 * `setState()`, direct `.state` access, non-string input and wide characters
 * all behave exactly as before because they are the original code. A wasm call
 * happens only when the state and the class are exactly what the wasm code
 * models; in any other case the method delegates to the original, so there is
 * no engine to "switch" and nothing to carry across.
 *
 * Nothing about a hasher lives in wasm memory. Each call writes what it needs
 * into one shared scratch region and reads the result back, so wasm memory
 * never grows and a dropped hasher leaks nothing.
 */

/** Byte offsets inside the Zig `md5.State` (src/hash/md5.zig), relative to STATE_OFF. */
const O_HASH = 0;
const O_LENGTH = 16;
const O_BUFFERED = 24;
const O_BUF = 32;
const SIZE = 96;
const BLOCK = 64;

/** The five internals the wasm code replaces. An override of any of them must be honored. */
const P = LegacyMd5.prototype;
const ORIGINAL_BLOCK = P.processBlock;
const ORIGINAL_BITS = P.addLengthBits;
const ORIGINAL_PAD = P.addPaddingISO7816;
const ORIGINAL_HASH = P.getStateHash;

// The wasm module is compiled on first use, not at import. A failure (no
// WebAssembly, CSP, Workers, ...) is remembered so it is not retried, and every
// call then delegates to the original.
let rt;
let rtTried = false;
let u8;
let i32;
let u32;
let wasmCalls = 0;

function runtime() {
  if (!rtTried) {
    rtTried = true;
    rt = instantiate(wasmBytes, {md5: SIZE});
    if (rt) {
      u8 = rt.u8;
      i32 = new Int32Array(u8.buffer);
      u32 = new Uint32Array(u8.buffer);
    }
  }
  return rt;
}

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = {
  /** Number of calls that ran in wasm so far. */
  wasmCalls() {
    return wasmCalls;
  },
  /** The instantiated wasm runtime, or null. */
  runtime() {
    return runtime();
  },
  /** Forget the cached runtime; with `disable`, behave as if WebAssembly failed. */
  reset(disable) {
    rtTried = !!disable;
    rt = null;
  }
};

/** Largest word magnitude for which the original's `word + a` is exact in a double (a is int32). */
const MAX_WORD = 2 ** 52;

/** True when the four hash words can be handed to wasm without changing what the original computes. */
function hashOk(hash) {
  // Any integer up to 2^52 in magnitude is safe: the original computes
  // (word + a) | 0 and word | 0, which equals int32 arithmetic while the double
  // sum is exact. Larger words round in the sum, and fractions or strings
  // behave differently still, so those go to the original.
  if (!Array.isArray(hash) || hash.length !== 4) return false;
  for (let i = 0; i < 4; i++) {
    const w = hash[i];
    if (typeof w !== 'number' || !Number.isInteger(w) || w > MAX_WORD || w < -MAX_WORD) return false;
  }
  return true;
}

/**
 * Run the first `total` characters of `message` (whole blocks, `hash` the four
 * state words) through wasm. False when a code unit above 0xFF turned up: what
 * was consumed before it is applied to `state` and the original must do the rest.
 */
function feed(state, message, hash, total) {
  const base = rt.base;
  const st = base + STATE_OFF;
  const input = base + INPUT_OFF;
  const w = st >> 2;
  i32[w] = hash[0];
  i32[w + 1] = hash[1];
  i32[w + 2] = hash[2];
  i32[w + 3] = hash[3];

  for (let pos = 0; pos < total;) {
    const end = Math.min(pos + rt.cap, total);
    let bits = 0;
    for (let i = pos, o = input; i < end; i++, o++) {
      const c = message.charCodeAt(i);
      bits |= c;
      u8[o] = c;
    }
    // A refused call (non-zero status) leaves the scratch State as it was.
    const status = bits > 0xff ? -1 : rt.ex.md5_blocks(st, input, end - pos);
    if (status !== 0) {
      // A code unit the wasm code cannot represent, or a call it refused: hand
      // over what has been consumed so far (always whole blocks) and let the
      // original do the rest. Nothing is applied if the first chunk is the one
      // that was refused.
      if (bits > 0xff || pos > 0) {
        hash[0] = i32[w];
        hash[1] = i32[w + 1];
        hash[2] = i32[w + 2];
        hash[3] = i32[w + 3];
        state.message = message.substr(pos);
      }
      return false;
    }
    pos = end;
  }
  wasmCalls++;
  hash[0] = i32[w];
  hash[1] = i32[w + 1];
  hash[2] = i32[w + 2];
  hash[3] = i32[w + 3];
  state.message = message.substr(total);
  return true;
}

/**
 * Calculates [MD5](https://tools.ietf.org/html/rfc1321) hash. Same API,
 * output and `getState()` JSON as crypto-api 0.8.5; see legacy/hasher/md5.mjs
 * for the original documentation and examples.
 */
class Md5 extends LegacyMd5 {
  /**
   * Process ready blocks
   *
   * @protected
   * @ignore
   */
  process() {
    const state = this.state;
    if (state === null || typeof state !== 'object') return super.process();
    const message = state.message;
    if (typeof message !== 'string') return super.process();
    const n = message.length;
    if (n < BLOCK) return;

    const hash = state.hash;
    if (this.processBlock !== ORIGINAL_BLOCK || !hashOk(hash) || !runtime()) return super.process();

    const total = n - n % BLOCK;
    let done;
    try {
      done = feed(state, message, hash, total);
    } finally {
      // Zero what the call wrote, whatever happened.
      wipe(u8, rt.base, Math.min(total, rt.cap));
    }
    if (!done) return super.process();
  }

  /**
   * Finalize hash and return result
   *
   * @returns {string}
   */
  finalize() {
    const state = this.state;
    if (state === null || typeof state !== 'object') return super.finalize();
    const message = state.message;
    const hash = state.hash;
    const length = state.length;
    if (typeof message !== 'string' || message.length >= BLOCK || !hashOk(hash) ||
      !Number.isSafeInteger(length) ||
      this.process !== Md5.prototype.process || this.processBlock !== ORIGINAL_BLOCK ||
      this.addLengthBits !== ORIGINAL_BITS || this.addPaddingISO7816 !== ORIGINAL_PAD ||
      this.getStateHash !== ORIGINAL_HASH || !runtime()) {
      return super.finalize();
    }

    const base = rt.base;
    const st = base + STATE_OFF;
    const n = message.length;
    const out = base + OUT_OFF;
    let digest = null;
    try {
      // Fill the scratch State. Nothing in `this` is touched until the message is
      // known to be representable.
      let ok = true;
      for (let i = 0, o = st + O_BUF; i < n; i++, o++) {
        const c = message.charCodeAt(i);
        if (c > 0xff) {
          ok = false;
          break;
        }
        u8[o] = c;
      }
      if (ok) {
        const w = st >> 2;
        i32[w] = hash[0];
        i32[w + 1] = hash[1];
        i32[w + 2] = hash[2];
        i32[w + 3] = hash[3];
        u32[(st + O_LENGTH) >> 2] = length >>> 0;
        u32[(st + O_LENGTH + 4) >> 2] = Math.floor(length / 4294967296) >>> 0;
        u32[(st + O_BUFFERED) >> 2] = n;

        // A refused call leaves `this` untouched and the original does the work.
        if (rt.ex.md5_final(st, out) === 0) {
          wasmCalls++;

          // What the original leaves behind: advanced hash words, drained buffer.
          hash[0] = i32[w];
          hash[1] = i32[w + 1];
          hash[2] = i32[w + 2];
          hash[3] = i32[w + 3];
          state.message = '';
          digest = String.fromCharCode.apply(null, u8.subarray(out, out + 16));
        }
      }
    } finally {
      wipe(u8, base, 0);
    }
    return digest === null ? super.finalize() : digest;
  }
}

export default Md5;
