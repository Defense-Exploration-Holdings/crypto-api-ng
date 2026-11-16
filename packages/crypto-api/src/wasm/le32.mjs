// crypto-api-ng:facade
'use strict';

import {instantiate, wipe, STATE_OFF, OUT_OFF, INPUT_OFF} from "./family.mjs";

/*
 * What the facades of every `Hasher32le` algorithm that is not MD5 (MD4,
 * HAS-160, RIPEMD-128/160/256/320) share: the scratch-region plumbing around
 * the wasm `<algo>_blocks` and `<algo>_final` exports. The per-algorithm file
 * (src/hasher/<algo>.mjs) extends the verbatim 0.8.5 class and decides *when*
 * the wasm path may be taken (class and option guards); this file does the
 * copying and writes the results back exactly the way the original does.
 *
 * The Zig side is src/hash/le32.zig. `State` layout, with `n` hash words:
 *
 *     hash: n x u32     at 0
 *     length: u64       at align8(4n)
 *     buffered: u32     at length + 8
 *     param: u32        at length + 12   (HAS-160: rounds)
 *     buf: 64 bytes     at length + 16
 */

export const BLOCK = 64;

/**
 * Largest hash-word magnitude handed to wasm. The original computes
 * `(word + x) | 0` with `x` an int32. For integers up to 2^52 the sum is exact
 * in a double, so `| 0` equals the int32 addition wasm performs; beyond that
 * the double sum rounds and the two can differ, so those states go to the
 * original code.
 */
const LIMIT = 2 ** 52;

/** True when `hash` has exactly `n` integer words that wasm can add exactly like the original. */
export function wordsOk(hash, n) {
  if (!Array.isArray(hash) || hash.length !== n) return false;
  for (let i = 0; i < n; i++) {
    const w = hash[i];
    if (!Number.isInteger(w) || w > LIMIT || w < -LIMIT) return false;
  }
  return true;
}

/**
 * One family wasm module, instantiated on first use. A failure (no
 * WebAssembly, CSP, Workers, ...) is remembered so it is not retried, and
 * every call then delegates to the original.
 */
export class Engine {
  /**
   * @param {() => Uint8Array} getBytes
   */
  constructor(getBytes) {
    this.getBytes = getBytes;
    this.variants = [];
    this.tried = false;
    this.rt = null;
    this.i32 = null;
    this.u32 = null;
    this.calls = 0;
  }

  /**
   * Declare an algorithm of this module: its export prefix and hash word count.
   * @param {string} prefix
   * @param {number} words
   * @returns {Variant}
   */
  variant(prefix, words) {
    const v = new Variant(this, prefix, words);
    this.variants.push(v);
    return v;
  }

  runtime() {
    if (!this.tried) {
      this.tried = true;
      const sizes = {};
      for (const v of this.variants) sizes[v.prefix] = v.size;
      this.rt = instantiate(this.getBytes, sizes);
      if (this.rt) {
        const buf = this.rt.u8.buffer;
        this.i32 = new Int32Array(buf);
        this.u32 = new Uint32Array(buf);
        for (const v of this.variants) {
          v.blocks = this.rt.ex[v.prefix + '_blocks'];
          v.final = this.rt.ex[v.prefix + '_final'];
        }
      }
    }
    return this.rt;
  }

  /** Test hook: forget the runtime; with `disable`, behave as if WebAssembly failed. */
  reset(disable) {
    this.tried = !!disable;
    this.rt = null;
    for (const v of this.variants) {
      v.blocks = null;
      v.final = null;
    }
  }

  /** The `_internal` object each facade exports for its tests. Not public API. */
  hooks() {
    return {
      /** Number of calls that ran in wasm so far. */
      wasmCalls: () => this.calls,
      /** The instantiated wasm runtime, or null. */
      runtime: () => this.runtime(),
      /** Forget the cached runtime; with `disable`, behave as if WebAssembly failed. */
      reset: (disable) => this.reset(disable)
    };
  }
}

/** One algorithm inside an Engine's module: export names and State offsets. */
export class Variant {
  constructor(engine, prefix, words) {
    this.engine = engine;
    this.prefix = prefix;
    this.words = words;
    this.lengthOff = (4 * words + 7) & ~7;
    this.bufferedOff = this.lengthOff + 8;
    this.paramOff = this.lengthOff + 12;
    this.bufOff = this.lengthOff + 16;
    this.size = this.bufOff + BLOCK;
    this.blocks = null;
    this.final = null;
  }
}

/** Copy the hash words out of the scratch State into the state object, the way the original leaves them. */
function store(state, hash, i32, w, n, replace) {
  if (replace) {
    // MD4: the original assigns a fresh array after every block.
    const out = [];
    for (let k = 0; k < n; k++) out.push(i32[w + k]);
    state.hash = out;
  } else {
    // Everything else writes the words into the existing array.
    for (let k = 0; k < n; k++) hash[k] = i32[w + k];
  }
}

/**
 * wasm version of `Hasher32le.process()` for a state object whose class and
 * options the caller has already checked. Returns `true` when all whole blocks
 * were consumed; `false` means the caller must run `super.process()`, with
 * `state` left in a consistent state (the blocks done so far are applied).
 *
 * @param {Variant} v
 * @param {*} state - `this.state`; must be an object whose `message` is a string of at least one block
 * @param {number} param - written to `State.param` (HAS-160 `rounds`)
 * @param {boolean} replace - assign a new `state.hash` array instead of writing in place
 * @returns {boolean}
 */
export function accelProcess(v, state, param, replace) {
  const message = state.message;
  const hash = state.hash;
  const n = v.words;
  if (!wordsOk(hash, n)) return false;
  const eng = v.engine;
  const rt = eng.runtime();
  if (!rt) return false;

  const u8 = rt.u8;
  const i32 = eng.i32;
  const base = rt.base;
  const st = base + STATE_OFF;
  const input = base + INPUT_OFF;
  const w = st >> 2;
  const total = message.length - message.length % BLOCK;
  // Bytes of the input region this call wrote; wiped on every way out.
  let used = 0;
  let done = true;
  try {
    for (let k = 0; k < n; k++) i32[w + k] = hash[k];
    eng.u32[(st + v.paramOff) >> 2] = param;

    for (let pos = 0; pos < total;) {
      const end = Math.min(pos + rt.cap, total);
      if (end - pos > used) used = end - pos;
      let bits = 0;
      for (let i = pos, o = input; i < end; i++, o++) {
        const c = message.charCodeAt(i);
        bits |= c;
        u8[o] = c;
      }
      // A refused call (non-zero status) leaves the scratch State as it was.
      if (bits > 0xff || v.blocks(st, input, end - pos) !== 0) {
        // A code unit the wasm code cannot represent, or a call it refused: apply
        // what has been consumed so far (always whole blocks) and let the original
        // do the rest. Nothing is touched if the very first chunk is the one that
        // failed.
        if (pos > 0) {
          store(state, hash, i32, w, n, replace);
          state.message = message.substr(pos);
        }
        done = false;
        break;
      }
      pos = end;
    }
    if (done) {
      eng.calls++;
      store(state, hash, i32, w, n, replace);
      state.message = message.substr(total);
    }
  } finally {
    wipe(u8, base, used);
  }
  return done;
}

/**
 * wasm version of the whole `finalize()` (padding, length field, last block(s)
 * and `getStateHash()`), or `null` when the state is not exactly what wasm
 * models. Nothing is modified before it is known that the call can be made.
 * The caller has already checked the class guards.
 *
 * @param {Variant} v
 * @param {*} state - `this.state`, an object
 * @param {number} param
 * @param {boolean} replace
 * @returns {string|null}
 */
export function accelFinalize(v, state, param, replace) {
  const message = state.message;
  const hash = state.hash;
  const length = state.length;
  const n = v.words;
  if (typeof message !== 'string' || message.length >= BLOCK || !wordsOk(hash, n) ||
    !Number.isSafeInteger(length)) {
    return null;
  }
  const eng = v.engine;
  const rt = eng.runtime();
  if (!rt) return null;

  const u8 = rt.u8;
  const i32 = eng.i32;
  const u32 = eng.u32;
  const base = rt.base;
  const st = base + STATE_OFF;
  const m = message.length;
  const out = base + OUT_OFF;
  let digest = null;
  try {
    let ok = true;
    for (let i = 0, o = st + v.bufOff; i < m; i++, o++) {
      const c = message.charCodeAt(i);
      if (c > 0xff) {
        ok = false;
        break;
      }
      u8[o] = c;
    }
    if (ok) {
      const w = st >> 2;
      for (let k = 0; k < n; k++) i32[w + k] = hash[k];
      u32[(st + v.lengthOff) >> 2] = length >>> 0;
      u32[(st + v.lengthOff + 4) >> 2] = Math.floor(length / 4294967296) >>> 0;
      u32[(st + v.bufferedOff) >> 2] = m;
      u32[(st + v.paramOff) >> 2] = param;

      // A refused call leaves `state` untouched and the original does the work.
      if (v.final(st, out) === 0) {
        eng.calls++;

        // What the original leaves behind: advanced hash words, drained buffer.
        store(state, hash, i32, w, n, replace);
        state.message = '';
        digest = String.fromCharCode.apply(null, u8.subarray(out, out + 4 * n));
      }
    }
  } finally {
    wipe(u8, base, 0);
  }
  return digest;
}
