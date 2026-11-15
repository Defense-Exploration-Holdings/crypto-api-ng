// crypto-api-ng:facade
'use strict';

import LegacyMd2 from "../../legacy/hasher/md2.mjs";
import {wasmBytes} from "../../wasm/md2.mjs";
import {instantiate, STATE_OFF, OUT_OFF, INPUT_OFF} from "../wasm/family.mjs";
import {prepareOptions} from "../tools/input.mjs";

/*
 * MD2 with the compression and padding done in wasm, and everything else left
 * to the original JavaScript. Same API, output and `getState()` JSON as
 * crypto-api 0.8.5; see legacy/hasher/md2.mjs for the original documentation
 * and examples. The recipe is the one of the MD5 template (src/hasher/md5.mjs); what is specific to MD2 is that it is a `Hasher8`
 * (16-byte blocks, no length field) and that its state is two arrays,
 * `state.hash` (48 numbers) and `state.checksum` (16 numbers).
 *
 * Wasm is used for options.rounds 1 to 2^32-1. The two arrays go to wasm when
 * every entry is an integer 0..255, or `undefined`/`null` (a pristine state
 * holds `new Array(48)` and `new Array(16)`, which JSON turns into nulls, and
 * the original reads those as 0). After any block that ran in wasm every entry
 * is a number again, as in the original. Any other value, option or state runs
 * the original code. `blockUnits` (an `@private` scratch array) is not filled.
 */

/** Byte offsets inside the Zig `md2.State` (src/hash/md2.zig), relative to STATE_OFF. */
const O_HASH = 0;
const O_CHECKSUM = 48;
const O_ROUNDS = 64;
const O_BUFFERED = 68;
const O_BUF = 72;
const SIZE = 88;
const BLOCK = 16;
const MAX_ROUNDS = 0xffffffff;

/** The internals the wasm code replaces. An override of any of them must be honored. */
const P = LegacyMd2.prototype;
const ORIGINAL_BLOCK = P.processBlock;
const ORIGINAL_PAD = P.addPaddingPKCS7;
const ORIGINAL_HASH = P.getStateHash;

// The wasm module is compiled on first use, not at import. A failure (no
// WebAssembly, CSP, Workers, ...) is remembered so it is not retried, and every
// call then delegates to the original.
let rt;
let rtTried = false;
let u8;
let u32;
let wasmCalls = 0;

function runtime() {
  if (!rtTried) {
    rtTried = true;
    rt = instantiate(wasmBytes, {md2: SIZE});
    if (rt) {
      u8 = rt.u8;
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

/** `options.rounds` if it is an integer in 1..2^32-1, else 0. */
function roundsOf(options) {
  if (options === null || typeof options !== 'object') return 0;
  const r = options.rounds;
  return Number.isInteger(r) && r >= 1 && r <= MAX_ROUNDS ? r : 0;
}

/**
 * Copy `n` state numbers to wasm memory at `o`. False, with the memory left
 * half written (it is scratch), when an entry is not a byte the original
 * would treat like wasm does.
 */
function load(array, n, o) {
  if (!Array.isArray(array) || array.length !== n) return false;
  for (let i = 0; i < n; i++) {
    const x = array[i];
    if (x === undefined || x === null) {
      u8[o + i] = 0;
    } else if (Number.isInteger(x) && x >= 0 && x <= 255) {
      u8[o + i] = x;
    } else {
      return false;
    }
  }
  return true;
}

/** Write `n` bytes from wasm memory back into the state array, in place. */
function store(array, n, o) {
  for (let i = 0; i < n; i++) array[i] = u8[o + i];
}

/** Supported `rounds`/`length` values (1.1 rejects the rest). */
const OPTIONS = {rounds: {min: 1, max: 255}};

/**
 * What the original constructor assigns when an option is missing, in its order
 * (see `explicitOptions` in tools/input.mjs).
 */
const DEFAULTS = {rounds: 18};

/**
 * Calculates [MD2](https://tools.ietf.org/html/rfc1319) hash
 */
class Md2 extends LegacyMd2 {
  /**
   * @param {Object} [options]
   * @param {number} [options.rounds=18] - Number of rounds (Must be greater than 0)
   */
  constructor(options) {
    // Explicit, so `Md2.length === 1` like the original (an implicit one has length 0).
    super(prepareOptions('Md2', options, OPTIONS, DEFAULTS));
  }

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
    if (this.blockSizeInBytes !== BLOCK) return super.process();
    const n = message.length;
    if (n < BLOCK) return;

    const rounds = roundsOf(this.options);
    if (this.processBlock !== ORIGINAL_BLOCK || !rounds || !runtime()) return super.process();

    const st = rt.base + STATE_OFF;
    if (!load(state.hash, 48, st + O_HASH) || !load(state.checksum, 16, st + O_CHECKSUM)) return super.process();
    u32[(st + O_ROUNDS) >> 2] = rounds;

    const input = rt.base + INPUT_OFF;
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
        if (pos > 0) {
          store(state.hash, 48, st + O_HASH);
          store(state.checksum, 16, st + O_CHECKSUM);
        }
        state.message = message.substr(pos);
        return super.process();
      }
      rt.ex.md2_blocks(st, input, end - pos);
      pos = end;
    }
    wasmCalls++;
    store(state.hash, 48, st + O_HASH);
    store(state.checksum, 16, st + O_CHECKSUM);
    state.message = message.substr(total);
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
    if (typeof message !== 'string' || message.length >= BLOCK || this.blockSizeInBytes !== BLOCK) {
      return super.finalize();
    }
    const rounds = roundsOf(this.options);
    if (!rounds || this.process !== Md2.prototype.process || this.processBlock !== ORIGINAL_BLOCK ||
      this.addPaddingPKCS7 !== ORIGINAL_PAD || this.getStateHash !== ORIGINAL_HASH || !runtime()) {
      return super.finalize();
    }

    const st = rt.base + STATE_OFF;
    const n = message.length;
    // Fill the scratch State. Nothing in `this` is touched until everything is
    // known to be representable.
    for (let i = 0, o = st + O_BUF; i < n; i++, o++) {
      const c = message.charCodeAt(i);
      if (c > 0xff) return super.finalize();
      u8[o] = c;
    }
    if (!load(state.hash, 48, st + O_HASH) || !load(state.checksum, 16, st + O_CHECKSUM)) return super.finalize();
    u32[(st + O_ROUNDS) >> 2] = rounds;
    u32[(st + O_BUFFERED) >> 2] = n;

    const out = rt.base + OUT_OFF;
    rt.ex.md2_final(st, out);
    wasmCalls++;

    // What the original leaves behind: advanced hash and checksum, drained buffer.
    store(state.hash, 48, st + O_HASH);
    store(state.checksum, 16, st + O_CHECKSUM);
    state.message = '';
    return String.fromCharCode.apply(null, u8.subarray(out, out + 16));
  }
}

export default Md2;
