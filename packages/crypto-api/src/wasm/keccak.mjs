// crypto-api-ng:facade
'use strict';

import {wasmBytes} from "../../wasm/keccak.mjs";
import {instantiate, STATE_OFF, INPUT_OFF} from "./family.mjs";

/*
 * Keccak-f[1600] for the SHA-3, SHAKE and Keccak hashers (src/hasher/sponge.mjs).
 *
 * Both functions work on the sponge state as an array of 50 int32 words (the 25
 * 64-bit lanes, low word first), which is what a hasher keeps in `state.hash`,
 * and on the message as a binary string. They run the permutation in the wasm
 * module when it can be instantiated and in plain JavaScript otherwise (no
 * WebAssembly, a Content-Security-Policy without 'wasm-unsafe-eval', ...); the
 * results are identical. The wasm module is compiled on first use, and a
 * failure is remembered.
 *
 * Wasm scratch layout (src/wasm/keccak.zig): the 208-byte State at +0, which
 * overlaps the usual output slot, the final partial block at the input offset
 * and the output 256 bytes above it.
 */

const WORDS = 50;
const STATE_SIZE = 208;
const RATE_OFF = 200;
const POS_OFF = 204;
const TAIL_OFF = INPUT_OFF;
const OUT_OFF = INPUT_OFF + 256;
const CHUNK = 8192;

let rt = null;
let tried = false;
let i32 = null;
let u32 = null;
let wasmCalls = 0;

function runtime() {
  if (!tried) {
    tried = true;
    rt = instantiate(wasmBytes, {keccak: STATE_SIZE});
    if (rt) {
      i32 = new Int32Array(rt.u8.buffer);
      u32 = new Uint32Array(rt.u8.buffer);
    }
  }
  return rt;
}

// ---------------------------------------------------------------------------
// Keccak-f[1600] in JavaScript (the fallback)
// ---------------------------------------------------------------------------

const RC_LO = new Int32Array(24);
const RC_HI = new Int32Array(24);
// Rotation offsets (rho) and destination lanes (pi), indexed x + 5 * y.
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const PI = new Array(25);

(function init() {
  // Round constants: bit 2^j - 1 of RC[r] is the LFSR output rc(j + 7 r) (FIPS 202, algorithm 5).
  function lfsr(t) {
    let r = 1;
    for (let i = 0; i < t % 255; i++) {
      r <<= 1;
      if (r & 0x100) r ^= 0x171;
    }
    return r & 1;
  }
  for (let ir = 0; ir < 24; ir++) {
    for (let j = 0; j < 7; j++) {
      if (lfsr(j + 7 * ir)) {
        const bit = (1 << j) - 1;
        if (bit < 32) RC_LO[ir] |= 1 << bit;
        else RC_HI[ir] |= 1 << (bit - 32);
      }
    }
  }
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);
  }
})();

const C = new Int32Array(10);
const B = new Int32Array(50);

/** Keccak-f[1600] on `s`, an Int32Array of 50 words. */
function permute(s) {
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x++) {
      const lo = C[2 * ((x + 1) % 5)];
      const hi = C[2 * ((x + 1) % 5) + 1];
      const dLo = C[2 * ((x + 4) % 5)] ^ (lo << 1 | hi >>> 31);
      const dHi = C[2 * ((x + 4) % 5) + 1] ^ (hi << 1 | lo >>> 31);
      for (let y = 0; y < 5; y++) {
        s[2 * (x + 5 * y)] ^= dLo;
        s[2 * (x + 5 * y) + 1] ^= dHi;
      }
    }
    for (let i = 0; i < 25; i++) {
      const n = ROT[i];
      const lo = s[2 * i];
      const hi = s[2 * i + 1];
      let rl;
      let rh;
      if (n === 0) {
        rl = lo;
        rh = hi;
      } else if (n < 32) {
        rl = lo << n | hi >>> (32 - n);
        rh = hi << n | lo >>> (32 - n);
      } else if (n === 32) {
        rl = hi;
        rh = lo;
      } else {
        rl = hi << (n - 32) | lo >>> (64 - n);
        rh = lo << (n - 32) | hi >>> (64 - n);
      }
      B[2 * PI[i]] = rl;
      B[2 * PI[i] + 1] = rh;
    }
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const i = 2 * (x + 5 * y);
        const j = 2 * ((x + 1) % 5 + 5 * y);
        const k = 2 * ((x + 2) % 5 + 5 * y);
        s[i] = B[i] ^ (~B[j] & B[k]);
        s[i + 1] = B[i + 1] ^ (~B[j + 1] & B[k + 1]);
      }
    }
    s[0] ^= RC_LO[round];
    s[1] ^= RC_HI[round];
  }
}

/** XOR `count` characters of `message` from `pos` into the sponge bytes starting at byte 0. */
function xorBytes(s, message, pos, count) {
  for (let i = 0; i < count; i++) {
    s[i >> 2] ^= (message.charCodeAt(pos + i) & 0xff) << ((i & 3) * 8);
  }
}

function jsAbsorb(hash, message, total, rate) {
  const s = new Int32Array(WORDS);
  for (let k = 0; k < WORDS; k++) s[k] = hash[k];
  for (let pos = 0; pos < total; pos += rate) {
    xorBytes(s, message, pos, rate);
    permute(s);
  }
  for (let k = 0; k < WORDS; k++) hash[k] = s[k];
}

function jsFinish(hash, tail, rate, suffix, outBytes) {
  const s = new Int32Array(WORDS);
  for (let k = 0; k < WORDS; k++) s[k] = hash[k];
  xorBytes(s, tail, 0, tail.length);
  s[tail.length >> 2] ^= suffix << ((tail.length & 3) * 8);
  s[(rate - 1) >> 2] ^= 0x80 << (((rate - 1) & 3) * 8);
  permute(s);
  let out = '';
  let pos = 0;
  const codes = new Array(Math.min(outBytes, CHUNK));
  for (let done = 0; done < outBytes;) {
    const n = Math.min(CHUNK, outBytes - done);
    codes.length = n;
    for (let i = 0; i < n; i++) {
      if (pos === rate) {
        permute(s);
        pos = 0;
      }
      codes[i] = (s[pos >> 2] >>> ((pos & 3) * 8)) & 0xff;
      pos++;
    }
    out += String.fromCharCode.apply(null, codes);
    done += n;
  }
  return out;
}

// ---------------------------------------------------------------------------
// wasm
// ---------------------------------------------------------------------------

function loadState(hash, rate) {
  const w = (rt.base + STATE_OFF) >> 2;
  for (let k = 0; k < WORDS; k++) i32[w + k] = hash[k];
  u32[(rt.base + STATE_OFF + RATE_OFF) >> 2] = rate;
  u32[(rt.base + STATE_OFF + POS_OFF) >> 2] = 0;
}

function wasmAbsorb(hash, message, total, rate) {
  const {u8, ex, base, cap} = rt;
  const st = base + STATE_OFF;
  const input = base + INPUT_OFF;
  loadState(hash, rate);
  const chunk = cap - cap % rate;
  for (let pos = 0; pos < total;) {
    const end = Math.min(pos + chunk, total);
    for (let i = pos, o = input; i < end; i++, o++) u8[o] = message.charCodeAt(i);
    ex.keccak_blocks(st, input, end - pos);
    pos = end;
  }
  wasmCalls++;
  const w = st >> 2;
  for (let k = 0; k < WORDS; k++) hash[k] = i32[w + k];
}

function wasmFinish(hash, tail, rate, suffix, outBytes) {
  const {u8, ex, base, cap} = rt;
  const st = base + STATE_OFF;
  const tailPtr = base + TAIL_OFF;
  const out = base + OUT_OFF;
  const outCap = cap - 256;
  loadState(hash, rate);
  for (let i = 0; i < tail.length; i++) u8[tailPtr + i] = tail.charCodeAt(i);
  let result = '';
  for (let done = 0; done < outBytes || done === 0;) {
    const n = Math.min(outCap, outBytes - done);
    if (done === 0) ex.keccak_final(st, tailPtr, tail.length, suffix, out, n);
    else ex.keccak_squeeze(st, out, n);
    for (let i = 0; i < n; i += CHUNK) {
      result += String.fromCharCode.apply(null, u8.subarray(out + i, out + Math.min(n, i + CHUNK)));
    }
    done += n;
    if (n === 0) break;
  }
  wasmCalls++;
  return result;
}

// ---------------------------------------------------------------------------
// public (package-internal) functions
// ---------------------------------------------------------------------------

/**
 * Absorb the first `total` characters of `message` (a multiple of `rate`)
 * into `hash`, in place.
 *
 * @param {number[]} hash - 50 int32 words, the sponge state
 * @param {string} message - binary string
 * @param {number} total
 * @param {number} rate - block size in bytes
 */
export function absorb(hash, message, total, rate) {
  if (runtime()) wasmAbsorb(hash, message, total, rate);
  else jsAbsorb(hash, message, total, rate);
}

/**
 * Pad `tail` (shorter than `rate`), permute and squeeze. Does not change `hash`.
 *
 * @param {number[]} hash - 50 int32 words, the sponge state
 * @param {string} tail - binary string, shorter than `rate`
 * @param {number} rate - block size in bytes
 * @param {number} suffix - domain suffix byte (0x06 SHA-3, 0x1f SHAKE, 0x01 Keccak)
 * @param {number} outBytes - digest length in bytes
 * @returns {string} binary string
 */
export function finish(hash, tail, rate, suffix, outBytes) {
  return runtime() ?
    wasmFinish(hash, tail, rate, suffix, outBytes) :
    jsFinish(hash, tail, rate, suffix, outBytes);
}

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = {
  /** Number of absorb/finish calls that ran in wasm so far. */
  wasmCalls() {
    return wasmCalls;
  },
  runtime() {
    return runtime();
  },
  /** Forget the instance; with `disable`, behave as if WebAssembly failed. */
  reset(disable) {
    tried = !!disable;
    rt = null;
  },
  /** The permutation in JavaScript, for tests. */
  permute
};
