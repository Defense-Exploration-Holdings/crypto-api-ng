// crypto-api-ng:facade
'use strict';

import {binaryOf} from "../wasm/family.mjs";

/*
 * The bytes path of `update()`.
 *
 * In crypto-api 0.8.5, `update()` appends its argument to the binary string
 * `state.message` and calls `process()`, which compresses the whole blocks and
 * keeps the rest. Turning a large Uint8Array into a string and then copying the
 * string into wasm memory one code unit at a time costs more than the hashing.
 *
 * A facade whose `process()` runs in wasm registers a handler for that exact
 * `process` function here. `Hasher#update()` looks the handler up by
 * `this.process`, so a subclass or instance that replaces `process()` never
 * takes this path. The handler either does the complete update, leaving
 * `this.state` exactly as `update(<the bytes as a binary string>)` would, and
 * returns true, or returns false without changing anything, and `update()`
 * goes on as before.
 */

const handlers = new Map();

/**
 * @param {Function} process - the facade's own `process` method
 * @param {(self: Object, bytes: Uint8Array) => boolean} handler
 */
export function registerBytes(process, handler) {
  handlers.set(process, handler);
}

/**
 * The bytes handler for `self`, or undefined.
 *
 * @param {Object} self
 * @returns {Function|undefined}
 */
export function bytesHandler(self) {
  const process = self.process;
  return typeof process === 'function' ? handlers.get(process) : undefined;
}

/**
 * The handler for a hasher whose `process()` compresses every whole block of
 * `state.message` (all the hashers ported from 0.8.5, and the sponge).
 *
 * The pending part of a block is completed from `bytes` and run through
 * `self.process()` as a string. The whole blocks after it go to `run()` as a
 * Uint8Array, and what is left becomes `state.message`.
 *
 * @param {number|function(Object): number} block - block size in bytes, or a function that
 *   returns it for a hasher (0 or less: not this path)
 * @param {(self: Object) => *} plan - checks that `run()` may be used for `self` now, without
 *   changing anything; returns what `run()` needs, or null
 * @param {(self: Object, plan: *, bytes: Uint8Array) => void} run - with `state.message`
 *   empty, does what `process()` does after `state.message = <bytes as a string>`
 * @returns {(self: Object, bytes: Uint8Array) => boolean}
 */
export function drainingHandler(blockSize, plan, run) {
  return function (self, bytes) {
    const block = typeof blockSize === 'function' ? blockSize(self) : blockSize;
    if (!(block > 0)) return false;
    const state = self.state;
    if (state === null || typeof state !== 'object') return false;
    const message = state.message;
    if (typeof message !== 'string') return false;
    const pending = message.length;
    if (pending + bytes.length < 2 * block || plan(self) === null) return false;
    const head = (block - pending % block) % block;
    state.message = message + binaryOf(bytes, 0, head);
    state.length += bytes.length;
    if (state.message.length > 0) self.process();
    const ctx = state.message === '' ? plan(self) : null;
    if (ctx === null) {
      state.message += binaryOf(bytes, head);
      self.process();
    } else {
      run(self, ctx, head === 0 ? bytes : bytes.subarray(head));
    }
    return true;
  };
}

/**
 * The handler for a hasher whose `process()` compresses every block of
 * `state.message` but the last one, which `finalize()` needs (BLAKE2, BLAKE3 and
 * the block hashers of src/blocks/): after `process()` the message is 1 to
 * `block` bytes long, or empty. With `keep` above 1, at least `keep` bytes and
 * the block they start in are kept back instead.
 *
 * @param {(self: Object) => number} blockSize - block size in bytes
 * @param {(self: Object) => number} keepSize - bytes always kept back (1: the last block)
 * @param {(self: Object, take: number) => *} plan - checks, without changing anything, that
 *   compressing `take` more bytes cannot throw and that `compress()` takes bytes; returns what
 *   `compress()` needs, or null
 * @param {(self: Object, plan: *, message: string|Uint8Array, start: number, end: number) => void} compress -
 *   compresses the whole blocks `message[start, end)` into `self.state`
 * @returns {(self: Object, bytes: Uint8Array) => boolean}
 */
export function keepingHandler(blockSize, keepSize, plan, compress) {
  return function (self, bytes) {
    const state = self.state;
    if (state === null || typeof state !== 'object') return false;
    const message = state.message;
    if (typeof message !== 'string') return false;
    const block = blockSize(self);
    const keep = keepSize(self);
    const pending = message.length;
    const total = pending + bytes.length;
    if (!(block > 0) || !(keep >= 1) || total - keep < 2 * block) return false;
    // What process() would compress: everything but what it keeps back.
    const take = Math.floor((total - keep) / block) * block;
    const head = (block - pending % block) % block;
    if (pending + head > take) return false;
    const ctx = plan(self, take);
    if (ctx === null) return false;
    state.length += bytes.length;
    if (pending + head > 0) compress(self, ctx, message + binaryOf(bytes, 0, head), 0, pending + head);
    compress(self, ctx, bytes, head, take - pending);
    state.message = binaryOf(bytes, take - pending);
    return true;
  };
}
