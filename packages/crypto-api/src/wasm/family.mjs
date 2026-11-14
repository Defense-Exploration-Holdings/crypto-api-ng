// crypto-api-ng:facade
'use strict';

/**
 * Synchronous instantiation of one family wasm module (see docs/abi.md).
 *
 * Returns `null` instead of throwing when WebAssembly is unavailable or the
 * module cannot be compiled (CSP without 'wasm-unsafe-eval', Cloudflare
 * Workers, IE11, ...). Callers then use the legacy JS engine. The result is
 * meant to be cached by the caller, so a failure is paid for once.
 *
 * Must stay equal to `runtime.abi_version` in src/runtime.zig (a test checks).
 */
export const ABI_VERSION = 1;

/** Scratch layout, identical for every family (src/wasm/common.zig). */
export const STATE_OFF = 0;
export const OUT_OFF = 128;
export const INPUT_OFF = 256;

/**
 * @param {() => Uint8Array} getBytes - returns the embedded wasm bytes
 * @param {Object<string, number>} stateSizes - expected `<algo>_state_size()` values
 * @returns {null | {ex: Object, u8: Uint8Array, base: number, cap: number}}
 *   `u8` views all of linear memory (it never grows), `base` is the scratch
 *   address, `cap` the input chunk capacity in bytes.
 */
export function instantiate(getBytes, stateSizes) {
  try {
    const instance = new WebAssembly.Instance(new WebAssembly.Module(getBytes()), {});
    const ex = instance.exports;
    if (ex.abi_version() !== ABI_VERSION) return null;
    for (const name in stateSizes) {
      if (ex[name + '_state_size']() !== stateSizes[name]) return null;
    }
    return {
      ex,
      u8: new Uint8Array(ex.memory.buffer),
      base: ex.scratch_ptr(),
      cap: ex.scratch_len() - INPUT_OFF
    };
  } catch (e) {
    return null;
  }
}
