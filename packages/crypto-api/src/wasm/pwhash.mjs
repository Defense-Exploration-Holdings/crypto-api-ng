// crypto-api-ng:facade
'use strict';

import {ABI_VERSION} from "./family.mjs";

/*
 * Runs the password-hashing families (`argon2`, `scrypt`; src/wasm/argon2.zig,
 * src/wasm/scrypt.zig). Unlike the hash families these need megabytes to gigabytes
 * of work memory, which the module takes from `memory.grow`. Linear memory cannot
 * shrink, so the module is compiled once and every derivation gets a fresh
 * instance that is dropped afterwards: the memory goes with it instead of staying
 * at its largest size for the life of the program.
 *
 * Before an instance is dropped, the work memory has been zeroed by the module
 * itself and the inputs and output written here are zeroed by `run`.
 */

/**
 * @param {() => Uint8Array} getBytes - the embedded wasm module
 * @returns {{run: Function, hooks: Function}}
 */
export default function createRunner(getBytes) {
  let tried = false;
  let module = null;
  let calls = 0;
  let instances = 0;
  // Tests can keep the last instance's memory to scan it for leftovers.
  let keep = false;
  let last = null;

  function compiled() {
    if (!tried) {
      tried = true;
      try {
        const m = new WebAssembly.Module(getBytes());
        const probe = new WebAssembly.Instance(m, {});
        if (probe.exports.abi_version() === ABI_VERSION) {
          module = m;
        }
      } catch (e) {
        module = null;
      }
    }
    return module;
  }

  return {
    /**
     * Call `job(ex, put, take)` in a fresh instance. `put(bytes)` copies a
     * `Uint8Array` in and returns its address (0 for no bytes), `take(len)`
     * reserves `len` bytes for the output and returns `{ptr, read}`, where
     * `read()` copies them out. Every byte `put` and `take` handed out is zeroed
     * before `run` returns.
     *
     * @param {Function} job - returns the module's status and the result
     * @returns {null|*} null when WebAssembly is not available here, the
     *   instance cannot be created, or the module refused the call; else what
     *   `job` returned as `result`
     */
    run(job) {
      const m = compiled();
      if (m === null) {
        return null;
      }
      let ex;
      try {
        ex = new WebAssembly.Instance(m, {}).exports;
      } catch (e) {
        // Typically no address space left for another memory.
        return null;
      }
      instances++;
      const written = [];
      const view = () => new Uint8Array(ex.memory.buffer);
      const put = (bytes) => {
        if (bytes.length === 0) {
          return 0;
        }
        const ptr = ex.alloc(bytes.length);
        if (ptr === 0) {
          throw new RangeError('wasm: cannot allocate ' + bytes.length + ' bytes');
        }
        written.push(ptr, bytes.length);
        view().set(bytes, ptr);
        return ptr;
      };
      const take = (len) => {
        const ptr = ex.alloc(len);
        if (ptr === 0) {
          throw new RangeError('wasm: cannot allocate ' + len + ' bytes');
        }
        written.push(ptr, len);
        return {ptr: ptr, read: () => view().slice(ptr, ptr + len)};
      };
      try {
        const answer = job(ex, put, take);
        if (answer.status !== 0) {
          return null;
        }
        calls++;
        return answer.result;
      } catch (e) {
        if (e instanceof RangeError) {
          return null;
        }
        throw e;
      } finally {
        // The memory may have grown during the call: take a new view.
        const u8 = view();
        for (let i = 0; i < written.length; i += 2) {
          u8.fill(0, written[i], written[i] + written[i + 1]);
        }
        last = keep ? ex.memory : null;
      }
    },

    /** Test-only hooks; not public API. */
    hooks() {
      return {
        /** Derivations that ran in wasm so far. */
        wasmCalls: () => calls,
        /** Instances created so far (one per derivation that tried wasm). */
        instances: () => instances,
        /** With `on`, keep the memory of the last instance for `lastMemory()`. */
        keepMemory: (on) => {
          keep = !!on;
          last = null;
        },
        /** The `WebAssembly.Memory` of the last instance while `keepMemory(true)` is on, or null. */
        lastMemory: () => last,
        /** The compiled module, or null. */
        module: () => compiled(),
        /** Forget the compiled module; with `disable`, behave as if WebAssembly failed. */
        reset: (disable) => {
          tried = !!disable;
          module = null;
        }
      };
    }
  };
}
