// crypto-api-ng:facade
'use strict';

import LegacyWhirlpool from "../../legacy/hasher/whirlpool.mjs";
import {wasmBytes} from "../../wasm/whirlpool.mjs";
import {createAccelerator, createFamily, roundsIn} from "../wasm/be32.mjs";

/*
 * Whirlpool, Whirlpool-T (`type: 't'`) and Whirlpool-0 (`type: '0'`) with the
 * compression and padding done in wasm, and everything else left to the original
 * JavaScript. Same API, output and `getState()` JSON as crypto-api 0.8.5; see
 * legacy/hasher/whirlpool.mjs for the original documentation and examples. How
 * this works, and the checks that make it safe: src/wasm/be32.mjs.
 *
 * Wasm is used for options.rounds 1 to 10. The three variants are three sets of
 * exports of one module (`whirlpool_*`, `whirlpool0_*`, `whirlpoolt_*`); which one
 * a hasher uses is read from the lookup tables the original picked for it in its
 * constructor (`this.C` and `this.RC`), not from `options.type`, so the odd
 * `type` values the original accepts (`0` as a number, `'T'`, `true`, ...) keep
 * selecting what they selected. Any other option value or state runs the
 * original code. Tables an instance or subclass replaced are not recognized and
 * run the original code too. Like the other facades, the facade does not fill
 * `blockUnits` (an `@private` scratch array).
 */

// 152 = sizeof(whirlpool.State) in src/hash/whirlpool.zig.
const family = createFamily(wasmBytes, {whirlpool: 152, whirlpool0: 152, whirlpoolt: 152});

function accelerator(name) {
  return createAccelerator({
    family,
    name,
    legacy: LegacyWhirlpool,
    words: 16,
    // Byte offsets inside the Zig `whirlpool.State` (src/hash/whirlpool.zig).
    roundsOff: 64,
    lengthOff: 72,
    bufferedOff: 80,
    bufOff: 88,
    // The State (152 bytes) is larger than the 128-byte state slot, so the digest goes
    // to the input region (256), which `whirlpool_final` does not read.
    outOff: 256,
    rounds: (options) => roundsIn(options, 10),
    outBytes: () => 64,
    facade: () => Whirlpool
  });
}

const accelPlain = accelerator('whirlpool');
const accelZero = accelerator('whirlpool0');
const accelT = accelerator('whirlpoolt');

// The module-private tables of the original, found through the instances it builds
// for each `type`, so that identity decides which wasm variant applies.
let tables = null;

function tablesOf(options) {
  const h = new LegacyWhirlpool(options);
  return {C: h.C, RC: h.RC};
}

/** The accelerator for the tables this hasher holds, or null for tables the wasm code does not know. */
function accelFor(hasher) {
  if (tables === null) {
    tables = {plain: tablesOf({}), zero: tablesOf({type: '0'}), t: tablesOf({type: 't'})};
  }
  const C = hasher.C;
  const RC = hasher.RC;
  if (C === tables.plain.C && RC === tables.plain.RC) return accelPlain;
  if (C === tables.zero.C && RC === tables.zero.RC) return accelZero;
  if (C === tables.t.C && RC === tables.t.RC) return accelT;
  return null;
}

/**
 * Calculates Whirlpool hash
 */
class Whirlpool extends LegacyWhirlpool {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Explicit, so `Whirlpool.length === 1` like the original (an implicit one has length 0).
    super(options);
  }

  /**
   * Process ready blocks
   *
   * @protected
   * @ignore
   */
  process() {
    const accel = accelFor(this);
    if (accel === null || !accel.process(this)) super.process();
  }

  /**
   * Finalize hash and return result
   *
   * @returns {string}
   */
  finalize() {
    const accel = accelFor(this);
    const result = accel === null ? null : accel.finalize(this);
    return result === null ? super.finalize() : result;
  }
}

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = {
  /** Number of calls that ran in wasm so far, over the three variants. */
  wasmCalls() {
    return accelPlain.internal.wasmCalls() + accelZero.internal.wasmCalls() + accelT.internal.wasmCalls();
  },
  /** The instantiated wasm runtime, or null. */
  runtime() {
    return family.runtime();
  },
  /** Forget the cached runtime; with `disable`, behave as if WebAssembly failed. */
  reset(disable) {
    family.reset(disable);
  }
};

export default Whirlpool;
