// Synchronous entry point: wasm bytes are embedded in js/generated/wasm-bytes.js
// (run `zig build js` to generate it), so importing this module instantiates
// immediately with no fetch/fs. Keep the wasm small: browsers limit synchronous
// compilation on the main thread.
import { loadSync } from './index.js';
import { wasmBytes } from './generated/wasm-bytes.js';

export const runtime = loadSync(wasmBytes());
export * from './index.js';
