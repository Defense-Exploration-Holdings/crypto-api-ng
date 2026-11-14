// Minimal loader for crypto-api.wasm.
//
// Responsibilities (and nothing more): fetch + instantiate the module, check
// the ABI version, and provide safe helpers for moving bytes in and out of
// linear memory. Per-algorithm JS wrappers are built on top of this.
//
// Works in Node >= 22 and evergreen browsers. No dependencies.

/** Must match `runtime.abi_version` in src/runtime.zig. */
export const EXPECTED_ABI_VERSION = 1;

const DEFAULT_WASM_URL = new URL('../zig-out/wasm/crypto-api.wasm', import.meta.url);

async function readSource(source) {
  if (source === undefined) source = DEFAULT_WASM_URL;

  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) return source;
  if (typeof Response !== 'undefined' && source instanceof Response) {
    return source.arrayBuffer();
  }

  const url = source instanceof URL ? source : new URL(source, import.meta.url);
  if (url.protocol === 'file:') {
    const { readFile } = await import('node:fs/promises');
    return readFile(url);
  }
  const res = await fetch(url);
  if (!res.ok) throw new Error(`crypto-api: failed to fetch ${url}: ${res.status}`);
  return res.arrayBuffer();
}

export class Runtime {
  /** @param {WebAssembly.Instance} instance */
  constructor(instance) {
    this.exports = instance.exports;
    this.memory = instance.exports.memory;

    const abi = this.exports.abi_version();
    if (abi !== EXPECTED_ABI_VERSION) {
      throw new Error(
        `crypto-api: wasm ABI version ${abi} does not match loader ABI version ${EXPECTED_ABI_VERSION}`,
      );
    }
  }

  /** Library version string reported by the wasm module. */
  get version() {
    const ptr = this.exports.version_ptr();
    const len = this.exports.version_len();
    return new TextDecoder().decode(this.view(ptr, len));
  }

  /**
   * Live view into linear memory. Do not hold it across any call that may
   * allocate: memory growth detaches the old ArrayBuffer.
   */
  view(ptr, len) {
    return new Uint8Array(this.memory.buffer, ptr, len);
  }

  /** Allocate `len` bytes in wasm memory. Throws on failure. */
  alloc(len) {
    const ptr = this.exports.alloc(len);
    if (ptr === 0 && len !== 0) throw new Error(`crypto-api: out of memory allocating ${len} bytes`);
    return ptr;
  }

  free(ptr, len) {
    this.exports.free(ptr, len);
  }

  /** Copy `bytes` into freshly allocated wasm memory. Caller must `free`. */
  write(bytes) {
    const ptr = this.alloc(bytes.length);
    if (bytes.length) this.view(ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  }

  /** Copy `len` bytes out of wasm memory into a fresh Uint8Array. */
  read(ptr, len) {
    return this.view(ptr, len).slice();
  }

  /**
   * Run `fn(ptr, len)` with `bytes` copied into wasm memory; always frees.
   * @template T
   * @param {Uint8Array} bytes
   * @param {(ptr: number, len: number) => T} fn
   * @returns {T}
   */
  withBytes(bytes, fn) {
    const { ptr, len } = this.write(bytes);
    try {
      return fn(ptr, len);
    } finally {
      this.free(ptr, len);
    }
  }
}

/**
 * Synchronously instantiate the wasm module from bytes already in memory.
 * Needed for APIs that must stay synchronous (the original crypto-api is).
 * Browsers cap synchronous compilation on the main thread, so keep the module small.
 * @param {ArrayBuffer | ArrayBufferView} bytes
 * @returns {Runtime}
 */
export function loadSync(bytes) {
  const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
  return new Runtime(instance);
}

/**
 * Instantiate the wasm module.
 * @param {ArrayBuffer | ArrayBufferView | Response | URL | string} [source]
 *   Defaults to the wasm built by `zig build wasm`.
 * @returns {Promise<Runtime>}
 */
export async function load(source) {
  const bytes = await readSource(source);
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return new Runtime(instance);
}
