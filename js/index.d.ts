export const EXPECTED_ABI_VERSION: number;

export class Runtime {
  readonly exports: WebAssembly.Exports & Record<string, any>;
  readonly memory: WebAssembly.Memory;
  readonly version: string;
  view(ptr: number, len: number): Uint8Array;
  alloc(len: number): number;
  free(ptr: number, len: number): void;
  write(bytes: Uint8Array): { ptr: number; len: number };
  read(ptr: number, len: number): Uint8Array;
  withBytes<T>(bytes: Uint8Array, fn: (ptr: number, len: number) => T): T;
}

export function load(
  source?: ArrayBuffer | ArrayBufferView | Response | URL | string,
): Promise<Runtime>;

export function loadSync(bytes: ArrayBuffer | ArrayBufferView): Runtime;
