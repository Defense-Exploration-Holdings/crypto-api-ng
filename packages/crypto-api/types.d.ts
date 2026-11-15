/**
 * Anything `update()` accepts: a binary string (every character in \x00-\xFF; convert
 * text with `fromUtf()`), or bytes.
 */
export type BinaryInput = string | ArrayBuffer | SharedArrayBuffer | ArrayBufferView;

/** What HMAC and `CryptoApi` need from a hasher. Every hasher class implements it. */
export interface HasherLike {
  /** Options the hasher was created with. */
  options: Record<string, any>;
  /** Size of a block in bytes. */
  readonly blockSizeInBytes: number;
  /** Back to the initial state, keeping the options. */
  reset(): void;
  /** Adds a binary string or bytes to the message. */
  update(message: BinaryInput): void;
  /** Finishes the message and returns the digest as a binary string. */
  finalize(): string;
  /** A JSON-serializable snapshot of the hasher. */
  getState(): Record<string, any>;
  /** Restores a snapshot made by `getState()` of a hasher with the same class and options. */
  setState(state: Record<string, any>): void;
}

export interface HmacLike {
  update(message: BinaryInput): void;
  /** Returns the MAC as a binary string. Can be called again; `update()` continues the message. */
  finalize(): string;
  /** Restart with the same key. */
  reset(): void;
}

export interface Has160Options { rounds?: number }
export interface Md2Options { rounds?: number }
export interface RipemdOptions { length?: 128 | 160 | 256 | 320 }
export interface Sha0Options { rounds?: number }
export interface Sha1Options { rounds?: number }
export interface Sha256Options { rounds?: number; length?: 224 | 256 }
export interface Sha512Options { rounds?: number; length?: number }
export interface Sm3Options { rounds?: number; length?: 256 }
export interface SnefruOptions { rounds?: number; length?: number }
export interface WhirlpoolOptions { rounds?: number; type?: '0' | 't' | (string & {}) }

/**
 * Options accepted by `getHasher()` and `hash()`. Which ones apply (and which values are valid)
 * depends on the algorithm; see the API reference.
 */
export interface HasherOptions {
  rounds?: number;
  length?: number;
  /** Whirlpool variant: `'0'` or `'t'`. */
  type?: '0' | 't' | (string & {});
}

/** Algorithm names understood by `getHasher()` and `hash()`. */
export type HasherName =
  | 'has160' | 'md2' | 'md4' | 'md5'
  | 'ripemd' | 'ripemd128' | 'ripemd160' | 'ripemd256' | 'ripemd320'
  | 'sha0' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha512/224' | 'sha512/256'
  | 'sm3'
  | 'snefru' | 'snefru128' | 'snefru128/8' | 'snefru128/2' | 'snefru256' | 'snefru256/8' | 'snefru256/4'
  | 'whirlpool' | 'whirlpool-0' | 'whirlpool-t';

export interface CryptoApiEncoder {
  /** JavaScript string to a binary string of its UTF-8 bytes. */
  fromUtf(message: string): string;
  /** `ArrayBuffer` to a binary string. */
  fromArrayBuffer(buffer: ArrayBuffer): string;
  /** Binary string to lowercase hex. */
  toHex(raw: string): string;
  /** Binary string to base64. */
  toBase64(raw: string): string;
}

export interface CryptoApi {
  readonly encoder: CryptoApiEncoder;
  /** A new hasher for a known name; `undefined` for any other name. */
  getHasher(name: HasherName, options?: HasherOptions): HasherLike;
  getHasher(name: string, options?: HasherOptions): HasherLike | undefined;
  /** Hash a message and return the digest in hex. A string message is UTF-8 encoded. */
  hash(name: HasherName | (string & {}), message: BinaryInput, options?: HasherOptions): string;
  /** HMAC over a hasher; `key` is a binary string or bytes. */
  getHmac(key: BinaryInput, hasher: HasherLike): HmacLike;
  /** HMAC with a UTF-8 key and message (strings are UTF-8 encoded), digest in hex. */
  hmac(key: BinaryInput, message: BinaryInput, hasher: HasherLike): string;
}
