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

export interface Pbkdf2Options {
  /** Number of HMAC iterations, 1 to 4294967295. Required: there is no safe default. */
  iterations: number;
  /** Binary string or bytes (default empty). */
  salt?: BinaryInput;
  /** Size of the derived key in bits, a multiple of 8 (default: the digest size of the hasher). */
  length?: number;
}
export interface HkdfOptions {
  /** Binary string or bytes (default empty, the same as a salt of zero bytes). */
  salt?: BinaryInput;
  /** Context for `finalize()` (default empty). */
  info?: BinaryInput;
  /** Size of the output of `finalize()` in bits, a multiple of 8, up to 255 times the digest size (default: the digest size). */
  length?: number;
}

export interface Blake2bOptions {
  /** Digest size in bits: 8 to 512 in steps of 8 (default 512). */
  length?: number;
  /** Up to 64 bytes. Makes the hash a MAC. */
  key?: BinaryInput;
  /** Up to 16 bytes, zero padded. */
  salt?: BinaryInput;
  /** Up to 16 bytes, zero padded. */
  personalization?: BinaryInput;
}
export interface Blake2sOptions {
  /** Digest size in bits: 8 to 256 in steps of 8 (default 256). */
  length?: number;
  /** Up to 32 bytes. Makes the hash a MAC. */
  key?: BinaryInput;
  /** Up to 8 bytes, zero padded. */
  salt?: BinaryInput;
  /** Up to 8 bytes, zero padded. */
  personalization?: BinaryInput;
}
/** `key` (keyed hash) and `context` (key derivation) exclude each other. */
export type Blake3Options = {
  /** Output size in bits: 8 to 8388608 in steps of 8 (default 256). */
  length?: number;
} & (
  | { key?: undefined; context?: undefined }
  /** Exactly 32 bytes. */
  | { key: BinaryInput; context?: undefined }
  /** The context string of the key derivation. */
  | { context: BinaryInput; key?: undefined }
);
export interface TigerOptions {
  /** Digest size in bits: 8 to 192 in steps of 8 (default 192). 160 is Tiger/160, 128 is Tiger/128. */
  length?: number;
}
export interface StreebogOptions {
  /** Digest size in bits: 256 or 512 (default 512). */
  length?: 256 | 512;
}
export interface XxHashOptions {
  /** The seed: an integer from 0 to 2^32 - 1 for `XxHash32`, from 0 to 2^53 - 1 for `XxHash64` (default 0). */
  seed?: number;
}
export interface Has160Options { rounds?: number }
export interface Md2Options { rounds?: number }
export interface RipemdOptions { length?: 128 | 160 | 256 | 320 }
export interface Sha0Options { rounds?: number }
export interface Sha1Options { rounds?: number }
export interface Sha256Options { rounds?: number; length?: 224 | 256 }
export interface Sha512Options { rounds?: number; length?: number }
export interface Sm3Options { rounds?: number; length?: 256 }
export interface Sha3Options { length?: 224 | 256 | 384 | 512 }
export interface KeccakOptions { length?: 224 | 256 | 384 | 512 }
export interface ShakeOptions {
  /** Security strength in bits: 128 is SHAKE128, 256 is SHAKE256. Default 128. */
  strength?: 128 | 256;
  /** Output length in bits, a multiple of 8 from 8 to 2^30. Default 256 for SHAKE128, 512 for SHAKE256. */
  length?: number;
}
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
  /** BLAKE2 and BLAKE3: the key of a keyed hash. */
  key?: BinaryInput;
  /** BLAKE2: salt. */
  salt?: BinaryInput;
  /** BLAKE2: personalization string. */
  personalization?: BinaryInput;
  /** BLAKE3: context string of the key derivation mode. */
  context?: BinaryInput;
  /** SHAKE security strength: 128 or 256. */
  strength?: 128 | 256;
  /** xxHash seed: 0 to 2^32 - 1 for `xxhash32`, 0 to 2^53 - 1 for `xxhash64`. */
  seed?: number;
}

/** Algorithm names understood by `getHasher()` and `hash()`. */
export type HasherName =
  | 'blake2b' | 'blake2b-512' | 'blake2b-384' | 'blake2b-256' | 'blake2b-160' | 'blake2b-128'
  | 'blake2s' | 'blake2s-256' | 'blake2s-224' | 'blake2s-160' | 'blake2s-128'
  | 'blake3'
  | 'has160' | 'md2' | 'md4' | 'md5'
  | 'ripemd' | 'ripemd128' | 'ripemd160' | 'ripemd256' | 'ripemd320'
  | 'sha0' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha512/224' | 'sha512/256'
  | 'sm3'
  | 'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512'
  | 'keccak224' | 'keccak256' | 'keccak384' | 'keccak512'
  | 'shake128' | 'shake256'
  | 'snefru' | 'snefru128' | 'snefru128/8' | 'snefru128/2' | 'snefru256' | 'snefru256/8' | 'snefru256/4'
  | 'tiger' | 'tiger192' | 'tiger160' | 'tiger128' | 'tiger2'
  | 'streebog' | 'streebog256' | 'streebog512'
  | 'crc32' | 'crc32c' | 'xxhash32' | 'xxhash64'
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
  /** PBKDF2 with HMAC over `hasher`; the password and `options.salt` are UTF-8 encoded if they are strings. Returns the key in hex. */
  pbkdf2(password: BinaryInput, hasher: HasherLike, options: Pbkdf2Options): string;
  /** HKDF with HMAC over `hasher`; `ikm`, `options.salt` and `options.info` are UTF-8 encoded if they are strings. Returns the key in hex. */
  hkdf(ikm: BinaryInput, hasher: HasherLike, options?: HkdfOptions): string;
}
