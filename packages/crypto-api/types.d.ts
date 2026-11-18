/**
 * Anything `update()` accepts: a binary string (every character in \x00-\xFF; convert
 * text with `fromUtf()`), or bytes.
 */
export type BinaryInput = string | ArrayBuffer | SharedArrayBuffer | ArrayBufferView;

/** Text encodings of `digest()`. `'binary'` is the binary string `finalize()` returns. */
export type DigestEncoding = 'hex' | 'base64' | 'base64url' | 'binary';

/** Anything that holds bytes: `ArrayBuffer`, `SharedArrayBuffer` or a view such as `Uint8Array`. */
export type Bytes = ArrayBuffer | SharedArrayBuffer | ArrayBufferView;

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
  /** Like `finalize()`, but returns the MAC as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the MAC as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
}

export interface Pbkdf2Options {
  /** Number of HMAC iterations, 1 to 4294967295. Required: there is no safe default. */
  iterations: number;
  /** Binary string or bytes (default empty). */
  salt?: BinaryInput;
  /** Size of the derived key in bits, a multiple of 8 (default: the digest size of the hasher). */
  length?: number;
}
export interface Argon2Options {
  /** 8 bytes or more; RFC 9106 recommends 16 random bytes. Required. */
  salt: BinaryInput;
  /** Passes over the memory, 1 to 4294967295. Required: there is no safe default. */
  iterations: number;
  /** Memory size in KiB, from 8 times `parallelism` to 4294967295. Required. */
  memory: number;
  /** Lanes, 1 to 16777215 (default 1). */
  parallelism?: number;
  /** Argon2 variant (default `'argon2id'`). */
  type?: "argon2id" | "argon2i" | "argon2d";
  /** Tag size in bits, a multiple of 8 from 32 (default 256). */
  length?: number;
  /** Key K, binary string or bytes (default empty). */
  secret?: BinaryInput;
  /** Associated data X, binary string or bytes (default empty). */
  associatedData?: BinaryInput;
}
export interface ScryptOptions {
  /** N: a power of two from 2, below 2^(16 * blockSize). Required. Memory use is about 128 * N * blockSize bytes. */
  cost: number;
  /** r, from 1 (default 8). */
  blockSize?: number;
  /** p, from 1 (default 1); `blockSize * parallelization` must be below 2^30. */
  parallelization?: number;
  /** Binary string or bytes (default empty). */
  salt?: BinaryInput;
  /** Size of the derived key in bits, a multiple of 8 (default 256). */
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
  /** The seed: an integer from 0 to 2^32 - 1 for `XxHash32`, from 0 to 2^53 - 1 for `XxHash64`, `XxHash3` and `XxHash128` (default 0). */
  seed?: number;
}
export interface SipHashOptions {
  /** Exactly 16 bytes. Required; should be random and secret. */
  key: BinaryInput;
}
export interface Murmur3Options {
  /** The seed: an integer from 0 to 2^32 - 1 (default 0). */
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
  /** BLAKE2 and BLAKE3: the key of a keyed hash. SipHash: the 16-byte key (required). */
  key?: BinaryInput;
  /** BLAKE2: salt. */
  salt?: BinaryInput;
  /** BLAKE2: personalization string. */
  personalization?: BinaryInput;
  /** BLAKE3: context string of the key derivation mode. */
  context?: BinaryInput;
  /** SHAKE security strength: 128 or 256. */
  strength?: 128 | 256;
  /** xxHash and MurmurHash3 seed: 0 to 2^32 - 1 for `xxhash32` and `murmur3*`, 0 to 2^53 - 1 for `xxhash64`, `xxhash3` and `xxhash128`. */
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
  | 'crc32' | 'crc32c' | 'xxhash32' | 'xxhash64' | 'xxhash3' | 'xxhash128'
  | 'siphash' | 'siphash-2-4' | 'siphash-1-3'
  | 'murmur3' | 'murmur3-x86-32' | 'murmur3-x64-128'
  | 'whirlpool' | 'whirlpool-0' | 'whirlpool-t';

export interface Base64Options {
  /** `'base64'` (`+` and `/`, the default) or `'base64url'` (`-` and `_`). */
  alphabet?: 'base64' | 'base64url';
}

export interface CryptoApiEncoder {
  /** JavaScript string to a binary string of its UTF-8 bytes. */
  fromUtf(message: string): string;
  /** `ArrayBuffer` to a binary string. */
  fromArrayBuffer(buffer: ArrayBuffer): string;
  /** Binary string to lowercase hex. */
  toHex(raw: string): string;
  /** Binary string to base64. */
  toBase64(raw: string): string;
  /** Text to the bytes of its UTF-8 encoding. An unpaired surrogate becomes U+FFFD. */
  utf8ToBytes(text: string): Uint8Array;
  /** UTF-8 bytes to text; invalid bytes become U+FFFD, or throw with `fatal`. */
  bytesToUtf8(bytes: Bytes, options?: { fatal?: boolean }): string;
  /** Bytes to lowercase hex. */
  bytesToHex(bytes: Bytes): string;
  /** Hex to bytes. Throws `SyntaxError` for an odd length or a character that is not a hex digit. */
  hexToBytes(hex: string): Uint8Array;
  /** Bytes to base64, padded unless `omitPadding` is set. */
  bytesToBase64(bytes: Bytes, options?: Base64Options & { omitPadding?: boolean }): string;
  /** Base64 to bytes. Padding is optional. Throws `SyntaxError` for malformed input. */
  base64ToBytes(text: string, options?: Base64Options): Uint8Array;
}

export interface CryptoApi {
  readonly encoder: CryptoApiEncoder;
  /** A new hasher for a known name; `undefined` for any other name. */
  getHasher(name: HasherName, options?: HasherOptions): HasherLike;
  getHasher(name: string, options?: HasherOptions): HasherLike | undefined;
  /** Hash a message and return the digest in hex. A string message is UTF-8 encoded. */
  hash(name: HasherName | (string & {}), message: BinaryInput, options?: HasherOptions): string;
  /** Like `hash()`, but returns the digest as bytes. */
  hashBytes(name: HasherName | (string & {}), message: BinaryInput, options?: HasherOptions): Uint8Array;
  /** HMAC over a hasher; `key` is a binary string or bytes. */
  getHmac(key: BinaryInput, hasher: HasherLike): HmacLike;
  /** HMAC with a UTF-8 key and message (strings are UTF-8 encoded), digest in hex. */
  hmac(key: BinaryInput, message: BinaryInput, hasher: HasherLike): string;
  /** Like `hmac()`, but returns the MAC as bytes. */
  hmacBytes(key: BinaryInput, message: BinaryInput, hasher: HasherLike): Uint8Array;
  /** PBKDF2 with HMAC over `hasher`; the password and `options.salt` are UTF-8 encoded if they are strings. Returns the key in hex. */
  pbkdf2(password: BinaryInput, hasher: HasherLike, options: Pbkdf2Options): string;
  /** HKDF with HMAC over `hasher`; `ikm`, `options.salt` and `options.info` are UTF-8 encoded if they are strings. Returns the key in hex. */
  hkdf(ikm: BinaryInput, hasher: HasherLike, options?: HkdfOptions): string;
  /** Like `pbkdf2()`, but returns the key as bytes. */
  pbkdf2Bytes(password: BinaryInput, hasher: HasherLike, options: Pbkdf2Options): Uint8Array;
  /** Like `hkdf()`, but returns the key as bytes. */
  hkdfBytes(ikm: BinaryInput, hasher: HasherLike, options?: HkdfOptions): Uint8Array;
  /** Argon2 (Argon2id by default); the password and the `salt`, `secret` and `associatedData` options are UTF-8 encoded if they are strings. Returns the tag in hex. */
  argon2(password: BinaryInput, options: Argon2Options): string;
  /** Like `argon2()`, but returns the tag as bytes. */
  argon2Bytes(password: BinaryInput, options: Argon2Options): Uint8Array;
  /** scrypt; the password and `options.salt` are UTF-8 encoded if they are strings. Returns the key in hex. */
  scrypt(password: BinaryInput, options: ScryptOptions): string;
  /** Like `scrypt()`, but returns the key as bytes. */
  scryptBytes(password: BinaryInput, options: ScryptOptions): Uint8Array;
}
