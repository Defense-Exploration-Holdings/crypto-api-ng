// Catalog of everything the original crypto-api exposes, as data the tests loop over.
//
// FAMILY   one hasher class (file under src/hasher/), with a grid of option cells.
// VARIANT  one named configuration with its own test vectors (24 in the original suite).
// GET_HASHER_NAMES   every name `CryptoApi.getHasher()` accepts.
//
// Option cells were probed against the original (see docs/test-harness.md). Values
// that make the original loop forever are deliberately absent (see HANGS below).

/** Hasher classes, in the order of the algorithm list in the README. */
export const FAMILIES = [
  { id: 'has160',    file: 'has160',    className: 'Has160',    blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'md2',       file: 'md2',       className: 'Md2',       blockBytes: 16,  lengthFieldBytes: 0 },
  { id: 'md4',       file: 'md4',       className: 'Md4',       blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'md5',       file: 'md5',       className: 'Md5',       blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'ripemd',    file: 'ripemd',    className: 'Ripemd',    blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'sha0',      file: 'sha0',      className: 'Sha0',      blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'sha1',      file: 'sha1',      className: 'Sha1',      blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'sha256',    file: 'sha256',    className: 'Sha256',    blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'sha512',    file: 'sha512',    className: 'Sha512',    blockBytes: 128, lengthFieldBytes: 16 },
  { id: 'sm3',       file: 'sm3',       className: 'Sm3',       blockBytes: 64,  lengthFieldBytes: 8 },
  { id: 'snefru',    file: 'snefru',    className: 'Snefru',    blockBytes: 48,  lengthFieldBytes: 0 },
  { id: 'whirlpool', file: 'whirlpool', className: 'Whirlpool', blockBytes: 64,  lengthFieldBytes: 32 },
];

export const BASE_CLASSES = [
  { file: 'hasher',     className: 'Hasher' },
  { file: 'hasher8',    className: 'Hasher8' },
  { file: 'hasher32be', className: 'Hasher32be' },
  { file: 'hasher32le', className: 'Hasher32le' },
];

/** The 24 variants with vectors in the original suite. `openssl` names a node:crypto digest when one exists. */
export const VARIANTS = [
  { id: 'has160',      family: 'has160',    options: {} },
  { id: 'md2',         family: 'md2',       options: {} },
  { id: 'md4',         family: 'md4',       options: {} },
  { id: 'md5',         family: 'md5',       options: {},                       openssl: 'md5' },
  { id: 'ripemd128',   family: 'ripemd',    options: { length: 128 } },
  { id: 'ripemd160',   family: 'ripemd',    options: { length: 160 },          openssl: 'ripemd160' },
  { id: 'ripemd256',   family: 'ripemd',    options: { length: 256 } },
  { id: 'ripemd320',   family: 'ripemd',    options: { length: 320 } },
  { id: 'sha0',        family: 'sha0',      options: {} },
  { id: 'sha1',        family: 'sha1',      options: {},                       openssl: 'sha1' },
  { id: 'sha224',      family: 'sha256',    options: { length: 224 },          openssl: 'sha224' },
  { id: 'sha256',      family: 'sha256',    options: { length: 256 },          openssl: 'sha256' },
  { id: 'sha384',      family: 'sha512',    options: { length: 384 },          openssl: 'sha384' },
  { id: 'sha512',      family: 'sha512',    options: { length: 512 },          openssl: 'sha512' },
  { id: 'sha512-224',  family: 'sha512',    options: { length: 224 },          openssl: 'sha512-224' },
  { id: 'sha512-256',  family: 'sha512',    options: { length: 256 },          openssl: 'sha512-256' },
  { id: 'sm3',         family: 'sm3',       options: {},                       openssl: 'sm3' },
  { id: 'snefru128-2', family: 'snefru',    options: { length: 128, rounds: 2 } },
  { id: 'snefru128-8', family: 'snefru',    options: { length: 128, rounds: 8 } },
  { id: 'snefru256-4', family: 'snefru',    options: { length: 256, rounds: 4 } },
  { id: 'snefru256-8', family: 'snefru',    options: { length: 256, rounds: 8 } },
  { id: 'whirlpool',   family: 'whirlpool', options: {} },
  { id: 'whirlpool-0', family: 'whirlpool', options: { type: '0' } },
  { id: 'whirlpool-t', family: 'whirlpool', options: { type: 't' } },
];

/** The 7 HMAC vector files in the original suite: file id -> hasher variant. */
export const HMAC_VARIANTS = ['has160', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

/** Every name accepted by CryptoApi.getHasher() in 0.8.5 (which lacks `sm3`). */
export const GET_HASHER_NAMES = [
  'has160', 'md2', 'md4', 'md5',
  'ripemd', 'ripemd128', 'ripemd160', 'ripemd256', 'ripemd320',
  'sha0', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256',
  'snefru', 'snefru128', 'snefru128/8', 'snefru256', 'snefru256/8', 'snefru128/2', 'snefru256/4',
  'whirlpool', 'whirlpool-0', 'whirlpool-t',
];

/** Names 1.1 adds to getHasher(), with the class they return. */
export const ADDED_HASHER_NAMES = [{ name: 'sm3', family: 'sm3', variant: 'sm3' }];

/** Names that look valid but return undefined from getHasher() (in 0.8.5 and 1.1, except `sm3`). */
export const UNKNOWN_HASHER_NAMES = ['sm3', 'SHA256', 'MD5', 'sha-256', 'nope', '', 'sha3-256', 'blake2b'];

// ---------------------------------------------------------------------------
// 1.1 option rules
// ---------------------------------------------------------------------------

const range = (min, max, step = 1) => {
  const out = [];
  for (let v = min; v <= max; v += step) out.push(v);
  return out;
};

/**
 * The `rounds`/`length` values 1.1 accepts, per family. Anything else given for
 * these keys (other numbers, strings, booleans, null, NaN) throws at
 * construction; an absent key or `undefined` means the default.
 * `rounds` may reduce the standard round count, never extend it (MD2, whose
 * rounds use no constants, allows up to 255); `length` is the set the original
 * documents.
 */
export const OPTION_RULES = {
  has160: { rounds: range(1, 80) },
  md2: { rounds: range(1, 255) },
  md4: {},
  md5: {},
  ripemd: { length: [128, 160, 256, 320] },
  sha0: { rounds: range(1, 80) },
  sha1: { rounds: range(1, 80) },
  sha256: { length: [224, 256], rounds: range(1, 64) },
  sha512: { length: range(32, 512, 32), rounds: range(1, 160) },
  sm3: { length: [256], rounds: range(1, 64) },
  snefru: { length: range(32, 448, 32), rounds: range(1, 8) },
  whirlpool: { rounds: range(1, 10) },
};

/** True when 1.1 accepts `options` for the family (see OPTION_RULES). */
export function optionSupported(familyId, options) {
  if (options === undefined || options === null || typeof options !== 'object') return true;
  const rules = OPTION_RULES[familyId];
  for (const key of Object.keys(rules)) {
    const v = options[key];
    if (v !== undefined && !rules[key].includes(v)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Option cells
// ---------------------------------------------------------------------------

/** Values handed to `rounds`/`length` that are not integers in range. The original coerces them silently. */
const ODD = [0, -1, 1.5, '7', true, null, NaN];

const grid = (key, values, base = {}) => values.map((v) => ({ ...base, [key]: v }));

/**
 * Option cells per family. Each cell is a plain object; tests clone it per
 * construction because the original mutates the options it is given.
 * `undefined` in the list means "pass no key at all".
 */
export const OPTION_CELLS = {
  has160: [
    {}, ...grid('rounds', [1, 2, 20, 40, 79, 80, 81, 100, 160, 255]), ...grid('rounds', ODD),
  ],
  md2: [
    {}, ...grid('rounds', [1, 2, 17, 18, 19, 50, 255, 256, 300]), ...grid('rounds', ODD),
  ],
  md4: [{}],
  md5: [{}],
  ripemd: [
    {}, ...grid('length', [128, 160, 256, 320]),
    ...grid('length', [0, 100, 224, 512, 64, '160', true, -1, 1.5, NaN]),
  ],
  sha0: [{}, ...grid('rounds', [1, 2, 40, 79, 80, 81, 100, 160]), ...grid('rounds', ODD)],
  sha1: [{}, ...grid('rounds', [1, 2, 40, 79, 80, 81, 100, 160]), ...grid('rounds', ODD)],
  sha256: [
    {}, ...grid('length', [224, 256]), ...grid('rounds', [1, 2, 32, 63, 64, 65, 80, 128]),
    ...grid('length', [160, 128, 384, 512, 32, 300, 0, '224', true, -1]),
    ...grid('rounds', [1, 33, 64], { length: 224 }), ...grid('rounds', ODD),
  ],
  sha512: [
    {}, ...grid('length', [384, 512, 224, 256]),
    ...grid('rounds', [1, 2, 3, 80, 159, 160, 161, 162, 200, 320]),
    ...grid('length', [160, 128, 1024, 8, 100, '256', true, -1, 0]),
    ...grid('rounds', [1, 3, 160], { length: 384 }), ...grid('rounds', [80, 160], { length: 256 }),
    ...grid('rounds', ODD),
  ],
  sm3: [
    {}, ...grid('rounds', [1, 2, 32, 63, 64, 65, 80, 128]),
    ...grid('length', [256, 224, 128, 512, 0, 32, '256']), ...grid('rounds', ODD),
  ],
  snefru: [
    {}, ...grid('length', [128, 256]), ...grid('rounds', [1, 2, 3, 4, 5, 8, 9, 10]),
    ...grid('length', [160, 96, 64, 32, 448, 480, 0, '128', '256', true, -1, 1.5]),
    ...grid('rounds', [2, 4, 8], { length: 256 }), ...grid('rounds', [2, 4], { length: 128 }),
    ...grid('rounds', ODD),
  ],
  whirlpool: [
    {}, ...grid('type', ['', '0', 't']), ...grid('type', [0, 'T', 'x', true, 1, null, false, 't ']),
    ...grid('rounds', [1, 2, 5, 9, 10, 11, 12]), ...grid('rounds', ODD),
    ...grid('rounds', [5, 10], { type: '0' }), ...grid('rounds', [5, 10], { type: 't' }),
  ],
};

/**
 * Configurations where the ORIGINAL never returns. They are not fuzzed against the
 * oracle (it would hang the test run). v1 throws RangeError for these instead.
 */
export const HANGS = [
  { family: 'snefru', options: { length: 512 }, note: 'block size 0, update() loops forever' },
  { family: 'snefru', options: { length: 544 }, note: 'negative block size, update() loops forever' },
  { family: 'snefru', options: { length: 1024 }, note: 'negative block size, update() loops forever' },
];

export function cellLabel(familyId, cell) {
  const body = Object.entries(cell)
    .map(([k, v]) => `${k}:${typeof v === 'string' ? JSON.stringify(v) : Object.is(v, -0) ? '-0' : String(v)}`)
    .join(',');
  return `${familyId}{${body}}`;
}

// ---------------------------------------------------------------------------
// Message length helpers
// ---------------------------------------------------------------------------

/** Lengths where padding and block boundaries fall, for a block size and length-field size. */
export function boundaryLengths(blockBytes, lengthFieldBytes) {
  const out = new Set([0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49]);
  const edge = (n) => { for (const d of [-1, 0, 1]) if (n + d >= 0) out.add(n + d); };
  for (let k = 1; k <= 3; k++) {
    edge(k * blockBytes);
    edge(k * blockBytes - lengthFieldBytes);          // padding forces an extra block here
    edge(k * blockBytes - lengthFieldBytes - 1);
  }
  for (const n of [55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 255, 256, 257]) out.add(n);
  return [...out].filter((n) => n >= 0).sort((a, b) => a - b);
}
