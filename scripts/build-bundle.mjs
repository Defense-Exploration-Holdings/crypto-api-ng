#!/usr/bin/env node
// Builds the UMD bundles of packages/crypto-api from its ES modules:
//
//   crypto-api.js            unminified, ES5 syntax
//   crypto-api.min.js(.map)  minified, ES5 syntax; the CDN / <script> build, defines the global `CryptoApi`
//   crypto-api.min.mjs(.map) minified ES module (ES2020) for <script type="module"> and CDNs: the
//                            CryptoApi object as the default export, the classes and encoders as named exports
//   crypto-api.min.d.mts     its declarations
//
// `index.js` (the CommonJS `main`) is a tiny hand-written file that requires crypto-api.js.
// The bundle contains the facades, the original JS engines and every embedded wasm module,
// so `zig build js --release=small` must have run first (it writes packages/crypto-api/wasm/).
//
// Pipeline: esbuild (bundle, no minify) -> UMD wrapper -> Babel preset-env targeting IE 11 (ES5
// syntax, no polyfills) -> Terser (ecma 5). The result exports exactly what the original's
// global build did: the CryptoApi singleton (the default export of src/crypto-api.mjs).
//
//   node scripts/build-bundle.mjs
import { build } from 'esbuild';
import { transformAsync } from '@babel/core';
import presetEnv from '@babel/preset-env';
import { minify } from 'terser';
import { readFileSync, writeFileSync, renameSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkgRoot = join(repoRoot, 'packages', 'crypto-api');

const BANNER = '/*! Port of crypto-api 0.8.5 (https://github.com/nf404/crypto-api), Copyright (c) 2015 nf404, MIT */';

/**
 * Replace a generated file in one step. The packaging test files run in parallel and each one
 * rebuilds the bundles, so a reader must never see a truncated or half-written file.
 */
export function writeFileAtomic(file, text) {
  // The temporary file stays at the package root: example/ is copied whole when staging.
  const tmp = join(pkgRoot, `.${basename(file)}.${process.pid}.tmp`);
  writeFileSync(tmp, text);
  renameSync(tmp, file);
}

/**
 * Named exports of the ES module bundle, next to the default export (the CryptoApi object).
 * [export name, module under packages/crypto-api, export of that module].
 */
export const ESM_EXPORTS = [
  ...[
    ['Blake2b', 'blake2b'], ['Blake2s', 'blake2s'], ['Blake3', 'blake3'], ['Crc32', 'crc32'], ['Crc32c', 'crc32c'],
    ['Has160', 'has160'], ['Keccak', 'keccak'], ['Md2', 'md2'], ['Md4', 'md4'], ['Md5', 'md5'], ['Ripemd', 'ripemd'],
    ['Sha0', 'sha0'], ['Sha1', 'sha1'], ['Sha256', 'sha256'], ['Sha3', 'sha3'], ['Sha512', 'sha512'], ['Shake', 'shake'],
    ['Sm3', 'sm3'], ['Snefru', 'snefru'], ['Streebog', 'streebog'], ['Tiger', 'tiger'], ['Tiger2', 'tiger2'],
    ['Whirlpool', 'whirlpool'], ['XxHash32', 'xxhash32'], ['XxHash64', 'xxhash64'],
  ].map(([name, file]) => [name, `src/hasher/${file}.mjs`, 'default']),
  ['Hmac', 'src/mac/hmac.mjs', 'default'],
  ['Pbkdf2', 'src/kdf/pbkdf2.mjs', 'default'],
  ['Hkdf', 'src/kdf/hkdf.mjs', 'default'],
  ['fromUtf', 'src/encoder/utf.mjs', 'fromUtf'],
  ['fromArrayBuffer', 'src/encoder/array-buffer.mjs', 'fromArrayBuffer'],
  ['toHex', 'src/encoder/hex.mjs', 'toHex'],
  ['toBase64', 'src/encoder/base64.mjs', 'toBase64'],
  ...['utf8ToBytes', 'bytesToUtf8', 'bytesToHex', 'hexToBytes', 'bytesToBase64', 'base64ToBytes']
    .map((name) => [name, 'src/encoder/bytes.mjs', name]),
];

/** Re-exports of ESM_EXPORTS from `./<module>`, in the given order: the entry of the bundle and its declarations. */
function esmReexports() {
  const lines = [`export { default } from './src/crypto-api.mjs';`];
  for (const [name, file, from] of ESM_EXPORTS) {
    lines.push(`export { ${from === name ? name : `${from} as ${name}`} } from './${file}';`);
  }
  return lines.join('\n') + '\n';
}

const ESM_DTS_HEADER = `/**
 * The ES module build (\`crypto-api.min.mjs\`): one file with every algorithm and its WebAssembly module,
 * for \`<script type="module">\` and CDNs. The default export is the \`CryptoApi\` object; the hasher
 * classes, \`Hmac\`, \`Pbkdf2\`, \`Hkdf\` and the encoders are named exports. They are the same classes
 * \`CryptoApi.getHasher()\` creates, so \`instanceof\` agrees between the two.
 *
 * @module
 */
`;

/** The ES module bundle and its source map. Sources in the map are files shipped next to it. */
async function buildEsm() {
  const out = await build({
    stdin: { contents: esmReexports(), resolveDir: pkgRoot, sourcefile: 'crypto-api.min.mjs' },
    bundle: true,
    format: 'esm',
    target: 'es2020',
    minify: true,
    keepNames: true,
    legalComments: 'none',
    banner: { js: BANNER },
    sourcemap: 'external',
    sourcesContent: false,
    outfile: join(pkgRoot, 'crypto-api.min.mjs'),
    write: false,
    logLevel: 'warning',
  });
  const files = {};
  for (const f of out.outputFiles) files[basename(f.path)] = f.text;
  // esbuild lists the stdin entry as a source; it has no file, and holds only re-exports.
  const map = JSON.parse(files['crypto-api.min.mjs.map']);
  if (!map.sources.every((s) => s === 'crypto-api.min.mjs' || existsSync(join(pkgRoot, s)))) {
    throw new Error(`crypto-api.min.mjs.map lists a source that is not in the package: ${map.sources.join(', ')}`);
  }
  return {
    'crypto-api.min.mjs': /sourceMappingURL=/.test(files['crypto-api.min.mjs'])
      ? files['crypto-api.min.mjs']
      : files['crypto-api.min.mjs'].replace(/\n?$/, '\n//# sourceMappingURL=crypto-api.min.mjs.map\n'),
    'crypto-api.min.mjs.map': files['crypto-api.min.mjs.map'],
    'crypto-api.min.d.mts': ESM_DTS_HEADER + '\n' + esmReexports(),
  };
}

export async function buildBundle({ write = true } = {}) {
  const wasmDir = join(pkgRoot, 'wasm');
  if (!existsSync(wasmDir) || readdirSync(wasmDir).length === 0) {
    throw new Error('packages/crypto-api/wasm is empty. Run: zig build js --release=small');
  }

  const bundled = await build({
    stdin: {
      contents: `export { default } from './src/crypto-api.mjs';`,
      resolveDir: pkgRoot,
      sourcefile: 'entry.mjs',
    },
    bundle: true,
    format: 'iife',
    globalName: '__cryptoApiModule',
    target: 'es2020',
    write: false,
    legalComments: 'none',
    keepNames: true, // class names survive esbuild's renaming of the facade and legacy classes that share a name
    logLevel: 'warning',
  });
  const iife = bundled.outputFiles[0].text;

  const umd = `${BANNER}
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else if (typeof define === 'function' && define.amd) define([], factory);
  else root.CryptoApi = factory();
})(typeof self !== 'undefined' ? self : typeof globalThis !== 'undefined' ? globalThis : this, function () {
${iife}
return __cryptoApiModule.default;
});
`;

  const es5 = await transformAsync(umd, {
    babelrc: false,
    configFile: false,
    sourceType: 'script',
    compact: false,
    comments: true,
    presets: [[presetEnv, { targets: { ie: '11' }, modules: false }]],
  });

  const min = await minify({ 'crypto-api.js': es5.code }, {
    ecma: 5,
    compress: { ecma: 5, keep_fnames: true },
    mangle: { keep_fnames: true },
    keep_fnames: true,
    format: { comments: /^!/, ecma: 5 },
    sourceMap: { filename: 'crypto-api.min.js', url: 'crypto-api.min.js.map' },
  });

  const files = {
    'crypto-api.js': es5.code,
    'crypto-api.min.js': min.code,
    'crypto-api.min.js.map': typeof min.map === 'string' ? min.map : JSON.stringify(min.map),
    ...(await buildEsm()),
  };
  if (write) for (const [name, text] of Object.entries(files)) writeFileAtomic(join(pkgRoot, name), text);
  return files;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = await buildBundle();
  for (const [name, text] of Object.entries(files)) console.log(`${name}: ${(text.length / 1024).toFixed(1)} KiB`);
}
