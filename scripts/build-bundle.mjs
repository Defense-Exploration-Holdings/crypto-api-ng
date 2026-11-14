#!/usr/bin/env node
// Builds the UMD bundles of packages/crypto-api from its ES modules:
//
//   crypto-api.js            unminified, ES5 syntax
//   crypto-api.min.js(.map)  minified, ES5 syntax; the CDN / <script> build, defines the global `CryptoApi`
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
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkgRoot = join(repoRoot, 'packages', 'crypto-api');

const BANNER = '/*! Port of crypto-api 0.8.5 (https://github.com/nf404/crypto-api), Copyright (c) 2015 nf404, MIT */';

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
  };
  if (write) for (const [name, text] of Object.entries(files)) writeFileSync(join(pkgRoot, name), text);
  return files;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = await buildBundle();
  for (const [name, text] of Object.entries(files)) console.log(`${name}: ${(text.length / 1024).toFixed(1)} KiB`);
}
