# Changelog

## 1.0.0 (unreleased)

Maintained Zig/WebAssembly port of `crypto-api` 0.8.5. Drop-in replacement: same API, same import paths, same results and `getState()` JSON. See "Differences from crypto-api 0.8.5" in the README for the complete list of deliberate differences.

* `main` works: `require()` returns the `CryptoApi` object (`index.js`)
* `src/index.mjs` default-exports the `CryptoApi` object
* Global build `crypto-api.min.js` (and `crypto-api.js`) in ES5 syntax with WebAssembly embedded and automatic fallback to the original JavaScript
* All `src/**/*.mjs` imports carry explicit `.mjs` extensions, so native Node ESM loads them
* Snefru throws `RangeError` instead of looping forever when `length` is 512 or more
* Hashers run compression in WebAssembly where ported (see the repository README for the list)

## History of crypto-api (nf404)

* 0.8.5
  - This version for deployment to npm
* 0.8.4
  - Add toBase64
  - Add fromArrayBuffer
  - Add support of SHA512/t hash
  - Optimize hash padding
  - Add SM3 hash
* 0.8.3
  - Fix Whirlpool bug
  - Add compiled es5 version for nodejs
* 0.8.2
  - technical version (fix npm key)
* 0.8.1
  - Add support for nodejs
  - Refactor reset function and fix bug with constructor calling in it
  - Fix es6 usage in documentation
* 0.8.0 **Breakable changes**
  - Rewrite to ES6
  - Refactor all code & invert dependencies
  - Add length option to Ripemd, Sha256, Sha512, Snefru
  - Add rounds option to Has160, Md2, Sha0, Sha1, Sha256, Sha512, Snefru, Whirlpool
  - WHIRLPOOL, WHIRLPOOL-0, WHIRLPOOL-T now selected by option type
  - Rewrite documentation to esdoc
* 0.7.5
  - Add Snefru v2.0, Snefru v2.5
* 0.7.4
  - Add HAS-160
  - Add WHIRLPOOL, WHIRLPOOL-0, WHIRLPOOL-T
* 0.7.3
  - Add RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320
* 0.7.2
  - Fix documentation
* 0.7.1
  - Add SHA512/224, SHA512/256
* 0.7.0
  - Add SHA384, SHA512
* 0.6.2
  - Perfomance optimization
  - Add benchmark
