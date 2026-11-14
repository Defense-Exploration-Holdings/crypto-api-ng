// crypto-api-ng:facade
'use strict';

/*
 * The original file ended with `module.exports = CryptoApi` inside an ES module,
 * which no loader accepts without the original's babel setup (native ESM and
 * webpack 5 both fail on it). v1 exports the same object as the default export.
 * This is intentional divergence 4; see packages/crypto-api/README.md.
 */
import CryptoApi from './crypto-api.mjs';

export default CryptoApi;
