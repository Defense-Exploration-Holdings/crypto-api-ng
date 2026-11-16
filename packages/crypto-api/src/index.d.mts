/**
 * The `CryptoApi` object: every hasher by name through `getHasher()` and `hash()`, HMAC, PBKDF2 and
 * HKDF helpers, and the encoders. For small bundles import the single algorithms instead, such as
 * `./sha256`.
 *
 * @module
 */

import type { CryptoApi } from "../types.js";

/**
 * The `CryptoApi` object.
 *
 * @example
 * ```ts
 * import CryptoApi from "@defense-exploration/crypto-api-ng";
 *
 * CryptoApi.hash("sha256", "message"); // hex digest of a UTF-8 string
 * ```
 */
declare const cryptoApi: CryptoApi;
export default cryptoApi;
