/**
 * Conversions between bytes (`Uint8Array`, `ArrayBuffer` and other views) and UTF-8 text, hex and base64.
 *
 * @module
 */

import type { Base64Options, Bytes } from "../../types.js";

/** Text to the bytes of its UTF-8 encoding. An unpaired surrogate becomes U+FFFD. */
export function utf8ToBytes(text: string): Uint8Array;
/** UTF-8 bytes to text; invalid bytes become U+FFFD, or throw `TypeError` with `fatal`. */
export function bytesToUtf8(bytes: Bytes, options?: { fatal?: boolean }): string;
/** Bytes to lowercase hex. */
export function bytesToHex(bytes: Bytes): string;
/** Hex (either case) to bytes. Throws `SyntaxError` for an odd length or a character that is not a hex digit. */
export function hexToBytes(hex: string): Uint8Array;
/** Bytes to base64 (RFC 4648), padded unless `omitPadding` is set. */
export function bytesToBase64(bytes: Bytes, options?: Base64Options & { omitPadding?: boolean }): string;
/** Base64 to bytes. Padding is optional and ASCII whitespace is ignored. Throws `SyntaxError` for malformed input. */
export function base64ToBytes(text: string, options?: Base64Options): Uint8Array;
