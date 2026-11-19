# Security policy

## Supported versions

Security fixes are released for the latest `1.x` version of `crypto-api-ng` and for the `1.0.x` line (npm dist-tag `v1-latest`), which keeps the exact behavior of crypto-api 0.8.5. Other releases are not patched; upgrade to the latest `1.x` or `1.0.x`.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. Use [Report a vulnerability](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/security/advisories/new) on the Security tab of this repository, which opens a private advisory visible only to the maintainers.

Include the affected version, the input or options that trigger the problem, and what you expected instead. In scope: a digest, MAC or derived key that differs from a published test vector, a hasher or KDF that reads or writes out of bounds, or a password, key or secret left in WebAssembly memory after a call returns. Expect an acknowledgement within a few days. Once a fix is released, the advisory is published and you are credited if you wish.

## What is not a vulnerability

MD2, MD4, MD5, SHA-0, SHA-1, HAS-160, RIPEMD-128 and Snefru are included for compatibility and are not collision resistant, so they are unsuitable for signatures and certificates. Use SHA-256 or stronger for new designs. The library does not claim constant-time execution and does not provide constant-time comparison. Compare MAC values with a constant-time function such as `crypto.timingSafeEqual` in Node.js.

Argon2 and scrypt were added in 1.5.0. They match the RFC test vectors and other implementations, but they have not had an independent review, and they run on a single thread. For storing user passwords, prefer a reviewed implementation such as `node:crypto` scrypt or a maintained Argon2 binding where one is available.

Reduced-round variants (the `rounds` option) exist for research and compatibility and are not secure by design.
