# Security policy

## Supported versions

Security fixes are released for the latest `1.x` version of `crypto-api-ng`. Older releases are not patched; upgrade to the latest `1.x`.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. Use [Report a vulnerability](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/security/advisories/new) on the Security tab of this repository, which opens a private advisory visible only to the maintainers.

Include the affected version, the input or options that trigger the problem, and what you expected instead. A digest that differs from a published test vector, or a hasher that reads or writes out of bounds, is in scope. Expect an acknowledgement within a few days. Once a fix is released, the advisory is published and you are credited if you wish.

## What is not a vulnerability

MD2, MD4, MD5, SHA-0, SHA-1 and HAS-160 are included for compatibility and are broken for collision resistance, so they are unsuitable for signatures and certificates. Use SHA-256 or stronger for new designs. This library hashes data; it is not a password hashing function and does not provide constant-time comparison.

Reduced-round variants (the `rounds` option) exist for research and compatibility and are not secure by design.
