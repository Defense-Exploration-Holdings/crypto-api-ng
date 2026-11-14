// Stand-in for `chai/register-assert` as used by the original crypto-api tests.
// They only call assert.equal (loose ==, same as chai), so node:assert is exact.
import assert from 'node:assert';
globalThis.assert = assert;
