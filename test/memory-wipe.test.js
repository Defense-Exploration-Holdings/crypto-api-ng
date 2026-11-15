// After a hash or HMAC call, nothing the call was given may be left in the
// family's wasm memory: not the message bytes, not the HMAC pad blocks, and not
// the digest or the hash words derived from them. The scan covers the whole
// linear memory of the module (scratch region, stack, data), not only the
// scratch slots the facade writes to.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import Has160, { _internal as has160 } from '../packages/crypto-api/src/hasher/has160.mjs';
import Md2, { _internal as md2 } from '../packages/crypto-api/src/hasher/md2.mjs';
import Md4, { _internal as md4 } from '../packages/crypto-api/src/hasher/md4.mjs';
import Md5, { _internal as md5 } from '../packages/crypto-api/src/hasher/md5.mjs';
import Ripemd, { _internal as ripemd } from '../packages/crypto-api/src/hasher/ripemd.mjs';
import Sha0, { _internal as sha0 } from '../packages/crypto-api/src/hasher/sha0.mjs';
import Sha1, { _internal as sha1 } from '../packages/crypto-api/src/hasher/sha1.mjs';
import Sha256, { _internal as sha256 } from '../packages/crypto-api/src/hasher/sha256.mjs';
import Sha512, { _internal as sha512 } from '../packages/crypto-api/src/hasher/sha512.mjs';
import Sm3, { _internal as sm3 } from '../packages/crypto-api/src/hasher/sm3.mjs';
import Snefru, { _internal as snefru } from '../packages/crypto-api/src/hasher/snefru.mjs';
import Whirlpool, { _internal as whirlpool } from '../packages/crypto-api/src/hasher/whirlpool.mjs';
import { rng } from './support/le32-suite.js';

const CASES = [
  ['md2', Md2, md2, undefined],
  ['md4', Md4, md4, undefined],
  ['md5', Md5, md5, undefined],
  ['has160', Has160, has160, undefined],
  ['ripemd128', Ripemd, ripemd, { length: 128 }],
  ['ripemd160', Ripemd, ripemd, undefined],
  ['ripemd256', Ripemd, ripemd, { length: 256 }],
  ['ripemd320', Ripemd, ripemd, { length: 320 }],
  ['sha0', Sha0, sha0, undefined],
  ['sha1', Sha1, sha1, undefined],
  ['sha224', Sha256, sha256, { length: 224 }],
  ['sha256', Sha256, sha256, undefined],
  ['sm3', Sm3, sm3, undefined],
  ['sha384', Sha512, sha512, { length: 384 }],
  ['sha512', Sha512, sha512, undefined],
  ['sha512/256', Sha512, sha512, { length: 256 }],
  ['snefru128', Snefru, snefru, undefined],
  ['snefru256', Snefru, snefru, { length: 256, rounds: 4 }],
  ['whirlpool', Whirlpool, whirlpool, undefined],
  ['whirlpool-t', Whirlpool, whirlpool, { type: 't' }],
  ['whirlpool-0', Whirlpool, whirlpool, { type: '0' }],
];

const WINDOW = 16;

function randomBytes(rand, n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (rand() * 256) | 0;
  return b;
}

const binary = (b) => b.toString('latin1');

/** Every aligned window of `bytes`, as it appears in memory directly and as 32-bit words written little-endian from a big-endian reading. */
function windows(bytes, size = WINDOW) {
  const out = [];
  for (let i = 0; i + size <= bytes.length; i += 4) {
    const w = Buffer.from(bytes.subarray(i, i + size));
    out.push({ at: i, form: 'bytes', needle: w });
    out.push({ at: i, form: 'swapped words', needle: Buffer.from(w).swap32() });
  }
  return out;
}

/** Offsets in the whole memory where any window of `bytes` shows up; empty when nothing is left. */
function leaks(memory, bytes, label) {
  const found = [];
  for (const { at, form, needle } of windows(bytes)) {
    const i = memory.indexOf(needle);
    if (i !== -1) found.push(`${label}[${at}..${at + needle.length}] (${form}) at memory offset ${i}`);
  }
  return found;
}

function scan(rt, secrets) {
  const memory = Buffer.from(rt.u8.buffer, rt.u8.byteOffset, rt.u8.byteLength);
  return secrets.flatMap(([label, bytes]) => leaks(memory, bytes, label));
}

test('the scan finds bytes that are there (control)', () => {
  const rt = md5.runtime();
  assert.ok(rt, 'run `zig build js` first');
  const bytes = randomBytes(rng(1), 48);
  rt.u8.set(bytes, rt.base + 256 + 100);
  try {
    assert.ok(scan(rt, [['control', bytes]]).length > 0);
  } finally {
    rt.u8.fill(0, rt.base + 256 + 100, rt.base + 256 + 148);
  }
  assert.deepEqual(scan(rt, [['control', bytes]]), []);
});

for (const [name, Cls, internal, options] of CASES) {
  const make = () => (options ? new Cls(Object.assign({}, options)) : new Cls());

  test(`${name}: no message bytes, pad blocks or digests stay in wasm memory`, () => {
    const rt = internal.runtime();
    assert.ok(rt, 'wasm failed to instantiate; run `zig build js` first');
    const rand = rng(0x1234 + name.length);
    // Three full blocks of every size plus a tail long enough to need a second padding block.
    const message = randomBytes(rand, 3 * 128 + 101);
    const key = randomBytes(rand, 23);
    const calls = internal.wasmCalls();

    // Plain hash, one update and many small ones, with a digest at the end.
    const digests = [];
    for (const pieces of [[message.length], [7, 64, 1, 300, message.length - 372]]) {
      const h = make();
      let pos = 0;
      for (const n of pieces) {
        h.update(binary(message.subarray(pos, pos + n)));
        pos += n;
      }
      digests.push(Buffer.from(h.finalize(), 'latin1'));
    }
    assert.ok(internal.wasmCalls() > calls, 'the wasm path was not taken');
    assert.deepEqual(scan(rt, [['message', message], ['digest', digests[0]]]), []);

    // HMAC: key-derived pad blocks and the inner digest pass through the same region.
    const blockSize = make().blockSizeInBytes;
    const ipad = Buffer.alloc(blockSize, 0x36);
    const opad = Buffer.alloc(blockSize, 0x5c);
    for (let i = 0; i < key.length; i++) {
      ipad[i] ^= key[i];
      opad[i] ^= key[i];
    }
    const mac = new Hmac(binary(key), make());
    mac.update(binary(message));
    const tag = Buffer.from(mac.finalize(), 'latin1');
    assert.deepEqual(scan(rt, [
      ['message', message], ['key', key], ['ipad', ipad], ['opad', opad], ['tag', tag],
    ]), []);

    // The fallback that hands a call back to the original code half way: a code unit above 0xFF after
    // some blocks (`update()` refuses those, `state.message` and `setState()` do not).
    const wide = make();
    wide.state.message = binary(message.subarray(0, 2 * blockSize)) + 'Ā' + binary(message.subarray(0, 40));
    wide.process();
    try {
      wide.finalize();
    } catch (e) {
      // 1.1 refuses to hash the garbage a wide character leaves behind (MD2's checksum).
      assert.ok(e instanceof TypeError, String(e));
    }
    assert.deepEqual(scan(rt, [['message', message]]), []);
  });
}
