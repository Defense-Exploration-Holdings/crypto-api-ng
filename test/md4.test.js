// MD4 facade tests: wasm-accelerated Md4 vs the untouched crypto-api 0.8.5 class.
// The shared checklist lives in support/le32-suite.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import Md4, { _internal } from '../packages/crypto-api/src/hasher/md4.mjs';
import LegacyMd4 from '../packages/crypto-api/legacy/hasher/md4.mjs';
import { defineSuite } from './support/le32-suite.js';

defineSuite({
  name: 'md4',
  Facade: Md4,
  Legacy: LegacyMd4,
  internal: _internal,
  words: 4,
  vectors: 'md4',
  replacesHash: true
});

test('md4: hash words in getState() JSON are int32 and the pristine state matches the original', () => {
  assert.equal(JSON.stringify(new Md4().getState()), JSON.stringify(new LegacyMd4().getState()));
  assert.equal(JSON.stringify(new Md4().getState()), '{"message":"","length":0,"hash":[1732584193,-271733879,-1732584194,271733878]}');
});
