// A parity harness that cannot fail proves nothing. This test builds copies of the
// original sources with one small deliberate defect each (a changed constant, a
// wrong default, an extra state field...) and requires the differential fuzzer,
// run against the plain original (FUZZ_REFERENCE=v1), to reject every one. The
// mutated trees come from the upstream checkout, not from packages/crypto-api, so
// the test stays valid once facades replace the vendored files.
//
// A second set breaks each v2 rule in a copy of the package and requires the
// fuzzer in its default mode (against the v2 model) to reject it.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, cpSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { plan } from '../../scripts/vendor-legacy.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fuzzFile = join(here, 'diff-hashers.test.js');

const MUTATIONS = [
  { name: 'md5 shift table', file: 'hasher/md5.mjs', from: '[7, 12, 17, 22]', to: '[7, 12, 17, 23]', only: 'md5' },
  { name: 'LE length field', file: 'hasher/hasher32le.mjs', from: 'this.state.length << 3 & 0xff', to: 'this.state.length << 2 & 0xff', only: 'md4' },
  { name: 'sha1 default rounds', file: 'hasher/sha1.mjs', from: 'this.options.rounds || 80', to: 'this.options.rounds || 79', only: 'sha1' },
  { name: 'sha512 round stride', file: 'hasher/sha512.mjs', from: 'i < this.options.rounds; i += 2', to: 'i < this.options.rounds; i += 1', only: 'sha512' },
  { name: 'whirlpool default rounds', file: 'hasher/whirlpool.mjs', from: "options.rounds || 10", to: "options.rounds || 9", only: 'whirlpool' },
  { name: 'snefru default length', file: 'hasher/snefru.mjs', from: 'options.length || 128', to: 'options.length || 160', only: 'snefru' },
  { name: 'extra field in getState()', file: 'hasher/hasher.mjs', from: 'return JSON.parse(JSON.stringify(this.state));', to: 'return Object.assign(JSON.parse(JSON.stringify(this.state)), {extra: 1});', only: 'has160' },
  { name: 'options no longer mutated', file: 'hasher/sha256.mjs', from: 'options = options || {};\n    options.length', to: 'options = Object.assign({}, options);\n    options.length', only: 'sha256' },
  { name: 'update() length written as a = a + b', file: 'hasher/hasher.mjs', from: 'this.state.length += message.length;', to: 'this.state.length = this.state.length + message.length;', only: 'md2', expectPass: true },
];

/** Defects in the v2 code of the package (paths relative to packages/crypto-api). */
const V2_MUTATIONS = [
  { name: 'v2: wide characters accepted', file: 'src/tools/input.mjs', from: 'const WIDE = /[^\\x00-\\xff]/;', to: 'const WIDE = /[^\\x00-\\uffff]/;', only: 'sha1' },
  { name: 'v2: bytes coerced with String()', file: 'src/tools/input.mjs', from: 'const bytes = bytesOf(input);', to: 'if (input !== null && typeof input === "object") return String(input);\n  const bytes = bytesOf(input);', only: 'md5' },
  { name: 'v2: rounds range one too wide', file: 'src/hasher/sha256.mjs', from: 'rounds: {min: 1, max: 64}', to: 'rounds: {min: 1, max: 65}', only: 'sha256' },
  { name: 'v2: length check missing', file: 'src/hasher/ripemd.mjs', from: "checkOptions('Ripemd', options, OPTIONS);", to: '', only: 'ripemd' },
];
const PACKAGE = join(here, '..', '..', 'packages', 'crypto-api');

let tmp;
const roots = new Map();

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'crypto-api-mutants-'));
  for (const m of MUTATIONS) {
    const root = join(tmp, m.name.replace(/\W+/g, '-'));
    for (const e of plan().filter((x) => x.kind === 'src')) {
      let content = e.content;
      if (e.rel === m.file) {
        assert.ok(content.includes(m.from), `mutation anchor not found in ${m.file}: ${m.from}`);
        content = content.replace(m.from, m.to);
      }
      const dest = join(root, 'src', e.rel);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, content);
    }
    roots.set(m.name, root);
  }
  for (const m of V2_MUTATIONS) {
    const root = join(tmp, m.name.replace(/\W+/g, '-'));
    for (const dir of ['src', 'legacy', 'wasm']) cpSync(join(PACKAGE, dir), join(root, dir), { recursive: true });
    const file = join(root, m.file);
    const content = readFileSync(file, 'utf8');
    assert.ok(content.includes(m.from), `mutation anchor not found in ${m.file}: ${m.from}`);
    writeFileSync(file, content.replace(m.from, m.to));
    roots.set(m.name, root);
  }
});

after(() => rmSync(tmp, { recursive: true, force: true }));

describe('harness self-test: the fuzzer rejects deliberately broken targets', () => {
  for (const m of MUTATIONS) {
    it(m.expectPass ? `${m.name} (equivalent mutant, must pass)` : m.name, () => {
      const env = { ...process.env, CRYPTO_API_TARGET: roots.get(m.name), FUZZ_ONLY: m.only, FUZZ_ITERS: '25', FUZZ_REFERENCE: 'v1' };
      delete env.NODE_TEST_CONTEXT;
      const r = spawnSync(process.execPath, ['--test', fuzzFile], { env, encoding: 'utf8' });
      if (m.expectPass) assert.equal(r.status, 0, r.stdout.slice(-2000));
      else assert.notEqual(r.status, 0, `fuzzer failed to detect mutation "${m.name}"`);
    });
  }

  it('the unmodified package copy passes in v2 mode (control)', () => {
    const root = join(tmp, 'v2-control');
    for (const dir of ['src', 'legacy', 'wasm']) cpSync(join(PACKAGE, dir), join(root, dir), { recursive: true });
    const env = { ...process.env, CRYPTO_API_TARGET: root, FUZZ_ONLY: 'sha256', FUZZ_ITERS: '25' };
    delete env.NODE_TEST_CONTEXT;
    const r = spawnSync(process.execPath, ['--test', fuzzFile], { env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout.slice(-2000));
  });

  for (const m of V2_MUTATIONS) {
    it(m.name, () => {
      const env = { ...process.env, CRYPTO_API_TARGET: roots.get(m.name), FUZZ_ONLY: m.only, FUZZ_ITERS: '25' };
      delete env.NODE_TEST_CONTEXT;
      delete env.FUZZ_REFERENCE;
      const r = spawnSync(process.execPath, ['--test', fuzzFile], { env, encoding: 'utf8' });
      assert.notEqual(r.status, 0, `fuzzer failed to detect mutation "${m.name}"`);
    });
  }
});
