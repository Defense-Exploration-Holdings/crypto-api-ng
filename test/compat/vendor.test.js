// The vendored sources under packages/crypto-api must be the original files with
// nothing changed but relative import specifiers, and every specifier must still
// point at the same module. Hand-written facades (marked `// crypto-api-ng:facade`)
// are exempt. Also guards generated artifacts against drift.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, posix, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO_ROOT, ORACLE_SRC, DEFAULT_TARGET, assertOracleCheckedOut } from '../harness/paths.mjs';
import { listOriginalFiles, isLegacyFile, isFacade, SPECIFIER_RE } from '../../scripts/vendor-legacy.mjs';

assertOracleCheckedOut();

// Replace each relative specifier by a placeholder and collect them.
function mask(text) {
  const specs = [];
  const masked = text.replace(SPECIFIER_RE, (m, kw, q, spec) => { specs.push(spec); return `${kw}${q}§${q}`; });
  return { masked, specs };
}
const withExt = (p) => (/\.[cm]?js$/.test(p) ? p : `${p}.mjs`);
const resolveIn = (rel, spec) => withExt(posix.normalize(posix.join(posix.dirname(rel), spec)));

describe('vendored sources are verbatim', () => {
  for (const rel of listOriginalFiles()) {
    const original = readFileSync(join(ORACLE_SRC, rel), 'utf8');
    const o = mask(original);

    it(`src/${rel}`, () => {
      const path = join(DEFAULT_TARGET, 'src', rel);
      assert.ok(existsSync(path), 'missing');
      if (isFacade(path)) return;
      const v = mask(readFileSync(path, 'utf8'));
      assert.equal(v.masked, o.masked, 'content differs beyond import specifiers');
      assert.deepStrictEqual(v.specs.map((s) => resolveIn(rel, s)), o.specs.map((s) => resolveIn(rel, s)), 'imports resolve elsewhere');
    });

    if (isLegacyFile(rel)) {
      it(`legacy/${rel}`, () => {
        const path = join(DEFAULT_TARGET, 'legacy', rel);
        assert.ok(existsSync(path), 'missing');
        const v = mask(readFileSync(path, 'utf8'));
        assert.equal(v.masked, o.masked, 'content differs beyond import specifiers');
        // every import must land on the single copy under src/ (base classes, tools)
        const landed = v.specs.map((s) => posix.normalize(posix.join('legacy', posix.dirname(rel), s)));
        const expected = o.specs.map((s) => posix.join('src', resolveIn(rel, s)));
        assert.deepStrictEqual(landed, expected);
      });
    }
  }
});

describe('generated files are current', () => {
  const run = (script) => spawnSync(process.execPath, [join(REPO_ROOT, 'scripts', script), '--check'], { encoding: 'utf8' });
  it('scripts/vendor-legacy.mjs --check', () => {
    const r = run('vendor-legacy.mjs');
    assert.equal(r.status, 0, r.stderr + r.stdout);
  });
  it('scripts/extract-vectors.mjs --check', () => {
    const r = run('extract-vectors.mjs');
    assert.equal(r.status, 0, r.stderr + r.stdout);
  });
  it('scripts/gen-snefru-rand.mjs --check', () => {
    const r = run('gen-snefru-rand.mjs');
    assert.equal(r.status, 0, r.stderr + r.stdout);
  });
});
