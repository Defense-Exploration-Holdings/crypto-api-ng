// The global build and the example pages in a real browser (Playwright Chromium): served normally, with
// WebAssembly removed, and under a Content-Security-Policy that forbids compiling wasm. Results must be
// identical in all three, and the wasm path must really be used in the first.
//
// Skipped when `playwright` is not importable. CI installs it (`npm i --no-save playwright`).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, extname } from 'node:path';
import { loadOracle } from '../harness/load.mjs';
import { SCRIPTS, ensureBuilt } from './support.js';

const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { /* not installed */ }

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.map': 'application/json' };

describe('global build in Chromium', { skip: chromium ? false : 'playwright is not installed' }, () => {
  let work;
  let server;
  let base;
  let browser;
  let csp = null;

  before(async () => {
    await ensureBuilt();
    const buildPackage = await import(join(SCRIPTS, 'build-package.mjs'));
    work = mkdtempSync(join(tmpdir(), 'crypto-api-browser-'));
    const root = join(work, 'stage');
    buildPackage.stage({ out: root, name: 'crypto-api-ng' });
    writeFileSync(join(root, 'example', 'probe.html'), `<!DOCTYPE html><meta charset="utf-8"><body>
      <script src="../crypto-api.min.js"></script><script src="probe.js"></script></body>`);
    writeFileSync(join(root, 'example', 'probe.js'), `
      var out = {};
      ['md5', 'sha256', 'sha512', 'ripemd160', 'snefru', 'whirlpool', 'md2'].forEach(function (n) { out[n] = CryptoApi.hash(n, 'abc'); });
      var h = CryptoApi.getHasher('md5'); h.update(new Array(5001).join('x')); out.md5big = CryptoApi.encoder.toHex(h.finalize());
      out.hmac = CryptoApi.hmac('key', 'message', CryptoApi.getHasher('sha1'));
      out.modules = window.__wasmModules;
      window.__result = out;`);

    server = createServer((req, res) => {
      const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      const file = join(root, path);
      if (!file.startsWith(root) || !existsSync(file)) { res.writeHead(404).end(); return; }
      const headers = { 'content-type': MIME[extname(file)] || 'application/octet-stream' };
      if (csp) headers['content-security-policy'] = csp;
      res.writeHead(200, headers).end(readFileSync(file));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch();
  });

  after(async () => {
    await browser?.close();
    server?.close();
    if (work) rmSync(work, { recursive: true, force: true });
  });

  async function openPage(path, { init, policy = null } = {}) {
    csp = policy;
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    // Count successful WebAssembly.Module compilations before any page script runs.
    await page.addInitScript(`
      window.__wasmModules = 0;
      if (window.WebAssembly) {
        var M = WebAssembly.Module;
        WebAssembly.Module = function (b) { var m = new M(b); window.__wasmModules++; return m; };
        WebAssembly.Module.prototype = M.prototype;
      }`);
    if (init) await page.addInitScript(init);
    await page.goto(`${base}${path}`);
    return { page, ctx, errors };
  }

  const probe = async (opts) => {
    const { page, ctx, errors } = await openPage('/example/probe.html', opts);
    const result = await page.evaluate(() => window.__result);
    await ctx.close();
    assert.deepEqual(errors, []);
    return result;
  };

  const withoutModules = ({ modules, ...rest }) => rest;

  it('CryptoApi works from a <script> tag and compiles the embedded wasm', async () => {
    const r = await probe();
    assert.equal(r.md5, '900150983cd24fb0d6963f7d28e17f72');
    assert.equal(r.sha256, createHash('sha256').update('abc').digest('hex'));
    assert.equal(r.md5big, createHash('md5').update('x'.repeat(5000)).digest('hex'));
    assert.equal(r.hmac, '2088df74d5f2146b48146caf4965377e9d0be3a4');
    assert.ok(r.modules >= 1, 'WebAssembly.Module was never constructed');
  });

  it('same results with no WebAssembly object at all', async () => {
    const reference = await probe();
    const r = await probe({ init: 'delete window.WebAssembly;' });
    assert.deepEqual(withoutModules(r), withoutModules(reference));
    assert.ok(!r.modules);
  });

  it('same results under a CSP without wasm-unsafe-eval (compilation is refused)', async () => {
    const reference = await probe();
    const r = await probe({ policy: "default-src 'self'" });
    assert.deepEqual(withoutModules(r), withoutModules(reference));
    assert.ok(!r.modules, 'the CSP should have blocked wasm compilation');
  });

  it("wasm is used under a CSP that allows 'wasm-unsafe-eval'", async () => {
    const r = await probe({ policy: "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'" });
    assert.ok(r.modules >= 1);
  });

  it('example/hasher-basic.html shows MD2("test message")', async () => {
    const { page, ctx, errors } = await openPage('/example/hasher-basic.html');
    const text = await page.textContent('#result');
    await ctx.close();
    assert.deepEqual(errors, []);
    assert.equal(text, (await loadOracle()).CryptoApi.hash('md2', 'test message'));
  });

  it('example/hasher-file.html hashes a chosen file in slices', async () => {
    const { page, ctx, errors } = await openPage('/example/hasher-file.html');
    const bytes = Buffer.alloc(10000);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + 7) & 0xff;
    await page.setInputFiles('#file', { name: 'blob.bin', mimeType: 'application/octet-stream', buffer: bytes });
    const expected = createHash('sha256').update(bytes).digest('hex');
    await page.waitForFunction(
      (e) => document.getElementById('hash').textContent === e && document.getElementById('hash-progress').textContent === '100%',
      expected, { timeout: 10000 },
    );
    await ctx.close();
    assert.deepEqual(errors, []);
  });

  it('example/unit-tests.html passes every vector of the original suite', async () => {
    const { page, ctx, errors } = await openPage('/example/unit-tests.html');
    const summary = await page.textContent('#summary');
    const failures = await page.$$eval('li.fail', (els) => els.map((e) => e.textContent));
    await ctx.close();
    assert.deepEqual(failures, []);
    assert.deepEqual(errors, []);
    assert.match(summary, /^\d+ passed, 0 failed$/);
    assert.ok(Number(summary.split(' ')[0]) > 200, summary);
  });
});
