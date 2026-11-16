// The package README tells readers how to load the global build safely and what not to rely on.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const readme = readFileSync(join(root, 'packages', 'crypto-api', 'README.md'), 'utf8');
const pkg = JSON.parse(readFileSync(join(root, 'packages', 'crypto-api', 'package.json'), 'utf8'));

describe('package README', () => {
  it('CDN snippet pins the package version and carries an integrity attribute', () => {
    const tag = readme.match(/<script src="(https:\/\/cdn\.jsdelivr\.net\/[^"]+)"[^>]*>/s);
    assert.ok(tag, 'no CDN script tag');
    assert.equal(tag[1], `https://cdn.jsdelivr.net/npm/${pkg.name}@${pkg.version}/crypto-api.min.js`);
    assert.match(tag[0], /integrity="sha384-[^"]+"/);
    assert.match(tag[0], /crossorigin="anonymous"/);
    assert.match(readme, /openssl dgst -sha384 -binary crypto-api\.min\.js \| openssl base64 -A/);
  });

  it('shows no concrete integrity value, so none can be stale or wrong', () => {
    assert.ok(!/sha384-[A-Za-z0-9+/]{64}/.test(readme));
  });

  it('has a Security notes section covering algorithms, rounds, timing and MAC comparison', () => {
    const i = readme.indexOf('## Security notes');
    assert.ok(i >= 0, 'no Security notes section');
    const section = readme.slice(i, readme.indexOf('\n## ', i + 1));
    for (const name of ['MD2', 'MD4', 'MD5', 'SHA-0', 'SHA-1', 'HAS-160', 'RIPEMD-128', 'Snefru']) {
      assert.ok(section.includes(name), `${name} missing`);
    }
    for (const word of ['rounds', 'constant-time', 'timingSafeEqual', 'Hmac', 'SECURITY.md']) {
      assert.ok(section.includes(word), `${word} missing`);
    }
  });
});
