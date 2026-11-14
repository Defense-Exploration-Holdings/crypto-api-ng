// The behaviors of crypto-api 0.8.5 that were verified by
// running the original, as executable probes. Each probe takes an API tree
// (oracle or target) and returns JSON-able observations. quirks.test.js pins the
// oracle's answers (so the claims stay true) and requires the target to give
// the same answers (so v1 keeps the quirks).
import { createHash } from 'node:crypto';

const out = (fn) => { try { return fn(); } catch (e) { return `!${e.constructor.name}`; } };
const hex = (api, h) => api.toHex(h.finalize());

export const QUIRK_PROBES = {
  'wide characters hash to neither UTF-8 nor Latin-1': (api) => {
    const h = new api.hashers.Sha256(); h.update('Привет');
    const got = hex(api, h);
    return {
      got,
      isUtf8: got === createHash('sha256').update('Привет', 'utf8').digest('hex'),
      isLatin1: got === createHash('sha256').update('Привет', 'latin1').digest('hex'),
    };
  },
  'update(Uint8Array) hashes the text "1,2" and counts 2': (api) => {
    const h = new api.hashers.Sha256(); h.update(new Uint8Array([1, 2]));
    return { message: h.state.message, length: h.state.length };
  },
  'sha256 rounds 80 runs on undefined constants': (api) => {
    const h = new api.hashers.Sha256({ rounds: 80 }); h.update('abc');
    return hex(api, h);
  },
  'snefru rounds 9 throws TypeError': (api) => out(() => { const h = new api.hashers.Snefru({ rounds: 9 }); h.update('abc'); return hex(api, h); }),
  'whirlpool type 0 equals plain whirlpool': (api) => {
    const a = new api.hashers.Whirlpool({ type: 0 }); a.update('abc');
    const b = new api.hashers.Whirlpool({}); b.update('abc');
    return { same: hex(api, a) === hex(api, b) };
  },
  'sha512 rounds 159 equals default': (api) => {
    const a = new api.hashers.Sha512({ rounds: 159 }); a.update('abc');
    const b = new api.hashers.Sha512(); b.update('abc');
    return { same: hex(api, a) === hex(api, b) };
  },
  'sha256 length 160 is a 5-word digest': (api) => {
    const h = new api.hashers.Sha256({ length: 160 }); h.update('abc');
    return hex(api, h).length;
  },
  'getHasher(sm3) and getHasher(SHA256) are undefined': (api) => ({
    sm3: api.CryptoApi.getHasher('sm3') === undefined,
    upper: api.CryptoApi.getHasher('SHA256') === undefined,
  }),
  'hash() of an unknown name throws TypeError': (api) => out(() => api.CryptoApi.hash('nope', 'x')),
  'hmac-md5 second finalize differs, first is correct': (api) => {
    const m = new api.Hmac('key', new api.hashers.Md5()); m.update('The quick brown fox jumps over the lazy dog');
    const first = api.toHex(m.finalize());
    const second = api.toHex(m.finalize());
    return { first, differs: first !== second };
  },
  'new Hmac(key, md5) leaves 64 bytes in the hasher': (api) => {
    const md5 = new api.hashers.Md5(); new api.Hmac('key', md5);
    return md5.state.length;
  },
  'md2 starts with 48 null hash words': (api) => {
    const s = new api.hashers.Md2().getState();
    return { hash: s.hash.every((x) => x === null) && s.hash.length, checksum: s.checksum.every((x) => x === null) && s.checksum.length };
  },
  'has160 IV is unsigned until the first block, signed after': (api) => {
    const h = new api.hashers.Has160();
    const before = h.getState().hash;
    h.update('x'.repeat(64));
    const after = h.getState().hash;
    return { before, afterHasNegative: after.some((x) => x < 0) };
  },
  'ripemd IV is unsigned until the first block': (api) => {
    const h = new api.hashers.Ripemd();
    return h.getState().hash;
  },
  'state.length high bits are dropped (2**29 vs 2**29 + 2**32)': (api) => {
    const run = (len) => { const h = new api.hashers.Sha256(); h.update('abc'); h.state.length = len; return hex(api, h); };
    return { same: run(2 ** 29) === run(2 ** 29 + 2 ** 32) };
  },
  'constructor writes defaults into the caller options': (api) => {
    const o = {}; new api.hashers.Sha256(o);
    const w = {}; new api.hashers.Whirlpool(w);
    return { sha256: o, whirlpool: w };
  },
  'fromUtf of a lone high surrogate is invalid UTF-8': (api) => api.toHex(api.fromUtf('a\ud800')),
  'toHex of a wide character is not two digits': (api) => api.toHex('Ā'),
  'ripemd has an own processBlock property': (api) => Object.prototype.hasOwnProperty.call(new api.hashers.Ripemd(), 'processBlock'),
  'setState keeps a live reference in the original': (api) => {
    const h = new api.hashers.Md5(); const s = h.getState();
    h.setState(s); h.update('abc');
    return { live: s.message === 'abc' };
  },
};
