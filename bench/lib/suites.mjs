// The measured suites. Runtime-agnostic: everything environment-specific comes in through `ctx`.
//
//   ctx = { orig, v1, wasmBytesOf(family), createHash | null, measure: {samples, minSampleMs, warmupMs}, log }
//
// Each case verifies that all contenders produce the original's digest before timing,
// so a number can never come from a contender that computes something else.
import { measureGroup } from './stats.mjs';
import {
  VARIANTS, makeRaw, makeNode, makeBytes, binaryString, hexOfBinary, hexOfBytes, chunksOf,
} from './contenders.mjs';
import { FAMILIES } from '../../test/harness/catalog.mjs';

export const SIZES = [0, 16, 64, 1024, 65536, 1048576, 16777216];
export const STREAM_CHUNK = 4096;

const fileOf = (variant) => FAMILIES.find((f) => f.id === variant.family).file;
const make = (Cls, options) => () => (Object.keys(options).length ? new Cls({ ...options }) : new Cls());

const inputCache = new Map();
function input(n) {
  let v = inputCache.get(n);
  if (!v) {
    inputCache.clear(); // sizes run in order; keep at most one big input alive
    const bytes = makeBytes(n);
    const str = binaryString(bytes);
    v = { bytes, str, chunks: chunksOf(str, STREAM_CHUNK) };
    inputCache.set(n, v);
  }
  return v;
}

const rawCache = new Map();
const rawFor = (ctx, v) => {
  if (!rawCache.has(v.id)) {
    let r = null;
    try { r = makeRaw(v, ctx.wasmBytesOf); } catch (e) { ctx.log?.(`  raw unavailable for ${v.id}: ${e.message}`); }
    rawCache.set(v.id, r);
  }
  return rawCache.get(v.id);
};

function pack(res, size) {
  const out = {};
  for (const [name, r] of Object.entries(res)) {
    out[name] = {
      median_ms: r.median, p95_ms: r.p95, min_ms: r.min, samples: r.samples, iters: r.iters,
      mb_per_s: size > 0 ? size / 1e6 / (r.median / 1000) : null,
      ops_per_s: 1000 / r.median,
    };
  }
  return out;
}

/** Throughput: new + update + finalize at each size, in one call and streamed in 4 KiB chunks. */
export function throughput(ctx, { sizes = SIZES, variants = VARIANTS, modes = ['oneshot', 'stream'] } = {}) {
  const rows = [];
  for (const v of variants) {
    const file = fileOf(v);
    const Orig = ctx.orig.hashers[file];
    const V1 = ctx.v1.hashers[file];
    const mkO = make(Orig, v.options);
    const mkN = make(V1, v.options);
    const raw = rawFor(ctx, v);
    const node = makeNode(v, ctx.createHash);
    for (const size of sizes) {
      const inp = input(size);
      for (const mode of modes) {
        if (mode === 'stream' && size < 65536) continue;
        const stream = mode === 'stream';
        const fnOrig = (mk) => stream
          ? () => { const h = mk(); for (const c of inp.chunks) h.update(c); return h.finalize(); }
          : () => { const h = mk(); h.update(inp.str); return h.finalize(); };
        const row = { variant: v.id, size, mode };
        let expected;
        try {
          expected = hexOfBinary(fnOrig(mkO)());
        } catch (e) {
          row.status = 'skipped';
          row.note = `0.8.5 itself throws ${e.name} here`;
          rows.push(row);
          ctx.log?.(`${v.id} ${size} ${mode}: skipped (${row.note})`);
          continue;
        }
        const contenders = [{ name: 'orig', fn: fnOrig(mkO) }, { name: 'v1', fn: fnOrig(mkN) }];
        const got = hexOfBinary(contenders[1].fn());
        if (got !== expected) throw new Error(`MISMATCH v1 ${v.id} ${size} ${mode}`);
        const chunk = stream ? STREAM_CHUNK : 0;
        for (const [name, f] of [['raw', raw], ['node', node]]) {
          if (!f) continue;
          const fn = () => f(inp.bytes, chunk);
          if (hexOfBytes(fn()) !== expected) {
            ctx.log?.(`  ${name} digest differs for ${v.id} (${size}); contender dropped`);
            row.dropped = [...(row.dropped || []), name];
            continue;
          }
          contenders.push({ name, fn });
        }
        row.status = 'ok';
        row.verified = contenders.length;
        row.results = pack(measureGroup(contenders, ctx.measure), size);
        rows.push(row);
        const r = row.results;
        ctx.log?.(`${v.id} ${size} ${mode}: orig ${fmt(r.orig.median_ms)} v1 ${fmt(r.v1.median_ms)} (${(r.orig.median_ms / r.v1.median_ms).toFixed(2)}x)`);
      }
    }
  }
  return rows;
}

const fmt = (ms) => (ms >= 1 ? `${ms.toFixed(2)} ms` : `${(ms * 1000).toFixed(2)} us`);

/** Construction cost: `new Hasher(options)`. */
export function construct(ctx, { variants = VARIANTS } = {}) {
  return variants.map((v) => {
    const file = fileOf(v);
    const res = measureGroup([
      { name: 'orig', fn: make(ctx.orig.hashers[file], v.options) },
      { name: 'v1', fn: make(ctx.v1.hashers[file], v.options) },
    ], ctx.measure);
    ctx.log?.(`construct ${v.id}: ${(res.orig.median / res.v1.median).toFixed(2)}x`);
    return { variant: v.id, results: pack(res, 0) };
  });
}

const API_NAMES = [
  'md2', 'md4', 'md5', 'has160', 'ripemd160', 'sha0', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
  'snefru', 'whirlpool', 'whirlpool-t',
];

/** `CryptoApi.hash(name, message)`: getHasher + UTF encode + update + finalize + hex. */
export function api(ctx, { names = API_NAMES } = {}) {
  const msg = 'The quick brown fox jumps over the lazy dog';
  return names.map((name) => {
    const a = ctx.orig.CryptoApi;
    const b = ctx.v1.CryptoApi;
    if (a.hash(name, msg) !== b.hash(name, msg)) throw new Error(`MISMATCH api ${name}`);
    const res = measureGroup([
      { name: 'orig', fn: () => a.hash(name, msg) },
      { name: 'v1', fn: () => b.hash(name, msg) },
    ], ctx.measure);
    ctx.log?.(`api ${name}: ${(res.orig.median / res.v1.median).toFixed(2)}x`);
    return { name, message_bytes: msg.length, results: pack(res, msg.length) };
  });
}

const HMAC_IDS = ['has160', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

/** HMAC over each hasher (the original's generic Hmac class, same code in both trees). */
export function hmac(ctx, { ids = HMAC_IDS, sizes = [64, 1024] } = {}) {
  const rows = [];
  const key = 'a key that is not a multiple of anything';
  for (const id of ids) {
    const v = VARIANTS.find((x) => x.id === id);
    const file = fileOf(v);
    for (const size of sizes) {
      const msg = input(size).str;
      const mk = (tree) => {
        const mkH = make(tree.hashers[file], v.options);
        return () => { const m = new tree.Hmac(key, mkH()); m.update(msg); return m.finalize(); };
      };
      const fa = mk(ctx.orig);
      const fb = mk(ctx.v1);
      if (hexOfBinary(fa()) !== hexOfBinary(fb())) throw new Error(`MISMATCH hmac ${id}`);
      const res = measureGroup([{ name: 'orig', fn: fa }, { name: 'v1', fn: fb }], ctx.measure);
      ctx.log?.(`hmac ${id} ${size}: ${(res.orig.median / res.v1.median).toFixed(2)}x`);
      rows.push({ variant: id, size, results: pack(res, size) });
    }
  }
  return rows;
}

/** `getState()` and `setState()` of a hasher that has consumed 1 KiB. Same JS in both trees: should be ~1x. */
export function state(ctx, { ids = ['md5', 'sha1', 'sha256', 'sha512', 'whirlpool'] } = {}) {
  const rows = [];
  const msg = input(1024).str;
  for (const id of ids) {
    const v = VARIANTS.find((x) => x.id === id);
    const file = fileOf(v);
    const prep = (tree) => {
      const h = make(tree.hashers[file], v.options)();
      h.update(msg);
      return h;
    };
    const ho = prep(ctx.orig);
    const hn = prep(ctx.v1);
    const stO = ho.getState();
    const stN = hn.getState();
    if (JSON.stringify(stO) !== JSON.stringify(stN)) throw new Error(`MISMATCH getState ${id}`);
    const g = measureGroup([{ name: 'orig', fn: () => ho.getState() }, { name: 'v1', fn: () => hn.getState() }], ctx.measure);
    const s = measureGroup([
      { name: 'orig', fn: () => { ho.setState(stO); return ho; } },
      { name: 'v1', fn: () => { hn.setState(stN); return hn; } },
    ], ctx.measure);
    ctx.log?.(`state ${id}: get ${(g.orig.median / g.v1.median).toFixed(2)}x set ${(s.orig.median / s.v1.median).toFixed(2)}x`);
    rows.push({ variant: id, getState: pack(g, 0), setState: pack(s, 0) });
  }
  return rows;
}
