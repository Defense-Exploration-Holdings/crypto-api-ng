// Scenario generation, execution and comparison for the differential fuzzer.
//
// A scenario is plain JSON (so a failure can be printed and replayed). Running it
// on an implementation yields a trace: every observable result of every step.
// Two implementations are equivalent for a scenario when their traces are equal.
import { make } from './load.mjs';
import { boundaryLengths } from './catalog.mjs';

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/** Non-string values update() may be handed. The original coerces them with `+=`; v2 hashes the bytes or throws. */
const HOSTILE = [
  { t: 'u8', v: [1, 2] },
  { t: 'u8', v: [] },
  { t: 'u8', v: [0, 255, 128, 7, 8, 9, 10] },
  { t: 'arr', v: [97, 98] },
  { t: 'num', v: 12345 },
  { t: 'undef' },
  { t: 'null' },
  { t: 'bool', v: true },
  { t: 'obj' },
  { t: 'buf', v: [1, 2, 3, 4] },
  { t: 'dv', v: [9, 8, 7, 6, 5] },
  { t: 'u16', v: [0x4142, 0xffff, 0] },
  { t: 'sub', v: [10, 20, 30, 40, 50, 60] },
];

export function realize(input) {
  switch (input.t) {
    case 's': return input.v;
    case 'u8': return Uint8Array.from(input.v);
    case 'buf': return Uint8Array.from(input.v).buffer;
    case 'dv': return new DataView(Uint8Array.from(input.v).buffer);
    case 'u16': return Uint16Array.from(input.v);
    case 'sub': return Uint8Array.from(input.v).subarray(2, 5);
    case 'arr': return [...input.v];
    case 'num': return input.v;
    case 'bool': return input.v;
    case 'undef': return undefined;
    case 'null': return null;
    case 'obj': return { toString: () => 'obj' };
    default: throw new Error(`unknown input kind ${input.t}`);
  }
}

// ---------------------------------------------------------------------------
// Scenario generation
// ---------------------------------------------------------------------------

function splitInto(rng, str, parts) {
  if (parts <= 1) return [str];
  const cuts = [];
  for (let i = 0; i < parts - 1; i++) cuts.push(rng.int(str.length + 1));
  cuts.sort((a, b) => a - b);
  const out = [];
  let prev = 0;
  for (const c of cuts) { out.push(str.slice(prev, c)); prev = c; }
  out.push(str.slice(prev));
  return out;
}

function pickLength(rng, family) {
  const r = rng.int(10);
  if (r < 5) return rng.pick(boundaryLengths(family.blockBytes, family.lengthFieldBytes));
  if (r < 9) return rng.range(0, 300);
  return rng.range(300, 1200);
}

/**
 * @param {Rng} rng
 * @param {object} family  catalog family
 * @param {{hostile?: boolean}} [opts]
 */
export function generateScenario(rng, family, opts = {}) {
  const hostile = opts.hostile ?? false;
  const steps = [];
  const message = rng.bytes(pickLength(rng, family));
  const chunks = splitInto(rng, message, rng.range(1, 6)).map((v) => ({ t: 's', v }));

  if (hostile) {
    // replace or insert one wide string or one non-string chunk
    const at = rng.int(chunks.length + 1);
    const bad = rng.chance(0.5)
      ? { t: 's', v: rng.wide(rng.range(1, 40)) }
      : rng.pick(HOSTILE);
    chunks.splice(at, 0, bad);
  }
  for (const c of chunks) steps.push({ op: 'update', input: c });

  // exercise state shape at random points
  if (rng.chance(0.2)) steps.splice(rng.int(steps.length + 1), 0, { op: 'getState' });

  steps.push({ op: 'finalize' });
  if (rng.chance(0.15)) steps.push({ op: 'finalize' }); // second finalize on a finalized state
  if (rng.chance(0.1)) {
    steps.push({ op: 'update', input: { t: 's', v: rng.bytes(rng.range(0, 70)) } }); // update after finalize
    steps.push({ op: 'finalize' });
  }
  if (rng.chance(0.3)) {
    steps.push({ op: 'reset' });
    const second = rng.bytes(pickLength(rng, family));
    for (const v of splitInto(rng, second, rng.range(1, 3))) steps.push({ op: 'update', input: { t: 's', v } });
    steps.push({ op: 'finalize' });
  }
  return { steps };
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

const err = (e) => `!${e?.constructor?.name ?? typeof e}: ${e?.message}`;

function attempt(fn) {
  try { return fn(); } catch (e) { return err(e); }
}

function stateJson(h) {
  return attempt(() => JSON.stringify(h.getState()));
}

/** Apply one step to a hasher, return what was observed. */
function applyStep(api, h, step) {
  switch (step.op) {
    case 'update': {
      const r = attempt(() => { h.update(realize(step.input)); return 'ok'; });
      return { op: 'update', r, state: stateJson(h) };
    }
    case 'finalize': {
      const r = attempt(() => api.toHex(h.finalize()));
      return { op: 'finalize', r, state: stateJson(h) };
    }
    case 'reset': {
      const r = attempt(() => { h.reset(); return 'ok'; });
      return { op: 'reset', r, state: stateJson(h) };
    }
    case 'getState':
      return { op: 'getState', r: stateJson(h) };
    case 'setState': {
      const r = attempt(() => { h.setState(JSON.parse(step.state)); return 'ok'; });
      return { op: 'setState', r, state: stateJson(h) };
    }
    default:
      throw new Error(`unknown op ${step.op}`);
  }
}

/** Run a whole scenario on one implementation. Returns { ctor, trace }. */
export function runScenario(api, family, options, scenario) {
  const arg = options === undefined ? undefined : structuredClone(options);
  let h;
  const ctor = attempt(() => { h = arg === undefined ? make(api, family) : make(api, family, arg); return 'ok'; });
  if (ctor !== 'ok') return { ctor, trace: [] };
  // `options` is the caller's object: the original mutates it (defaults are written
  // back) and keeps a reference to it.
  const optionsAfter = [
    attempt(() => JSON.stringify(h.options, replacer)),
    `caller:${JSON.stringify(arg, replacer)}`,
    `same:${h.options === arg}`,
  ].join(' ');
  return { ctor, optionsAfter, trace: scenario.steps.map((s) => applyStep(api, h, s)) };
}

// JSON.stringify drops undefined/NaN differences we want to see.
function replacer(_k, v) {
  if (typeof v === 'number' && !Number.isFinite(v)) return `#${v}`;
  if (v === undefined) return '#undefined';
  return v;
}

/**
 * Run the first `cut` steps on `from`, move the state with getState()/setState()
 * onto a brand new instance of `to`, run the rest there. Returns the trace of
 * the remaining steps plus the state that was moved.
 */
export function runHandoff(from, to, family, options, scenario, cut) {
  const a = make(from, family, options === undefined ? undefined : structuredClone(options));
  const head = scenario.steps.slice(0, cut).map((s) => applyStep(from, a, s));
  const moved = stateJson(a);
  const b = make(to, family, options === undefined ? undefined : structuredClone(options));
  const set = applyStep(to, b, { op: 'setState', state: moved });
  const tail = scenario.steps.slice(cut).map((s) => applyStep(to, b, s));
  return { head, moved, set, tail };
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/** With `loose`, a thrown error is compared by its class only ("!TypeError: ..." -> "!TypeError"). */
const normalizer = (loose) => (loose ? (v) => (typeof v === 'string' && v.startsWith('!') ? v.replace(/:[\s\S]*$/, '') : v) : (v) => v);

/**
 * Returns null when equal, else a short description of the first difference.
 * `opts.loose` compares thrown errors by class only (for the v2 model, see v2-model.mjs).
 */
export function diffRuns(expected, actual, opts = {}) {
  const n = normalizer(opts.loose);
  if (n(expected.ctor) !== n(actual.ctor)) {
    return `constructor: expected ${expected.ctor}, got ${actual.ctor}`;
  }
  if (expected.optionsAfter !== actual.optionsAfter) {
    return `options after construction: expected ${expected.optionsAfter}, got ${actual.optionsAfter}`;
  }
  for (let i = 0; i < expected.trace.length; i++) {
    const e = expected.trace[i];
    const a = actual.trace[i];
    for (const k of Object.keys(e)) {
      if (n(e[k]) !== n(a[k])) return `step ${i} (${e.op}) ${k}:\n  expected ${trunc(e[k])}\n  actual   ${trunc(a[k])}`;
    }
  }
  return null;
}

const trunc = (s) => (typeof s === 'string' && s.length > 400 ? `${s.slice(0, 400)}…(${s.length} chars)` : s);

/** Compare the tail of a handoff run with the matching tail of a straight-through oracle run. */
export function diffHandoff(straight, handoff, cut, opts = {}) {
  const n = normalizer(opts.loose);
  const expectedTail = straight.trace.slice(cut);
  if (handoff.set.r !== 'ok') return `setState failed: ${handoff.set.r}`;
  for (let i = 0; i < expectedTail.length; i++) {
    const e = expectedTail[i];
    const a = handoff.tail[i];
    for (const k of Object.keys(e)) {
      if (n(e[k]) !== n(a[k])) return `step ${cut + i} (${e.op}) after handoff ${k}:\n  expected ${trunc(e[k])}\n  actual   ${trunc(a[k])}`;
    }
  }
  return null;
}

/** Everything needed to replay a failure by hand. */
export function reproduction({ seed, label, iteration, options, scenario, cut }) {
  return [
    `FUZZ_SEED=${seed}  cell=${label}  iteration=${iteration}${cut === undefined ? '' : `  handoff-cut=${cut}`}`,
    `options: ${JSON.stringify(options, replacer)}`,
    `scenario: ${JSON.stringify(scenario)}`,
  ].join('\n');
}
