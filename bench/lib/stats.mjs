// Timing core: calibrated, interleaved, median/p95. No dependencies.
//
// measureGroup() takes several contenders that do the same work and times them
// in round-robin order (A, B, C, A, B, C, ...), so slow drift of the machine
// (thermal, noisy neighbours, GC pressure) hits every contender equally.

export const now = () => performance.now();

/** Defeats dead-code elimination: every result's length ends up here. */
export let sink = 0;
const consume = (r) => {
  sink += r === undefined || r === null ? 0 : r.length === undefined ? 1 : r.length;
};

export function quantile(sorted, q) {
  if (sorted.length === 0) return NaN;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

export function summarize(perOp) {
  const sorted = [...perOp].sort((a, b) => a - b);
  return {
    median: quantile(sorted, 0.5),
    p95: quantile(sorted, 0.95),
    min: sorted[0],
    max: sorted[sorted.length - 1],
    samples: sorted.length,
  };
}

function runBatch(fn, iters) {
  const t0 = now();
  for (let i = 0; i < iters; i++) consume(fn());
  return now() - t0;
}

/**
 * @param {{name: string, fn: () => any}[]} contenders
 * @param {{samples?: number, minSampleMs?: number, warmupMs?: number, slowSamples?: number}} [o]
 * @returns {Object<string, {median:number,p95:number,min:number,max:number,samples:number,iters:number}>}
 *   times in milliseconds per operation
 */
export function measureGroup(contenders, o = {}) {
  const { samples: wantSamples = 15, minSampleMs = 25, warmupMs = 80, slowSamples = 5 } = o;

  // Warm-up and calibration, per contender.
  const iters = [];
  let slowest = 0;
  for (const c of contenders) {
    const w0 = now();
    let calls = 0;
    let last = 0;
    while (calls < 2 || now() - w0 < warmupMs) {
      const t = now();
      consume(c.fn());
      last = now() - t;
      calls++;
      if (last > 200 && calls >= 1) break; // very slow op: one warm call is enough
    }
    // Calibrate the iteration count so one sample takes about minSampleMs.
    let n = 1;
    for (let round = 0; round < 4; round++) {
      const t = runBatch(c.fn, n);
      if (t >= minSampleMs * 0.8 && t <= minSampleMs * 3) break;
      n = Math.max(1, Math.ceil((n * minSampleMs * 1.1) / Math.max(t, 1e-4)));
    }
    iters.push(n);
    slowest = Math.max(slowest, last);
  }

  // Slow operations (hundreds of ms and up) get fewer samples; the rest get the full count.
  const samples = slowest > 500 ? slowInt(slowSamples) : wantSamples;
  const per = contenders.map(() => []);
  for (let s = 0; s < samples; s++) {
    for (let i = 0; i < contenders.length; i++) {
      per[i].push(runBatch(contenders[i].fn, iters[i]) / iters[i]);
    }
  }
  const out = {};
  contenders.forEach((c, i) => {
    out[c.name] = { ...summarize(per[i]), iters: iters[i] };
  });
  return out;
}

const slowInt = (n) => Math.max(1, Math.floor(n));

/** Geometric mean of positive numbers. */
export function geomean(xs) {
  const v = xs.filter((x) => x > 0 && Number.isFinite(x));
  return v.length ? Math.exp(v.reduce((a, x) => a + Math.log(x), 0) / v.length) : NaN;
}

export function median(xs) {
  return quantile([...xs].sort((a, b) => a - b), 0.5);
}
