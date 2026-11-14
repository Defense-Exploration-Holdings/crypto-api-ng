// Small seeded PRNG (xoshiro128**) so every fuzz failure is reproducible from
// (FUZZ_SEED, cell label, iteration).

function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function splitmix32(a) {
  return () => {
    a = (a + 0x9e3779b9) | 0;
    let t = a ^ (a >>> 16);
    t = Math.imul(t, 0x21f0aaad);
    t ^= t >>> 15;
    t = Math.imul(t, 0x735a2d97);
    return (t ^ (t >>> 15)) >>> 0;
  };
}

export class Rng {
  /** @param {number|string} seed @param {string} [stream] independent stream name */
  constructor(seed, stream = '') {
    const sm = splitmix32((typeof seed === 'number' ? seed : fnv1a(String(seed))) ^ fnv1a(stream));
    this.s = [sm(), sm(), sm(), sm()];
    if (this.s.every((v) => v === 0)) this.s[0] = 1;
  }

  /** uint32 */
  next() {
    const s = this.s;
    const result = Math.imul(rotl(Math.imul(s[1], 5), 7), 9) >>> 0;
    const t = s[1] << 9;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 11);
    return result;
  }

  /** integer in [0, n) */
  int(n) { return n <= 1 ? 0 : this.next() % n; }
  /** integer in [lo, hi] */
  range(lo, hi) { return lo + this.int(hi - lo + 1); }
  pick(list) { return list[this.int(list.length)]; }
  chance(p) { return this.next() / 0x100000000 < p; }

  /** Binary string of `n` bytes (code units 0..255). Mix of uniform noise and structured fills. */
  bytes(n) {
    const mode = this.int(8);
    let s = '';
    if (mode === 0) return String.fromCharCode(this.int(256)).repeat(n); // constant fill
    for (let i = 0; i < n; i++) {
      s += String.fromCharCode(mode === 1 ? 0x61 + this.int(26) : this.int(256));
    }
    return s;
  }

  /** String with code units above 0xFF mixed in (what a careless caller passes to update()). */
  wide(n) {
    let s = '';
    for (let i = 0; i < n; i++) {
      const r = this.int(6);
      s += String.fromCharCode(r === 0 ? 0x100 + this.int(0xff00) : r === 1 ? 0xd800 + this.int(0x800) : this.int(256));
    }
    return s;
  }
}

const rotl = (x, k) => (x << k) | (x >>> (32 - k));
