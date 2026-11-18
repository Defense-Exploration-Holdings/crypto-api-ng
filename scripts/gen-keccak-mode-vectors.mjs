// Writes test/vectors/keccak-modes/{sp800-185,kangarootwelve}.json from published test vectors, so
// the tests do not depend on a network or on third-party code:
//
//   sp800-185.json       the NIST SP 800-185 samples (cSHAKE, KMAC, KMACXOF, TupleHash, TupleHashXOF,
//                        ParallelHash, ParallelHashXOF) as the Keccak team lists them in
//                        tests/UnitTests/testSP800-185.c of XKCP (github.com/XKCP/XKCP)
//   kangarootwelve.json  the RFC 9861 vectors: KT128 from tests/TestVectors/KangarooTwelve.txt of XKCP,
//                        TurboSHAKE128/256 from lib/Crypto/SelfTest/Hash/test_TurboSHAKE.py of
//                        PyCryptodome, KT256 from lib/std/crypto/kangarootwelve.zig of Zig 0.17.1
//
// The files are only parsed as text, nothing in them is run.
//
//   node scripts/gen-keccak-mode-vectors.mjs <testSP800-185.c> <KangarooTwelve.txt> <test_TurboSHAKE.py> <kangarootwelve.zig>
import { readFileSync, writeFileSync } from 'node:fs';

const [spPath, ktPath, turboPath, zigPath] = process.argv.slice(2);
if (!zigPath) {
  console.error('usage: node scripts/gen-keccak-mode-vectors.mjs <testSP800-185.c> <KangarooTwelve.txt> <test_TurboSHAKE.py> <kangarootwelve.zig>');
  process.exit(2);
}
const out = new URL('../test/vectors/keccak-modes/', import.meta.url);
const write = (name, rows) => writeFileSync(new URL(name, out), JSON.stringify(rows, null, 0).replace(/\},\{"/g, '},\n{"') + '\n');
const toHex = (s) => Buffer.from(s, 'latin1').toString('hex');

// ---- SP 800-185 ---------------------------------------------------------------------------------

const c = readFileSync(spPath, 'utf8');

/** A C string literal (several adjacent pieces) with \xHH escapes, as a binary string. */
function cString(text) {
  let s = '';
  for (const piece of text.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    s += piece[1].replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
  return s;
}

/** `const BitSequence *NAME = (const BitSequence *) "..." "...";` definitions in `text`. */
function definitions(text) {
  const map = {};
  for (const m of text.matchAll(/const\s+BitSequence\s+\*(\w+)\s*=\s*\(const\s+BitSequence\s*\*\)((?:\s*"(?:[^"\\]|\\.)*")+)\s*;/g)) {
    map[m[1]] = cString(m[2]);
  }
  return map;
}

/** The body of `static void <name>(void)` and its top-level `{ ... }` test blocks. */
function testBlocks(name) {
  const start = c.indexOf(`static void ${name}(void)`);
  if (start < 0) throw new Error(`no function ${name}`);
  const end = c.indexOf('\n}\n', start);
  const body = c.slice(start, end);
  const blocks = [...body.matchAll(/\n {4}\{\n([\s\S]*?)\n {4}\}/g)].map((m) => m[1]);
  return { shared: definitions(body.replace(/\n {4}\{\n[\s\S]*?\n {4}\}/g, '')), blocks };
}

const sp = [];
const add = (row) => sp.push(row);

for (const [fn, xof] of [['performTestcSHAKE_NIST', false]]) {
  for (const block of testBlocks(fn).blocks) {
    const d = definitions(block);
    const m = block.match(/cSHAKE(128|256)\( data, (\d+), output, (\d+),/);
    add({ algo: 'cshake', strength: Number(m[1]), xof, input: toHex(d.data), functionName: d.N, customization: d.S, length: Number(m[3]), output: toHex(d.O) });
    if (d.data.length * 8 !== Number(m[2])) throw new Error('cSHAKE input length');
  }
}
for (const [fn, xof] of [['performTestKMAC_NIST', false], ['performTestKMACXOF_NIST', true]]) {
  for (const block of testBlocks(fn).blocks) {
    const d = definitions(block);
    const m = xof ?
      block.match(/KMAC(128|256)_Squeeze\(&km, output, (\d+)\)/) :
      block.match(/KMAC(128|256)\( K, \d+, data, \d+, output, (\d+),/);
    add({ algo: 'kmac', strength: Number(m[1]), xof, key: toHex(d.K), input: toHex(d.data), customization: d.S, length: Number(m[2]), output: toHex(d.O) });
  }
}
for (const [fn, xof] of [['performTestTupleHash_NIST', false], ['performTestTupleHashXOF_NIST', true]]) {
  const { shared, blocks } = testBlocks(fn);
  for (const block of blocks) {
    const d = Object.assign({}, shared, definitions(block));
    const tuple = [...block.matchAll(/tuple\[\d\]\.input = (\w+);/g)].map((t) => toHex(d[t[1]]));
    let strength, count, length, custom;
    if (xof) {
      const init = block.match(/TupleHash(128|256)_Initialize\(&th, 0, (\w+),/);
      [strength, custom] = [init[1], init[2]];
      count = block.match(/_Update\(&th, tuple, (\d)\)/)[1];
      length = block.match(/_Squeeze\(&th, output, (\d+)\)/)[1];
    } else {
      const m = block.match(/TupleHash(128|256)\( tuple, (\d), output, (\d+), (\w+),/);
      [strength, count, length, custom] = [m[1], m[2], m[3], m[4]];
    }
    if (Number(count) !== tuple.length) throw new Error('tuple size');
    add({ algo: 'tuplehash', strength: Number(strength), xof, tuple, customization: d[custom], length: Number(length), output: toHex(d.O) });
  }
}
for (const [fn, xof] of [['performTestParallelHash_NIST', false], ['performTestParallelHashXOF_NIST', true]]) {
  const { shared, blocks } = testBlocks(fn);
  for (const block of blocks) {
    const d = Object.assign({}, shared, definitions(block));
    let strength, blockSize, custom, length;
    if (xof) {
      const init = block.match(/ParallelHash(128|256)_Initialize\(&ph, (\d+), 0, (\w+),/);
      [strength, blockSize, custom] = [init[1], init[2], init[3]];
      length = block.match(/_Squeeze\(&ph, output, (\d+)\)/)[1];
    } else {
      const m = block.match(/ParallelHash(128|256)\( X192, 192, (\d+), output, (\d+), (\w+),/);
      [strength, blockSize, length, custom] = [m[1], m[2], m[3], m[4]];
    }
    add({ algo: 'parallelhash', strength: Number(strength), xof, blockSize: Number(blockSize), input: toHex(d.X192), customization: d[custom], length: Number(length), output: toHex(d.O) });
  }
}
for (const row of sp) {
  if (row.output.length !== row.length / 4) throw new Error(`${row.algo}: output length`);
}
write('sp800-185.json', sp);

// ---- RFC 9861 -----------------------------------------------------------------------------------

// A message or customization: {pattern: n} is 00 01 .. FA repeated to n bytes, {ff: n} is n bytes FF.
const kt = [];
const kText = readFileSync(ktPath, 'utf8');
for (const m of kText.matchAll(/KangarooTwelve\(M=([^,]+), C=([^,]+), (\d+) bytes\)(, last (\d+) bytes)?:\n([0-9a-f ]+)/g)) {
  const spec = (s) => {
    if (s === 'empty') return { pattern: 0 };
    let p = s.match(/^pattern 0x00 to 0xFA for (\d+)\^(\d+) bytes$/);
    if (p) return { pattern: Number(p[1]) ** Number(p[2]) };
    p = s.match(/^(\d+) times byte 0xFF$/);
    if (p) return { ff: Number(p[1]) };
    throw new Error(`unknown spec ${s}`);
  };
  const output = m[6].replace(/ /g, '');
  const length = Number(m[3]);
  kt.push({ algo: 'kt128', message: spec(m[1]), customization: spec(m[2]), length, skip: m[5] ? length - Number(m[5]) : 0, output });
}
if (kt.length < 14) throw new Error('expected 14 KT128 vectors');

const py = readFileSync(turboPath, 'utf8');
for (const [cls, strength] of [['TestTurboSHAKE128TV', 128], ['TestTurboSHAKE256TV', 256]]) {
  const start = py.indexOf(`class ${cls}`);
  const next = py.indexOf('\nclass ', start + 1);
  const body = py.slice(start, next < 0 ? undefined : next);
  for (const t of body.split(/\n {4}def test_/).slice(1)) {
    const tv = t.match(/tv = """([\s\S]*?)"""/)[1].replace(/\s+/g, '').toLowerCase();
    const call = t.match(/res = TurboSHAKE\d+\.new\((.*)\)\.read\((\d+)\)(\[-(\d+):\])?/);
    const args = call[1];
    let message = { pattern: 0 };
    let p;
    if ((p = args.match(/data=ptn\((\d+)(?:\*\*(\d+))?\)/))) message = { pattern: Number(p[1]) ** Number(p[2] ?? 1) };
    else if ((p = args.match(/data=b"((?:\\xff)+)"(?: \* (\d+))?/))) message = { ff: (p[1].length / 4) * Number(p[2] ?? 1) };
    else if (/data=data/.test(args)) {
      p = t.match(/data = ptn\((\d+)\*\*(\d+)\)/);
      message = { pattern: Number(p[1]) ** Number(p[2]) };
    } else if (args.trim() !== '' && !/^domain=/.test(args.trim())) throw new Error(`unknown TurboSHAKE input ${args}`);
    const domain = (p = args.match(/domain=0x([0-9A-Fa-f]{2})/)) ? parseInt(p[1], 16) : 0x1f;
    const length = Number(call[2]);
    kt.push({ algo: `turboshake${strength}`, message, domain, length, skip: call[4] ? length - Number(call[4]) : 0, output: tv });
  }
}

const zig = readFileSync(zigPath, 'utf8');
for (const m of zig.matchAll(/test "KT256: (empty|pattern) message(?: \((\d+) bytes?\))?, empty customization, (\d+) bytes"[\s\S]*?hexToBytes\(&expected, "([0-9A-F]+)"\)/g)) {
  kt.push({ algo: 'kt256', message: { pattern: m[1] === 'empty' ? 0 : Number(m[2]) }, customization: { pattern: 0 }, length: Number(m[3]), skip: 0, output: m[4].toLowerCase() });
}
for (const row of kt) {
  if (row.output.length !== 2 * (row.length - row.skip)) throw new Error(`${row.algo}: output length`);
}
write('kangarootwelve.json', kt);
console.log(`sp800-185.json: ${sp.length} rows, kangarootwelve.json: ${kt.length} rows`);
