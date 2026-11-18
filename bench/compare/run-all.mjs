#!/usr/bin/env node
// Runs bench/compare/run.mjs under every runtime found on PATH (node, bun, deno), one after another,
// then writes the report. Extra arguments go to every run (for example --quick or --algorithms).
//
//   node bench/compare/run-all.mjs [--machine name] [--runtimes node,bun,deno] [run.mjs options]
//
// --machine names the computer in the result labels (default: the host name), so results from
// several machines can sit side by side in bench/results/.
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
const args = process.argv.slice(2);
const take = (name) => {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return null;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
const machine = (take('machine') ?? os.hostname()).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
const wanted = (take('runtimes') ?? 'node,bun,deno').split(',');
const win = process.platform === 'win32';

const version = (cmd) => {
  const r = spawnSync(cmd, ['--version'], { encoding: 'utf8', shell: win });
  if (r.status !== 0) return null;
  const m = /(\d+)\.\d+/.exec(r.stdout);
  return m ? m[1] : '';
};

const script = join(HERE, 'run.mjs');
const ran = [];
for (const rt of wanted) {
  const major = version(rt);
  if (major === null) {
    console.error(`== ${rt}: not found on PATH, skipped`);
    continue;
  }
  const label = `${machine}-${rt}${major}`;
  const argv = rt === 'deno' ? ['run', '-A', script] : [script];
  console.error(`\n== ${rt} (label ${label})`);
  const r = spawnSync(rt, [...argv, '--label', label, ...args], { cwd: REPO, stdio: 'inherit', shell: win });
  if (r.status !== 0) {
    console.error(`== ${rt} failed with status ${r.status}`);
    process.exitCode = 1;
  } else ran.push(label);
}
if (ran.length) {
  spawnSync(process.execPath, [join(HERE, 'report.mjs')], { cwd: REPO, stdio: 'inherit' });
}
