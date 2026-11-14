// Records where a benchmark ran, so numbers are never shown without their machine.
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { REPO } from './trees.mjs';

const sh = (cmd, args) => {
  try {
    return execFileSync(cmd, args, { cwd: REPO, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
};

export async function environment() {
  const bun = typeof Bun !== 'undefined';
  const cpus = os.cpus();
  return {
    runtime: bun ? 'bun' : 'node',
    runtime_version: bun ? Bun.version : process.versions.node,
    v8: process.versions.v8 ?? null,
    platform: `${os.platform()} ${os.arch()} ${os.release()}`,
    cpu: cpus[0]?.model ?? 'unknown',
    cpu_count: cpus.length,
    memory_mb: Math.round(os.totalmem() / 1048576),
    zig: sh('zig', ['version']),
    commit: sh('git', ['rev-parse', '--short', 'HEAD']),
    original: sh('git', ['-C', 'crypto-api', 'rev-parse', '--short', 'HEAD']),
    note: 'Shared cloud sandbox, not a quiet dedicated machine.',
  };
}
