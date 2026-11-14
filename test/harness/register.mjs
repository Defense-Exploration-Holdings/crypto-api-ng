// Registers the resolve hook. Use as `node --import ./test/harness/register.mjs`
// or import it before any dynamic import() of oracle / target modules.
import { register } from 'node:module';

let done = false;
export function ensureHook() {
  if (done) return;
  register('./hook.mjs', import.meta.url);
  done = true;
}
ensureHook();
