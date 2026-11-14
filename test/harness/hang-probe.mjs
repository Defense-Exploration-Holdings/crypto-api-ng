// Child process for divergences.test.js: constructs a hasher, hashes "abc", and
// prints the name of the error (or "ok <digest>"). A hang is detected by the parent's timeout.
import './register.mjs';
const [, , which, familyId, optionsJson] = process.argv;
const { loadOracle, loadTarget, make } = await import('./load.mjs');
const { FAMILIES } = await import('./catalog.mjs');
const api = which === 'oracle' ? await loadOracle() : await loadTarget();
try {
  const h = make(api, FAMILIES.find((f) => f.id === familyId), JSON.parse(optionsJson));
  h.update('abc');
  console.log(`ok ${api.toHex(h.finalize())}`);
} catch (e) {
  console.log(`${e.constructor.name}: ${e.message}`);
}
