// One cold start: import a module, make the first digest, make a second one. Prints JSON.
// Run by bench/startup.mjs in a fresh process each time (so nothing is warm).
import { pathToFileURL } from 'node:url';

const [file, kind] = process.argv.slice(2);
const t0 = performance.now();
const mod = await import(pathToFileURL(file).href);
const t1 = performance.now();
const once = () => {
  if (kind === 'api') return mod.default.hash('md5', 'hello');
  const h = new mod.default();
  h.update('hello');
  return h.finalize();
};
once();
const t2 = performance.now();
once();
const t3 = performance.now();
console.log(JSON.stringify({ import: t1 - t0, first: t2 - t1, second: t3 - t2 }));
