// Grouped horizontal bar chart (speedup per algorithm at two input sizes) as a standalone SVG.
// Colors are the documented categorical slots 1 and 2 (blue, orange), stepped for light and dark
// surfaces; the SVG switches with prefers-color-scheme because GitHub renders it as an <img>.

const W = 760;
const LEFT = 118;
const RIGHT = 28;
const TOP = 64;
const ROW = 24;
const BAR = 8;
const GAP = 2;

const niceMax = (v) => {
  for (const step of [2, 5, 10]) if (v <= Math.ceil(v / step) * step && v < 40) return Math.ceil(v / step) * step;
  return Math.ceil(v / 10) * 10;
};

export function renderChart({ rows, labelA, labelB }) {
  const max = niceMax(Math.max(...rows.flatMap((r) => [r.a ?? 0, r.b ?? 0]), 2));
  const step = max <= 10 ? 2 : max <= 20 ? 5 : 10;
  const plotW = W - LEFT - RIGHT;
  const H = TOP + rows.length * ROW + 40;
  const sx = (v) => LEFT + (Math.max(v, 0) / max) * plotW;
  const bar = (v, y, cls) => {
    if (v == null) return '';
    const w = Math.max(sx(v) - LEFT, 1);
    // 4px rounded data end, square baseline end.
    const r = Math.min(4, w, BAR / 2);
    return `<path class="${cls}" d="M${LEFT} ${y} h${w - r} a${r} ${r} 0 0 1 ${r} ${r} v${BAR - 2 * r} a${r} ${r} 0 0 1 -${r} ${r} h-${w - r} z"><title>${v.toFixed(2)}×</title></path>`;
  };
  const ticks = [];
  for (let v = 0; v <= max; v += step) ticks.push(v);
  const grid = ticks.map((v) => `<line class="grid" x1="${sx(v)}" x2="${sx(v)}" y1="${TOP - 8}" y2="${TOP + rows.length * ROW}"/><text class="muted" x="${sx(v)}" y="${TOP + rows.length * ROW + 16}" text-anchor="middle">${v}×</text>`).join('');
  const body = rows.map((r, i) => {
    const y0 = TOP + i * ROW;
    return `<text class="label" x="${LEFT - 10}" y="${y0 + 13}" text-anchor="end">${r.name}</text>${bar(r.a, y0 + 3, 'a')}${bar(r.b, y0 + 3 + BAR + GAP, 'b')}`;
  }).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" role="img" aria-label="Speedup of v1 over crypto-api 0.8.5 per algorithm at ${labelA} and ${labelB} inputs">
<style>
svg{--bg:#fcfcfb;--ink:#0b0b0b;--muted:#52514e;--grid:#e6e5e1;--a:#2a78d6;--b:#eb6834;font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:12px}
@media (prefers-color-scheme:dark){svg{--bg:#1a1a19;--ink:#f0efec;--muted:#c3c2b7;--grid:#34332f;--a:#3987e5;--b:#d95926}}
.bg{fill:var(--bg)}.label{fill:var(--ink)}.muted{fill:var(--muted)}.grid{stroke:var(--grid);stroke-width:1}.base{stroke:var(--muted);stroke-width:1.5}
.a{fill:var(--a)}.b{fill:var(--b)}.title{font-size:15px;font-weight:600;fill:var(--ink)}
</style>
<rect class="bg" width="${W}" height="${H}"/>
<text class="title" x="${LEFT - 100 + 12}" y="24">Speedup of v1 over crypto-api 0.8.5 (higher is faster)</text>
<text class="muted" x="${LEFT - 100 + 12}" y="42">new + update + finalize, one call; Node 22</text>
<rect class="a" x="${W - 190}" y="16" width="10" height="10" rx="2"/><text class="label" x="${W - 174}" y="25">${labelA}</text>
<rect class="b" x="${W - 120}" y="16" width="10" height="10" rx="2"/><text class="label" x="${W - 104}" y="25">${labelB}</text>
${grid}
<line class="base" x1="${sx(1)}" x2="${sx(1)}" y1="${TOP - 8}" y2="${TOP + rows.length * ROW}"/>
<text class="muted" x="${sx(1) + 6}" y="${TOP + rows.length * ROW + 32}">1× = same speed as 0.8.5</text>
${body}
</svg>
`;
}
