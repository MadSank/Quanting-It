// Quatinit site: particle story, Eve's dial, copy button.
import { sha256Bits, seal, onStep, bb84, reduced } from './crypto.js';

const $ = (s) => document.querySelector(s);
const css = getComputedStyle(document.documentElement);
const C = (n) => css.getPropertyValue(n).trim();
const DEFAULT = 'meet me at the north gate at nine';
const text = () => ($('#text').value.trim() || DEFAULT).slice(0, 48);

/* ---------- the particle story ---------- */
const cv = $('#cv'), ctx = cv.getContext('2d');
let W = 0, H = 0, step = 0, parts = [], bits = '', ct = '', t0 = 0, errs = 0, seen = 0;
const PHOTONS = 20, MORPH = 900;

function size() {
  const r = cv.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 2);
  W = r.width; H = r.height; cv.width = W * d; cv.height = H * d; ctx.setTransform(d, 0, 0, d, 0, 0);
}
function flow(str, font, px, lh, maxW, x0, cy) {
  ctx.font = `${px}px ${font}`;
  const lines = [[]]; let w = 0;
  for (const word of str.split(' ')) {
    const ww = ctx.measureText(word + ' ').width;
    if (w + ww > maxW && lines.at(-1).length) { lines.push([]); w = 0; }
    lines.at(-1).push(word); w += ww;
  }
  const out = [], top = cy - (lines.length * lh) / 2;
  lines.forEach((ln, li) => {
    let x = x0;
    for (const ch of ln.join(' ')) { out.push({ ch, x, y: top + li * lh, size: px, font }); x += ctx.measureText(ch).width; }
    out.push({ ch: ' ', x, y: top + li * lh, size: px, font, hide: true });
  });
  return out;
}
function grid(str, cols, px, gap, cx, cy, font) {
  const rows = Math.ceil(str.length / cols), lh = px * 1.5;
  return [...str].map((ch, i) => ({ ch, x: cx + (i % cols) * gap - ((cols - 1) * gap) / 2, y: cy + Math.floor(i / cols) * lh - (rows * lh) / 2, size: px, font }));
}
function targets(s) {
  const serif = C('--font-display'), mono = C('--font-outlier'), mid = H / 2 - 20, px = Math.max(26, Math.min(56, W / 9));
  if (s === 0 || s === 5) return flow(text(), serif, px, px * 1.08, W - 40, 20, mid).map((p) => ({ ...p, col: s === 5 ? '--color-live' : '--color-ink' }));
  if (s === 1) return grid(bits, 8, Math.min(26, W / 16), Math.min(40, W / 10), W / 2, mid, mono).map((p) => ({ ...p, col: '--color-accent' }));
  if (s === 2 || s === 3) return [...Array(PHOTONS)].map((_, i) => ({ ch: '|/-\\'[i % 4], x: 0, y: mid, size: Math.min(24, W / 18), font: mono, beam: i, col: '--color-accent' }));
  if (s === 4) { const cols = W < 480 ? 12 : 16; return grid(ct.slice(0, cols * 4), cols, Math.min(18, W / 24), Math.min(28, (W - 40) / cols), W / 2, mid, mono).map((p) => ({ ...p, col: '--color-accent' })); }
  return [];
}
function layout(s, snap = false) {
  const tg = targets(s);
  while (parts.length < tg.length) parts.push({ x: W / 2, y: H / 2, a: 0, size: 20, ch: ' ', font: C('--font-outlier'), col: '--color-ink' });
  parts.forEach((p, i) => {
    const t = tg[i];
    p.fx = p.x; p.fy = p.y; p.fa = p.a; p.fs = p.size; p.tapped = false;
    if (t) Object.assign(p, { tx: t.x, ty: t.y, ta: t.hide ? 0 : 1, ts: t.size, nch: t.ch, nfont: t.font, ncol: t.col, beam: t.beam });
    else Object.assign(p, { tx: p.x, ty: p.y + 24, ta: 0, ts: p.size, nch: p.ch, nfont: p.font, ncol: p.col, beam: undefined });
    p.delay = snap || reduced() ? 0 : Math.random() * 0.35;
  });
  t0 = snap ? -1e9 : performance.now(); errs = 0; seen = 0;
}
const ease = (x) => 1 - Math.pow(1 - x, 3);
function frame(now) {
  ctx.clearRect(0, 0, W, H);
  const lane = H / 2 - 20, eveX = W / 2, still = reduced();
  if (step === 2 || step === 3) {
    ctx.strokeStyle = C('--color-rule-2'); ctx.setLineDash([4, 6]); ctx.beginPath(); ctx.moveTo(20, lane + 10); ctx.lineTo(W - 20, lane + 10); ctx.stroke(); ctx.setLineDash([]);
    ctx.font = `14px ${C('--font-body')}`; ctx.fillStyle = C('--color-muted'); ctx.textAlign = 'left'; ctx.fillText('alice', 20, lane - 30);
    ctx.textAlign = 'right'; ctx.fillText('bob', W - 20, lane - 30); ctx.textAlign = 'left';
    if (step === 3) { ctx.strokeStyle = C('--color-accent-2'); ctx.strokeRect(eveX - 40, lane - 30, 80, 70); ctx.fillStyle = C('--color-accent-2'); ctx.textAlign = 'center'; ctx.fillText('eve', eveX, lane - 40); ctx.textAlign = 'left'; }
  }
  for (const p of parts) {
    const k = still ? 1 : Math.min(1, Math.max(0, (now - t0) / MORPH - p.delay)), e = ease(k);
    if (k >= 0.5) { p.ch = p.nch; p.font = p.nfont; p.col = p.ncol; }
    let tx = p.tx, ty = p.ty;
    if (p.beam !== undefined) {
      ty = lane;
      if (k >= 1 && !still) {
        const pos = ((now / 1000) * 0.12 + p.beam / PHOTONS) % 1; tx = 30 + pos * (W - 60);
        if (pos < 0.02) p.tapped = false;
        if (step === 3 && !p.counted && Math.abs(tx - eveX) < 4) { p.counted = true; p.tapped = Math.random() < 0.25; seen++; if (p.tapped) errs++; }
        if (Math.abs(tx - eveX) > 8) p.counted = false;
      } else tx = 30 + (p.beam / PHOTONS) * (W - 60);
    }
    p.x = p.fx + (tx - p.fx) * e; p.y = p.fy + (ty - p.fy) * e; p.a = p.fa + (p.ta - p.fa) * e; p.size = p.fs + (p.ts - p.fs) * e;
    if (p.a < 0.02) continue;
    ctx.globalAlpha = p.a; ctx.font = `${p.size}px ${p.font}`;
    ctx.fillStyle = C(p.tapped && step === 3 && tx > eveX ? '--color-accent-2' : p.col);
    ctx.fillText(p.ch, p.x, p.y + p.size);
  }
  ctx.globalAlpha = 1;
  meter();
  if (!still) requestAnimationFrame(frame);
}
function meter() {
  const m = $('#meter');
  if (step === 3) {
    const q = seen ? errs / seen : 0;
    m.innerHTML = `errors at bob <b class="${q > 0.11 ? 'bad' : ''}">${Math.round(q * 100)}%</b>${seen > 6 && q > 0.11 ? ', key thrown away' : ''}`;
  } else if (step === 2) m.innerHTML = 'errors at bob <b>1.5%</b>';
  else m.textContent = '';
}
const WHERE = ['alice’s screen', 'alice signs', 'the fibre', 'the fibre, tapped', 'the wire', 'bob’s screen'];
async function refresh() { bits = await sha256Bits(text()); ct = await seal(text()); }
function redrawStill() { if (reduced()) requestAnimationFrame(frame); }

size();
addEventListener('resize', () => { size(); layout(step, true); redrawStill(); });
onStep((s) => { step = s; $('#where').textContent = WHERE[s]; layout(s); redrawStill(); });
$('#text').addEventListener('input', async () => { await refresh(); layout(step); redrawStill(); });
$('#compose').addEventListener('submit', (e) => { e.preventDefault(); $('#story').scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth' }); });
await refresh(); layout(0, true); requestAnimationFrame(frame);

/* ---------- hero teaser: letters flicker into ciphertext ---------- */
const teaser = $('#teaser');
let mix = 0, dir = 1;
function tease() {
  const t = text(), h = ct || '';
  teaser.innerHTML = [...t].map((c, i) => {
    const on = c !== ' ' && ((i * 7919) % 100) / 100 < mix;
    return on ? `<span class="x">${h[(i * 2) % Math.max(1, h.length)] || '0'}</span>` : c.replace(/[&<>]/g, (x) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[x]));
  }).join('');
}
if (reduced()) { mix = 0.5; tease(); }
else setInterval(() => { mix += dir * 0.04; if (mix > 1.15 || mix < -0.15) dir *= -1; tease(); }, 90);
$('#text').addEventListener('input', tease);

/* ---------- Eve's dial ---------- */
const frac = $('#frac');
function dial() {
  const f = +frac.value / 100, r = bb84(3000, f), q = r.qber, abort = q > 0.11;
  $('#fracOut').textContent = `${frac.value}%`;
  $('#qber').textContent = `${(q * 100).toFixed(1)}%`; $('#qber').classList.toggle('bad', abort);
  $('#kept').textContent = r.sifted.toLocaleString('en-GB');
  const bar = $('#bar'); bar.style.transform = `scaleX(${Math.min(q / 0.30, 1)})`; bar.classList.toggle('bad', abort);
  $('#verdict').textContent = f === 0 ? 'Nobody listening. The errors are the fibre’s own.'
    : abort ? `Caught. Bob throws the key away, so nothing Eve learned is ever used.`
    : `Under the line, for now. Eve has touched ${Math.round(f * 100)}% of the photons but knows for sure only about half of those bits.`;
}
frac.addEventListener('input', dial); $('#rerun').addEventListener('click', dial); dial();

/* ---------- copy the run commands ---------- */
$('#copy').addEventListener('click', async (e) => {
  const lines = $('#cmds').innerText.split('\n').map((l) => l.replace(/^\$\s*/, '')).join('\n');
  try { await navigator.clipboard.writeText(lines); e.currentTarget.textContent = 'Copied'; }
  catch { e.currentTarget.textContent = 'Select and copy above'; }
  setTimeout(() => { $('#copy').textContent = 'Copy commands'; }, 1600);
});
