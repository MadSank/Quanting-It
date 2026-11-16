// Shared helpers for the Lumen variants: real crypto in the browser and a scroll-step observer.
export const enc = new TextEncoder();
export const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
export async function sha256Bits(text, n = 32) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  return Array.from(h.slice(0, Math.ceil(n / 8)), (b) => b.toString(2).padStart(8, '0')).join('').slice(0, n);
}
export async function seal(text) { // AES-256-GCM with a fresh random key
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return hex(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text))));
}
export function onStep(cb) {
  const io = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return;
    document.querySelectorAll('.step').forEach((x) => x.classList.toggle('on', x === e.target));
    cb(+e.target.dataset.s, e.target);
  }), { rootMargin: '-45% 0px -45% 0px' });
  document.querySelectorAll('.step').forEach((s) => io.observe(s));
}
export const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
// One BB84 run over n photons; eve = fraction of photons Eve measures.
export function bb84(n, eve) {
  let sifted = 0, errs = 0; const trace = [];
  for (let i = 0; i < n; i++) {
    const a = Math.random() < .5 ? 0 : 1, bit = Math.random() < .5 ? 0 : 1, b = Math.random() < .5 ? 0 : 1;
    let s = { basis: a, bit }, tapped = Math.random() < eve;
    if (tapped) { const e = Math.random() < .5 ? 0 : 1; s = { basis: e, bit: e === a ? bit : (Math.random() < .5 ? 0 : 1) }; }
    let got = b === s.basis ? s.bit : (Math.random() < .5 ? 0 : 1);
    if (Math.random() < 0.015) got ^= 1;
    const keep = a === b, err = keep && got !== bit;
    if (keep) { sifted++; if (err) errs++; }
    trace.push({ a, b, keep, err, tapped });
  }
  return { sifted, errs, qber: sifted ? errs / sifted : 0, trace };
}
