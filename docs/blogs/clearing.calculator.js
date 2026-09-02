// Dependency-free wire-size calculator for the clearing article. The palette and
// monospace type follow the article's other figures.
//
// The model is the codec, not a fit: every byte below follows the encodings in
// clearing/src/bajillion (varints for lengths, sequence numbers, amounts, and counts;
// four-byte positions; one-byte option tags; BMT range proofs with the storage crate's
// sibling rule). Fed the benchmark's per-slice counts it reproduces the measured sizes
// bench to the byte. The calculator spreads accounts, senders, edges, and recipients
// evenly over the 256 slices and assumes every edge credits a distinct account.

const RED = '#d9251c';
const GRAY = '#666666';
const GRID = '#e4e4e4';
const INK = '#111111';
const DASH = '#8a8a8a';

const SLICES = 256;
const KEY = 32;
const SIG = 64;
const DIGEST = 32;
const LTHASH = 2048;
const BOUNDARY = 140;
const AGG = 48;
const LEAF = 65;
const GUARD = KEY + DIGEST;
const HEADER = 32;
const ROOTS = 164;

function varint(v) {
  let n = 1;
  while (v >= 128) {
    v = Math.floor(v / 128);
    n += 1;
  }
  return n;
}

function levels(leafCount) {
  if (leafCount <= 1) return 1;
  return Math.ceil(Math.log2(leafCount)) + 1;
}

// Siblings of the inclusive leaf range [start, end] in a BMT of leafCount leaves.
function siblings(leafCount, start, end) {
  if (leafCount === 0) return 0;
  let count = 0;
  let levelStart = start;
  let levelEnd = end;
  let levelSize = leafCount;
  for (let level = 0; level < levels(leafCount) - 1; level += 1) {
    if (levelStart % 2 === 1) count += 1;
    if (levelEnd % 2 === 0 && levelEnd + 1 < levelSize) count += 1;
    levelStart = Math.floor(levelStart / 2);
    levelEnd = Math.floor(levelEnd / 2);
    levelSize = Math.ceil(levelSize / 2);
  }
  return count;
}

// A range opening: the start position, the leaf count, and the sibling digests.
function opening(leafCount, start, end) {
  if (leafCount === 0) return 4 + 4 + varint(0);
  const n = siblings(leafCount, start, end);
  return 4 + 4 + varint(n) + DIGEST * n;
}

// The range a bracket opens for members [start, end) plus its guards.
function bracket(len, start, end) {
  const pred = start > 0;
  const succ = end < len;
  return { pred, succ, first: start - (pred ? 1 : 0), last: end - 1 + (succ ? 1 : 0) };
}

// One slice's shape: cumulative positions at its start and end in the predecessor,
// change, successor, and transpose vectors, plus its senders and recipient groups.
function shape(p0, p1, c0, c1, s0, s1, t0, t1, senders, groups) {
  return { p0, p1, c0, c1, s0, s1, t0, t1, senders, groups };
}

// Exact dealt bytes of one proof slice covering slices [lo, hi).
function dealtSpan(counts, lo, hi, totals, entriesPerSender, gapBytes) {
  const span = hi - lo;
  const first = counts[lo];
  const last = counts[hi - 1];
  const rows = last.c1 - first.c0;
  const transpose = last.t1 - first.t0;
  let senders = 0;
  let groups = 0;
  let aggregates = varint(span);
  let groupCounts = 0;
  for (let i = lo; i < hi; i += 1) {
    const c = counts[i];
    senders += c.senders;
    groups += c.groups;
    aggregates += 1 + (c.senders > 0 ? AGG : 0);
    const t = c.t1 - c.t0;
    if (c.groups > 0) {
      const per = Math.floor(t / c.groups);
      const rem = t - per * c.groups;
      groupCounts += rem * varint(per + 1) + (c.groups - rem) * varint(per);
    }
  }
  let bytes = 4 + 2 + 2;
  bytes += varint(span + 1) + (span + 1) * BOUNDARY;
  bytes += rows * (1 + gapBytes) + senders * (varint(0) + SIG);
  bytes += senders * (varint(entriesPerSender) + entriesPerSender * (KEY + 1 + 1));
  bytes += transpose === 0 ? varint(0) : varint(groups) + groups * KEY + groupCounts + transpose * (KEY + 1 + 1);
  bytes += aggregates;
  bytes += 2 * LTHASH;
  const c = bracket(totals.rows, first.c0, last.c1);
  const p = bracket(totals.pred, first.p0, last.p1);
  const s = bracket(totals.succ, first.s0, last.s1);
  bytes += opening(SLICES + 1, lo, hi);
  bytes += opening(totals.rows, c.first, c.last);
  bytes += opening(totals.pred, p.first, p.last);
  bytes += opening(totals.succ, s.first, s.last);
  bytes += 1 + (transpose > 0 ? opening(totals.transpose, first.t0, last.t1 - 1) : 0);
  bytes += 1;
  bytes += (1 + GUARD) * (c.pred + c.succ) + (1 + LEAF) * (p.pred + p.succ + s.pred + s.succ);
  bytes += (!c.pred) + (!c.succ) + (!p.pred) + (!p.succ) + (!s.pred) + (!s.succ);
  return bytes;
}

// Exact bytes of the certified close as posted against the reader's replica.
function certified(rows, senders, edges, indexBytes, gapBytes, senderSlices) {
  let bytes = HEADER + ROOTS + varint(rows);
  bytes += rows * (1 + gapBytes) + senders * (varint(0) + SIG);
  bytes += senders * varint(edges / Math.max(senders, 1)) + edges * (indexBytes + 1 + 1);
  bytes += varint(SLICES) + SLICES + AGG * senderSlices;
  return bytes;
}

// Splits a total evenly over the slices with exact integer cumulative positions.
function spread(total) {
  const cut = [];
  for (let i = 0; i <= SLICES; i += 1) cut.push(Math.round((total * i) / SLICES));
  return cut;
}

// Mean varint width of a uniformly distributed row index below `rows`.
function meanIndexBytes(rows) {
  if (rows <= 0) return 1;
  let bytes = 0;
  let lower = 0;
  let width = 1;
  for (let bound = 128; lower < rows; bound *= 128, width += 1) {
    const upper = Math.min(rows, bound);
    bytes += (upper - lower) * width;
    lower = upper;
  }
  return bytes / rows;
}

// The scenario: N live accounts, E = N * k edges, every edge crediting a distinct account.
// Below out-degree one only E accounts send (out-degree one each); at one and above every
// account sends k edges and every account receives.
function scenario(N, k) {
  const E = Math.round(N * k);
  const S = Math.min(N, E);
  const R = Math.min(N, E);
  const A = Math.min(N, S + R);
  const perSender = S > 0 ? E / S : 0;
  const pred = spread(N);
  const rows = spread(A);
  const send = spread(S);
  const trans = spread(E);
  const groups = spread(R);
  const counts = [];
  for (let i = 0; i < SLICES; i += 1) {
    counts.push(shape(
      pred[i], pred[i + 1], rows[i], rows[i + 1], pred[i], pred[i + 1],
      trans[i], trans[i + 1], send[i + 1] - send[i], groups[i + 1] - groups[i],
    ));
  }
  const gapBytes = A > 0 ? varint(Math.max(0, Math.floor(N / A) - 1)) : 1;
  const senderSlices = counts.filter((c) => c.senders > 0).length;
  return {
    E, S, R, A, perSender, gapBytes, senderSlices, counts,
    totals: { pred: N, rows: A, succ: N, transpose: E },
  };
}

function corpus(sc) {
  let bytes = 0;
  for (let i = 0; i < SLICES; i += 1) {
    bytes += dealtSpan(sc.counts, i, i + 1, sc.totals, Math.max(1, sc.perSender), sc.gapBytes);
  }
  return bytes;
}

// The quorum window holding slice s: q consecutive validators starting at floor(s n / S).
function spans(n, q, validator) {
  const held = [];
  for (let s = 0; s < SLICES; s += 1) {
    const start = Math.floor((s * n) / SLICES);
    const end = start + q;
    if ((validator >= start && validator < end) || (end > n && validator < end - n)) held.push(s);
  }
  const out = [];
  for (const s of held) {
    if (out.length && out[out.length - 1][1] === s) out[out.length - 1][1] = s + 1;
    else out.push([s, s + 1]);
  }
  return out;
}

function committee(sc, n, q) {
  let busiest = 0;
  let egress = 0;
  for (let v = 0; v < n; v += 1) {
    let dealing = 0;
    for (const [lo, hi] of spans(n, q, v)) {
      dealing += dealtSpan(sc.counts, lo, hi, sc.totals, Math.max(1, sc.perSender), sc.gapBytes);
    }
    busiest = Math.max(busiest, dealing);
    egress += dealing;
  }
  return { busiest, egress };
}

// The live-state BMT a full reader holds: 65 B leaves plus a 32 B digest per tree node.
function stateBmt(N) {
  return 65 * N + 32 * (2 * N - 1);
}

function sig3(x) {
  const m = Math.pow(10, Math.floor(Math.log10(x)) - 2);
  return Math.round(x / m) * m;
}

function bytesText(b) {
  if (b >= 1e12) return `${(b / 1e12).toPrecision(3)} TB`;
  if (b >= 1e9) return `${(b / 1e9).toPrecision(3)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toPrecision(3)} MB`;
  if (b >= 1e3) return `${Math.round(b / 1e3)} KB`;
  return `${Math.round(b)} B`;
}

function count(n) {
  return Math.round(n).toLocaleString('en-US');
}

const STYLE_ID = 'clearing-calculator-style';

function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .clearing-calculator-panel {
      font-family: monospace;
      font-size: 14px;
      line-height: 1.45;
    }
    .clearing-calculator-row {
      align-items: center;
      display: grid;
      gap: 6px 14px;
      grid-template-columns: 190px 1fr 230px;
      margin: 0 0 10px;
    }
    .clearing-calculator-row label { color: ${GRAY}; }
    .clearing-calculator-row .value {
      color: ${RED};
      font-weight: 700;
      text-align: right;
      white-space: nowrap;
    }
    .clearing-calculator-row input[type="range"] {
      accent-color: ${RED};
      margin: 0;
      width: 100%;
    }
    .clearing-calculator canvas {
      display: block;
      margin: 12px 0 6px;
      width: 100%;
    }
    .clearing-calculator-out {
      border-top: 1px dashed ${GRID};
      display: flex;
      flex-wrap: wrap;
      gap: 4px 22px;
      padding: 7px 0;
    }
    .clearing-calculator-out:first-of-type { border-top: 0; }
    .clearing-calculator-out .tag {
      color: ${RED};
      font-weight: 700;
      letter-spacing: 0.06em;
      min-width: 130px;
      text-transform: uppercase;
    }
    .clearing-calculator-out.committee { border-top: 1px solid ${GRID}; }
    .clearing-calculator-out b { color: ${INK}; font-weight: 700; }
    .clearing-calculator-out span { color: ${GRAY}; }
    @media (max-width: 640px) {
      .clearing-calculator-row { grid-template-columns: 1fr; gap: 4px; }
      .clearing-calculator-row .value { text-align: left; }
    }
  `;
  document.head.appendChild(style);
}

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text !== undefined) node.textContent = text;
  return node;
}

function slider(panel, id, label, min, max, step, value) {
  const row = el('div', { class: 'clearing-calculator-row' });
  const lab = el('label', { for: id }, label);
  const input = el('input', { type: 'range', id, min, max, step, value });
  const out = el('span', { class: 'value' });
  row.append(lab, input, out);
  panel.append(row);
  return { input, out };
}

function readout(line, label, id) {
  const span = el('span');
  span.append(document.createTextNode(`${label} `));
  const value = el('b', { id });
  span.append(value);
  line.append(span);
  return value;
}

function mount(root) {
  injectStyles();
  root.replaceChildren();
  const panel = el('div', { class: 'clearing-calculator-panel' });
  root.append(panel);

  const sN = slider(panel, 'clearing-calc-n', 'accounts N', 3, 9, 0.01, 6);
  const sK = slider(panel, 'clearing-calc-k', 'mean out-degree', -3, 3.0103, 0.005, 0);
  const sV = slider(panel, 'clearing-calc-v', 'validators n', 0.602, 3.011, 0.005, 2);

  const canvas = el('canvas', {
    height: '360',
    role: 'img',
    'aria-label':
      'Log-log plot of wire sizes against mean out-degree: the certified close, the dealt corpus, and the live-state tree. The certified close carries no account-count term, and the dealt corpus tracks the movers above a small witness floor.',
  });
  panel.append(canvas);

  const line = (tag, cls) => {
    const out = el('div', { class: `clearing-calculator-out${cls ? ` ${cls}` : ''}` });
    out.append(el('span', { class: 'tag' }, tag));
    panel.append(out);
    return out;
  };
  const perClose = line('per close');
  const oCertified = readout(perClose, 'certified', 'clearing-calc-certified');
  const oDealt = readout(perClose, 'dealt', 'clearing-calc-dealt');
  const oE = readout(perClose, 'edges', 'clearing-calc-e');
  const oRows = readout(perClose, 'rows', 'clearing-calc-rows');
  const perCommittee = line('per committee', 'committee');
  const oBusiest = readout(perCommittee, 'busiest dealing', 'clearing-calc-busiest');
  const oEgress = readout(perCommittee, 'operator egress', 'clearing-calc-egress');

  const curN = () => sig3(Math.pow(10, parseFloat(sN.input.value)));
  const curK = () => {
    const k = Math.pow(10, parseFloat(sK.input.value));
    if (k < 1) return Number(k.toPrecision(2));
    return k < 10 ? Math.round(k * 10) / 10 : sig3(k);
  };
  // Committee sizes snap to n = 3f + 1.
  const curV = () => {
    const f = Math.max(1, Math.round((Math.pow(10, parseFloat(sV.input.value)) - 1) / 3));
    return { n: 3 * f + 1, q: 2 * f + 1 };
  };

  function draw() {
    const N = curN();
    const K = curK();
    const V = curV();
    const sc = scenario(N, K);
    const st = stateBmt(N);
    sN.out.textContent = `${count(N)}  (state ${bytesText(st)})`;
    sK.out.textContent = `${K}  (E = ${count(sc.E)})`;
    sV.out.textContent = `${count(V.n)}  (q = ${count(V.q)})`;

    const posted = certified(sc.A, sc.S, sc.E, meanIndexBytes(sc.A), sc.gapBytes, sc.senderSlices);
    const dt = corpus(sc);
    const cm = committee(sc, V.n, V.q);
    oCertified.textContent = bytesText(posted);
    oDealt.textContent = bytesText(dt);
    oE.textContent = count(sc.E);
    oRows.textContent = count(sc.A);
    oBusiest.textContent = bytesText(cm.busiest);
    oEgress.textContent = bytesText(cm.egress);

    const w = canvas.clientWidth || 840;
    const h = Math.max(240, Math.round(w * 0.42));
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    canvas.style.height = `${h}px`;
    const g = canvas.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.fillStyle = 'white';
    g.fillRect(0, 0, w, h);
    const L = 64;
    const R = 16;
    const T = 16;
    const Bm = 38;
    const pw = w - L - R;
    const ph = h - T - Bm;
    const kMin = 0.001;
    const kMax = 1024;
    const STEPS = 120;
    const ks = [];
    const cv = [];
    const dv = [];
    let yMin = Infinity;
    let yMax = 0;
    for (let j = 0; j <= STEPS; j += 1) {
      const kj = kMin * Math.pow(kMax / kMin, j / STEPS);
      const sj = scenario(N, kj);
      const pj = certified(sj.A, sj.S, sj.E, meanIndexBytes(sj.A), sj.gapBytes, sj.senderSlices);
      const dj = corpus(sj);
      ks.push(kj);
      cv.push(pj);
      dv.push(dj);
      yMin = Math.min(yMin, pj);
      yMax = Math.max(yMax, dj);
    }
    yMin = Math.min(yMin, st) * 0.55;
    yMax = Math.max(yMax, st) * 1.5;
    const X = (k) => L + (pw * Math.log(k / kMin)) / Math.log(kMax / kMin);
    const Y = (b) => T + ph * (1 - Math.log(b / yMin) / Math.log(yMax / yMin));

    g.font = '12px monospace';
    g.strokeStyle = GRID;
    g.fillStyle = GRAY;
    g.lineWidth = 1;
    const decades = Math.log10(yMax / yMin);
    const step10 = decades > 8 ? 2 : 1;
    let p10 = Math.ceil(Math.log10(yMin));
    if (step10 === 2 && p10 % 2) p10 += 1;
    for (; Math.pow(10, p10) < yMax; p10 += step10) {
      const yv = Math.pow(10, p10);
      const yy = Y(yv);
      g.beginPath();
      g.moveTo(L, yy);
      g.lineTo(w - R, yy);
      g.stroke();
      g.textAlign = 'right';
      g.textBaseline = 'middle';
      g.fillText(bytesText(yv).replace('.00', ''), L - 8, yy);
    }
    for (const kt of [0.001, 0.01, 0.1, 1, 10, 100, 1000]) {
      const xx = X(kt);
      g.beginPath();
      g.moveTo(xx, T);
      g.lineTo(xx, T + ph);
      g.stroke();
      g.textAlign = 'center';
      g.textBaseline = 'top';
      g.fillText(String(kt), xx, T + ph + 8);
    }
    g.textAlign = 'center';
    g.fillText('mean out-degree', L + pw / 2, T + ph + 23);

    const trace = (vals) => {
      g.beginPath();
      for (let j = 0; j <= STEPS; j += 1) {
        if (j === 0) g.moveTo(X(ks[j]), Y(vals[j]));
        else g.lineTo(X(ks[j]), Y(vals[j]));
      }
      g.stroke();
    };
    const ySt = Y(st);
    g.strokeStyle = DASH;
    g.setLineDash([5, 4]);
    g.lineWidth = 1.5;
    g.beginPath();
    g.moveTo(L, ySt);
    g.lineTo(w - R, ySt);
    g.stroke();
    g.setLineDash([]);
    g.strokeStyle = INK;
    g.lineWidth = 1.6;
    trace(dv);
    g.strokeStyle = RED;
    g.lineWidth = 2.2;
    trace(cv);

    const labels = [
      { y: Y(dv[STEPS]), text: 'dealt', color: INK },
      { y: ySt, text: 'state', color: GRAY },
      { y: Y(cv[STEPS]), text: 'certified', color: RED },
    ].sort((a, b) => a.y - b.y);
    for (let i = 1; i < labels.length; i += 1) {
      if (labels[i].y - labels[i - 1].y < 14) labels[i].y = labels[i - 1].y + 14;
    }
    g.textAlign = 'right';
    g.textBaseline = 'bottom';
    for (const label of labels) {
      g.fillStyle = label.color;
      g.fillText(label.text, w - R - 4, label.y - 3);
    }

    const cx = X(Math.max(kMin, Math.min(kMax, K)));
    g.strokeStyle = GRAY;
    g.setLineDash([2, 3]);
    g.beginPath();
    g.moveTo(cx, T);
    g.lineTo(cx, T + ph);
    g.stroke();
    g.setLineDash([]);
    g.fillStyle = INK;
    g.beginPath();
    g.arc(cx, Y(dt), 3, 0, 7);
    g.fill();
    g.fillStyle = RED;
    g.strokeStyle = 'white';
    g.lineWidth = 2;
    g.beginPath();
    g.arc(cx, Y(posted), 4.5, 0, 7);
    g.fill();
    g.stroke();
    g.fillStyle = RED;
    g.textBaseline = Y(posted) < T + 24 ? 'top' : 'bottom';
    g.textAlign = cx > w - 130 ? 'right' : 'left';
    g.fillText(bytesText(posted), cx + (cx > w - 130 ? -8 : 8), Y(posted) + (Y(posted) < T + 24 ? 8 : -8));
  }

  for (const s of [sN, sK, sV]) s.input.addEventListener('input', draw);
  window.addEventListener('resize', draw);
  draw();
}

if (typeof document !== 'undefined') {
  const root = document.getElementById('clearing-fig-calculator');
  if (root) mount(root);
}
