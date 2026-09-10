// Wire sizes for a concrete unit-payment graph using clearing/src/bajillion's codecs.
// Accounts occupy ordered ranks distributed across key-prefix slices. Sparse senders
// occupy the first ranks and pay the last ranks; dense senders pay their next k neighbors.

const RED = '#d9251c';
const GRAY = '#666666';
const GRID = '#e4e4e4';
const INK = '#111111';
const DASH = '#8a8a8a';

// Account-key prefixes give power-of-two slices, capped at the codec's eight-bit prefix limit.
function sliceCount(n) {
  let slices = 1;
  while (slices < n) slices *= 2;
  return Math.min(slices, 256);
}
const KEY = 32;
const SIG = 64;
const DIGEST = 32;
const LTHASH = 2048;
const AGG = 48;
const LEAF = 65;
const GUARD = KEY + DIGEST;
const HEADER = 32;
const ROOTS = 164;
const MAX_VECTOR_LENGTH = 1 << 24;

function byteSize(parts) {
  return Object.values(parts).reduce((total, bytes) => total + bytes, 0);
}

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

// One coverage boundary on the wire: three varint positions, the eight varint prefix fields
// (debit, credit, payout, deposit, withdrawal, withdrawal count, outgoing entries, transpose
// entries), and two 32-byte accumulator checksums.
function boundary(pred, change, succ, prefix) {
  let bytes = varint(pred) + varint(change) + varint(succ) + 2 * DIGEST;
  for (const v of prefix) bytes += varint(v);
  return bytes;
}

// Each chunk resets rank gaps at its own retained slice, including in a merged span.
function dealtSpan(sc, lo, hi) {
  const { counts, totals, slices } = sc;
  const span = hi - lo;
  const first = counts[lo];
  const last = counts[hi - 1];
  const transpose = last.t1 - first.t0;
  const parts = {
    fixed: 8,
    boundaries: varint(span + 1) + boundary(first.p0, first.c0, first.p0, first.x0),
    rows: 0,
    entries: 0,
    transpose: 0,
    aggregates: varint(span),
    starts: 2 * LTHASH,
  };
  for (let i = lo; i < hi; i += 1) {
    const c = counts[i];
    parts.rows += c.rowBytes;
    parts.entries += c.entryBytes;
    parts.transpose += c.transposeBytes;
    parts.aggregates += 1 + (c.senders > 0 ? AGG : 0);
    parts.boundaries += boundary(c.p1, c.c1, c.p1, c.x1);
  }
  const c = bracket(totals.rows, first.c0, last.c1);
  const p = bracket(totals.pred, first.p0, last.p1);
  parts.openings = opening(slices + 1, lo, hi)
    + opening(totals.rows, c.first, c.last)
    + 2 * opening(totals.pred, p.first, p.last)
    + 2 + (transpose > 0 ? opening(totals.transpose, first.t0, last.t1 - 1) : 0);
  parts.guards = 6 + GUARD * (c.pred + c.succ) + 2 * LEAF * (p.pred + p.succ);
  return parts;
}

function certified(sc) {
  return {
    fixed: HEADER + ROOTS + varint(sc.A),
    rows: sc.A + sc.gapBytes + sc.S * (1 + SIG),
    vectors: sc.A - sc.S + sc.S * varint(sc.perSender) + sc.indexBytes + 2 * sc.E,
    aggregates: varint(sc.slices) + sc.slices + AGG * sc.senderSlices,
  };
}

// Sum rank gaps for changed intervals within one retained range [start, end).
function rankGapBytes(intervals, start, end) {
  let cursor = start;
  let bytes = 0;
  for (const [lo, hi] of intervals) {
    const a = Math.max(start, lo);
    const b = Math.min(end, hi);
    if (a >= b) continue;
    bytes += varint(a - cursor) + b - a - 1;
    cursor = b;
  }
  return bytes;
}

// Sum varint widths of every index in [0, end).
function indexBytesBefore(end) {
  let bytes = end;
  for (let bound = 128; bound < end; bound *= 128) bytes += end - bound;
  return bytes;
}

function maxDegree(N) {
  return Math.min(1024, N - 1, Math.floor(MAX_VECTOR_LENGTH / N));
}

// One sequence-1 batch per sender, with unit amounts/counts and enough opening balance.
// All accounts stay live; sparse sender and recipient cohorts may overlap.
function scenario(N, k, slices) {
  const S = k < 1 ? Math.round(N * k) : N;
  const perSender = k < 1 ? 1 : Math.min(maxDegree(N), Math.max(1, Math.round(k)));
  const E = S * perSender;
  const A = Math.min(N, 2 * S);
  const intervals = S === 0 ? [] : 2 * S < N ? [[0, S], [N - S, N]] : [[0, N]];
  const sendersBefore = (p) => Math.min(p, S);
  const recipientsBefore = (p) => Math.max(0, p - (N - S));
  const rowsBefore = (p) => sendersBefore(p) + recipientsBefore(p) - Math.max(0, Math.min(p, S) - (N - S));
  const prefix = (p) => {
    const outgoing = sendersBefore(p) * perSender;
    const incoming = recipientsBefore(p) * perSender;
    return [outgoing, incoming, 0, 0, 0, 0, outgoing, incoming];
  };
  const counts = [];
  for (let i = 0; i < slices; i += 1) {
    const p0 = Math.floor(N * i / slices);
    const p1 = Math.floor(N * (i + 1) / slices);
    const c0 = rowsBefore(p0);
    const c1 = rowsBefore(p1);
    const senders = sendersBefore(p1) - sendersBefore(p0);
    const groups = recipientsBefore(p1) - recipientsBefore(p0);
    counts.push({
      p0, p1, c0, c1, senders, groups,
      t0: recipientsBefore(p0) * perSender,
      t1: recipientsBefore(p1) * perSender,
      x0: prefix(p0), x1: prefix(p1),
      rowBytes: c1 - c0 + rankGapBytes(intervals, p0, p1) + senders * (1 + SIG),
      entryBytes: senders * (varint(perSender) + perSender * (KEY + 2)),
      transposeBytes: varint(groups) + groups * (KEY + varint(perSender) + perSender * (KEY + 2)),
    });
  }
  const senderSlices = counts.filter((c) => c.senders > 0).length;
  return {
    E, S, A, perSender, senderSlices, counts, slices,
    gapBytes: rankGapBytes(intervals, 0, N),
    indexBytes: S === N ? perSender * indexBytesBefore(N) : indexBytesBefore(A) - indexBytesBefore(A - S),
    totals: { pred: N, rows: A, transpose: E },
  };
}

function corpus(sc) {
  const parts = dealtSpan(sc, 0, 1);
  for (let i = 1; i < sc.slices; i += 1) {
    for (const [name, bytes] of Object.entries(dealtSpan(sc, i, i + 1))) parts[name] += bytes;
  }
  return parts;
}

// The quorum window holding slice s: q consecutive validators starting at floor(s n / S).
function spans(n, q, validator, slices) {
  const held = [];
  for (let s = 0; s < slices; s += 1) {
    const start = Math.floor((s * n) / slices);
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
    for (const [lo, hi] of spans(n, q, v, sc.slices)) {
      dealing += byteSize(dealtSpan(sc, lo, hi));
    }
    busiest = Math.max(busiest, dealing);
    egress += dealing;
  }
  return { busiest, egress };
}

// The live-state BMT a full reader holds: 65 B leaves plus a 32 B digest per tree node.
function stateBmt(N) {
  let nodes = 1;
  for (let level = N; level > 1; level = Math.ceil(level / 2)) nodes += level;
  return LEAF * N + DIGEST * nodes;
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
    .clearing-calculator-out details { min-width: 0; max-width: 100%; }
    .clearing-calculator-out details[open] { flex-basis: 100%; }
    .clearing-calculator-out summary { color: ${GRAY}; cursor: pointer; }
    .clearing-calculator-out summary b { border-bottom: 1px dotted ${GRAY}; }
    .clearing-calculator-card {
      background: white;
      border: 1px solid ${GRID};
      border-radius: 6px;
      margin-top: 6px;
      max-width: 480px;
      padding: 10px 12px 8px;
      width: 100%;
    }
    .clearing-calculator-card .title {
      border-bottom: 1px solid ${GRID};
      color: ${INK};
      display: block;
      font-weight: 700;
      margin-bottom: 6px;
      padding-bottom: 6px;
    }
    .clearing-calculator-card .row {
      display: flex;
      font-variant-numeric: tabular-nums;
      gap: 18px;
      justify-content: space-between;
      padding: 2px 0;
    }
    .clearing-calculator-card .row .term { min-width: 0; overflow-wrap: anywhere; white-space: normal; }
    .clearing-calculator-card .row .amount { color: ${INK}; font-weight: 700; margin-left: auto; white-space: nowrap; }
    .clearing-calculator-card .row .share { min-width: 38px; text-align: right; }
    .clearing-calculator-card .note {
      color: ${GRAY};
      display: block;
      font-size: 12px;
      padding-top: 5px;
      white-space: normal;
    }
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

function readout(line, label, id, withCard = false) {
  const container = el(withCard ? 'details' : 'span');
  const summary = withCard ? el('summary') : container;
  summary.append(document.createTextNode(`${label} `));
  const value = el('b', { id });
  summary.append(value);
  let card = null;
  if (withCard) {
    card = el('div', { class: 'clearing-calculator-card' });
    container.append(summary, card);
  }
  line.append(container);
  return { value, card };
}

// Fills a breakdown card: the total, one row per term with its share, and an optional note.
// A row may carry its own share text instead of a percentage of the total.
function fillCard(card, total, rows, note) {
  card.replaceChildren();
  card.append(el('span', { class: 'title' }, bytesText(total)));
  for (const [label, amount, share] of rows) {
    const row = el('span', { class: 'row' });
    row.append(el('span', { class: 'term' }, label));
    row.append(el('span', { class: 'amount' }, typeof amount === 'string' ? amount : bytesText(amount)));
    row.append(el('span', { class: 'share' }, share === undefined ? `${Math.round((100 * amount) / total)}%` : share));
    card.append(row);
  }
  if (note) card.append(el('span', { class: 'note' }, note));
}

function mount(root) {
  injectStyles();
  root.replaceChildren();
  const panel = el('div', { class: 'clearing-calculator-panel' });
  root.append(panel);

  const sN = slider(panel, 'clearing-calc-n', 'accounts N', 3, Math.log10(MAX_VECTOR_LENGTH), 0.01, 6);
  const sK = slider(panel, 'clearing-calc-k', 'mean out-degree', -3, Math.log10(maxDegree(1e6)), 0.005, 0);
  const sV = slider(panel, 'clearing-calc-v', 'validators n', 0.602, 3.011, 0.005, 2);

  const canvas = el('canvas', {
    height: '360',
    role: 'img',
    'aria-label':
      'Log-log comparison of the posted close, dealt corpus, and retained live-state tree as mean out-degree changes.',
  });
  panel.append(canvas);

  const line = (tag, cls) => {
    const out = el('div', { class: `clearing-calculator-out${cls ? ` ${cls}` : ''}` });
    out.append(el('span', { class: 'tag' }, tag));
    panel.append(out);
    return out;
  };
  const perClose = line('per close');
  const oCertified = readout(perClose, 'posted', 'clearing-calc-certified', true);
  const oDealt = readout(perClose, 'dealt', 'clearing-calc-dealt', true);
  const oE = readout(perClose, 'edges', 'clearing-calc-e').value;
  const oRows = readout(perClose, 'rows', 'clearing-calc-rows').value;
  const perCommittee = line('per committee', 'committee');
  const oBusiest = readout(perCommittee, 'busiest dealing', 'clearing-calc-busiest', true);
  const oEgress = readout(perCommittee, 'operator egress', 'clearing-calc-egress', true);

  // Committee sizes snap to n = 3f + 1.
  const curV = () => {
    const f = Math.max(1, Math.round((Math.pow(10, parseFloat(sV.input.value)) - 1) / 3));
    const n = 3 * f + 1;
    return { n, q: 2 * f + 1, slices: sliceCount(n) };
  };

  function draw() {
    const N = Math.min(MAX_VECTOR_LENGTH, sig3(Math.pow(10, parseFloat(sN.input.value))));
    const kMax = maxDegree(N);
    sK.input.max = Math.log10(kMax);
    const V = curV();
    const sc = scenario(N, Math.pow(10, parseFloat(sK.input.value)), V.slices);
    const K = sc.E / N;
    const st = stateBmt(N);
    sN.out.textContent = `${count(N)}  (state ${bytesText(st)})`;
    sK.out.textContent = `${Number(K.toPrecision(3))}  (E = ${count(sc.E)})`;
    sV.out.textContent = `${count(V.n)}  (q = ${count(V.q)}, S = ${count(V.slices)})`;
    for (const s of [sN, sK, sV]) s.input.setAttribute('aria-valuetext', s.out.textContent);

    const postedParts = certified(sc);
    const dealtParts = corpus(sc);
    const posted = byteSize(postedParts);
    const dt = byteSize(dealtParts);
    const cm = committee(sc, V.n, V.q);
    oCertified.value.textContent = bytesText(posted);
    oDealt.value.textContent = bytesText(dt);
    oE.textContent = count(sc.E);
    oRows.textContent = count(sc.A);
    oBusiest.value.textContent = bytesText(cm.busiest);
    oEgress.value.textContent = bytesText(cm.egress);

    fillCard(oCertified.card, posted, [
      ['header + root bundle', postedParts.fixed],
      ['rows (rank gap, seq, signature)', postedParts.rows],
      ['outgoing vectors (lengths + entries)', postedParts.vectors],
      ['per-slice operator aggregates', postedParts.aggregates],
    ]);
    fillCard(oDealt.card, dt, [
      ['rows (rank gap, seq, signature)', dealtParts.rows],
      ['outgoing entries', dealtParts.entries],
      ['transpose groups + entries', dealtParts.transpose],
      ['operator aggregates', dealtParts.aggregates],
      ['witness (header, boundaries, accumulators, openings, guards)',
        dealtParts.fixed + dealtParts.boundaries + dealtParts.starts + dealtParts.openings + dealtParts.guards],
    ], 'every slice once; states, prefixes, and endpoint bodies are derived from the retained interval');
    fillCard(oBusiest.card, cm.busiest, [
      ['dealt corpus', dt, ''],
      ['busiest validator share', `x ${(cm.busiest / dt).toPrecision(2)}`, ''],
    ], `each slice has ${count(V.q)} of ${count(V.n)} validators; each validator holds one or two spans`);
    fillCard(oEgress.card, cm.egress, [
      ['mean dealing', cm.egress / V.n, ''],
      ['one per validator', `x ${count(V.n)}`, ''],
    ], 'every slice lands on q validators; each span carries one witness');

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
    const STEPS = 120;
    const ks = [];
    const cv = [];
    const dv = [];
    let yMin = Infinity;
    let yMax = 0;
    for (let j = 0; j <= STEPS; j += 1) {
      const kj = kMin * Math.pow(kMax / kMin, j / STEPS);
      const sj = scenario(N, kj, V.slices);
      const pj = byteSize(certified(sj));
      const dj = byteSize(corpus(sj));
      ks.push(sj.E / N);
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
      if (kt > kMax) continue;
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
      { y: Y(cv[STEPS]), text: 'posted', color: RED },
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
