// Modeled keyed encoding. Every validator holds the previous QMDB account state.

const BLUE = '#2424d4';
const GRAY = '#666666';
const GRID = '#e4e4e4';
const INK = '#111111';
const SIG = 64;
const KEY = 32;
const AGG = 48;
const ACCOUNT_RECORD = KEY + 8;

// Validators reconstruct the roots and outflow totals bound by this header.
const METADATA = 32;
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

// Sum unsigned varint widths for consecutive row indices in [start, end).
function indexBytes(start, end) {
  let bytes = end - start;
  for (let threshold = 128; threshold < end; threshold *= 128) {
    bytes += end - Math.max(start, threshold);
  }
  return bytes;
}

function maxDegree(N) {
  return Math.min(1024, N - 1, Math.floor(MAX_VECTOR_LENGTH / N));
}

// Each sender signs one sequence-1 batch with one unit payment per recipient.
// Sparse senders use the first keys and pay the last keys; when all accounts
// send, each pays its next k neighbors cyclically. All accounts remain live.
function scenario(N, k) {
  const S = k < 1 ? Math.round(N * k) : N;
  const perSender = k < 1 ? 1 : Math.min(maxDegree(N), Math.round(k));
  const E = S * perSender;
  const A = Math.min(N, 2 * S);

  const references = S < N ? indexBytes(A - S, A) : perSender * indexBytes(0, N);

  // Rows carry a full key and an outgoing flag; sending rows include sequence 1.
  const parts = {
    rows: varint(A) + A * (KEY + 1) + S,
    signatures: S * SIG,
    entries: S * varint(perSender) + (A - S) + references + 2 * E,
    operator: 1 + (S > 0 ? AGG : 0),
    metadata: METADATA,
  };
  return { E, A, parts };
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

function injectStyles() {
  const style = document.createElement('style');
  style.textContent = `
    .clearing-calculator-panel {
      font-family: monospace;
      font-size: 14px;
      line-height: 1.45;
    }
    .clearing-calculator-controls {
      display: grid;
      gap: 18px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .clearing-calculator-row {
      display: grid;
      align-content: start;
      gap: 8px;
      min-width: 0;
    }
    .clearing-calculator-row label { color: ${INK}; font-size: 13px; }
    .clearing-calculator-row .value {
      color: ${BLUE};
      font-size: 20px;
      font-weight: 700;
      white-space: nowrap;
    }
    .clearing-calculator-row input[type="range"] {
      accent-color: ${BLUE};
      margin: 0;
      width: 100%;
    }
    .clearing-calculator-row .hint { color: ${GRAY}; font-size: 12px; }
    .clearing-calculator-activity {
      border-bottom: 1px solid ${GRID};
      color: ${GRAY};
      display: flex;
      flex-wrap: wrap;
      gap: 6px 24px;
      font-size: 12px;
      margin: 18px 0;
      padding-bottom: 14px;
    }
    .clearing-calculator-activity b { color: ${INK}; }
    .clearing-calculator-legend {
      color: ${BLUE};
      display: flex;
      flex-wrap: wrap;
      gap: 6px 24px;
      font-size: 12px;
    }
    .clearing-calculator-legend span { display: inline-flex; align-items: center; gap: 8px; }
    .clearing-calculator-legend span::before {
      content: '';
      border-top: 2px solid currentColor;
      flex-shrink: 0;
      width: 22px;
    }
    .clearing-calculator-legend .state { color: ${GRAY}; }
    .clearing-calculator-legend .state::before { border-top-style: dotted; }
    .clearing-calculator canvas {
      display: block;
      margin-top: 12px;
      width: 100%;
    }
    .clearing-calculator-axis { color: ${GRAY}; font-size: 12px; text-align: center; }
    .clearing-calculator-out {
      border-top: 1px solid ${GRID};
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 20px;
      margin-top: 22px;
      padding-top: 18px;
    }
    .clearing-calculator-out .label { color: ${INK}; font-size: 13px; }
    .clearing-calculator-out .value { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; margin: 6px 0; }
    .clearing-calculator-out .value b {
      color: ${BLUE};
      font-size: 22px;
      font-weight: 700;
    }
    .clearing-calculator-out .egress { color: ${GRAY}; font-size: 13px; }
    .clearing-calculator-out .scope {
      color: ${GRAY};
      display: block;
      font-size: 12px;
    }
    .clearing-calculator-breakdown {
      color: ${GRAY};
      font-size: 12px;
      margin-top: 6px;
    }
    .clearing-calculator-breakdown .row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      font-variant-numeric: tabular-nums;
      gap: 8px;
      padding: 4px 0;
    }
    .clearing-calculator-breakdown .row .term { min-width: 0; overflow-wrap: anywhere; white-space: normal; }
    .clearing-calculator-breakdown .row .amount { color: ${INK}; font-weight: 700; white-space: nowrap; }
    .clearing-calculator-breakdown .row .share { text-align: right; }
    @media (max-width: 640px) {
      .clearing-calculator-controls { grid-template-columns: 1fr; gap: 16px; }
      .clearing-calculator-row { grid-template-columns: minmax(0, 1fr) auto; gap: 6px 12px; }
      .clearing-calculator-row .value { font-size: 17px; text-align: right; }
      .clearing-calculator-row input, .clearing-calculator-row .hint { grid-column: 1 / -1; }
      .clearing-calculator-out { grid-template-columns: 1fr; }
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

function slider(panel, id, label, hint, min, max, step, value) {
  const row = el('div', { class: 'clearing-calculator-row' });
  const lab = el('label', { for: id }, label);
  const input = el('input', { type: 'range', id, min, max, step, value, 'aria-describedby': `${id}-hint` });
  const out = el('span', { class: 'value' });
  const help = el('span', { class: 'hint', id: `${id}-hint` }, hint);
  row.append(lab, out, input, help);
  panel.append(row);
  return { input, out, help };
}

function fillBreakdown(breakdown, total, rows) {
  breakdown.replaceChildren();
  for (const [label, amount] of rows) {
    const share = Math.round((100 * amount) / total);
    const row = el('span', { class: 'row' });
    row.append(el('span', { class: 'term' }, label));
    row.append(el('span', { class: 'amount' }, bytesText(amount)));
    row.append(el('span', { class: 'share' }, amount > 0 && share === 0 ? '<1%' : `${share}%`));
    breakdown.append(row);
  }
}

function mount(root) {
  injectStyles();
  root.replaceChildren();
  const panel = el('div', { class: 'clearing-calculator-panel' });
  root.append(panel);

  const controls = el('div', { class: 'clearing-calculator-controls' });
  panel.append(controls);
  const sN = slider(controls, 'clearing-calc-n', 'Live accounts', 'Includes accounts with no activity.', 3, Math.log10(MAX_VECTOR_LENGTH), 0.01, 6);
  const sK = slider(controls, 'clearing-calc-k', 'Recipients per account', 'Average over all live accounts.', -3, Math.log10(maxDegree(1e6)), 0.005, 0);
  const sV = slider(controls, 'clearing-calc-v', 'Validators', 'Each receives the same complete update.', 0.602, 3.011, 0.005, 2);

  const activity = el('div', { class: 'clearing-calculator-activity' });
  const pairs = el('span');
  const oE = el('b', { id: 'clearing-calc-e' });
  pairs.append(oE, document.createTextNode(' sender-recipient pairs'));
  const accounts = el('span');
  const oRows = el('b', { id: 'clearing-calc-rows' });
  accounts.append(oRows, document.createTextNode(' accounts with activity'));
  activity.append(pairs, accounts);
  panel.append(activity);

  const legend = el('div', { class: 'clearing-calculator-legend' });
  const oState = el('span', { class: 'state' });
  legend.append(el('span', {}, 'Validator dealing (estimate)'), oState);
  panel.append(legend);

  const canvas = el('canvas', {
    height: '360',
    role: 'img',
  });
  panel.append(canvas, el('div', { class: 'clearing-calculator-axis' }, 'Recipients per live account (average)'));

  const results = el('div', { class: 'clearing-calculator-out' });
  panel.append(results);
  const dealing = el('div', { class: 'dealing' });
  const value = el('div', { class: 'value' });
  const oDealing = el('b', { id: 'clearing-calc-dealing' });
  const oEgress = el('span', { id: 'clearing-calc-egress', class: 'egress' });
  const scope = el('span', { class: 'scope' });
  value.append(oDealing, oEgress);
  dealing.append(el('div', { class: 'label' }, 'Validator dealing'), value, scope);
  const composition = el('div', { class: 'composition' });
  const breakdown = el('div', { class: 'clearing-calculator-breakdown' });
  composition.append(el('div', { class: 'label' }, 'Composition'), breakdown);
  results.append(dealing, composition);

  // Committee sizes snap to n = 3f + 1.
  const curV = () => {
    const f = Math.round((Math.pow(10, parseFloat(sV.input.value)) - 1) / 3);
    return 3 * f + 1;
  };

  function draw() {
    const N = Math.min(MAX_VECTOR_LENGTH, sig3(Math.pow(10, parseFloat(sN.input.value))));
    const kMax = maxDegree(N);
    sK.input.max = Math.log10(kMax);
    const validators = curV();
    const sc = scenario(N, Math.pow(10, parseFloat(sK.input.value)));
    const K = sc.E / N;
    sN.out.textContent = count(N);
    sK.out.textContent = Number(K.toPrecision(3));
    sV.out.textContent = count(validators);
    for (const s of [sN, sK, sV]) s.input.setAttribute('aria-valuetext', s.out.textContent);

    const parts = sc.parts;
    const payload = byteSize(parts);
    const total = validators * payload;
    const state = ACCOUNT_RECORD * N;
    oDealing.textContent = bytesText(payload);
    scope.textContent = 'Modeled keyed encoding; excludes certificates and other traffic.';
    oE.textContent = count(sc.E);
    oRows.textContent = count(sc.A);
    oEgress.textContent = `(${bytesText(total)} total egress)`;
    oState.textContent = `Full state records: ${bytesText(state)}`;
    canvas.setAttribute('aria-label', `Modeled keyed update size sent to each validator as recipients per live account increase. At the selected average of ${Number(K.toPrecision(3))} recipients, the operator sends ${bytesText(payload)} per validator, with total egress of ${bytesText(total)} per close. A dotted reference line shows all live account records, ${bytesText(state)} at ${ACCOUNT_RECORD} bytes each, excluding database overhead and retained evidence. Both axes use logarithmic scales.`);

    const components = [
      ['Accounts and sequences', parts.rows],
      ['Payer signatures', parts.signatures],
      ['Payment entries', parts.entries],
      ['Operator signature', parts.operator],
      ['Commitment', parts.metadata],
    ];
    fillBreakdown(breakdown, payload, components);

    const w = canvas.clientWidth;
    const h = Math.max(240, Math.round(w * 0.42));
    const dpr = window.devicePixelRatio;
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
    const Bm = 26;
    const pw = w - L - R;
    const ph = h - T - Bm;
    const kMin = 0.001;
    const STEPS = 120;
    const ks = [];
    const dealings = [];
    let yMin = Infinity;
    let yMax = 0;
    for (let j = 0; j <= STEPS; j += 1) {
      const kj = kMin * Math.pow(kMax / kMin, j / STEPS);
      const sj = scenario(N, kj);
      const bytes = byteSize(sj.parts);
      ks.push(sj.E / N);
      dealings.push(bytes);
      yMin = Math.min(yMin, bytes);
      yMax = Math.max(yMax, bytes);
    }
    yMin = Math.min(yMin, payload, state) * 0.55;
    yMax = Math.max(yMax, payload, state) * 1.5;
    const X = (k) => L + (pw * Math.log(k / ks[0])) / Math.log(kMax / ks[0]);
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
      if (kt < ks[0] || kt > kMax) continue;
      const xx = X(kt);
      g.beginPath();
      g.moveTo(xx, T);
      g.lineTo(xx, T + ph);
      g.stroke();
      g.textAlign = 'center';
      g.textBaseline = 'top';
      g.fillText(String(kt), xx, T + ph + 8);
    }
    g.strokeStyle = GRAY;
    g.lineWidth = 1.6;
    g.setLineDash([2, 4]);
    g.beginPath();
    g.moveTo(L, Y(state));
    g.lineTo(w - R, Y(state));
    g.stroke();
    g.setLineDash([]);

    g.strokeStyle = BLUE;
    g.lineWidth = 2.2;
    g.beginPath();
    for (let j = 0; j <= STEPS; j += 1) {
      if (j === 0) g.moveTo(X(ks[j]), Y(dealings[j]));
      else g.lineTo(X(ks[j]), Y(dealings[j]));
    }
    g.stroke();

    const cx = X(K);
    g.strokeStyle = GRAY;
    g.setLineDash([2, 3]);
    g.beginPath();
    g.moveTo(cx, T);
    g.lineTo(cx, T + ph);
    g.stroke();
    g.setLineDash([]);
    g.fillStyle = BLUE;
    g.strokeStyle = 'white';
    g.lineWidth = 2;
    g.beginPath();
    g.arc(cx, Y(payload), 4.5, 0, 7);
    g.fill();
    g.stroke();
  }

  for (const s of [sN, sK, sV]) s.input.addEventListener('input', draw);
  window.addEventListener('resize', draw);

  draw();
}

if (typeof document !== 'undefined') {
  const root = document.getElementById('clearing-fig-calculator');
  if (root) mount(root);
}
