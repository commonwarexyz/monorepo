// Looping message-sequence diagrams for the Multimmit launch post. Each
// figure is an SVG timeline: rows are participants, the x-axis is time in
// units of the message delay δ, and arrows draw in as the playhead advances.
// Figures share one px-per-δ scale so finality gaps compare across figures.

const SVG_NS = 'http://www.w3.org/2000/svg';
const DESIGN_W = 1024;
const PLOT_X0 = 170;
const PLOT_X1 = 1014;

const RED = '#d9251c';
const BLUE = '#1f1fd1';
const GRAY = '#8a8a8a';
const FAINT = '#b5b5b5';
const GOLD = '#b89b37';
const GOLD_FILL = '#fffbe8';

const STYLES = {
  tx: { stroke: RED, width: 2.4, opacity: 1 },
  blk: { stroke: RED, width: 3.4, opacity: 0.95 },
  ctl: { stroke: BLUE, width: 2, opacity: 0.9 },
  mesh: { stroke: BLUE, width: 1.4, opacity: 0.45 },
  sup: { stroke: GOLD, width: 2.2, opacity: 0.95 },
  bg: { stroke: FAINT, width: 1.6, opacity: 0.6 },
};

// Playback pacing: δ-units per second, plus holds (in seconds) so each loop
// opens on an empty stage and rests on the finished diagram before fading.
const SPEED = 0.9;
const START_HOLD = 0.8;
const END_HOLD = 2.6;
const FADE_S = 0.45;

const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
const lerp = (a, b, t) => a + (b - a) * t;

const ROWS_CONSENSUS = [
  { id: 'user', label: 'User' },
  { id: 'api', label: 'API node' },
  { id: 'leader', label: 'Leader' },
  { id: 'v2', label: 'Validator 2' },
  { id: 'v3', label: 'Validator 3' },
  { id: 'v4', label: 'Validator 4' },
];
const VALIDATORS = ['leader', 'v2', 'v3', 'v4'];

const FIGURES = {
  'multimmit-fig-simplex': {
    height: 440,
    rows: ROWS_CONSENSUS,
    rowTop: 84,
    rowGap: 57,
    axis: { min: -0.4, max: 7.6, origin: null },
    variants: [{
      end: 5,
      phases: [
        { t: 0, d: 1, label: 'submit' },
        { t: 1, d: 1, label: 'forward' },
        { t: 2, d: 1, label: 'block' },
        { t: 3, d: 1, label: 'notarize' },
        { t: 4, d: 1, label: 'finalize' },
      ],
      events: [
        { k: 'msg', from: 'user', to: 'api', t: 0, d: 1, style: 'tx', label: 'tx' },
        { k: 'msg', from: 'api', to: 'leader', t: 1, d: 1, style: 'tx' },
        { k: 'emit', row: 'leader', t: 2, color: RED, label: 'block' },
        { k: 'fan', from: 'leader', to: ['v2', 'v3', 'v4'], t: 2, d: 1, style: 'blk' },
        { k: 'mesh', among: VALIDATORS, t: 3, d: 1 },
        { k: 'mesh', among: VALIDATORS, t: 4, d: 1 },
        { k: 'mark', t: 5, label: 'finalized', sub: 'block + 3δ' },
      ],
      token: [
        { t0: -0.4, t1: 0, at: 'user' },
        { t0: 0, t1: 1, from: 'user', to: 'api' },
        { t0: 1, t1: 2, from: 'api', to: 'leader' },
        { t0: 2, t1: 3, from: 'leader', to: 'v3' },
        { t0: 3, t1: 99, at: 'v3' },
      ],
    }],
  },

  'multimmit-fig-lanes': {
    height: 440,
    rows: ROWS_CONSENSUS,
    rowTop: 84,
    rowGap: 57,
    axis: { min: -0.4, max: 7.6, origin: null },
    variants: [{
      end: 7,
      phases: [
        { t: 0, d: 1, label: 'submit' },
        { t: 1, d: 1, label: 'batch' },
        { t: 2, d: 1, label: 'DA-votes' },
        { t: 3, d: 1, label: 'PoA cert' },
        { t: 4, d: 1, label: 'proposal' },
        { t: 5, d: 1, label: 'notarize' },
        { t: 6, d: 1, label: 'finalize' },
      ],
      events: [
        { k: 'msg', from: 'user', to: 'api', t: 0, d: 1, style: 'tx', label: 'tx' },
        { k: 'emit', row: 'api', t: 1, color: RED, label: 'batch b' },
        { k: 'fan', from: 'api', to: VALIDATORS, t: 1, d: 1, style: 'blk' },
        { k: 'fan', from: VALIDATORS, to: 'api', t: 2, d: 1, style: 'ctl' },
        { k: 'emit', row: 'api', t: 3, color: BLUE, label: 'PoA' },
        { k: 'fan', from: 'api', to: VALIDATORS, t: 3, d: 1, style: 'ctl' },
        { k: 'emit', row: 'leader', t: 4, color: BLUE, label: 'block (refs PoA)', labelSide: 'right' },
        { k: 'fan', from: 'leader', to: ['v2', 'v3', 'v4'], t: 4, d: 1, style: 'ctl' },
        { k: 'mesh', among: VALIDATORS, t: 5, d: 1 },
        { k: 'mesh', among: VALIDATORS, t: 6, d: 1 },
        { k: 'mark', t: 7, label: 'finalized', sub: 'batch + 6δ' },
      ],
      token: [
        { t0: -0.4, t1: 0, at: 'user' },
        { t0: 0, t1: 1, from: 'user', to: 'api' },
        { t0: 1, t1: 2, from: 'api', to: 'v3' },
        { t0: 2, t1: 99, at: 'v3' },
      ],
    }],
  },

  'multimmit-fig-checkpoint': {
    height: 440,
    rows: ROWS_CONSENSUS,
    rowTop: 84,
    rowGap: 57,
    axis: { min: -0.4, max: 7.6, origin: null },
    variants: [{
      tag: 'leader checkpoints b',
      end: 4,
      phases: [
        { t: 0, d: 1, label: 'submit' },
        { t: 1, d: 1, label: 'block' },
        { t: 2, d: 1, label: 'proposal' },
        { t: 3, d: 1, label: 'votes' },
      ],
      events: [
        { k: 'msg', from: 'user', to: 'api', t: 0, d: 1, style: 'tx', label: 'tx' },
        { k: 'emit', row: 'api', t: 1, color: RED, label: 'block b' },
        { k: 'fan', from: 'api', to: VALIDATORS, t: 1, d: 1, style: 'blk' },
        { k: 'emit', row: 'leader', t: 2, color: BLUE, label: 'refs b' },
        { k: 'fan', from: 'leader', to: ['v2', 'v3', 'v4'], t: 2, d: 1, style: 'ctl' },
        { k: 'fan', from: VALIDATORS, to: 'api', t: 2, d: 1, style: 'bg' },
        { k: 'fan', from: 'api', to: VALIDATORS, t: 3, d: 1, style: 'bg' },
        { k: 'mesh', among: VALIDATORS, t: 3, d: 1 },
        { k: 'mark', t: 4, label: 'finalized', sub: 'block + 3δ' },
        { k: 'mark', t: 5, sub: 'fig. 1', ghost: true },
        { k: 'mark', t: 7, sub: 'fig. 2', ghost: true },
      ],
      token: [
        { t0: -0.4, t1: 0, at: 'user' },
        { t0: 0, t1: 1, from: 'user', to: 'api' },
        { t0: 1, t1: 2, from: 'api', to: 'v3' },
        { t0: 2, t1: 99, at: 'v3' },
      ],
    }],
  },

  'multimmit-fig-extend': {
    height: 440,
    rows: ROWS_CONSENSUS,
    rowTop: 84,
    rowGap: 57,
    axis: { min: -0.4, max: 7.6, origin: null },
    variants: [{
      tag: 'voters extend',
      end: 4,
      phases: [
        { t: 0, d: 1, label: 'submit' },
        { t: 2, d: 1, label: 'extension votes' },
      ],
      events: [
        { k: 'msg', from: 'user', to: 'api', t: 0, d: 1, style: 'tx', label: 'tx' },
        { k: 'emit', row: 'api', t: 1, color: RED, label: 'block b' },
        { k: 'fan', from: 'api', to: VALIDATORS, t: 1, d: 1, style: 'blk' },
        { k: 'emit', row: 'leader', t: 1, color: BLUE, label: 'proposal (no b)', labelSide: 'left' },
        { k: 'fan', from: 'leader', to: ['v2', 'v3', 'v4'], t: 1, d: 1, style: 'ctl' },
        { k: 'mesh', among: VALIDATORS, t: 2, d: 1 },
        { k: 'fan', from: VALIDATORS, to: 'api', t: 2, d: 1, style: 'bg' },
        { k: 'fan', from: 'api', to: VALIDATORS, t: 3, d: 1, style: 'bg' },
        { k: 'mark', t: 3, label: 'finalized', sub: 'block + 2δ' },
        { k: 'mark', t: 4, sub: 'fig. 3', ghost: true },
        { k: 'mark', t: 5, sub: 'fig. 1', ghost: true },
        { k: 'mark', t: 7, sub: 'fig. 2', ghost: true },
      ],
      token: [
        { t0: -0.4, t1: 0, at: 'user' },
        { t0: 0, t1: 1, from: 'user', to: 'api' },
        { t0: 1, t1: 2, from: 'api', to: 'v3' },
        { t0: 2, t1: 99, at: 'v3' },
      ],
    }],
  },

  'multimmit-fig-dagstructure': {
    height: 360,
    rows: [
      { id: 'v1', label: 'Validator 1' },
      { id: 'v2', label: 'Validator 2' },
      { id: 'v3', label: 'Validator 3' },
      { id: 'v4', label: 'Validator 4' },
    ],
    rowTop: 78,
    rowGap: 62,
    axis: { min: -0.5, max: 5.5, origin: null, unit: 'round' },
    variants: [{
      tag: 'each vertex references n−f of the previous round',
      end: 5.5,
      phases: [],
      events: [
        ...Array.from({ length: 6 }, (_, round) =>
          ['v1', 'v2', 'v3', 'v4'].map(row => ({ k: 'emit', row, t: round, color: RED }))
        ).flat(),
        ...Array.from({ length: 5 }, (_, i) => {
          const round = i + 1;
          const edges = [];
          ['v1', 'v2', 'v3', 'v4'].forEach((row, childIdx) => {
            ['v1', 'v2', 'v3', 'v4'].forEach((parent, parentIdx) => {
              // Each vertex references n-f = 3 of the 4 previous-round
              // vertices, skipping a different one per child for texture.
              if (parentIdx === (childIdx + round) % 4) return;
              edges.push({ k: 'edge', fromRow: row, fromT: round, toRow: parent, toT: round - 1, t: round, d: 0.45 });
            });
          });
          return edges;
        }).flat(),
      ],
      token: [],
    }],
  },

  'multimmit-fig-dagfinality': {
    height: 360,
    rows: [
      { id: 'v1', label: 'Validator 1' },
      { id: 'v2', label: 'Validator 2' },
      { id: 'v3', label: 'Validator 3' },
      { id: 'v4', label: 'Validator 4' },
    ],
    rowTop: 78,
    rowGap: 62,
    axis: { min: -0.5, max: 5.5, origin: null, unit: 'round' },
    variants: [{
      tag: 'an anchor commits only after more rounds build on it',
      end: 5.5,
      phases: [],
      events: [
        ...Array.from({ length: 6 }, (_, round) =>
          ['v1', 'v2', 'v3', 'v4'].map((row, idx) => {
            // Anchor A is validator 2's round-1 vertex. Its causal history
            // is its three round-0 parents (the skip rule below excludes
            // index 2), and exactly that set turns gold at the commit.
            const anchor = round === 1 && idx === 1;
            const inHistory = anchor || (round === 0 && idx !== 2);
            return {
              k: 'emit', row, t: round, color: RED,
              ...(anchor ? { label: 'A' } : {}),
              ...(inHistory ? { finalAt: 3.5 } : {}),
            };
          })
        ).flat(),
        ...Array.from({ length: 5 }, (_, i) => {
          const round = i + 1;
          const edges = [];
          ['v1', 'v2', 'v3', 'v4'].forEach((row, childIdx) => {
            ['v1', 'v2', 'v3', 'v4'].forEach((parent, parentIdx) => {
              if (parentIdx === (childIdx + round) % 4) return;
              // Round-2 references to A are its support, drawn gold.
              const sup = round === 2 && parentIdx === 1;
              edges.push({
                k: 'edge', fromRow: row, fromT: round, toRow: parent, toT: round - 1,
                t: round, d: 0.45, ...(sup ? { style: 'sup' } : {}),
              });
            });
          });
          return edges;
        }).flat(),
        { k: 'mark', t: 3.5, label: 'A finalized', sub: 'A + 2 rounds' },
      ],
      token: [],
    }],
  },

  'multimmit-fig-dagfetch': {
    height: 360,
    rows: [
      { id: 'v1', label: 'Validator 1' },
      { id: 'v2', label: 'Validator 2' },
      { id: 'v3', label: 'Validator 3' },
      { id: 'v4', label: 'Validator 4' },
    ],
    rowTop: 78,
    rowGap: 62,
    axis: { min: -0.5, max: 6.6, origin: null },
    variants: [{
      tag: 'one withheld vertex stalls the whole DAG',
      end: 6.3,
      phases: [],
      events: [
        { k: 'emit', row: 'v1', t: 0, color: RED, label: 'r' },
        { k: 'emit', row: 'v2', t: 0, color: RED },
        { k: 'emit', row: 'v3', t: 0, color: RED },
        { k: 'emit', row: 'v4', t: 0, color: RED },
        { k: 'emit', row: 'v1', t: 1, color: RED, label: 'r+1' },
        { k: 'emit', row: 'v2', t: 1, color: RED },
        { k: 'emit', row: 'v3', t: 1, color: RED, missingUntil: 4.6, label: 'withheld', labelSide: 'left' },
        { k: 'emit', row: 'v4', t: 1, color: RED },
        { k: 'edge', fromRow: 'v1', fromT: 1, toRow: 'v1', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v1', fromT: 1, toRow: 'v3', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v1', fromT: 1, toRow: 'v4', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v2', fromT: 1, toRow: 'v1', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v2', fromT: 1, toRow: 'v2', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v2', fromT: 1, toRow: 'v4', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v4', fromT: 1, toRow: 'v2', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v4', fromT: 1, toRow: 'v3', toT: 0, t: 1, d: 0.45 },
        { k: 'edge', fromRow: 'v4', fromT: 1, toRow: 'v4', toT: 0, t: 1, d: 0.45 },
        { k: 'emit', row: 'v1', t: 2, color: RED, label: 'r+2' },
        { k: 'emit', row: 'v2', t: 2, color: RED },
        { k: 'emit', row: 'v4', t: 2, color: RED },
        { k: 'edge', fromRow: 'v1', fromT: 2, toRow: 'v1', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v1', fromT: 2, toRow: 'v2', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v1', fromT: 2, toRow: 'v4', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v2', fromT: 2, toRow: 'v3', toT: 1, t: 2, d: 0.45, style: 'tx' },
        { k: 'edge', fromRow: 'v2', fromT: 2, toRow: 'v1', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v2', fromT: 2, toRow: 'v4', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v4', fromT: 2, toRow: 'v1', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v4', fromT: 2, toRow: 'v2', toT: 1, t: 2, d: 0.45 },
        { k: 'edge', fromRow: 'v4', fromT: 2, toRow: 'v4', toT: 1, t: 2, d: 0.45 },
        { k: 'msg', from: 'v1', to: 'v2', t: 2.6, d: 1, style: 'ctl', label: 'fetch' },
        { k: 'msg', from: 'v4', to: 'v2', t: 2.6, d: 1, style: 'ctl' },
        { k: 'msg', from: 'v2', to: 'v1', t: 3.6, d: 1, style: 'blk' },
        { k: 'msg', from: 'v2', to: 'v4', t: 3.6, d: 1, style: 'blk' },
        { k: 'mark', t: 3, sub: 'r+3 without the fault', ghost: true },
        { k: 'emit', row: 'v1', t: 4.7, color: RED, label: 'r+3' },
        { k: 'emit', row: 'v2', t: 4.7, color: RED },
        { k: 'emit', row: 'v4', t: 4.7, color: RED },
        ...['v1', 'v2', 'v4'].flatMap(row =>
          ['v1', 'v2', 'v4'].map(parent => (
            { k: 'edge', fromRow: row, fromT: 4.7, toRow: parent, toT: 2, t: 4.7, d: 0.45 }
          ))
        ),
        { k: 'emit', row: 'v1', t: 5.7, color: RED, label: 'r+4' },
        { k: 'emit', row: 'v2', t: 5.7, color: RED },
        { k: 'emit', row: 'v4', t: 5.7, color: RED },
        ...['v1', 'v2', 'v4'].flatMap(row =>
          ['v1', 'v2', 'v4'].map(parent => (
            { k: 'edge', fromRow: row, fromT: 5.7, toRow: parent, toT: 4.7, t: 5.7, d: 0.45 }
          ))
        ),
      ],
      token: [],
    }],
  },

  'multimmit-fig-dag': {
    height: 400,
    plotX0: 214,
    rows: [
      { id: 'dag', label: 'DAG producer' },
      { id: 'mm', label: 'Multimmit producer' },
    ],
    rowTop: 96,
    rowGap: 164,
    arcDepth: 66,
    axis: { min: -0.4, max: 8, origin: null },
    variants: [{
      end: 8,
      phases: [],
      events: [
        { k: 'emit', row: 'dag', t: 0, color: RED, label: 'v1', certAt: 2 },
        { k: 'arc', row: 'dag', t: 0, d: 2, label: 'PoA' },
        { k: 'emit', row: 'dag', t: 2, color: RED, label: 'v2', certAt: 4 },
        { k: 'arc', row: 'dag', t: 2, d: 2 },
        { k: 'emit', row: 'dag', t: 4, color: RED, label: 'v3', certAt: 6 },
        { k: 'arc', row: 'dag', t: 4, d: 2 },
        { k: 'emit', row: 'dag', t: 6, color: RED, label: 'v4', certAt: 8 },
        { k: 'arc', row: 'dag', t: 6, d: 2 },
        { k: 'counter', row: 'dag', unit: 'blocks' },
        { k: 'emit', row: 'mm', t: 0, color: RED, label: 'b1', certAt: 2 },
        ...Array.from({ length: 10 }, (_, i) => (
          { k: 'emit', row: 'mm', t: (i + 1) * 0.7, color: RED, certAt: (i + 1) * 0.7 + 2 }
        )),
        { k: 'arc', row: 'mm', t: 0, d: 2, label: 'PoA' },
        ...Array.from({ length: 10 }, (_, i) => (
          { k: 'arc', row: 'mm', t: (i + 1) * 0.7, d: 2, faint: true }
        )),
        { k: 'counter', row: 'mm', unit: 'blocks' },
      ],
      token: [],
    }],
  },
};

const STYLE_ID = 'multimmit-loops-style';

// Layout-critical rules (mount aspect ratios, noscript fallbacks) live in an
// inline <style> in the markdown so they apply at first paint. Everything
// here only styles elements this module creates.
function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .cw-loop-svg {
      background: white;
      cursor: pointer;
      display: block;
      height: auto;
      width: 100%;
    }

    .cw-loop-svg text {
      font-family: monospace;
      user-select: none;
    }
  `;
  document.head.appendChild(style);
}

function svgEl(name, attrs = {}) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  return el;
}

function text(x, y, str, attrs = {}) {
  const el = svgEl('text', { x, y, 'font-size': 15, fill: 'black', ...attrs });
  el.textContent = str;
  return el;
}

// Progressive line reveal: the full geometry is set once and the dash offset
// exposes a prefix of it each frame. Heads fade in as the line completes.
function makeLine(x0, y0, x1, y1, style) {
  const s = STYLES[style];
  const length = Math.hypot(x1 - x0, y1 - y0);
  const line = svgEl('line', {
    x1: x0, y1: y0, x2: x1, y2: y1,
    stroke: s.stroke, 'stroke-width': s.width, 'stroke-linecap': 'round',
    'stroke-dasharray': length, 'stroke-dashoffset': length, opacity: s.opacity,
  });
  const ux = (x1 - x0) / (length || 1);
  const uy = (y1 - y0) / (length || 1);
  const size = s.width >= 3 ? 11 : 8.5;
  const bx = x1 - ux * size;
  const by = y1 - uy * size;
  const half = size * 0.42;
  const head = svgEl('polygon', {
    points: `${x1},${y1} ${bx - uy * half},${by + ux * half} ${bx + uy * half},${by - ux * half}`,
    fill: s.stroke, opacity: 0,
  });
  return {
    line, head, length,
    set(frac) {
      line.setAttribute('opacity', frac === 0 ? 0 : s.opacity);
      line.setAttribute('stroke-dashoffset', length * (1 - frac));
      head.setAttribute('opacity', frac > 0.97 ? s.opacity : 0);
    },
  };
}

function buildFigure(mount, cfg) {
  const H = cfg.height;
  const svg = svgEl('svg', {
    viewBox: `0 0 ${DESIGN_W} ${H}`,
    class: 'cw-loop-svg',
    role: 'img',
  });
  if (mount.getAttribute('aria-label')) {
    svg.setAttribute('aria-label', mount.getAttribute('aria-label'));
  }
  mount.textContent = '';
  mount.appendChild(svg);

  const x0 = cfg.plotX0 ?? PLOT_X0;
  const pxPerDelta = (PLOT_X1 - x0) / (cfg.axis.max - cfg.axis.min);
  const xOf = t => x0 + (t - cfg.axis.min) * pxPerDelta;
  const rowY = {};
  cfg.rows.forEach((row, i) => { rowY[row.id] = cfg.rowTop + i * cfg.rowGap; });

  const staticLayer = svgEl('g');
  svg.appendChild(staticLayer);

  const axisY = H - 34;
  for (let t = Math.ceil(cfg.axis.min); t <= Math.floor(cfg.axis.max); t++) {
    const x = xOf(t);
    staticLayer.appendChild(svgEl('line', {
      x1: x, y1: 46, x2: x, y2: axisY - 12,
      stroke: '#e4e4e4', 'stroke-width': 1,
    }));
    let label;
    if (cfg.axis.unit === 'round') {
      label = t === 0 ? 'round r' : `r+${t}`;
    } else if (cfg.axis.origin === null) {
      label = t === 0 ? '0' : `${t}δ`;
    } else {
      const k = t - cfg.axis.origin;
      label = k === 0 ? 't' : (k > 0 ? `t+${k}δ` : `t−${-k}δ`);
    }
    staticLayer.appendChild(text(x, axisY + 4, label, {
      'text-anchor': 'middle', fill: GRAY, 'font-size': 14,
    }));
  }

  for (const row of cfg.rows) {
    const y = rowY[row.id];
    staticLayer.appendChild(text(x0 - 18, y + 5, row.label, {
      'text-anchor': 'end', 'font-size': 17, 'font-weight': row.id === 'user' ? 400 : 600,
    }));
    staticLayer.appendChild(svgEl('line', {
      x1: x0 - 6, y1: y, x2: PLOT_X1, y2: y,
      stroke: '#cfcfcf', 'stroke-width': 1.2,
    }));
  }

  // Ghost markers persist across the loop fade, so they get their own layer
  // beneath everything time-dependent, which goes in one group the loop can
  // fade out.
  const ghostLayer = svgEl('g');
  svg.appendChild(ghostLayer);
  const dyn = svgEl('g');
  svg.appendChild(dyn);

  const variantTag = text(PLOT_X1, 22, '', {
    'text-anchor': 'end', 'font-size': 16, fill: BLUE, 'font-weight': 600,
  });
  svg.appendChild(variantTag);

  const builders = {
    msg(ev) {
      const arrow = makeLine(xOf(ev.t), rowY[ev.from], xOf(ev.t + ev.d), rowY[ev.to], ev.style);
      dyn.append(arrow.line, arrow.head);
      let labelEl = null;
      if (ev.label) {
        const midX = (xOf(ev.t) + xOf(ev.t + ev.d)) / 2;
        const midY = (rowY[ev.from] + rowY[ev.to]) / 2;
        labelEl = text(midX + 10, midY - 8, ev.label, { fill: STYLES[ev.style].stroke, 'font-size': 15 });
        labelEl.setAttribute('opacity', 0);
        dyn.appendChild(labelEl);
      }
      return tau => {
        const frac = clamp((tau - ev.t) / ev.d, 0, 1);
        arrow.set(frac);
        if (labelEl) labelEl.setAttribute('opacity', frac > 0.15 ? 1 : 0);
      };
    },
    fan(ev) {
      const froms = Array.isArray(ev.from) ? ev.from : [ev.from];
      const tos = Array.isArray(ev.to) ? ev.to : [ev.to];
      const arrows = [];
      for (const f of froms) {
        for (const t of tos) {
          if (f === t) continue;
          arrows.push(makeLine(xOf(ev.t), rowY[f], xOf(ev.t + ev.d), rowY[t], ev.style));
        }
      }
      for (const a of arrows) dyn.append(a.line, a.head);
      let labelEl = null;
      if (ev.label) {
        const ys = [...froms, ...tos].map(id => rowY[id]);
        labelEl = text((xOf(ev.t) + xOf(ev.t + ev.d)) / 2, Math.max(...ys) + 24, ev.label, {
          'text-anchor': 'middle', fill: STYLES[ev.style].stroke, 'font-size': 14,
        });
        labelEl.setAttribute('opacity', 0);
        dyn.appendChild(labelEl);
      }
      return tau => {
        const frac = clamp((tau - ev.t) / ev.d, 0, 1);
        for (const a of arrows) a.set(frac);
        if (labelEl) labelEl.setAttribute('opacity', frac > 0.15 ? 1 : 0);
      };
    },
    mesh(ev) {
      const arrows = [];
      for (const f of ev.among) {
        for (const t of ev.among) {
          if (f === t) continue;
          arrows.push(makeLine(xOf(ev.t), rowY[f], xOf(ev.t + ev.d), rowY[t], 'mesh'));
        }
      }
      for (const a of arrows) dyn.append(a.line, a.head);
      let labelEl = null;
      if (ev.label) {
        const ys = ev.among.map(id => rowY[id]);
        labelEl = text((xOf(ev.t) + xOf(ev.t + ev.d)) / 2, Math.max(...ys) + 24, ev.label, {
          'text-anchor': 'middle', fill: BLUE, 'font-size': 14,
        });
        labelEl.setAttribute('opacity', 0);
        dyn.appendChild(labelEl);
      }
      return tau => {
        const frac = clamp((tau - ev.t) / ev.d, 0, 1);
        for (const a of arrows) a.set(frac);
        if (labelEl) labelEl.setAttribute('opacity', frac > 0.15 ? 1 : 0);
      };
    },
    emit(ev) {
      const x = xOf(ev.t);
      const y = rowY[ev.row];
      const size = 13;
      const rect = svgEl('rect', {
        x: x - size / 2, y: y - size / 2, width: size, height: size,
        fill: ev.color, stroke: 'black', 'stroke-width': 1, opacity: 0,
      });
      dyn.appendChild(rect);
      let labelEl = null;
      if (ev.label) {
        const left = ev.labelSide === 'left';
        const right = ev.labelSide === 'right';
        labelEl = text(left ? x - 12 : (right ? x + 12 : x), left ? y + 5 : y - 13, ev.label, {
          'text-anchor': left ? 'end' : (right ? 'start' : 'middle'),
          fill: ev.missingUntil !== undefined ? GRAY : (ev.color === RED ? RED : BLUE), 'font-size': 14,
        });
        labelEl.setAttribute('opacity', 0);
        dyn.appendChild(labelEl);
      }
      let holeEl = null;
      if (ev.missingUntil !== undefined) {
        holeEl = text(x, y + 5, '?', { 'text-anchor': 'middle', fill: GRAY, 'font-size': 13, 'font-weight': 700 });
        holeEl.setAttribute('opacity', 0);
        dyn.appendChild(holeEl);
      }
      return tau => {
        const on = tau >= ev.t;
        // Certification swaps the fill so in-flight blocks read as pending,
        // an anchor's commit turns ordered vertices gold, and a withheld
        // vertex is a dashed hole until fetched.
        const certified = ev.certAt !== undefined && tau >= ev.certAt;
        const finalized = ev.finalAt !== undefined && tau >= ev.finalAt;
        const missing = ev.missingUntil !== undefined && tau < ev.missingUntil;
        rect.setAttribute('opacity', on ? 1 : 0);
        rect.setAttribute('fill', missing ? 'white' : (finalized ? GOLD_FILL : (certified ? 'white' : ev.color)));
        rect.setAttribute('stroke', missing ? GRAY : (finalized ? GOLD : (certified ? ev.color : 'black')));
        rect.setAttribute('stroke-width', finalized || certified ? 2 : 1);
        rect.setAttribute('stroke-dasharray', missing ? '3 2' : 'none');
        if (labelEl) labelEl.setAttribute('opacity', on ? 1 : 0);
        if (holeEl) holeEl.setAttribute('opacity', on && missing ? 1 : 0);
      };
    },
    mark(ev) {
      const x = xOf(ev.t);
      const group = svgEl('g', { opacity: 0 });
      const lineEl = svgEl('line', {
        x1: x, y1: 46, x2: x, y2: H - 46,
        stroke: ev.ghost ? GRAY : GOLD, 'stroke-width': ev.ghost ? 1.5 : 2.5,
        'stroke-dasharray': ev.ghost ? '5 4' : 'none',
      });
      const halo = svgEl('rect', {
        x: x - 9, y: 46, width: 18, height: H - 92,
        fill: GOLD_FILL, opacity: 0,
      });
      group.append(halo, lineEl);
      if (ev.label) {
        group.appendChild(text(x, 40, ev.label, {
          'text-anchor': 'middle', 'font-size': ev.ghost ? 14 : 17,
          fill: ev.ghost ? GRAY : GOLD, 'font-weight': ev.ghost ? 400 : 700,
        }));
      }
      if (ev.sub) {
        // Labels sit beside the line, never on it: gold finality on the
        // left, ghost references on the right.
        group.appendChild(text(ev.ghost ? x + 7 : x - 7, H - 52, ev.sub, {
          'text-anchor': ev.ghost ? 'start' : 'end', 'font-size': ev.ghost ? 14 : 15,
          fill: ev.ghost ? GRAY : GOLD, 'font-weight': ev.ghost ? 400 : 700,
        }));
      }
      (ev.ghost ? ghostLayer : dyn).appendChild(group);
      return tau => {
        // Ghost markers are comparison context, visible for the whole loop.
        const on = ev.ghost || tau >= ev.t;
        group.setAttribute('opacity', on ? 1 : 0);
        if (!ev.ghost) halo.setAttribute('opacity', on ? clamp(1 - (tau - ev.t) / 0.8, 0, 1) * 0.9 : 0);
      };
    },
    edge(ev) {
      // A DAG reference: drawn from the child vertex back to its parent, so
      // the arrowhead lands on the block being referenced.
      const arrow = makeLine(
        xOf(ev.fromT) - 9, rowY[ev.fromRow],
        xOf(ev.toT) + 9, rowY[ev.toRow],
        ev.style ?? 'mesh',
      );
      dyn.append(arrow.line, arrow.head);
      return tau => arrow.set(clamp((tau - ev.t) / ev.d, 0, 1));
    },
    arc(ev) {
      const y = rowY[ev.row];
      const x0 = xOf(ev.t);
      const x1 = xOf(ev.t + ev.d);
      const depth = cfg.arcDepth;
      const path = svgEl('path', {
        d: `M ${x0} ${y + 9} C ${x0} ${y + depth}, ${x1} ${y + depth}, ${x1} ${y + 9}`,
        fill: 'none', stroke: ev.faint ? FAINT : BLUE,
        'stroke-width': ev.faint ? 1.4 : 2, opacity: ev.faint ? 0.55 : 0.85,
      });
      dyn.appendChild(path);
      const length = path.getTotalLength();
      path.setAttribute('stroke-dasharray', length);
      path.setAttribute('stroke-dashoffset', length);
      let labelEl = null;
      if (ev.label) {
        labelEl = text((x0 + x1) / 2, y + depth + 6, ev.label, {
          'text-anchor': 'middle', fill: BLUE, 'font-size': 14,
        });
        labelEl.setAttribute('opacity', 0);
        dyn.appendChild(labelEl);
      }
      return tau => {
        const frac = clamp((tau - ev.t) / ev.d, 0, 1);
        path.setAttribute('stroke-dashoffset', length * (1 - frac));
        if (labelEl) labelEl.setAttribute('opacity', frac > 0.3 ? 1 : 0);
      };
    },
    counter(ev) {
      const labelEl = text(PLOT_X1, rowY[ev.row] - 22, '', {
        'text-anchor': 'end', 'font-size': 16, fill: 'black', 'font-weight': 600,
      });
      dyn.appendChild(labelEl);
      return (tau, variant) => {
        const count = variant.events.filter(e => e.k === 'emit' && e.row === ev.row && tau >= e.t).length;
        labelEl.textContent = count > 0 ? `${count} ${count === 1 ? 'block' : ev.unit}` : '';
      };
    },
  };

  const token = svgEl('circle', { r: 6, fill: RED, stroke: 'white', 'stroke-width': 1.5, opacity: 0 });

  let updaters = [];
  let activeVariant = null;

  function mountVariant(variant) {
    ghostLayer.textContent = '';
    dyn.textContent = '';
    activeVariant = variant;
    updaters = variant.events.map(ev => builders[ev.k](ev));

    for (const phase of variant.phases) {
      const labelEl = text((xOf(phase.t) + xOf(phase.t + phase.d)) / 2, 22, phase.label, {
        'text-anchor': 'middle', 'font-size': 15, fill: 'black',
      });
      labelEl.setAttribute('opacity', 0);
      dyn.appendChild(labelEl);
      updaters.push(tau => labelEl.setAttribute('opacity', tau >= phase.t ? 1 : 0.0));
    }

    if (variant.token.length > 0) dyn.appendChild(token);
    variantTag.textContent = variant.tag || '';
  }

  function render(tau) {
    for (const update of updaters) update(tau, activeVariant);

    // The token's worldline: it glides right along a row while waiting
    // (x is time) and rides the diagonal while a message carries it.
    const seg = activeVariant.token.findLast(s => tau >= s.t0);
    if (seg) {
      const frac = clamp((tau - seg.t0) / (seg.t1 - seg.t0), 0, 1);
      if (seg.at) {
        token.setAttribute('cx', xOf(clamp(tau, seg.t0, Math.min(seg.t1, cfg.axis.max))));
        token.setAttribute('cy', rowY[seg.at]);
      } else {
        token.setAttribute('cx', lerp(xOf(seg.t0), xOf(seg.t1), frac));
        token.setAttribute('cy', lerp(rowY[seg.from], rowY[seg.to], frac));
      }
      token.setAttribute('opacity', 1);
    } else {
      token.setAttribute('opacity', 0);
    }
  }

  return { svg, dyn, mountVariant, render };
}

function initFigure(mount, cfg, reducedMotion, freezeSeconds) {
  if (typeof mount.cwDispose === 'function') mount.cwDispose();
  mount.cwDispose = null;
  const fig = buildFigure(mount, cfg);

  if (reducedMotion) {
    // Static fallback: the completed diagram of the final variant.
    const variant = cfg.variants[cfg.variants.length - 1];
    fig.mountVariant(variant);
    fig.render(variant.end + 0.01);
    fig.svg.style.cursor = 'default';
    return;
  }

  const loopSeconds = variant =>
    START_HOLD + ((variant.holdTo ?? variant.end) - cfg.axis.min) / SPEED + END_HOLD;

  let epoch = performance.now();
  let paused = false;
  let pausedAt = 0;
  let visible = false;
  let rafId = 0;

  const cycleSeconds = cfg.variants.reduce((sum, v) => sum + loopSeconds(v), 0);

  function frame(now) {
    rafId = 0;
    let into = ((now - epoch) / 1000) % cycleSeconds;
    let index = 0;
    while (index < cfg.variants.length - 1 && into >= loopSeconds(cfg.variants[index])) {
      into -= loopSeconds(cfg.variants[index]);
      index += 1;
    }
    const variant = cfg.variants[index];
    if (fig.dynVariant !== variant) {
      fig.mountVariant(variant);
      fig.dynVariant = variant;
    }

    const dur = loopSeconds(variant);
    const tau = cfg.axis.min + Math.max(0, into - START_HOLD) * SPEED;
    fig.render(Math.min(tau, (variant.holdTo ?? variant.end) + 0.011));

    const fadeIn = clamp(into / 0.3, 0, 1);
    const fadeOut = clamp((dur - into) / FADE_S, 0, 1);
    fig.dyn.setAttribute('opacity', Math.min(fadeIn, fadeOut));

    if (visible && !paused) rafId = requestAnimationFrame(frame);
  }

  function start() {
    if (!rafId && visible && !paused) rafId = requestAnimationFrame(frame);
  }

  // Debug and card-capture hook: ?freeze=<seconds> renders the frame that a
  // live loop would show that many seconds in, with no animation.
  if (freezeSeconds !== null) {
    visible = true;
    paused = true;
    epoch = 0;
    frame(freezeSeconds * 1000);
    return;
  }

  fig.svg.addEventListener('click', () => {
    paused = !paused;
    if (paused) {
      pausedAt = performance.now();
      if (rafId) cancelAnimationFrame(rafId);
      rafId = 0;
    } else {
      epoch += performance.now() - pausedAt;
      start();
    }
  });
  const tooltip = svgEl('title');
  tooltip.textContent = 'Click to pause';
  fig.svg.appendChild(tooltip);

  // Restart from the beginning whenever the figure scrolls into view so
  // readers always catch the opening, and stop burning frames offscreen.
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      const wasVisible = visible;
      visible = entry.isIntersecting;
      if (visible && !wasVisible) {
        epoch = performance.now();
        paused = false;
        start();
      }
      if (!visible && rafId) {
        cancelAnimationFrame(rafId);
        rafId = 0;
      }
    }
  }, { threshold: 0.25 });
  observer.observe(mount);

  mount.cwDispose = () => {
    if (rafId) cancelAnimationFrame(rafId);
    rafId = 0;
    paused = true;
    observer.disconnect();
  };
}

function initAll() {
  injectStyles();
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const freezeParam = new URLSearchParams(window.location.search).get('freeze');
  const freezeSeconds = freezeParam === null ? null : Number(freezeParam);
  for (const [id, cfg] of Object.entries(FIGURES)) {
    const mount = document.getElementById(id);
    if (!mount) continue;
    initFigure(mount, cfg, reducedMotion.matches, freezeSeconds);
  }
  // Re-init statically if the preference flips on after load. Flipping it
  // back off requires a reload, which is fine for an edge case.
  reducedMotion.addEventListener('change', event => {
    if (!event.matches) return;
    for (const [id, cfg] of Object.entries(FIGURES)) {
      const mount = document.getElementById(id);
      if (mount) initFigure(mount, cfg, true, null);
    }
  });
}

initAll();
