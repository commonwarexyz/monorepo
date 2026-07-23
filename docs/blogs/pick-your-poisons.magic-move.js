const MOUNT_ID = 'pick-your-poisons-magic-move';

const LEFT_COLUMN_X = 19;
const MIDDLE_COLUMN_X = 52;
const RIGHT_COLUMN_X = 80;

// slide1 is the DAG layout; slide2 is the tradeoff-column layout (null fades
// the box out during the final transition instead of moving it).
const BOXES = [
  { id: 'bte', title: 'Batched Threshold Encryption', papers: 'CGPP24', slide1: { x: 38.5, y: 12 }, slide2: { x: LEFT_COLUMN_X, y: 27 } },
  { id: 'ste', title: 'Silent Threshold Encryption', papers: 'GKPW24, WW25', slide1: { x: 77.25, y: 12 }, slide2: null },
  { id: 'beat', title: 'BEAT-MEV(++)', papers: 'BFOQ25, ABDGMPRY25', slide1: { x: 63, y: 28 }, slide2: { x: MIDDLE_COLUMN_X, y: 27 } },
  { id: 'pfbte', title: 'Partial Fraction-BTE', papers: 'BNRT26', slide1: { x: 15.75, y: 31.5 }, slide2: { x: RIGHT_COLUMN_X, y: 27 } },
  { id: 'btibe', title: 'Batched Threshold IBE', papers: 'CGPW25, AFP25, GWWW25', slide1: { x: 47.25, y: 44 }, slide2: { x: LEFT_COLUMN_X, y: 41 } },
  { id: 'simple', title: 'Simple BTE, BTX', papers: 'Pol26a, ADGRS26', slide1: { x: 20.75, y: 56.25 }, slide2: { x: RIGHT_COLUMN_X, y: 41 } },
  { id: 'trx', title: 'TrX', papers: 'FPTX25', slide1: { x: 43.75, y: 62.5 }, slide2: { x: LEFT_COLUMN_X, y: 69 } },
  { id: 'sbtibe', title: 'Silent Batched (T)IBE', papers: 'GWWW25', slide1: { x: 65.25, y: 62.5 }, slide2: { x: LEFT_COLUMN_X, y: 55 } },
  { id: 'beast', title: 'BEAST-MEV', papers: 'BCFGOPQW25', slide1: { x: 88.75, y: 62.5 }, slide2: { x: MIDDLE_COLUMN_X, y: 41 } },
];

const EPRINT_URLS = {
  CGPP24: 'https://eprint.iacr.org/2024/669',
  GKPW24: 'https://eprint.iacr.org/2024/263',
  WW25: 'https://eprint.iacr.org/2025/1547',
  BFOQ25: 'https://eprint.iacr.org/2024/1533',
  ABDGMPRY25: 'https://eprint.iacr.org/2025/2115',
  BNRT26: 'https://eprint.iacr.org/2026/674',
  CGPW25: 'https://eprint.iacr.org/2024/1516',
  AFP25: 'https://eprint.iacr.org/2024/1575',
  GWWW25: 'https://eprint.iacr.org/2025/2103',
  Pol26a: 'https://eprint.iacr.org/2026/760',
  ADGRS26: 'https://eprint.iacr.org/2026/754',
  FPTX25: 'https://eprint.iacr.org/2025/2032',
  BCFGOPQW25: 'https://eprint.iacr.org/2025/1419',
  Pol26b: 'https://eprint.iacr.org/2026/1452',
};

const ARROWS = [
  { from: 'bte', to: 'simple' },
  { from: 'bte', to: 'pfbte' },
  { from: 'bte', to: 'btibe' },
  { from: 'bte', to: 'beat' },
  { from: 'btibe', to: 'trx' },
  { from: 'btibe', to: 'sbtibe' },
  { from: 'ste', to: 'sbtibe' },
  { from: 'ste', to: 'beast' },
  { from: 'beat', to: 'beast' },
];

const HEADERS = [
  { text: 'Epoch Restriction', x: LEFT_COLUMN_X, y: 13 },
  { text: 'Censorship Issues', x: MIDDLE_COLUMN_X, y: 13 },
  { text: 'Complicated Setup', x: RIGHT_COLUMN_X, y: 13 },
];

const DIVIDERS = [
  { x: 38.5, y1: 7, y2: 71 },
  { x: 65.5, y1: 7, y2: 71 },
];

// Scroll progress where the DAG story hands off to the final tradeoff layout.
const STORY_END = 0.82;

const WINDOWS = {
  arrowsFade: [0.82, 0.91],
  unmatchedFade: [0.84, 0.94],
  textCross: [0.82, 0.91],
  slide2Fade: [0.87, 0.99],
  dreamFade: [0.89, 1.00],
  storyFade: [0.78, 0.84],
};

const STEP_PHASE = {
  arrow: [0.08, 0.24],
  rootNode: [0.00, 0.08],
  childNode: [0.25, 0.36],
  textIn: [0.08, 0.36],
  textOut: [0.88, 0.99],
  finalFull: 0.96,
};

// Nodes highlighted at each step, paired 1:1 with the paragraphs in
// #pick-your-poisons-story-source. Arrows draw when their target node first
// reveals. A node may repeat (e.g. 'beat') so a later paragraph re-highlights it.
const STORY_STEPS = [
  ['bte'],
  ['btibe'],
  ['beat'],
  ['beat'],
  ['trx'],
  ['pfbte'],
  ['simple'],
  ['ste', 'sbtibe', 'beast'],
];

const NODE_REVEAL_STEP = {};
STORY_STEPS.forEach((nodes, index) => {
  for (const node of nodes) {
    if (!(node in NODE_REVEAL_STEP)) NODE_REVEAL_STEP[node] = index;
  }
});

const NODE_HAS_INCOMING = {};
for (const arrow of ARROWS) NODE_HAS_INCOMING[arrow.to] = true;

// Scroll stops for arrow-key navigation, Keynote style: the settled point of
// each story step (arrow drawn, node revealed, text readable), then the fully
// lit DAG at the end of slide 1, then the completed tradeoff layout with the
// dream-goal text.
const KEY_STOPS = [
  ...STORY_STEPS.map((_, index) => ((index + 0.62) / STORY_STEPS.length) * STORY_END),
  STORY_END,
  1,
];

// Static copy of the completed Slide 1 DAG, extended with the two new
// constructions (highlighted).
const FINAL_MOUNT_ID = 'pick-your-poisons-new-constructions';
const FINAL_BOXES = [
  ...BOXES,
  { id: 'isbte', title: 'Indexed Simple BTE', papers: 'Pol26a', slide1: { x: 20.75, y: 81 }, slide2: null },
  { id: 'pol26b', title: 'Labeled Multi-Key Batched IBE', papers: 'Pol26b', slide1: { x: 54.5, y: 81 }, slide2: null },
];
const FINAL_ARROWS = [
  ...ARROWS,
  { from: 'simple', to: 'isbte' },
  { from: 'trx', to: 'pol26b' },
  { from: 'sbtibe', to: 'pol26b' },
];
const FINAL_HIGHLIGHTS = ['isbte', 'pol26b'];

const STYLE_ID = 'pick-your-poisons-magic-move-style';
const SVG_NS = 'http://www.w3.org/2000/svg';
const DESIGN_WIDTH = 1024;
const DESIGN_HEIGHT = 576;
const DESIGN_STAGE_HEIGHT = 485;
const ARROW_DASH = 6;
const ARROW_GAP = 5;
const DIMMED_OPACITY = 0.38;
const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
const lerp = (a, b, t) => a + (b - a) * t;
const easeInOutCubic = t => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const window01 = (p, [start, end]) => clamp((p - start) / (end - start), 0, 1);

// Layout-critical rules (track height, source-div hiding, and the
// prefers-reduced-motion swap) live in an inline <style> in the markdown so
// they apply at first paint — before this module executes — and the prose
// sources never flash. Everything here only styles elements this module
// creates.
function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;

  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .cw-magic-move,
    .cw-magic-final {
      --cw-magic-ink: currentColor;
      --cw-magic-box-red: #d9251c;
      --cw-magic-arrow-blue: #1f1fd1;
      display: block;
    }

    .cw-magic-move *,
    .cw-magic-final * {
      box-sizing: border-box;
    }

    .cw-magic-final .cw-magic-stage {
      aspect-ratio: ${DESIGN_WIDTH} / ${DESIGN_HEIGHT};
    }

    .cw-magic-final .cw-magic-box.is-active {
      background: #fffbe8;
      border-color: #d8ca8d;
      box-shadow: 0 0 0 4px rgb(216 202 141 / 28%);
    }

    .cw-magic-sticky {
      background: white;
      position: sticky;
      top: 44px;
      width: 100%;
    }

    .cw-magic-stage {
      aspect-ratio: ${DESIGN_WIDTH} / ${DESIGN_STAGE_HEIGHT};
      background: white;
      height: auto;
      overflow: hidden;
      position: relative;
      width: 100%;
    }

    .cw-magic-canvas {
      height: ${DESIGN_HEIGHT}px;
      left: 0;
      position: absolute;
      top: 0;
      transform-origin: top left;
      width: ${DESIGN_WIDTH}px;
    }

    .cw-magic-morph {
      left: 0;
      position: absolute;
      top: 0;
      will-change: transform, opacity;
    }

    .cw-magic-headline {
      color: var(--cw-magic-ink);
      display: grid;
      font-family: inherit;
      font-size: 1.5em;
      font-weight: 700;
      line-height: 1.1;
      margin: 0;
      padding: 0 0.5em;
      text-align: center;
    }

    .cw-magic-headline span {
      grid-area: 1 / 1;
    }

    .cw-magic-box {
      background: white;
      border: 2px solid var(--cw-magic-box-red);
      color: var(--cw-magic-ink);
      font-family: ui-monospace, "SF Mono", Menlo, "Courier New", monospace;
      font-size: 19px;
      line-height: 1.35;
      padding: 0.35em 0.55em;
      text-align: center;
      white-space: nowrap;
      z-index: 3;
    }

    .cw-magic-box.is-active {
      box-shadow: 0 0 0 3px rgb(217 37 28 / 16%);
    }

    .cw-magic-box span {
      display: block;
    }

    .cw-magic-work-name {
      font-weight: 600;
    }

    .cw-magic-header {
      color: var(--cw-magic-ink);
      font-family: inherit;
      font-size: 1.5em;
      font-weight: 700;
      line-height: 1.1;
      text-align: center;
      z-index: 2;
    }

    .cw-magic-divider {
      background: var(--cw-magic-ink);
      position: absolute;
      transform: translateX(-50%);
      width: 2px;
      will-change: opacity;
      z-index: 1;
    }

    .cw-magic-arrows {
      height: 100%;
      inset: 0;
      pointer-events: none;
      position: absolute;
      width: 100%;
      will-change: opacity;
      z-index: 2;
    }

    .cw-magic-arrow-path,
    .cw-magic-arrow-stem {
      fill: none;
      stroke: var(--cw-magic-arrow-blue);
      stroke-linecap: round;
      stroke-width: 2;
    }

    .cw-magic-arrow-head {
      fill: var(--cw-magic-arrow-blue);
      opacity: 0;
    }

    .cw-magic-copy {
      font-family: inherit;
      margin: 8px auto 0;
      width: min(86%, 880px);
    }

    .cw-magic-story {
      color: var(--cw-magic-ink);
      font-family: inherit;
      opacity: 0;
      width: 100%;
      will-change: opacity, transform;
    }

    .cw-magic-story-body {
      color: var(--cw-magic-ink);
      margin: 0;
    }

    .cw-magic-dream {
      color: var(--cw-magic-ink);
      font-family: inherit;
      opacity: 0;
      text-align: left;
      width: 100%;
      will-change: opacity, transform;
    }

    .cw-magic-scroll-hint {
      --cw-scroll-hint-opacity: 1;
      animation: cw-magic-scroll-pulse 1.6s ease-in-out infinite;
      bottom: 18px;
      color: gray;
      font-family: inherit;
      left: 50%;
      pointer-events: none;
      position: fixed;
      text-align: center;
      transform: translateX(-50%);
      z-index: 20;
    }

    @keyframes cw-magic-scroll-pulse {
      0%, 100% { opacity: calc(var(--cw-scroll-hint-opacity) * 0.25); }
      50% { opacity: calc(var(--cw-scroll-hint-opacity) * 0.8); }
    }

    .cw-magic-dream p {
      margin: 0 0 5px;
    }

    .cw-magic-dream blockquote {
      margin: 12px 0;
    }

    .cw-magic-dream blockquote p {
      font-weight: 650;
      margin: 12px 0;
    }

    @media (max-width: 600px) {
      .cw-magic-box {
        font-size: 21px;
      }
    }
  `;
  document.head.appendChild(style);
}

function createSpan(text, className) {
  const span = document.createElement('span');
  if (className) span.className = className;
  span.textContent = text;
  return span;
}

function renderMath(container) {
  if (!window.katex) {
    window.addEventListener('load', () => renderMath(container), { once: true });
    return;
  }

  container.querySelectorAll('.math').forEach(el => {
    // Skip elements already rendered (e.g. by the page-level KaTeX onload hook).
    if (el.querySelector('.katex')) return;
    window.katex.render(el.textContent, el, {
      displayMode: el.classList.contains('display'),
      throwOnError: false,
    });
  });
}

// The source divs are hidden by the inline styles in the markdown and shown
// again under prefers-reduced-motion (or via <noscript> with scripting off),
// so the prose stays readable without the animation.
function readMarkdownSource() {
  const storySource = document.getElementById('pick-your-poisons-story-source');
  const dreamSource = document.getElementById('pick-your-poisons-dream-source');

  return {
    storyBodies: storySource
      ? Array.from(storySource.querySelectorAll('p')).map(paragraph => paragraph.innerHTML)
      : [],
    dreamHtml: dreamSource ? dreamSource.innerHTML : '',
  };
}

function createStage() {
  const stage = document.createElement('div');
  stage.className = 'cw-magic-stage';

  const canvas = document.createElement('div');
  canvas.className = 'cw-magic-canvas';

  const arrowLayer = document.createElementNS(SVG_NS, 'svg');
  arrowLayer.classList.add('cw-magic-arrows');
  arrowLayer.setAttribute('aria-hidden', 'true');
  arrowLayer.setAttribute('viewBox', `0 0 ${DESIGN_WIDTH} ${DESIGN_HEIGHT}`);
  const defs = document.createElementNS(SVG_NS, 'defs');
  arrowLayer.appendChild(defs);

  canvas.appendChild(arrowLayer);
  stage.appendChild(canvas);
  return { stage, canvas, arrowLayer, defs };
}

function createBoxEl(box) {
  const el = document.createElement('div');
  el.className = 'cw-magic-morph cw-magic-box';
  el.appendChild(createSpan(box.title, 'cw-magic-work-name'));

  const papers = document.createElement('span');
  box.papers.split(', ').forEach((paper, index) => {
    if (index > 0) papers.appendChild(document.createTextNode(', '));
    const url = EPRINT_URLS[paper];
    if (url) {
      const link = document.createElement('a');
      link.href = url;
      link.textContent = paper;
      papers.appendChild(link);
    } else {
      papers.appendChild(document.createTextNode(paper));
    }
  });
  el.appendChild(papers);
  return el;
}

function createArrowLines(arrowLayer, defs, arrows, maskPrefix) {
  return arrows.map((arrow, index) => {
    const maskId = `${maskPrefix}-arrow-mask-${index}`;
    const maskEl = document.createElementNS(SVG_NS, 'mask');
    maskEl.setAttribute('id', maskId);
    maskEl.setAttribute('maskUnits', 'userSpaceOnUse');
    const maskPath = document.createElementNS(SVG_NS, 'path');
    maskPath.setAttribute('fill', 'none');
    maskPath.setAttribute('stroke', 'white');
    maskPath.setAttribute('stroke-linecap', 'round');
    maskPath.setAttribute('stroke-width', '6');
    maskEl.appendChild(maskPath);
    defs.appendChild(maskEl);

    const pathEl = document.createElementNS(SVG_NS, 'path');
    pathEl.classList.add('cw-magic-arrow-path');
    pathEl.setAttribute('mask', `url(#${maskId})`);
    const stemEl = document.createElementNS(SVG_NS, 'path');
    stemEl.classList.add('cw-magic-arrow-stem');
    const headEl = document.createElementNS(SVG_NS, 'polygon');
    headEl.classList.add('cw-magic-arrow-head');
    arrowLayer.append(pathEl, stemEl, headEl);
    return { path: pathEl, maskPath, stem: stemEl, head: headEl, length: 1, stemLength: 1, ...arrow };
  });
}

function edgePoint(from, to, boxEl, gap = 0) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  const ex = boxEl.offsetWidth / 2 + gap;
  const ey = boxEl.offsetHeight / 2 + gap;
  const dist = Math.min(
    ux !== 0 ? ex / Math.abs(ux) : Infinity,
    uy !== 0 ? ey / Math.abs(uy) : Infinity,
  );
  return { x: from.x + ux * dist, y: from.y + uy * dist };
}

function arrowTip(tip, from, length = 8, width = 7) {
  const dx = tip.x - from.x;
  const dy = tip.y - from.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  const base = { x: tip.x - ux * length, y: tip.y - uy * length };
  const half = width / 2;
  const left = { x: base.x - uy * half, y: base.y + ux * half };
  const right = { x: base.x + uy * half, y: base.y - ux * half };
  const stemStart = { x: base.x - ux * 5, y: base.y - uy * 5 };

  return { base, stemStart, points: `${tip.x},${tip.y} ${left.x},${left.y} ${right.x},${right.y}` };
}

function boxRect(center, el, padding = 8) {
  return {
    left: center.x - el.offsetWidth / 2 - padding,
    right: center.x + el.offsetWidth / 2 + padding,
    top: center.y - el.offsetHeight / 2 - padding,
    bottom: center.y + el.offsetHeight / 2 + padding,
  };
}

function pointInRect(point, rect) {
  return point.x >= rect.left && point.x <= rect.right && point.y >= rect.top && point.y <= rect.bottom;
}

function sampleLine(from, to, count = 24) {
  return Array.from({ length: count + 1 }, (_, index) => {
    const t = index / count;
    return { x: lerp(from.x, to.x, t), y: lerp(from.y, to.y, t) };
  });
}

function sampleCurve(from, control, to, count = 32) {
  return Array.from({ length: count + 1 }, (_, index) => {
    const t = index / count;
    const a = (1 - t) * (1 - t);
    const b = 2 * (1 - t) * t;
    const c = t * t;
    return {
      x: a * from.x + b * control.x + c * to.x,
      y: a * from.y + b * control.y + c * to.y,
    };
  });
}

function segments(points) {
  return points.slice(1).map((point, index) => [points[index], point]);
}

function orientation(a, b, c) {
  return (b.y - a.y) * (c.x - b.x) - (b.x - a.x) * (c.y - b.y);
}

function segmentsIntersect(a, b, c, d) {
  const o1 = orientation(a, b, c);
  const o2 = orientation(a, b, d);
  const o3 = orientation(c, d, a);
  const o4 = orientation(c, d, b);
  return o1 * o2 < 0 && o3 * o4 < 0;
}

function routeScore(candidate, routedSegments, obstacles) {
  const boxHits = candidate.points.reduce((hits, point) => (
    hits + obstacles.filter(rect => pointInRect(point, rect)).length
  ), 0);
  const crossings = segments(candidate.points).reduce((count, segment) => (
    count + routedSegments.filter(other => segmentsIntersect(segment[0], segment[1], other[0], other[1])).length
  ), 0);

  return boxHits * 1000 + crossings * 40 + (candidate.control ? 8 : 0);
}

function arrowCandidates(from, to) {
  const base = [{ control: null, points: sampleLine(from, to) }];
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const len = Math.hypot(dx, dy) || 1;
  const normal = { x: -dy / len, y: dx / len };
  const midpoint = { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 };
  const offsets = [60, -60, 105, -105, 150, -150];

  for (const offset of offsets) {
    const control = {
      x: clamp(midpoint.x + normal.x * offset, 20, DESIGN_WIDTH - 20),
      y: clamp(midpoint.y + normal.y * offset, 20, DESIGN_HEIGHT - 20),
    };
    base.push({ control, points: sampleCurve(from, control, to) });
  }

  return base;
}

function chooseRoute(from, to, routedSegments, obstacles) {
  return arrowCandidates(from, to)
    .map(candidate => ({ ...candidate, score: routeScore(candidate, routedSegments, obstacles) }))
    .sort((a, b) => a.score - b.score)[0];
}

function place(el, xPct, yPct) {
  const px = (xPct / 100) * DESIGN_WIDTH;
  const py = (yPct / 100) * DESIGN_HEIGHT;
  el.style.transform = `translate(calc(-50% + ${px}px), calc(-50% + ${py}px))`;
}

// Routes every arrow between the slide1 box positions and draws its dashed
// path, reveal mask, stem, and head, avoiding other boxes and prior arrows.
function layoutArrows(arrowLines, boxEls) {
  const centerById = {};
  const elById = {};
  for (const { config, el } of boxEls) {
    centerById[config.id] = {
      x: (config.slide1.x / 100) * DESIGN_WIDTH,
      y: (config.slide1.y / 100) * DESIGN_HEIGHT,
    };
    elById[config.id] = el;
  }

  const routedSegments = [];
  for (const arrow of arrowLines) {
    const p1 = edgePoint(centerById[arrow.from], centerById[arrow.to], elById[arrow.from]);
    const tip = edgePoint(centerById[arrow.to], centerById[arrow.from], elById[arrow.to]);
    const obstacles = boxEls
      .filter(({ config }) => config.id !== arrow.from && config.id !== arrow.to)
      .map(({ config, el }) => boxRect(centerById[config.id], el));
    const route = chooseRoute(p1, tip, routedSegments, obstacles);
    const headFrom = route.control ?? p1;
    const head = arrowTip(tip, headFrom);

    const d = route.control
      ? `M ${p1.x} ${p1.y} Q ${route.control.x} ${route.control.y} ${head.stemStart.x} ${head.stemStart.y}`
      : `M ${p1.x} ${p1.y} L ${head.stemStart.x} ${head.stemStart.y}`;
    arrow.path.setAttribute('d', d);
    arrow.maskPath.setAttribute('d', d);
    arrow.stem.setAttribute('d', `M ${head.stemStart.x} ${head.stemStart.y} L ${head.base.x} ${head.base.y}`);
    arrow.head.setAttribute('points', head.points);
    arrow.length = arrow.path.getTotalLength();
    arrow.stemLength = arrow.stem.getTotalLength();
    arrow.path.style.strokeDasharray = `${ARROW_DASH} ${ARROW_GAP}`;
    arrow.maskPath.style.strokeDasharray = arrow.length;
    arrow.stem.style.strokeDasharray = arrow.stemLength;
    routedSegments.push(...segments(route.points));
  }
}

// Re-runs layout when the stage resizes, fonts load (box sizes change), or
// the window resizes (scroll geometry depends on viewport height).
function watchLayout(stage, update) {
  window.addEventListener('resize', update);
  window.addEventListener('load', update);
  if (document.fonts) document.fonts.ready.then(update);
  if ('ResizeObserver' in window) {
    new ResizeObserver(update).observe(stage);
  }
  update();
}

function initMagicMove(mount) {
  injectStyles();
  const markdownSource = readMarkdownSource();
  mount.textContent = '';

  const { stage, canvas, arrowLayer, defs } = createStage();

  const sticky = document.createElement('div');
  sticky.className = 'cw-magic-sticky';

  const headline = document.createElement('h2');
  headline.className = 'cw-magic-headline';
  const headlineText1 = createSpan('BTE Schemes');
  const headlineText2 = createSpan('Pick Your Poisons');
  headline.append(headlineText1, headlineText2);

  if (markdownSource.storyBodies.length !== STORY_STEPS.length) {
    console.warn(
      `pick-your-poisons: ${STORY_STEPS.length} story steps but ` +
      `${markdownSource.storyBodies.length} paragraphs in the story source`,
    );
  }

  const story = document.createElement('div');
  story.className = 'cw-magic-story';
  const storyParagraphs = markdownSource.storyBodies.map(html => {
    const paragraph = document.createElement('p');
    paragraph.className = 'cw-magic-story-body';
    paragraph.innerHTML = html;
    renderMath(paragraph);
    story.appendChild(paragraph);
    return paragraph;
  });

  const dream = document.createElement('div');
  dream.className = 'cw-magic-dream';
  dream.innerHTML = markdownSource.dreamHtml;
  // Keep fragment IDs on the visible reduced-motion source rather than
  // duplicating them in this animated copy.
  for (const el of dream.querySelectorAll('[id]')) el.removeAttribute('id');
  renderMath(dream);

  const copy = document.createElement('div');
  copy.className = 'cw-magic-copy';
  copy.append(story, dream);

  const scrollHint = document.createElement('div');
  scrollHint.className = 'cw-magic-scroll-hint';
  // Only advertise arrow keys on devices that likely have a keyboard.
  const startHint = window.matchMedia('(hover: hover) and (pointer: fine)').matches
    ? 'scroll or press \u2190 \u2192'
    : 'scroll';
  scrollHint.textContent = startHint;

  sticky.append(headline, stage, copy, scrollHint);
  mount.append(sticky);

  const boxEls = BOXES.map(box => {
    const el = createBoxEl(box);
    canvas.appendChild(el);
    return { config: box, el };
  });

  const headerEls = [];
  const dividerEls = [];

  for (const header of HEADERS) {
    const el = document.createElement('div');
    el.className = 'cw-magic-morph cw-magic-header';
    el.textContent = header.text;
    canvas.appendChild(el);
    headerEls.push({ config: header, el });
  }

  for (const divider of DIVIDERS) {
    const el = document.createElement('div');
    el.className = 'cw-magic-divider';
    el.style.left = `${divider.x}%`;
    el.style.top = `${divider.y1}%`;
    el.style.height = `${divider.y2 - divider.y1}%`;
    canvas.appendChild(el);
    dividerEls.push(el);
  }

  const arrowLines = createArrowLines(arrowLayer, defs, ARROWS, MOUNT_ID);

  let trackTop = 0;
  let trackScrollable = 1;
  let ticking = false;

  function measure() {
    const rect = mount.getBoundingClientRect();
    trackTop = rect.top + window.scrollY;
    trackScrollable = Math.max(mount.offsetHeight - window.innerHeight, 1);

    canvas.style.transform = `scale(${stage.clientWidth / DESIGN_WIDTH})`;
    layoutArrows(arrowLines, boxEls);
  }

  function render() {
    const rawP = (window.scrollY - trackTop) / trackScrollable;
    const p = clamp(rawP, 0, 1);
    const storyP = clamp(p / STORY_END, 0, 1);
    const finalP = window01(p, [STORY_END, 1]);
    const finalT = easeInOutCubic(finalP);
    const stepCount = STORY_STEPS.length;
    const stepFloat = Math.min(storyP * stepCount, stepCount - 0.001);
    const stepIndex = Math.floor(stepFloat);
    const stepLocal = stepFloat - stepIndex;
    const currentStep = STORY_STEPS[stepIndex];
    const allNodesActive = storyP >= STEP_PHASE.finalFull || finalP > 0;

    const stepProgress = (targetStep, phase) => {
      if (targetStep < stepIndex) return 1;
      if (targetStep > stepIndex) return 0;
      return window01(stepLocal, phase);
    };

    const textCross = window01(p, WINDOWS.textCross);
    headlineText1.style.opacity = 1 - textCross;
    headlineText2.style.opacity = textCross;

    const unmatchedOut = 1 - window01(p, WINDOWS.unmatchedFade);
    const slide2In = window01(p, WINDOWS.slide2Fade);
    const dreamIn = window01(p, WINDOWS.dreamFade);
    // The hint stays up for the whole pinned animation (scroll and arrow keys
    // work throughout) and fades once the reader moves past the figure, using
    // the unclamped progress since p saturates at 1.
    scrollHint.style.setProperty('--cw-scroll-hint-opacity', 1 - window01(rawP, [1.01, 1.05]));

    for (const [index, paragraph] of storyParagraphs.entries()) {
      paragraph.style.display = index === stepIndex ? 'block' : 'none';
    }
    const storyIn = window01(stepLocal, STEP_PHASE.textIn);
    const storyOut = 1 - window01(stepLocal, STEP_PHASE.textOut);
    const storyOpacity = Math.min(storyIn, storyOut) * (1 - window01(p, WINDOWS.storyFade));
    story.style.display = storyOpacity > 0 || dreamIn === 0 ? 'block' : 'none';
    story.style.opacity = storyOpacity;
    story.style.transform = `translateY(${lerp(24, 0, easeInOutCubic(storyIn))}px)`;

    for (const { config, el } of boxEls) {
      const revealStep = NODE_REVEAL_STEP[config.id];
      const hasIncomingArrow = NODE_HAS_INCOMING[config.id];
      const reveal = stepProgress(revealStep, hasIncomingArrow ? STEP_PHASE.childNode : STEP_PHASE.rootNode);
      const active = currentStep.includes(config.id) && reveal > 0.85 && !allNodesActive;
      const inactiveOpacity = allNodesActive ? 1 : DIMMED_OPACITY;
      const nodeOpacity = reveal * (active ? 1 : inactiveOpacity);

      el.classList.toggle('is-active', active);
      if (config.slide2) {
        place(el, lerp(config.slide1.x, config.slide2.x, finalT), lerp(config.slide1.y, config.slide2.y, finalT));
      } else {
        place(el, config.slide1.x, config.slide1.y);
      }
      const opacity = config.slide2 ? nodeOpacity : nodeOpacity * unmatchedOut;
      el.style.opacity = opacity;
      // Keep the paper links in invisible boxes from capturing clicks.
      el.style.pointerEvents = opacity < 0.05 ? 'none' : '';
    }

    arrowLayer.style.opacity = 1 - window01(p, WINDOWS.arrowsFade);
    for (const arrow of arrowLines) {
      const revealStep = NODE_REVEAL_STEP[arrow.to];
      const draw = stepProgress(revealStep, STEP_PHASE.arrow);
      const stemDraw = window01(draw, [0.78, 1]);
      // Match the box highlight: stay lit whenever the target node is part of
      // the current step, even if the arrow was drawn in an earlier step.
      const active = currentStep.includes(arrow.to) && draw > 0 && !allNodesActive;
      const arrowOpacity = draw === 0 ? 0 : (active || allNodesActive ? 1 : DIMMED_OPACITY);
      arrow.maskPath.style.strokeDashoffset = arrow.length * (1 - draw);
      arrow.stem.style.strokeDashoffset = arrow.stemLength * (1 - stemDraw);
      arrow.path.style.opacity = arrowOpacity;
      arrow.stem.style.opacity = arrowOpacity;
      arrow.head.style.opacity = draw > 0.98 ? arrowOpacity : 0;
    }

    for (const { config, el } of headerEls) {
      place(el, config.x, config.y);
      el.style.opacity = slide2In;
    }
    for (const el of dividerEls) el.style.opacity = slide2In;

    dream.style.display = dreamIn > 0 ? 'block' : 'none';
    dream.style.opacity = dreamIn;
    dream.style.transform = `translateY(${lerp(24, 0, easeInOutCubic(dreamIn))}px)`;
  }

  function update() {
    measure();
    render();
  }

  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      render();
      ticking = false;
    });
  }

  // Arrow keys jump between story steps, Keynote style. Forward from above
  // the track enters the deck and forward past the last stop exits into the
  // article; backward steps all the way out to the top of the page. Outside
  // that range keys stay native so readers are never trapped. Bail under
  // prefers-reduced-motion (the preference can turn on after init) as the
  // track is hidden and the stops would be meaningless.
  function onKeyDown(event) {
    if (reducedMotion.matches) return;
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
    const forward = event.key === 'ArrowRight' || event.key === 'ArrowDown';
    const backward = event.key === 'ArrowLeft' || event.key === 'ArrowUp';
    if (!forward && !backward) return;

    const p = (window.scrollY - trackTop) / trackScrollable;
    if (p > 1.02 || (p < -0.02 && !forward)) return;

    const epsilon = 0.01;
    const stop = forward
      ? KEY_STOPS.find(candidate => candidate > p + epsilon)
      : KEY_STOPS.findLast(candidate => candidate < p - epsilon) ?? (p > epsilon ? 0 : undefined);

    let top;
    if (stop !== undefined) {
      top = trackTop + stop * trackScrollable;
    } else if (forward) {
      // Past the last stop, one more press scrolls the article below the
      // figure into view; from there keys are native again.
      top = trackTop + mount.offsetHeight - 8;
    } else {
      // Before the first stop, one more press returns to the page top.
      if (window.scrollY === 0) return;
      top = 0;
    }

    event.preventDefault();
    window.scrollTo({ top, behavior: 'smooth' });
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('keydown', onKeyDown);

  const dreamLink = document.querySelector('a[href="#dream-goal"]');
  if (dreamLink) {
    dreamLink.addEventListener('click', event => {
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

      event.preventDefault();
      window.history.pushState(null, '', dreamLink.hash);
      window.scrollTo({
        top: trackTop + trackScrollable,
        behavior: 'smooth',
      });
    });
  }

  watchLayout(stage, update);
}

// Non-scrolling copy of the completed DAG with the Pol26b construction added.
function initFinalFigure(mount) {
  injectStyles();
  mount.textContent = '';

  const { stage, canvas, arrowLayer, defs } = createStage();
  mount.append(stage);

  const boxEls = FINAL_BOXES.map(box => {
    const el = createBoxEl(box);
    el.classList.toggle('is-active', FINAL_HIGHLIGHTS.includes(box.id));
    place(el, box.slide1.x, box.slide1.y);
    canvas.appendChild(el);
    return { config: box, el };
  });

  // The static figure needs no draw-in effects: drop the reveal mask and show
  // the arrowheads (hidden by default for the scroll animation) immediately.
  const arrowLines = createArrowLines(arrowLayer, defs, FINAL_ARROWS, FINAL_MOUNT_ID);
  for (const arrow of arrowLines) {
    arrow.path.removeAttribute('mask');
    arrow.head.style.opacity = 1;
  }

  function update() {
    canvas.style.transform = `scale(${stage.clientWidth / DESIGN_WIDTH})`;
    layoutArrows(arrowLines, boxEls);
  }

  watchLayout(stage, update);
}

// Module scripts run after the document is parsed, so the mounts already exist.
// Under prefers-reduced-motion the markdown's inline styles hide the animation
// and show the prose sources instead, so defer the scroll machinery until the
// preference lifts. Its key handler must not run while the track is
// display:none, since it would compute stops against a zero-height track
// and swallow arrow-key scrolling at the top of the page.
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const mount = document.getElementById(MOUNT_ID);
if (mount && reducedMotion.matches) {
  reducedMotion.addEventListener('change', () => initMagicMove(mount), { once: true });
} else if (mount) {
  initMagicMove(mount);
}

const finalMount = document.getElementById(FINAL_MOUNT_ID);
if (finalMount) initFinalFigure(finalMount);
