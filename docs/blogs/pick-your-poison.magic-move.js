const MOUNT_ID = 'pick-your-poison-magic-move';

const BOX_CONTENT = [
  { id: 'bte', title: 'Batched Threshold Encryption', papers: 'CGPP24' },
  { id: 'ste', title: 'Silent Threshold Encryption', papers: 'GKPW24, WW25' },
  { id: 'beat', title: 'BEAT-MEV(++)', papers: 'BFOQ25, ABDGMPRY25' },
  { id: 'pfbte', title: 'Partial Fraction-BTE', papers: 'BNRT26' },
  { id: 'btibe', title: 'Batched Threshold IBE', papers: 'CGPW25, AFP25, GWWW25' },
  { id: 'simple', title: 'Simple-BTE, BTX', papers: 'Pol26, ADGRS26' },
  { id: 'trx', title: 'TrX', papers: 'FPTX25' },
  { id: 'sbtibe', title: 'Silent Batched (T)IBE', papers: 'GWWW25' },
  { id: 'beast', title: 'BEAST-MEV', papers: 'BCFGOPQW25' },
];

const SLIDE1_POSITIONS = {
  bte: { x: 38.5, y: 12 },
  ste: { x: 77.25, y: 12 },
  trx: { x: 43.75, y: 62.5 },
  btibe: { x: 47.25, y: 44 },
  sbtibe: { x: 65.25, y: 62.5 },
  beast: { x: 88.75, y: 62.5 },
  beat: { x: 63, y: 28 },
  pfbte: { x: 15.75, y: 31.5 },
  simple: { x: 20.75, y: 56.25 },
};

const LEFT_COLUMN_X = 19;
const MIDDLE_COLUMN_X = 52;
const RIGHT_COLUMN_X = 80;

const SLIDE2_POSITIONS = {
  bte: { x: LEFT_COLUMN_X, y: 27 },
  btibe: { x: LEFT_COLUMN_X, y: 41 },
  sbtibe: { x: LEFT_COLUMN_X, y: 55 },
  trx: { x: LEFT_COLUMN_X, y: 69 },
  beat: { x: MIDDLE_COLUMN_X, y: 27 },
  beast: { x: MIDDLE_COLUMN_X, y: 41 },
  pfbte: { x: RIGHT_COLUMN_X, y: 27 },
  simple: { x: RIGHT_COLUMN_X, y: 41 },
};

const BOXES = BOX_CONTENT.map(box => ({
  ...box,
  slide1: SLIDE1_POSITIONS[box.id],
  slide2: SLIDE2_POSITIONS[box.id] ?? null,
}));

const ARROWS = [
  { id: 'bte-simple', from: 'bte', to: 'simple' },
  { id: 'bte-pfbte', from: 'bte', to: 'pfbte' },
  { id: 'bte-btibe', from: 'bte', to: 'btibe' },
  { id: 'bte-beat', from: 'bte', to: 'beat' },
  { id: 'btibe-trx', from: 'btibe', to: 'trx' },
  { id: 'btibe-sbtibe', from: 'btibe', to: 'sbtibe' },
  { id: 'ste-sbtibe', from: 'ste', to: 'sbtibe' },
  { id: 'ste-beast', from: 'ste', to: 'beast' },
  { id: 'beat-beast', from: 'beat', to: 'beast' },
];

const HEADERS = [
  { lines: ['Epoch Restriction'], x: LEFT_COLUMN_X, y: 13 },
  { lines: ['Censorship Issues'], x: MIDDLE_COLUMN_X, y: 13 },
  { lines: ['Complicated Setup'], x: RIGHT_COLUMN_X, y: 13 },
];

const DIVIDERS = [
  { x: 38.5, y1: 7, y2: 71 },
  { x: 65.5, y1: 7, y2: 71 },
];

const WINDOWS = {
  storyEnd: 0.82,
  finalStart: 0.82,
  arrowsFade: [0.82, 0.91],
  unmatchedFade: [0.84, 0.94],
  textCross: [0.82, 0.91],
  slide2Fade: [0.87, 0.99],
  dreamFade: [0.89, 1.00],
};

const STEP_PHASE = {
  arrow: [0.08, 0.24],
  rootNode: [0.00, 0.08],
  childNode: [0.25, 0.36],
  textIn: [0.08, 0.36],
  textOut: [0.88, 0.99],
  finalFull: 0.96,
};

const STORY_STEPS = [
  {
    nodes: ['bte'],
    arrows: [],
  },
  {
    nodes: ['btibe'],
    arrows: ['bte-btibe'],
  },
  {
    nodes: ['beat'],
    arrows: ['bte-beat'],
  },
  {
    nodes: ['beat'],
    arrows: [],
  },
  {
    nodes: ['trx'],
    arrows: ['btibe-trx'],
  },
  {
    nodes: ['pfbte'],
    arrows: ['bte-pfbte'],
  },
  {
    nodes: ['simple'],
    arrows: ['bte-simple'],
  },
  {
    nodes: ['ste', 'sbtibe', 'beast'],
    arrows: ['ste-sbtibe', 'btibe-sbtibe', 'ste-beast', 'beat-beast'],
  },
];

function firstRevealStep(itemsKey) {
  return STORY_STEPS.reduce((acc, step, index) => {
    for (const item of step[itemsKey]) {
      if (acc[item] === undefined) acc[item] = index;
    }
    return acc;
  }, {});
}

const NODE_REVEAL_STEP = firstRevealStep('nodes');
const ARROW_REVEAL_STEP = firstRevealStep('arrows');
const NODE_HAS_INCOMING_AT_REVEAL = ARROWS.reduce((acc, arrow) => {
  if (ARROW_REVEAL_STEP[arrow.id] === NODE_REVEAL_STEP[arrow.to]) acc[arrow.to] = true;
  return acc;
}, {});

const STYLE_ID = 'pick-your-poison-magic-move-style';
const SVG_NS = 'http://www.w3.org/2000/svg';
const DESIGN_WIDTH = 1024;
const DESIGN_HEIGHT = 576;
const DESIGN_STAGE_HEIGHT = 485;
const ARROW_DASH = 6;
const ARROW_GAP = 5;
const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
const lerp = (a, b, t) => a + (b - a) * t;
const easeInOutCubic = t => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const window01 = (p, [start, end]) => clamp((p - start) / (end - start), 0, 1);

function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;

  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .cw-magic-move {
      --cw-magic-track-height: 740vh;
      --cw-magic-ink: currentColor;
      --cw-magic-box-red: #d9251c;
      --cw-magic-arrow-blue: #1f1fd1;
      display: block;
      height: var(--cw-magic-track-height);
      margin: 44px 0 20px;
      position: relative;
    }

    .cw-magic-move * {
      box-sizing: border-box;
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
      white-space: normal;
      width: 100%;
      z-index: 5;
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

    .cw-magic-header span {
      display: block;
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
      min-height: 170px;
      position: relative;
      width: min(86%, 880px);
    }

    .cw-magic-story {
      color: var(--cw-magic-ink);
      font-family: inherit;
      left: 0;
      opacity: 0;
      position: absolute;
      top: 0;
      width: 100%;
      will-change: opacity, transform;
      z-index: 6;
    }

    .cw-magic-story-body {
      color: var(--cw-magic-ink);
      margin: 0;
    }

    .cw-magic-dream {
      color: var(--cw-magic-ink);
      font-family: inherit;
      left: 0;
      opacity: 0;
      position: absolute;
      text-align: left;
      top: 0;
      width: 100%;
      will-change: opacity, transform;
      z-index: 7;
    }

    .cw-magic-dream p {
      margin: 0;
    }

    .cw-magic-dream blockquote {
      margin: 12px 0;
    }

    .cw-magic-dream blockquote p {
      font-weight: 650;
      margin: 12px 0;
    }

    .cw-magic-story-source,
    .cw-magic-dream-source {
      display: none;
    }

    @media (max-width: 600px) {
      .cw-magic-move {
        --cw-magic-track-height: 680vh;
      }

      .cw-magic-box {
        font-size: 21px;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      .cw-magic-move {
        height: auto;
      }

      .cw-magic-sticky {
        display: block;
        position: static;
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
    if (el.dataset.cwMagicMathRendered) return;
    window.katex.render(el.textContent, el, {
      displayMode: el.classList.contains('display'),
      throwOnError: false,
    });
    el.dataset.cwMagicMathRendered = 'true';
  });
}

function readMarkdownSource() {
  const storySource = document.getElementById('pick-your-poison-story-source');
  const dreamSource = document.getElementById('pick-your-poison-dream-source');
  const storyBodies = storySource
    ? Array.from(storySource.querySelectorAll('p')).map(paragraph => paragraph.innerHTML)
    : [];
  const dreamHtml = dreamSource ? dreamSource.innerHTML : '';

  if (storySource) storySource.hidden = true;
  if (dreamSource) dreamSource.hidden = true;

  return {
    storyBodies,
    dreamHtml,
  };
}

function initMagicMove(mount) {
  injectStyles();
  const markdownSource = readMarkdownSource();
  mount.textContent = '';

  const stage = document.createElement('div');
  stage.className = 'cw-magic-stage';

  const sticky = document.createElement('div');
  sticky.className = 'cw-magic-sticky';

  const canvas = document.createElement('div');
  canvas.className = 'cw-magic-canvas';

  const headline = document.createElement('h2');
  headline.className = 'cw-magic-headline';
  const headlineText1 = createSpan('BTE Schemes');
  const headlineText2 = createSpan('Pick Your Poison');
  headline.append(headlineText1, headlineText2);

  const story = document.createElement('div');
  story.className = 'cw-magic-story';
  const storyBody = document.createElement('p');
  storyBody.className = 'cw-magic-story-body';
  story.append(storyBody);

  const dream = document.createElement('div');
  dream.className = 'cw-magic-dream';
  dream.innerHTML = markdownSource.dreamHtml;
  renderMath(dream);

  const arrowLayer = document.createElementNS(SVG_NS, 'svg');
  arrowLayer.classList.add('cw-magic-arrows');
  arrowLayer.setAttribute('aria-hidden', 'true');
  arrowLayer.setAttribute('viewBox', `0 0 ${DESIGN_WIDTH} ${DESIGN_HEIGHT}`);
  const defs = document.createElementNS(SVG_NS, 'defs');
  arrowLayer.appendChild(defs);

  const copy = document.createElement('div');
  copy.className = 'cw-magic-copy';
  copy.append(story, dream);

  canvas.append(arrowLayer);
  stage.append(canvas);
  sticky.append(headline, stage, copy);
  mount.append(sticky);

  const boxById = {};
  const boxEls = [];
  const headerEls = [];
  const dividerEls = [];
  const arrowLines = [];

  for (const box of BOXES) {
    const el = document.createElement('div');
    el.className = 'cw-magic-morph cw-magic-box';
    el.append(createSpan(box.title, 'cw-magic-work-name'), createSpan(box.papers));

    canvas.appendChild(el);
    const boxEntry = { config: box, el };
    boxById[box.id] = boxEntry;
    boxEls.push(boxEntry);
  }

  for (const header of HEADERS) {
    const el = document.createElement('div');
    el.className = 'cw-magic-morph cw-magic-header';
    for (const line of header.lines) el.appendChild(createSpan(line));
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

  for (const [index, arrow] of ARROWS.entries()) {
    const maskId = `${MOUNT_ID}-arrow-mask-${index}`;
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
    arrowLines.push({ path: pathEl, maskPath, stem: stemEl, head: headEl, length: 1, stemLength: 1, ...arrow });
  }

  let trackTop = 0;
  let trackScrollable = 1;
  let ticking = false;

  const slide1Center = id => ({
    x: boxById[id].config.slide1.x / 100 * DESIGN_WIDTH,
    y: boxById[id].config.slide1.y / 100 * DESIGN_HEIGHT,
  });

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

  function boxRect(id, padding = 8) {
    const center = slide1Center(id);
    const el = boxById[id].el;
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

  function routeScore(candidate, arrow, routedSegments) {
    const otherRects = boxEls
      .filter(({ config }) => config.id !== arrow.from && config.id !== arrow.to)
      .map(({ config }) => boxRect(config.id));
    const boxHits = candidate.points.reduce((hits, point) => (
      hits + otherRects.filter(rect => pointInRect(point, rect)).length
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

  function chooseRoute(arrow, from, to, routedSegments) {
    return arrowCandidates(from, to)
      .map(candidate => ({ ...candidate, score: routeScore(candidate, arrow, routedSegments) }))
      .sort((a, b) => a.score - b.score)[0];
  }

  function place(el, xPct, yPct) {
    const px = (xPct / 100) * DESIGN_WIDTH;
    const py = (yPct / 100) * DESIGN_HEIGHT;
    el.style.transform = `translate(calc(-50% + ${px}px), calc(-50% + ${py}px))`;
  }

  function measure() {
    const rect = mount.getBoundingClientRect();
    trackTop = rect.top + window.scrollY;
    trackScrollable = Math.max(mount.offsetHeight - window.innerHeight, 1);

    const scale = stage.clientWidth / DESIGN_WIDTH;
    canvas.style.transform = `scale(${scale})`;

    const routedSegments = [];
    for (const arrow of arrowLines) {
      const cFrom = slide1Center(arrow.from);
      const cTo = slide1Center(arrow.to);
      const p1 = edgePoint(cFrom, cTo, boxById[arrow.from].el);
      const tip = edgePoint(cTo, cFrom, boxById[arrow.to].el);
      const route = chooseRoute(arrow, p1, tip, routedSegments);
      const headFrom = route.control ?? p1;
      const head = arrowTip(tip, headFrom);

      if (route.control) {
        arrow.path.setAttribute('d', `M ${p1.x} ${p1.y} Q ${route.control.x} ${route.control.y} ${head.stemStart.x} ${head.stemStart.y}`);
        arrow.maskPath.setAttribute('d', `M ${p1.x} ${p1.y} Q ${route.control.x} ${route.control.y} ${head.stemStart.x} ${head.stemStart.y}`);
      } else {
        arrow.path.setAttribute('d', `M ${p1.x} ${p1.y} L ${head.stemStart.x} ${head.stemStart.y}`);
        arrow.maskPath.setAttribute('d', `M ${p1.x} ${p1.y} L ${head.stemStart.x} ${head.stemStart.y}`);
      }
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

  function render() {
    const p = clamp((window.scrollY - trackTop) / trackScrollable, 0, 1);
    const storyP = clamp(p / WINDOWS.storyEnd, 0, 1);
    const finalP = window01(p, [WINDOWS.finalStart, 1]);
    const finalT = easeInOutCubic(finalP);
    const stepCount = STORY_STEPS.length;
    const stepFloat = Math.min(storyP * stepCount, stepCount - 0.001);
    const stepIndex = Math.floor(stepFloat);
    const stepLocal = stepFloat - stepIndex;
    const currentStep = STORY_STEPS[stepIndex];
    const allNodesActive = storyP >= STEP_PHASE.finalFull || finalP > 0;

    const stepProgress = (targetStep, window) => {
      if (targetStep < stepIndex) return 1;
      if (targetStep > stepIndex) return 0;
      return window01(stepLocal, window);
    };

    const textCross = window01(p, WINDOWS.textCross);
    headlineText1.style.opacity = 1 - textCross;
    headlineText2.style.opacity = textCross;

    const unmatchedOut = 1 - window01(p, WINDOWS.unmatchedFade);
    const slide2In = window01(p, WINDOWS.slide2Fade);
    const dreamIn = window01(p, WINDOWS.dreamFade);

    if (storyBody.dataset.step !== String(stepIndex)) {
      storyBody.innerHTML = markdownSource.storyBodies[stepIndex] ?? '';
      storyBody.dataset.step = String(stepIndex);
      renderMath(storyBody);
    }
    const storyIn = window01(stepLocal, STEP_PHASE.textIn);
    const storyOut = 1 - window01(stepLocal, STEP_PHASE.textOut);
    const storyOpacity = Math.min(storyIn, storyOut) * (1 - window01(p, [0.78, 0.84]));
    story.style.opacity = storyOpacity;
    story.style.transform = `translateY(${lerp(24, 0, easeInOutCubic(storyIn))}px)`;

    for (const { config, el } of boxEls) {
      const revealStep = NODE_REVEAL_STEP[config.id] ?? 0;
      const hasIncomingArrow = NODE_HAS_INCOMING_AT_REVEAL[config.id];
      const reveal = stepProgress(revealStep, hasIncomingArrow ? STEP_PHASE.childNode : STEP_PHASE.rootNode);
      const active = currentStep.nodes.includes(config.id) && reveal > 0.85 && !allNodesActive;
      const inactiveOpacity = allNodesActive ? 1 : 0.38;
      const nodeOpacity = reveal * (active ? 1 : inactiveOpacity);

      el.classList.toggle('is-active', active);
      if (config.slide2) {
        place(el, lerp(config.slide1.x, config.slide2.x, finalT), lerp(config.slide1.y, config.slide2.y, finalT));
        el.style.opacity = nodeOpacity;
      } else {
        place(el, config.slide1.x, config.slide1.y);
        el.style.opacity = nodeOpacity * unmatchedOut;
      }
    }

    arrowLayer.style.opacity = 1 - window01(p, WINDOWS.arrowsFade);
    for (const arrow of arrowLines) {
      const revealStep = ARROW_REVEAL_STEP[arrow.id] ?? stepCount;
      const draw = stepProgress(revealStep, STEP_PHASE.arrow);
      const stemDraw = window01(draw, [0.78, 1]);
      const active = revealStep === stepIndex && draw > 0 && !allNodesActive;
      const arrowOpacity = draw === 0 ? 0 : (active || allNodesActive ? 1 : 0.38);
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

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', update);
  window.addEventListener('load', update);
  if (document.fonts) document.fonts.ready.then(update);
  if ('ResizeObserver' in window) {
    const resizeObserver = new ResizeObserver(update);
    resizeObserver.observe(mount);
    resizeObserver.observe(stage);
  }

  update();
}

function boot() {
  const mount = document.getElementById(MOUNT_ID);
  if (mount) initMagicMove(mount);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
