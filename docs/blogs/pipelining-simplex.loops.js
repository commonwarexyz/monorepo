// Animated SVG diagrams for the Pipelining Simplex post.

const SVG_NS = 'http://www.w3.org/2000/svg';
const WIDTH = 1024;
const RED = '#d9251c';
const BLUE = '#1f1fd1';
const GRAY = '#8a8a8a';
const LIGHT = '#e6e6e6';
const LOOP_MS = 7600;
const HOLD_MS = 900;

const svgEl = (name, attrs = {}) => {
  const el = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  return el;
};

const addText = (parent, x, y, value, attrs = {}) => {
  const el = svgEl('text', {
    x,
    y,
    fill: 'black',
    'font-family': 'monospace',
    'font-size': 16,
    ...attrs,
  });
  el.textContent = value;
  parent.appendChild(el);
  return el;
};

const addLine = (parent, x1, y1, x2, y2, attrs = {}) => {
  const el = svgEl('line', {
    x1,
    y1,
    x2,
    y2,
    stroke: GRAY,
    'stroke-width': 1.4,
    ...attrs,
  });
  parent.appendChild(el);
  return el;
};

const addArrow = (parent, x1, y1, x2, y2, color, delay, duration = 0.1) => {
  const group = svgEl('g');
  const line = addLine(group, x1, y1, x2, y2, {
    stroke: color,
    'stroke-width': 2.5,
    'stroke-linecap': 'round',
  });
  const length = Math.hypot(x2 - x1, y2 - y1);
  line.setAttribute('stroke-dasharray', length);
  line.setAttribute('stroke-dashoffset', length);
  const angle = Math.atan2(y2 - y1, x2 - x1);
  const size = 9;
  const points = [
    [x2, y2],
    [x2 - size * Math.cos(angle - 0.5), y2 - size * Math.sin(angle - 0.5)],
    [x2 - size * Math.cos(angle + 0.5), y2 - size * Math.sin(angle + 0.5)],
  ].map(point => point.join(',')).join(' ');
  const head = svgEl('polygon', { points, fill: color, opacity: 0 });
  group.appendChild(head);
  parent.appendChild(group);
  return {
    set(progress) {
      const value = Math.max(0, Math.min(1, (progress - delay) / duration));
      line.setAttribute('stroke-dashoffset', length * (1 - value));
      head.setAttribute('opacity', value > 0.96 ? 1 : 0);
    },
  };
};

const addReveal = (el, delay, duration = 0.06) => ({
  set(progress) {
    const value = Math.max(0, Math.min(1, (progress - delay) / duration));
    el.setAttribute('opacity', value);
  },
});

const makeSvg = (mount, height) => {
  const svg = svgEl('svg', {
    viewBox: `0 0 ${WIDTH} ${height}`,
    class: 'simplex-loop-svg',
    'aria-hidden': 'true',
    focusable: 'false',
  });
  mount.textContent = '';
  mount.appendChild(svg);
  return svg;
};

function buildCadence(mount) {
  const svg = makeSvg(mount, 400);
  const squares = [];
  addText(svg, 20, 38, '5ms view intervals', { 'font-size': 20, 'font-weight': 700 });
  const counter = addText(svg, 1004, 38, '000 / 200', {
    'font-size': 20,
    'font-weight': 700,
    'text-anchor': 'end',
    fill: BLUE,
  });

  const x0 = 197;
  const y0 = 72;
  const size = 22;
  const xGap = 10;
  const yGap = 6;
  for (let index = 0; index < 200; index++) {
    const column = index % 20;
    const row = Math.floor(index / 20);
    const x = x0 + column * (size + xGap);
    const y = y0 + row * (size + yGap);
    const background = svgEl('rect', { x, y, width: size, height: size, rx: 2, fill: LIGHT });
    const square = svgEl('rect', { x, y, width: size, height: size, rx: 2, fill: RED, opacity: 0 });
    svg.appendChild(background);
    svg.appendChild(square);
    squares.push(square);
  }

  addText(svg, 512, 378, '5ms is faster than a typical screen refresh', {
    'text-anchor': 'middle',
    fill: GRAY,
  });

  return [{
    set(progress) {
      const fillEnd = 0.25;
      const holdEnd = 0.625;
      const clearEnd = 0.875;
      if (progress < fillEnd) {
        const count = Math.floor((progress / fillEnd) * 200);
        squares.forEach((square, index) => square.setAttribute('opacity', index < count ? 1 : 0));
        counter.textContent = `${String(count).padStart(3, '0')} / 200`;
      } else if (progress < holdEnd) {
        squares.forEach(square => square.setAttribute('opacity', 1));
        counter.textContent = '200 / 200';
      } else if (progress < clearEnd) {
        const cleared = Math.floor(((progress - holdEnd) / (clearEnd - holdEnd)) * 200);
        squares.forEach((square, index) => square.setAttribute('opacity', index < cleared ? 0 : 1));
        counter.textContent = '200 / 200';
      } else {
        squares.forEach(square => square.setAttribute('opacity', 0));
        counter.textContent = '000 / 200';
      }
    },
  }];
}

function buildLeaders(mount) {
  const svg = makeSvg(mount, 430);
  const animated = [];
  addText(svg, 20, 35, 'Round-robin leaders', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 20, 232, 'Stable leaders (4-view terms)', { 'font-size': 18, 'font-weight': 700 });

  const x0 = 160;
  const gap = 74;
  const viewCount = 12;
  const termLength = 4;
  const leaders = ['L1', 'L2', 'L3'];
  const rotatingY = { L1: 82, L2: 132, L3: 182 };
  const stableY = { L1: 282, L2: 332, L3: 382 };
  for (const [leader, y] of Object.entries(rotatingY)) {
    addText(svg, 105, y + 5, leader, { 'text-anchor': 'end', 'font-weight': 700 });
    addLine(svg, 122, y, 995, y, { stroke: LIGHT });
  }
  for (const [leader, y] of Object.entries(stableY)) {
    addText(svg, 105, y + 5, leader, { 'text-anchor': 'end', 'font-weight': 700 });
    addLine(svg, 122, y, 995, y, { stroke: LIGHT });
  }

  const rotatingOwners = Array.from({ length: viewCount }, (_, index) => leaders[index % leaders.length]);
  rotatingOwners.forEach((owner, index) => {
    const x = x0 + index * gap;
    addText(svg, x, 57, `v${index + 1}`, { 'text-anchor': 'middle', fill: GRAY, 'font-size': 14 });
    const block = svgEl('rect', {
      x: x - 11,
      y: rotatingY[owner] - 11,
      width: 22,
      height: 22,
      rx: 3,
      fill: RED,
      opacity: 0,
    });
    svg.appendChild(block);
    animated.push(addReveal(block, 0.06 + index * 0.06));
    if (index < rotatingOwners.length - 1) {
      animated.push(addArrow(
        svg,
        x + 13,
        rotatingY[owner],
        x + gap - 13,
        rotatingY[rotatingOwners[index + 1]],
        GRAY,
        0.09 + index * 0.06,
        0.05,
      ));
    }
  });

  const stableOwners = Array.from({ length: viewCount }, (_, index) => leaders[Math.floor(index / termLength)]);
  stableOwners.forEach((owner, index) => {
    const x = x0 + index * gap;
    addText(svg, x, 257, `v${index + 1}`, { 'text-anchor': 'middle', fill: GRAY, 'font-size': 14 });
    const block = svgEl('rect', {
      x: x - 11,
      y: stableY[owner] - 11,
      width: 22,
      height: 22,
      rx: 3,
      fill: RED,
      opacity: 0,
    });
    svg.appendChild(block);
    animated.push(addReveal(block, 0.06 + index * 0.06));
    if (index < stableOwners.length - 1) {
      const nextOwner = stableOwners[index + 1];
      const handoff = nextOwner !== owner;
      animated.push(addArrow(
        svg,
        x + 13,
        stableY[owner],
        x + gap - 13,
        stableY[nextOwner],
        handoff ? BLUE : RED,
        0.09 + index * 0.06,
        0.05,
      ));
    }
  });

  for (let term = 0; term < leaders.length; term++) {
    const center = x0 + (term * termLength + (termLength - 1) / 2) * gap;
    addText(svg, center, 420, `term ${term + 1}`, {
      'text-anchor': 'middle',
      fill: GRAY,
      'font-size': 14,
    });
  }

  [termLength, termLength * 2].forEach((boundaryView, index) => {
    const x = x0 + (boundaryView - 0.5) * gap;
    const boundary = addLine(svg, x, 246, x, 402, {
      stroke: BLUE,
      'stroke-dasharray': '7 7',
      'stroke-width': 2,
      opacity: 0,
    });
    animated.push(addReveal(boundary, 0.27 + index * termLength * 0.06));
  });
  return animated;
}

function buildValidation(mount) {
  const svg = makeSvg(mount, 430);
  const animated = [];
  const x0 = 190;
  const sequentialGap = 186;
  const optimisticGap = 92;
  const parentSpan = sequentialGap;
  const finalizationSpan = sequentialGap;

  addText(svg, 20, 28, 'Waiting for parent notarization', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 20, 225, 'Optimistic validation', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 112, 72, 'views', { 'text-anchor': 'end', 'font-weight': 700 });
  addText(svg, 112, 125, 'notarize', { 'text-anchor': 'end', 'font-weight': 700 });
  addText(svg, 112, 178, 'finalize', { 'text-anchor': 'end', 'font-weight': 700 });
  addText(svg, 112, 269, 'views', { 'text-anchor': 'end', 'font-weight': 700 });
  addText(svg, 112, 322, 'notarize', { 'text-anchor': 'end', 'font-weight': 700 });
  addText(svg, 112, 375, 'finalize', { 'text-anchor': 'end', 'font-weight': 700 });
  [72, 125, 178, 269, 322, 375].forEach(y => addLine(svg, 130, y, 976, y, { stroke: LIGHT }));

  for (let index = 0; index < 5; index++) {
    const x = x0 + index * sequentialGap;
    const block = svgEl('rect', { x: x - 14, y: 58, width: 28, height: 28, rx: 3, fill: RED, opacity: 0 });
    svg.appendChild(block);
    animated.push(addReveal(block, 0.06 + index * 0.17));
    addText(svg, x, 50, `v${index + 1}`, { 'text-anchor': 'middle', fill: GRAY });
    const notarizedX = x + parentSpan;
    const notarized = svgEl('circle', { cx: notarizedX, cy: 125, r: 8, fill: BLUE, opacity: 0 });
    svg.appendChild(notarized);
    if (index < 4) animated.push(addArrow(svg, x + 16, 72, x + sequentialGap - 16, 72, RED, 0.1 + index * 0.17, 0.08));
    animated.push(addArrow(svg, x, 88, notarizedX - 9, 125, BLUE, 0.12 + index * 0.17, 0.1));
    animated.push(addReveal(notarized, 0.21 + index * 0.17));
    animated.push(addArrow(svg, notarizedX, 116, notarizedX, 88, BLUE, 0.22 + index * 0.17, 0.04));
    const finalizedX = notarizedX + finalizationSpan;
    const finalized = svgEl('circle', { cx: finalizedX, cy: 178, r: 8, fill: BLUE, opacity: 0 });
    svg.appendChild(finalized);
    animated.push(addArrow(svg, notarizedX + 9, 125, finalizedX - 9, 178, BLUE, 0.23 + index * 0.17, 0.1));
    animated.push(addReveal(finalized, 0.33 + index * 0.17));
  }

  for (let index = 0; index < 9; index++) {
    const x = x0 + index * optimisticGap;
    const block = svgEl('rect', { x: x - 14, y: 255, width: 28, height: 28, rx: 3, fill: RED, opacity: 0 });
    svg.appendChild(block);
    animated.push(addReveal(block, 0.06 + index * 0.075));
    addText(svg, x, 247, `v${index + 1}`, { 'text-anchor': 'middle', fill: GRAY });
    if (index < 8) animated.push(addArrow(svg, x + 16, 269, x + optimisticGap - 16, 269, RED, 0.09 + index * 0.075, 0.05));
    const notarizedX = x + parentSpan;
    const notarized = svgEl('circle', { cx: notarizedX, cy: 322, r: 8, fill: BLUE, opacity: 0 });
    svg.appendChild(notarized);
    animated.push(addReveal(notarized, 0.22 + index * 0.075));
    animated.push(addArrow(svg, x, 285, notarizedX - 9, 322, BLUE, 0.1 + index * 0.075, 0.11));
    const finalizedX = notarizedX + finalizationSpan;
    const finalized = svgEl('circle', { cx: finalizedX, cy: 375, r: 8, fill: BLUE, opacity: 0 });
    svg.appendChild(finalized);
    animated.push(addArrow(svg, notarizedX + 9, 322, finalizedX - 9, 375, BLUE, 0.23 + index * 0.075, 0.11));
    animated.push(addReveal(finalized, 0.34 + index * 0.075));
  }
  const note = addText(svg, 968, 415, 'notarization and finalization remain pipelined', { 'text-anchor': 'end', fill: BLUE, opacity: 0 });
  animated.push(addReveal(note, 0.73));
  return animated;
}

function run(mount, builder, loopMs = LOOP_MS, holdMs = HOLD_MS, staticProgress = 1) {
  const description = mount.getAttribute('aria-label');
  const animated = builder(mount);
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const makeStatic = () => {
    mount.setAttribute('role', 'img');
    mount.removeAttribute('tabindex');
    mount.removeAttribute('aria-pressed');
    mount.setAttribute('aria-label', description);
  };
  const makeInteractive = () => {
    mount.setAttribute('role', 'button');
    mount.setAttribute('tabindex', '0');
    mount.setAttribute('aria-pressed', 'false');
    mount.setAttribute('aria-label', `Animated figure. ${description} Activate to pause or resume.`);
  };
  const progressAt = elapsed =>
    Math.max(0, Math.min(1, (elapsed - holdMs) / (loopMs - holdMs * 2)));

  const frozen = new URLSearchParams(window.location.search).get('freeze');
  if (frozen !== null) {
    const seconds = Number(frozen);
    const progress = Number.isFinite(seconds)
      ? progressAt(((seconds * 1000) % loopMs + loopMs) % loopMs)
      : staticProgress;
    makeStatic();
    animated.forEach(item => item.set(progress));
    return;
  }
  if (reducedMotion) {
    makeStatic();
    animated.forEach(item => item.set(staticProgress));
    return;
  }
  makeInteractive();

  let started = performance.now();
  let pausedAt = 0;
  let userPaused = false;
  let visible = true;
  let frame;

  const render = now => {
    const progress = progressAt((now - started) % loopMs);
    animated.forEach(item => item.set(progress));
    if (!userPaused && visible) frame = requestAnimationFrame(render);
  };

  const toggle = () => {
    if (userPaused) {
      started = performance.now() - pausedAt;
      userPaused = false;
      mount.setAttribute('aria-pressed', 'false');
      if (visible) frame = requestAnimationFrame(render);
    } else {
      pausedAt = performance.now() - started;
      userPaused = true;
      mount.setAttribute('aria-pressed', 'true');
      cancelAnimationFrame(frame);
    }
  };
  mount.addEventListener('click', toggle);
  mount.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      toggle();
    }
  });

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(entries => {
      const latest = entries[entries.length - 1];
      if (!latest) return;
      visible = latest.isIntersecting;
      cancelAnimationFrame(frame);
      if (visible && !userPaused) {
        started = performance.now();
        frame = requestAnimationFrame(render);
      }
    });
    observer.observe(mount);
  }
  frame = requestAnimationFrame(render);
}

const style = document.createElement('style');
style.textContent = `
  .simplex-loop-svg {
    background: white;
    display: block;
    height: auto;
    width: 100%;
  }

  .simplex-loop[role="button"] .simplex-loop-svg {
    cursor: pointer;
  }
`;
document.head.appendChild(style);

const figures = [
  ['simplex-fig-cadence', buildCadence, 4600, 300, 0.4],
  ['simplex-fig-leaders', buildLeaders, LOOP_MS, HOLD_MS, 1],
  ['simplex-fig-validation', buildValidation, LOOP_MS, HOLD_MS, 1],
];
for (const [id, builder, loopMs, holdMs, staticProgress] of figures) {
  const mount = document.getElementById(id);
  if (mount) run(mount, builder, loopMs, holdMs, staticProgress);
}
