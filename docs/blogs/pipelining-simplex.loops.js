// Animated SVG diagrams for the Pipelining Simplex post.

const SVG_NS = 'http://www.w3.org/2000/svg';
const WIDTH = 1024;
const RED = '#d9251c';
const BLUE = '#1f1fd1';
const GREEN = '#18864b';
const GRAY = '#8a8a8a';
const ARROW = '#a2a2a2';
const MUTED = '#b8b8b8';
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

const addArrow = (
  parent,
  x1,
  y1,
  x2,
  y2,
  color,
  delay,
  duration = 0.1,
  { strokeWidth = 2.5, headSize = 9, opacity = 1 } = {},
) => {
  const group = svgEl('g', { opacity });
  const line = addLine(group, x1, y1, x2, y2, {
    stroke: color,
    'stroke-width': strokeWidth,
    'stroke-linecap': 'round',
  });
  const length = Math.hypot(x2 - x1, y2 - y1);
  line.setAttribute('stroke-dasharray', length);
  line.setAttribute('stroke-dashoffset', length);
  const angle = Math.atan2(y2 - y1, x2 - x1);
  const size = headSize;
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

const addCurvedArrow = (
  parent,
  x1,
  y1,
  controlX,
  controlY,
  x2,
  y2,
  color,
  delay,
  duration = 0.1,
  { strokeWidth = 2.5, headSize = 9, opacity = 1 } = {},
) => {
  const group = svgEl('g', { opacity });
  const path = svgEl('path', {
    d: `M ${x1} ${y1} Q ${controlX} ${controlY} ${x2} ${y2}`,
    fill: 'none',
    stroke: color,
    'stroke-width': strokeWidth,
    'stroke-linecap': 'round',
    pathLength: 1,
    'stroke-dasharray': 1,
    'stroke-dashoffset': 1,
  });
  group.appendChild(path);
  const angle = Math.atan2(y2 - controlY, x2 - controlX);
  const points = [
    [x2, y2],
    [x2 - headSize * Math.cos(angle - 0.5), y2 - headSize * Math.sin(angle - 0.5)],
    [x2 - headSize * Math.cos(angle + 0.5), y2 - headSize * Math.sin(angle + 0.5)],
  ].map(point => point.join(',')).join(' ');
  const head = svgEl('polygon', { points, fill: color, opacity: 0 });
  group.appendChild(head);
  parent.appendChild(group);
  return {
    set(progress) {
      const value = Math.max(0, Math.min(1, (progress - delay) / duration));
      path.setAttribute('stroke-dashoffset', 1 - value);
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

const addStep = (el, delay) => ({
  set(progress) {
    el.setAttribute('opacity', progress >= delay ? 1 : 0);
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

  addText(svg, 512, 378, 'A 5ms interval is shorter than a typical screen refresh', {
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
  addText(svg, 20, 35, 'Round-robin (2 hops per view)', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 20, 232, 'Stable Leader (1 hop within each 4-view term)', { 'font-size': 18, 'font-weight': 700 });

  const x0 = 150;
  const hop = 60;
  const rotatingViewCount = 7;
  const stableViewCount = 12;
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

  const addTwoHops = (x1, y1, x2, y2, color, delay) => {
    const midX = (x1 + x2) / 2;
    const midY = (y1 + y2) / 2;
    const style = { strokeWidth: 1.6, headSize: 6.5 };
    animated.push(addArrow(svg, x1, y1, midX - 4, midY, color, delay, 0.035, style));
    animated.push(addArrow(svg, midX + 4, midY, x2, y2, color, delay + 0.04, 0.035, style));
  };

  const rotatingOwners = Array.from({ length: rotatingViewCount }, (_, index) => leaders[index % leaders.length]);
  rotatingOwners.forEach((owner, index) => {
    const x = x0 + index * hop * 2;
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
    animated.push(addReveal(block, 0.06 + index * 0.1));
    if (index < rotatingOwners.length - 1) {
      addTwoHops(
        x + 13,
        rotatingY[owner],
        x + hop * 2 - 13,
        rotatingY[rotatingOwners[index + 1]],
        GRAY,
        0.09 + index * 0.1,
      );
    }
  });

  const stableOwners = Array.from({ length: stableViewCount }, (_, index) => leaders[Math.floor(index / termLength)]);
  const stableX = [x0];
  for (let index = 1; index < stableViewCount; index++) {
    const handoff = index % termLength === 0;
    stableX.push(stableX[index - 1] + hop * (handoff ? 2 : 1));
  }
  stableOwners.forEach((owner, index) => {
    const x = stableX[index];
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
      if (handoff) {
        addTwoHops(
          x + 13,
          stableY[owner],
          stableX[index + 1] - 13,
          stableY[nextOwner],
          ARROW,
          0.09 + index * 0.06,
        );
      } else {
        animated.push(addArrow(
          svg,
          x + 13,
          stableY[owner],
          stableX[index + 1] - 13,
          stableY[nextOwner],
          ARROW,
          0.09 + index * 0.06,
          0.05,
          { strokeWidth: 1.6, headSize: 6.5 },
        ));
      }
    }
  });

  for (let term = 0; term < leaders.length; term++) {
    const start = term * termLength;
    const end = start + termLength - 1;
    const center = (stableX[start] + stableX[end]) / 2;
    addText(svg, center, 420, `term ${term + 1}`, {
      'text-anchor': 'middle',
      fill: GRAY,
      'font-size': 14,
    });
  }

  [termLength, termLength * 2].forEach((boundaryView, index) => {
    const x = (stableX[boundaryView - 1] + stableX[boundaryView]) / 2;
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
  const svg = makeSvg(mount, 380);
  const animated = [];
  const x0 = 190;
  const sequentialGap = 186;
  const optimisticGap = 62;
  const networkHop = sequentialGap;
  const laneGap = 40;
  const arrowInset = 9;
  const topY = 80;
  const bottomY = 265;

  addText(svg, 20, 30, 'Stable Leader', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 20, 215, 'Stable Leader + Optimistic Validation', { 'font-size': 18, 'font-weight': 700 });

  const addLanes = proposalY => {
    const lanes = [
      ['propose', proposalY],
      ['notarize', proposalY + laneGap],
      ['finalize', proposalY + laneGap * 2],
    ];
    lanes.forEach(([label, y]) => {
      addText(svg, 125, y + 5, label, {
        'text-anchor': 'end',
        'font-size': 16,
        fill: GRAY,
      });
      addLine(svg, 145, y, 976, y, {
        stroke: LIGHT,
        'stroke-width': label === 'propose' ? 3 : 1.4,
      });
    });
  };
  addLanes(topY);
  addLanes(bottomY);

  const addCadenceArrows = (count, gap, y, firstProposalAt, proposalStep) => {
    for (let index = 0; index < count - 1; index++) {
      const x = x0 + index * gap;
      animated.push(addArrow(
        svg,
        x + 17,
        y,
        x + gap - 17,
        y,
        ARROW,
        firstProposalAt + index * proposalStep + proposalStep * 0.45,
        proposalStep * 0.35,
        { strokeWidth: 1.6, headSize: 6.5 },
      ));
    }
  };

  const sequentialCount = 5;
  const optimisticCount = 13;
  addCadenceArrows(sequentialCount, sequentialGap, topY, 0.05, 0.15);
  addCadenceArrows(optimisticCount, optimisticGap, bottomY, 0.05, 0.05);

  const addNetworkRounds = (x, y, proposedAt, linksNextProposal) => {
    animated.push(addArrow(
      svg,
      x + arrowInset,
      y,
      x + networkHop - arrowInset,
      y + laneGap,
      ARROW,
      proposedAt + 0.01,
      0.13,
      { strokeWidth: 1.4, headSize: 6, opacity: 0.8 },
    ));
    if (linksNextProposal) {
      animated.push(addArrow(
        svg,
        x + networkHop,
        y + laneGap - 6,
        x + networkHop,
        y + 17,
        ARROW,
        proposedAt + 0.14,
        0.01,
        { strokeWidth: 1.4, headSize: 6, opacity: 0.8 },
      ));
    }
    animated.push(addArrow(
      svg,
      x + networkHop + arrowInset,
      y + laneGap,
      x + networkHop * 2 - arrowInset,
      y + laneGap * 2,
      GREEN,
      proposedAt + 0.16,
      0.13,
      { strokeWidth: 1.4, headSize: 6, opacity: 0.65 },
    ));
  };

  const addBlock = (x, y, label, proposedAt, notarizedAt, finalizedAt) => {
    addText(svg, x, y - 27, label, { 'text-anchor': 'middle', fill: GRAY });
    const rectAttrs = {
      x: x - 15,
      y: y - 15,
      width: 30,
      height: 30,
      rx: 3,
      opacity: 0,
    };
    const proposed = svgEl('rect', { ...rectAttrs, fill: RED });
    svg.appendChild(proposed);
    animated.push(addStep(proposed, proposedAt));

    if (notarizedAt !== null) {
      const notarized = svgEl('rect', { ...rectAttrs, fill: GRAY });
      svg.appendChild(notarized);
      animated.push(addStep(notarized, notarizedAt));
      const check = addText(svg, x, y + 6, '\u2713', {
        'font-family': 'sans-serif',
        'font-size': 18,
        'font-weight': 700,
        'text-anchor': 'middle',
        fill: 'white',
        opacity: 0,
      });
      animated.push(addStep(check, notarizedAt));
    }

    if (finalizedAt !== null) {
      const finalized = svgEl('rect', { ...rectAttrs, fill: GREEN });
      svg.appendChild(finalized);
      animated.push(addStep(finalized, finalizedAt));
      const checks = addText(svg, x, y + 5, '\u2713\u2713', {
        'font-family': 'sans-serif',
        'font-size': 12,
        'font-weight': 700,
        'letter-spacing': -2,
        'text-anchor': 'middle',
        fill: 'white',
        opacity: 0,
      });
      animated.push(addStep(checks, finalizedAt));
    }
  };

  for (let index = 0; index < sequentialCount; index++) {
    const proposedAt = 0.05 + index * 0.15;
    addNetworkRounds(x0 + index * sequentialGap, topY, proposedAt, true);
    addBlock(
      x0 + index * sequentialGap,
      topY,
      `v${index + 1}`,
      proposedAt,
      proposedAt + 0.15,
      proposedAt + 0.3,
    );
  }

  for (let index = 0; index < optimisticCount; index++) {
    const proposedAt = 0.05 + index * 0.05;
    addNetworkRounds(x0 + index * optimisticGap, bottomY, proposedAt, false);
    addBlock(
      x0 + index * optimisticGap,
      bottomY,
      `v${index + 1}`,
      proposedAt,
      proposedAt + 0.15,
      proposedAt + 0.3,
    );
  }
  return animated;
}

function buildRecovery(mount) {
  const svg = makeSvg(mount, 320);
  const animated = [];
  const y = 125;
  const x0 = 135;
  const gap = 90;
  const views = Array.from({ length: 8 }, (_, index) => x0 + index * gap);
  const nextView = 875;
  const continuationView = 965;

  addText(svg, 20, 32, 'A timeout ends the optimistic pipeline', {
    'font-size': 18,
    'font-weight': 700,
  });
  addText(svg, 450, 66, 'term 1', { 'text-anchor': 'middle', fill: GRAY });
  addText(svg, (nextView + continuationView) / 2, 66, 'term 2', {
    'text-anchor': 'middle',
    fill: GRAY,
  });
  addLine(svg, 95, y, 1010, y, { stroke: LIGHT, 'stroke-width': 3 });
  addLine(svg, 825, 48, 825, 205, {
    stroke: BLUE,
    'stroke-dasharray': '7 7',
    'stroke-width': 2,
  });

  views.slice(0, 5).forEach((x, index) => {
    addText(svg, x, 100, `v${index + 1}`, { 'text-anchor': 'middle', fill: GRAY });
  });

  const addState = (x, fill, checks, delay) => {
    const block = svgEl('rect', {
      x: x - 17,
      y: y - 17,
      width: 34,
      height: 34,
      rx: 4,
      fill,
      opacity: 0,
    });
    svg.appendChild(block);
    animated.push(addStep(block, delay));
    if (!checks) return;
    const mark = addText(svg, x, y + (checks === 1 ? 6 : 5), checks === 1 ? '\u2713' : '\u2713\u2713', {
      'font-family': 'sans-serif',
      'font-size': checks === 1 ? 18 : 12,
      'font-weight': 700,
      'letter-spacing': checks === 1 ? 0 : -2,
      'text-anchor': 'middle',
      fill: 'white',
      opacity: 0,
    });
    animated.push(addStep(mark, delay));
  };

  const proposalTimes = [0.05, 0.15, 0.25, 0.35, 0.45];
  for (let index = 0; index < proposalTimes.length - 1; index++) {
    animated.push(addArrow(
      svg,
      views[index] + 19,
      y,
      views[index + 1] - 19,
      y,
      ARROW,
      proposalTimes[index] + 0.04,
      0.05,
      { strokeWidth: 1.6, headSize: 6.5 },
    ));
  }

  addState(views[0], RED, 0, proposalTimes[0]);
  addState(views[0], GRAY, 1, 0.13);
  addState(views[0], GREEN, 2, 0.22);
  addState(views[1], RED, 0, proposalTimes[1]);
  addState(views[1], GRAY, 1, 0.28);
  addState(views[1], GREEN, 2, 0.78);
  addState(views[2], RED, 0, proposalTimes[2]);
  addState(views[3], RED, 0, proposalTimes[3]);
  addState(views[4], RED, 0, proposalTimes[4]);

  const failed = svgEl('rect', {
    x: views[2] - 17,
    y: y - 17,
    width: 34,
    height: 34,
    rx: 4,
    fill: LIGHT,
    opacity: 0,
  });
  svg.appendChild(failed);
  animated.push(addStep(failed, 0.55));

  const failureMark = svgEl('g', { opacity: 0 });
  addLine(failureMark, views[2] - 10, y - 10, views[2] + 10, y + 10, {
    stroke: RED,
    'stroke-width': 3,
  });
  addLine(failureMark, views[2] + 10, y - 10, views[2] - 10, y + 10, {
    stroke: RED,
    'stroke-width': 3,
  });
  svg.appendChild(failureMark);
  animated.push(addStep(failureMark, 0.55));
  const failureLabel = addText(svg, views[2], 210, 'times out', {
    'text-anchor': 'middle',
    fill: RED,
    opacity: 0,
  });
  animated.push(addStep(failureLabel, 0.55));

  for (let index = 3; index < 5; index++) {
    const inert = svgEl('rect', {
      x: views[index] - 17,
      y: y - 17,
      width: 34,
      height: 34,
      rx: 4,
      fill: '#efcecc',
      opacity: 0,
    });
    svg.appendChild(inert);
    animated.push(addStep(inert, 0.63));
    const slash = addLine(svg, views[index] - 10, y + 10, views[index] + 10, y - 10, {
      stroke: RED,
      'stroke-width': 2.5,
      opacity: 0,
    });
    animated.push(addStep(slash, 0.63));
  }
  const discardedLabel = addText(svg, (views[3] + views[4]) / 2, 210, 'discarded', {
    'text-anchor': 'middle',
    fill: RED,
    opacity: 0,
  });
  animated.push(addStep(discardedLabel, 0.63));

  for (let index = 5; index < 8; index++) {
    const label = addText(svg, views[index], 100, `v${index + 1}`, {
      'text-anchor': 'middle',
      fill: GRAY,
      opacity: 0,
    });
    animated.push(addReveal(label, 0.68, 0.03));
    const unproposed = svgEl('rect', {
      x: views[index] - 17,
      y: y - 17,
      width: 34,
      height: 34,
      rx: 4,
      fill: 'white',
      stroke: MUTED,
      'stroke-dasharray': '4 4',
      'stroke-width': 1.5,
      opacity: 0,
    });
    svg.appendChild(unproposed);
    animated.push(addReveal(unproposed, 0.68, 0.03));
  }
  const unproposedLabel = addText(svg, views[6], 210, 'skipped', {
    'text-anchor': 'middle',
    fill: GRAY,
    opacity: 0,
  });
  animated.push(addReveal(unproposedLabel, 0.68, 0.03));

  const skipLabel = addText(svg, 575, 290, 'nullify v3; skip rest of term', {
    'text-anchor': 'middle',
    fill: BLUE,
    opacity: 0,
  });
  animated.push(addStep(skipLabel, 0.72));
  animated.push(addArrow(
    svg,
    views[2] + 20,
    255,
    810,
    255,
    BLUE,
    0.72,
    0.08,
    { strokeWidth: 1.8, headSize: 7 },
  ));
  animated.push(addCurvedArrow(
    svg,
    views[1] + 18,
    y + 19,
    560,
    190,
    nextView - 20,
    y + 19,
    ARROW,
    0.80,
    0.05,
    { strokeWidth: 1.8, headSize: 7 },
  ));

  const nextLabel = addText(svg, nextView, 100, 'v9', {
    'text-anchor': 'middle',
    fill: GRAY,
    opacity: 0,
  });
  animated.push(addStep(nextLabel, 0.85));
  addState(nextView, RED, 0, 0.86);
  addState(nextView, GRAY, 1, 0.90);
  addState(nextView, GREEN, 2, 0.94);

  animated.push(addArrow(
    svg,
    nextView + 19,
    y,
    continuationView - 19,
    y,
    ARROW,
    0.88,
    0.025,
    { strokeWidth: 1.6, headSize: 6.5 },
  ));
  const continuationLabel = addText(svg, continuationView, 100, 'v10', {
    'text-anchor': 'middle',
    fill: GRAY,
    opacity: 0,
  });
  animated.push(addStep(continuationLabel, 0.90));
  addState(continuationView, RED, 0, 0.91);
  addState(continuationView, GRAY, 1, 0.95);
  addState(continuationView, GREEN, 2, 0.99);
  animated.push(addArrow(
    svg,
    continuationView + 19,
    y,
    WIDTH - 10,
    y,
    ARROW,
    0.93,
    0.05,
    { strokeWidth: 1.6, headSize: 6.5 },
  ));

  return animated;
}

function run(
  mount,
  builder,
  loopMs = LOOP_MS,
  startHoldMs = HOLD_MS,
  endHoldMs = startHoldMs,
  staticProgress = 1,
) {
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
    Math.max(0, Math.min(1, (elapsed - startHoldMs) / (loopMs - startHoldMs - endHoldMs)));

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
  ['simplex-fig-cadence', buildCadence, 4600, 300, 300, 0.4],
  ['simplex-fig-leaders', buildLeaders, LOOP_MS, HOLD_MS, HOLD_MS, 1],
  ['simplex-fig-validation', buildValidation, 8500, HOLD_MS, 1800, 1],
  ['simplex-fig-recovery', buildRecovery, 8500, HOLD_MS, 1800, 1],
];
for (const [id, builder, loopMs, startHoldMs, endHoldMs, staticProgress] of figures) {
  const mount = document.getElementById(id);
  if (mount) run(mount, builder, loopMs, startHoldMs, endHoldMs, staticProgress);
}
