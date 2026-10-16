// Animated SVG diagrams for the Many Too Many post.

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

// Backend colors, used consistently across figures.
const SCALAR = GRAY;
const X86_V4C = BLUE;
const NEON = GREEN;
const ARM_V9 = RED;

const clamp01 = value => Math.max(0, Math.min(1, value));
const lerp = (from, to, value) => from + (to - from) * value;
// Normalized progress of a phase: 0 before start, 1 after end.
const phase = (progress, start, end) => clamp01((progress - start) / (end - start));
// Smooth ease for movement.
const ease = value => value * value * (3 - 2 * value);

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

const addRect = (parent, x, y, width, height, attrs = {}) => {
  const el = svgEl('rect', { x, y, width, height, rx: 3, fill: LIGHT, ...attrs });
  parent.appendChild(el);
  return el;
};

// Arrow which draws itself between delay and delay + duration (in progress units).
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
      const value = clamp01((progress - delay) / duration);
      line.setAttribute('stroke-dashoffset', length * (1 - value));
      head.setAttribute('opacity', value > 0.96 ? 1 : 0);
    },
  };
};

// Fades an element in between delay and delay + duration.
const addReveal = (el, delay, duration = 0.06) => ({
  set(progress) {
    el.setAttribute('opacity', clamp01((progress - delay) / duration));
  },
});

// Shows an element from delay onwards.
const addStep = (el, delay) => ({
  set(progress) {
    el.setAttribute('opacity', progress >= delay ? 1 : 0);
  },
});

// Shows an element only within [start, end).
const addWindow = (el, start, end) => ({
  set(progress) {
    el.setAttribute('opacity', progress >= start && progress < end ? 1 : 0);
  },
});

// Arbitrary per-frame callback receiving the global progress in [0, 1].
const addFn = fn => ({ set: fn });

// A status line whose text depends on the current phase. Entries are
// [start, text] pairs sorted by start; the last entry whose start <= progress wins.
const addStatus = (parent, x, y, entries, attrs = {}) => {
  const el = addText(parent, x, y, entries[0][1], {
    'text-anchor': 'middle',
    fill: GRAY,
    ...attrs,
  });
  return {
    set(progress) {
      let text = entries[0][1];
      for (const [start, value] of entries) if (progress >= start) text = value;
      if (el.textContent !== text) el.textContent = text;
    },
  };
};

const makeSvg = (mount, height) => {
  const svg = svgEl('svg', {
    viewBox: `0 0 ${WIDTH} ${height}`,
    class: 'mtm-svg',
    'aria-hidden': 'true',
    focusable: 'false',
  });
  mount.textContent = '';
  mount.appendChild(svg);
  return svg;
};


function buildAutovec(mount) {
  const height = 290;
  const svg = makeSvg(mount, height);
  const animated = [];

  const count = 16;
  const cell = 44;
  const gap = 6;
  const x0 = 20;
  const pad = 4;
  const counterX = 1004;

  // Shared clock: one instruction per tick in both rows.
  const start = 0.04;
  const tick = 0.82 / count;
  const moveShare = 0.35;
  const fillShare = 0.35;

  const rows = [
    {
      title: 'Scalar loop',
      note: 'out[i] = a[i] + b[i]',
      noteX: 160,
      titleY: 34,
      y: 52,
      lanes: 1,
      color: RED,
    },
    {
      title: 'Auto-vectorized (4 lanes)',
      note: '4 elements per instruction',
      noteX: 312,
      titleY: 152,
      y: 170,
      lanes: 4,
      color: BLUE,
    },
  ];

  const cellX = index => x0 + index * (cell + gap);

  for (const row of rows) {
    addText(svg, x0, row.titleY, row.title, { 'font-size': 18, 'font-weight': 700 });
    addText(svg, row.noteX, row.titleY, row.note, { fill: GRAY });

    const fills = [];
    const labels = [];
    for (let index = 0; index < count; index++) {
      const x = cellX(index);
      addRect(svg, x, row.y, cell, cell);
      const fill = addRect(svg, x, row.y, cell, cell, { fill: row.color, opacity: 0 });
      const label = addText(svg, x + cell / 2, row.y + cell / 2 + 5, String(index), {
        'text-anchor': 'middle',
        'font-size': 14,
        fill: GRAY,
      });
      fills.push(fill);
      labels.push(label);
    }

    const span = row.lanes * (cell + gap) - gap;
    const cursor = svgEl('rect', {
      x: x0 - pad,
      y: row.y - pad,
      width: span + pad * 2,
      height: cell + pad * 2,
      rx: 6,
      fill: 'none',
      stroke: 'black',
      'stroke-width': 2.5,
      opacity: 0,
    });
    svg.appendChild(cursor);

    const counter = addText(svg, counterX, row.y + cell / 2 + 6, 'instructions: 0', {
      'text-anchor': 'end',
      fill: GRAY,
    });

    const steps = count / row.lanes;
    const done = start + steps * tick;

    animated.push(addFn(progress => {
      // Cursor position (in groups) and visibility.
      let position = 0;
      for (let step = 1; step < steps; step++) {
        position += ease(phase(progress, start + step * tick, start + (step + moveShare) * tick));
      }
      const fadeIn = phase(progress, start, start + moveShare * tick * 0.6);
      const fadeOut = 1 - phase(progress, done, done + moveShare * tick);
      cursor.setAttribute('x', cellX(position * row.lanes) - pad);
      cursor.setAttribute('opacity', Math.min(fadeIn, fadeOut));

      // Fill each group once the cursor has arrived.
      let issued = 0;
      for (let step = 0; step < steps; step++) {
        const fillStart = start + (step + moveShare) * tick;
        const value = phase(progress, fillStart, fillStart + fillShare * tick);
        if (progress >= fillStart) issued = step + 1;
        for (let lane = 0; lane < row.lanes; lane++) {
          const index = step * row.lanes + lane;
          fills[index].setAttribute('opacity', value);
          labels[index].setAttribute('fill', value > 0.5 ? 'white' : GRAY);
        }
      }

      const finished = progress >= done;
      const text = 'instructions: ' + issued;
      if (counter.textContent !== text) counter.textContent = text;
      counter.setAttribute('fill', finished ? row.color : GRAY);
      counter.setAttribute('font-weight', finished ? 700 : 400);
    }));
  }

  animated.push(addStatus(svg, WIDTH / 2, 270, [
    [0, 'Same loop: one element vs. four elements per instruction'],
    [start + 4 * tick + 0.02, 'Vectorized loop done after 4 instructions; scalar continues'],
    [start + count * tick + 0.02, 'Four times fewer instructions, when LLVM manages it'],
  ]));

  return animated;
}

function buildSpill(mount) {
  const HEIGHT = 310;
  const svg = makeSvg(mount, HEIGHT);
  const items = [];

  // Geometry. Each register sits directly below the stack pair it holds, so
  // loads and stores travel straight down and up without crossing any text.
  const CELL_W = 44;
  const CELL_H = 36;
  const LANE_GAP = 2;
  const PAIR_W = 2 * CELL_W + LANE_GAP;
  const PAIR_STEP = PAIR_W + 10;
  const BOX_X = 150;
  const BOX_W = 844;
  const GROUP_X = { a: 170, b: 594 };
  const STACK_Y = 54;
  const REG_Y = 186;
  const pairX = (name, r) => GROUP_X[name] + r * PAIR_STEP;

  // Timing (progress units) for one load/compute/store cycle.
  const OP_START = [0, 0.49];
  const OP_NAME = ['add', 'xor'];
  const LOAD_STEP = 0.018;
  const MOVE = 0.07;
  const WORK_START = 0.205;
  const WORK_STEP = 0.02;
  const WORK_FLASH = 0.05;
  const STORE_START = 0.32;
  const STORE_STEP = 0.022;
  const LAND_FADE = 0.025;
  const CLEAR = [0.456, 0.48];

  const loadStart = (k, i) => OP_START[k] + i * LOAD_STEP;
  const workStart = (k, r) => OP_START[k] + WORK_START + r * WORK_STEP;
  const storeStart = (k, r) => OP_START[k] + STORE_START + r * STORE_STEP;
  // Opacity of op k's register contents (cleared before the next op).
  const resident = (k, p) =>
    k + 1 < OP_START.length ? 1 - phase(p, OP_START[k] + CLEAR[0], OP_START[k] + CLEAR[1]) : 1;

  // Panel labels and boxes.
  addText(svg, 30, STACK_Y + 24, 'Stack', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 30, REG_Y + 20, 'Registers', { 'font-size': 18, 'font-weight': 700 });
  addText(svg, 30, REG_Y + 43, '(128-bit)', { 'font-size': 14, fill: GRAY });
  addRect(svg, BOX_X, 20, BOX_W, 88, { rx: 6, fill: 'none', stroke: MUTED, 'stroke-width': 1.4 });
  addRect(svg, BOX_X, 168, BOX_W, 92, { rx: 6, fill: 'none', stroke: MUTED, 'stroke-width': 1.4 });

  // Stack: two [u64; 8] values side by side.
  for (const name of ['a', 'b']) {
    const label = addText(svg, GROUP_X[name], 44, name, { 'font-weight': 700 });
    const type = svgEl('tspan', { fill: GRAY, 'font-weight': 400, 'font-size': 14 });
    type.textContent = ': [u64; 8]';
    label.appendChild(type);
    for (let j = 0; j < 8; j++) {
      const x = pairX(name, Math.floor(j / 2)) + (j % 2) * (CELL_W + LANE_GAP);
      addRect(svg, x, STACK_Y, CELL_W, CELL_H, { rx: 2 });
      addText(svg, x + CELL_W / 2, STACK_Y + 23, name + j, {
        'font-size': 14,
        'text-anchor': 'middle',
        fill: GRAY,
      });
    }
  }

  // Source code being executed.
  const codeLines = ['a = a + b;', 'a = a ^ b;'].map((line, k) =>
    addText(svg, 30, 134 + k * 22, line, { 'font-size': 15 }));
  items.push(addFn(p => {
    const active = p < OP_START[1] ? 0 : 1;
    codeLines.forEach((el, k) => {
      el.setAttribute('fill', k === active ? 'black' : MUTED);
      el.setAttribute('font-weight', k === active ? 700 : 400);
    });
  }));

  // Registers: v0..v3 hold a, v4..v7 hold b.
  for (const name of ['a', 'b']) {
    for (let r = 0; r < 4; r++) {
      const x = pairX(name, r);
      const reg = name === 'a' ? r : r + 4;
      addRect(svg, x - 3, REG_Y - 3, PAIR_W + 6, CELL_H + 6, {
        rx: 4,
        fill: 'none',
        stroke: MUTED,
        'stroke-width': 1.2,
      });
      addRect(svg, x, REG_Y, CELL_W, CELL_H, { rx: 2 });
      addRect(svg, x + CELL_W + LANE_GAP, REG_Y, CELL_W, CELL_H, { rx: 2 });
      addText(svg, x + PAIR_W / 2, REG_Y + CELL_H + 22, 'v' + reg, {
        'font-size': 14,
        'text-anchor': 'middle',
        fill: GRAY,
      });
    }
  }

  // A pair of lanes that can move as one unit.
  const makeToken = (name, r) => {
    const g = svgEl('g', { opacity: 0 });
    const rects = [];
    for (let w = 0; w < 2; w++) {
      const x = w * (CELL_W + LANE_GAP);
      rects.push(addRect(g, x, 0, CELL_W, CELL_H, { rx: 2, fill: GRAY }));
      addText(g, x + CELL_W / 2, 23, name + (2 * r + w), {
        'font-size': 14,
        'text-anchor': 'middle',
        fill: 'white',
      });
    }
    return { g, rects };
  };
  const place = (g, x, y) => g.setAttribute('transform', 'translate(' + x + ' ' + y + ')');

  const tokenLayer = svgEl('g');
  const storeLayer = svgEl('g');
  svg.appendChild(tokenLayer);
  svg.appendChild(storeLayer);

  for (let k = 0; k < OP_START.length; k++) {
    // Loads: a's pairs into v0..v3, then b's pairs into v4..v7.
    for (let i = 0; i < 8; i++) {
      const name = i < 4 ? 'a' : 'b';
      const r = i % 4;
      const token = makeToken(name, r);
      tokenLayer.appendChild(token.g);
      const x = pairX(name, r);
      const start = loadStart(k, i);
      const flash = workStart(k, r);
      items.push(addFn(p => {
        const t = ease(phase(p, start, start + MOVE));
        place(token.g, x, lerp(STACK_Y, REG_Y, t));
        token.g.setAttribute('opacity', p > start ? resident(k, p) : 0);
        const hot = p >= flash && p < flash + WORK_FLASH;
        token.rects.forEach(rect => rect.setAttribute('fill', hot ? RED : GRAY));
      }));
    }

    // Useful work: one instruction per register pair, writing into v0..v3.
    // The label sits above its register and fades before the store passes.
    for (let r = 0; r < 4; r++) {
      const label = addText(svg, pairX('a', r) + PAIR_W / 2, 146, OP_NAME[k], {
        'text-anchor': 'middle',
        'font-weight': 700,
        fill: RED,
        opacity: 0,
      });
      const start = workStart(k, r);
      items.push(addFn(p => {
        const end = storeStart(k, r);
        const fade = 1 - phase(p, end - 0.02, end);
        label.setAttribute('opacity', phase(p, start, start + 0.02) * fade);
      }));
    }

    // Stores: v0..v3 back into a.
    for (let r = 0; r < 4; r++) {
      const token = makeToken('a', r);
      storeLayer.appendChild(token.g);
      const x = pairX('a', r);
      const start = storeStart(k, r);
      items.push(addFn(p => {
        const t = ease(phase(p, start, start + MOVE));
        place(token.g, x, lerp(REG_Y, STACK_Y, t));
        const landed = phase(p, start + MOVE, start + MOVE + LAND_FADE);
        token.g.setAttribute('opacity', p >= start ? 1 - landed : 0);
      }));
    }
  }

  // Running tally of glue (moves) versus useful (compute) instructions.
  const glueText = addText(svg, 884, 294, '', { 'font-weight': 700, fill: GRAY, 'text-anchor': 'end' });
  const workText = addText(svg, 994, 294, '', { 'font-weight': 700, fill: RED, 'text-anchor': 'end' });
  items.push(addFn(p => {
    let glue = 0;
    let work = 0;
    for (let k = 0; k < OP_START.length; k++) {
      for (let i = 0; i < 8; i++) if (p > loadStart(k, i)) glue++;
      for (let r = 0; r < 4; r++) {
        if (p >= workStart(k, r)) work++;
        if (p >= storeStart(k, r)) glue++;
      }
    }
    glueText.textContent = 'glue: ' + glue;
    workText.textContent = 'work: ' + work;
  }));

  items.push(addStatus(svg, 30, 294, [
    [0, 'Load a and b from the stack into registers'],
    [OP_START[0] + WORK_START, 'add: the only useful work'],
    [OP_START[0] + STORE_START, 'Store the result back to the stack'],
    [OP_START[1], 'Next operation: load everything again'],
    [OP_START[1] + WORK_START, 'xor: the only useful work'],
    [OP_START[1] + STORE_START, 'Store the result back again'],
    [0.972, 'Most instructions just move data'],
  ], { 'text-anchor': 'start' }));

  return items;
}

function buildCompose(mount) {
  const height = 372;
  const svg = makeSvg(mount, height);
  const items = [];

  // Abstract time units; the composed path finishes at total.
  const total = 7.6;
  const t0 = 0.03;
  const scale = 0.94 / total;
  const at = t => t0 + t * scale;
  const timeOf = p => (p - t0) / scale;

  const startX = 150;
  const aX = 300;
  const bX = 720;
  const endX = 876;
  const boxW = 60;
  const boxH = 40;
  const token = 16;

  // Sample a point at fraction f (by arc length) along a polyline.
  const sample = (points, f) => {
    const lengths = [];
    let sum = 0;
    for (let i = 1; i < points.length; i++) {
      const l = Math.hypot(points[i][0] - points[i - 1][0], points[i][1] - points[i - 1][1]);
      lengths.push(l);
      sum += l;
    }
    let target = clamp01(f) * sum;
    for (let i = 0; i < lengths.length; i++) {
      if (target <= lengths[i] || i === lengths.length - 1) {
        const v = lengths[i] === 0 ? 0 : clamp01(target / lengths[i]);
        return [
          lerp(points[i][0], points[i + 1][0], v),
          lerp(points[i][1], points[i + 1][1], v),
        ];
      }
      target -= lengths[i];
    }
    return points[points.length - 1];
  };

  // Position along a schedule of [start, end, points] moves; holds between moves.
  const position = (schedule, t) => {
    let point = schedule[0][2][0];
    for (const [start, end, points] of schedule) {
      if (t < start) break;
      point = sample(points, ease(clamp01((t - start) / (end - start))));
    }
    return point;
  };

  const lane = (y, title, titleY) => {
    addText(svg, 24, titleY, title, { 'font-size': 20, 'font-weight': 700 });
    addRect(svg, 24, y - 26, 976, 52, { fill: LIGHT, opacity: 0.45 });
    addText(svg, 36, y + 5, 'registers', { fill: GRAY, 'font-size': 14 });
  };

  const box = (x, y, label, windowStart, windowEnd) => {
    const rect = addRect(svg, x - boxW / 2, y - boxH / 2, boxW, boxH, {
      fill: 'white',
      stroke: 'black',
      'stroke-width': 1.4,
    });
    addText(svg, x, y + 6, label, {
      'font-size': 18,
      'font-weight': 700,
      'text-anchor': 'middle',
    });
    items.push(addFn(p => {
      const t = timeOf(p);
      const active = t >= windowStart && t < windowEnd;
      rect.setAttribute('stroke', active ? BLUE : 'black');
      rect.setAttribute('stroke-width', active ? 2.5 : 1.4);
    }));
  };

  const regLine = (x1, y1, x2, y2, head) => {
    if (head) {
      addArrow(svg, x1, y1, x2, y2, BLUE, -1, 0.01, { strokeWidth: 2, headSize: 8 }).set(1);
    } else {
      addLine(svg, x1, y1, x2, y2, { stroke: BLUE, 'stroke-width': 2 });
    }
  };

  const stackLine = (points) => {
    const d = points.map((pt, i) => (i ? 'L' : 'M') + ' ' + pt[0] + ' ' + pt[1]).join(' ');
    svg.appendChild(svgEl('path', {
      d,
      fill: 'none',
      stroke: GRAY,
      'stroke-width': 2,
      'stroke-dasharray': '6 5',
      'stroke-linejoin': 'round',
    }));
    const [x1, y1] = points[points.length - 2];
    const [x2, y2] = points[points.length - 1];
    const angle = Math.atan2(y2 - y1, x2 - x1);
    const size = 8;
    const head = [
      [x2, y2],
      [x2 - size * Math.cos(angle - 0.5), y2 - size * Math.sin(angle - 0.5)],
      [x2 - size * Math.cos(angle + 0.5), y2 - size * Math.sin(angle + 0.5)],
    ].map(pt => pt.join(',')).join(' ');
    svg.appendChild(svgEl('polygon', { points: head, fill: GRAY }));
  };

  const timeBar = (y, segments) => {
    const x = 760;
    const w = 240;
    addText(svg, x - 10, y + 10, 'time', { fill: GRAY, 'font-size': 14, 'text-anchor': 'end' });
    addRect(svg, x, y, w, 10, { rx: 2, fill: LIGHT });
    const fills = segments.map(([start, end, color]) => ({
      start,
      end,
      el: addRect(svg, x + (start / total) * w, y, 0, 10, { rx: 0, fill: color }),
    }));
    items.push(addFn(p => {
      const t = timeOf(p);
      for (const { start, end, el } of fills) {
        const filled = Math.max(0, Math.min(t, end) - start);
        el.setAttribute('width', (filled / total) * w);
      }
    }));
  };

  const addToken = (schedule) => {
    const el = addRect(svg, 0, 0, token, token, { rx: 2, fill: BLUE });
    items.push(addFn(p => {
      const [x, y] = position(schedule, timeOf(p));
      el.setAttribute('x', x - token / 2);
      el.setAttribute('y', y - token / 2);
    }));
  };

  // Composed: A, store to the stack, load, then B.
  const y1 = 88;
  const stackY = 180;
  const stackX = 510;
  const stackW = 170;
  const parkX = stackX + 45;
  const downX = 400;
  const upX = 620;
  lane(y1, 'Composed across a platform boundary', 34);
  timeBar(22, [[0, 1.6, BLUE], [1.6, 6.2, GRAY], [6.2, total, BLUE]]);
  regLine(startX - 10, y1, aX - boxW / 2 - 2, y1, true);
  regLine(bX + boxW / 2, y1, endX + 30, y1, true);
  stackLine([[aX + boxW / 2, y1], [downX, y1], [downX, stackY], [stackX - stackW / 2 - 2, stackY]]);
  stackLine([[stackX + stackW / 2, stackY], [upX, stackY], [upX, y1], [bX - boxW / 2 - 2, y1]]);
  addRect(svg, stackX - stackW / 2, stackY - 20, stackW, 40, { fill: LIGHT });
  addText(svg, stackX - 30, stackY + 5, 'stack', { 'text-anchor': 'middle' });
  addText(svg, downX - 10, (y1 + stackY) / 2 + 14, 'store', {
    fill: GRAY,
    'font-size': 14,
    'text-anchor': 'end',
  });
  addText(svg, upX + 10, (y1 + stackY) / 2 + 14, 'load', { fill: GRAY, 'font-size': 14 });
  // Tokens are drawn beneath the operation boxes, which hide them while working.
  addToken([
    [0, 1.0, [[startX, y1], [aX, y1]]],
    [1.6, 3.6, [[aX, y1], [downX, y1], [downX, stackY], [parkX, stackY]]],
    [4.2, 6.2, [[parkX, stackY], [upX, stackY], [upX, y1], [bX, y1]]],
    [6.8, total, [[bX, y1], [endX, y1]]],
  ]);
  box(aX, y1, 'A', 1.0, 1.6);
  box(bX, y1, 'B', 6.2, 6.8);

  // Inlined: A then B, entirely in registers.
  const y2 = 292;
  lane(y2, 'Inlined', 246);
  timeBar(234, [[0, 4.2, BLUE]]);
  regLine(startX - 10, y2, aX - boxW / 2 - 2, y2, true);
  regLine(aX + boxW / 2, y2, bX - boxW / 2 - 2, y2, true);
  regLine(bX + boxW / 2, y2, endX + 30, y2, true);
  addToken([
    [0, 1.0, [[startX, y2], [aX, y2]]],
    [1.6, 2.8, [[aX, y2], [bX, y2]]],
    [3.4, 4.2, [[bX, y2], [endX, y2]]],
  ]);
  box(aX, y2, 'A', 1.0, 1.6);
  box(bX, y2, 'B', 2.8, 3.4);

  items.push(addStatus(svg, 512, 356, [
    [0, 'Two operations, each with its own boundary'],
    [at(1.6), 'The intermediate value round-trips through the stack'],
    [at(4.2), 'Inlined: the value never leaves a register'],
  ]));

  return items;
}


// Call tree: generic nodes are shared, leaf operations resolve to one backend path.
const TREE_IDS = { next: 0 };

function buildTree(mount) {
  const svg = makeSvg(mount, 340);
  const uid = TREE_IDS.next++;
  const defs = svgEl('defs');
  svg.appendChild(defs);

  // Backend order matches the legend: portable, x86_v4c, neon, arm_v9.
  const colors = [SCALAR, X86_V4C, NEON, ARM_V9];
  const names = ['portable', 'x86_v4c', 'neon', 'arm_v9'];
  // Selection order in the animation, with the label shown for each.
  const order = [
    { index: 1, label: 'NativeX86V4C' },
    { index: 2, label: 'NativeNeon' },
    { index: 3, label: 'NativeArmV9' },
    { index: 0, label: 'EmulatedScalar' },
  ];

  // Timing (progress units).
  const first = 0.1;
  const span = 0.225;
  const collapse = 0.07;
  const hold = 0.105;
  const restore = span - collapse - hold;
  const stagger = 0.012;
  const starts = order.map((_, i) => first + span * i);
  const labelStarts = starts.map((s, i) => (i === 0 ? s : s - restore));
  const reset = starts[3] + collapse + hold;

  addText(svg, 20, 38, 'Specialization resolves every leaf', {
    'font-size': 20,
    'font-weight': 700,
  });
  const label = addText(svg, 1004, 38, '', {
    'font-size': 20,
    'font-weight': 700,
    'text-anchor': 'end',
  });
  const labelKey = svgEl('tspan');
  labelKey.textContent = 'S = ';
  const labelValue = svgEl('tspan', { fill: GRAY });
  labelValue.textContent = '?';
  label.appendChild(labelKey);
  label.appendChild(labelValue);

  // Layout.
  const rowY = [66, 142, 222];
  const nodeH = 34;
  const leafH = 42;
  const generic = {
    hash: { x: 450, y: rowY[0], w: 100 },
    load: { x: 190, y: rowY[1], w: 100 },
    compress: { x: 470, y: rowY[1], w: 120 },
    finish: { x: 720, y: rowY[1], w: 100 },
  };
  const leaves = [
    { name: 'initialize', parent: 'load', x: 190 },
    { name: 'rounds4', parent: 'compress', x: 380 },
    { name: 'schedule4', parent: 'compress', x: 560 },
  ];
  const leafW = 150;

  const items = [];

  // Edges (static, shared code).
  const edge = (x1, y1, x2, y2) =>
    items.push(addArrow(svg, x1, y1, x2, y2, ARROW, -1, 0.1, { strokeWidth: 1.8, headSize: 8 }));
  for (const key of ['load', 'compress', 'finish']) {
    const node = generic[key];
    edge(generic.hash.x, generic.hash.y + nodeH, node.x, node.y - 2);
  }
  for (const leaf of leaves) {
    const parent = generic[leaf.parent];
    edge(parent.x, parent.y + nodeH, leaf.x, rowY[2] - 2);
  }

  // Generic nodes.
  for (const [name, node] of Object.entries(generic)) {
    addRect(svg, node.x - node.w / 2, node.y, node.w, nodeH, {
      rx: 6,
      fill: 'white',
      stroke: 'black',
      'stroke-width': 1.6,
    });
    addText(svg, node.x, node.y + nodeH / 2 + 5, name, {
      'font-size': 15,
      'text-anchor': 'middle',
    });
  }

  // Row labels.
  addText(svg, 20, (rowY[0] + rowY[1] + nodeH) / 2 + 5, 'generic', { 'font-size': 14, fill: GRAY });
  addText(svg, 20, rowY[2] + leafH / 2 + 5, 'leaf ops', { 'font-size': 14, fill: GRAY });

  // Leaf operations: four colored segments clipped to a rounded box.
  const leafSegments = leaves.map((leaf, j) => {
    const x0 = leaf.x - leafW / 2;
    const id = 'tree-clip-' + uid + '-' + j;
    const clip = svgEl('clipPath', { id });
    clip.appendChild(svgEl('rect', { x: x0, y: rowY[2], width: leafW, height: leafH, rx: 6 }));
    defs.appendChild(clip);
    const group = svgEl('g', { 'clip-path': 'url(#' + id + ')' });
    svg.appendChild(group);
    const segments = colors.map(color =>
      addRect(group, x0, rowY[2], leafW / 4, leafH, { rx: 0, fill: color }));
    addText(svg, leaf.x, rowY[2] + leafH / 2 + 5, leaf.name, {
      'font-size': 15,
      'font-weight': 700,
      'text-anchor': 'middle',
      fill: 'white',
      stroke: 'rgba(0, 0, 0, 0.4)',
      'stroke-width': 3,
      'stroke-linejoin': 'round',
      'paint-order': 'stroke',
    });
    return { x0, segments };
  });

  // Legend.
  const legendX = 846;
  const legend = names.map((name, k) => {
    const y = 104 + k * 32;
    const group = svgEl('g');
    svg.appendChild(group);
    addRect(group, legendX, y - 13, 16, 16, { rx: 3, fill: colors[k] });
    addText(group, legendX + 26, y, name, { 'font-size': 15 });
    return group;
  });

  // Current selection and collapse amount for leaf j at progress p.
  const state = (p, j) => {
    for (let i = 0; i < order.length; i++) {
      const s = starts[i];
      if (p >= s && p < s + span) {
        const amount =
          ease(phase(p, s + j * stagger, s + j * stagger + collapse)) -
          ease(phase(p, s + collapse + hold, s + span));
        return { index: order[i].index, amount: clamp01(amount) };
      }
    }
    return { index: 0, amount: 0 };
  };

  items.push(addFn(progress => {
    leafSegments.forEach((leaf, j) => {
      const { index, amount } = state(progress, j);
      let x = leaf.x0;
      leaf.segments.forEach((segment, k) => {
        const w = (leafW / 4) * (1 - amount) + (k === index ? leafW * amount : 0);
        segment.setAttribute('x', x);
        segment.setAttribute('width', Math.max(0, w));
        x += w;
      });
    });

    const { index, amount } = state(progress, leaves.length - 1);
    legend.forEach((group, k) => {
      group.setAttribute('opacity', k === index ? 1 : 1 - 0.7 * amount);
    });

    let value = '?';
    let color = GRAY;
    for (let i = 0; i < order.length; i++) {
      if (progress >= labelStarts[i]) {
        value = order[i].label;
        color = colors[order[i].index];
      }
    }
    if (progress >= reset) {
      value = '?';
      color = GRAY;
    }
    if (labelValue.textContent !== value) labelValue.textContent = value;
    labelValue.setAttribute('fill', color);
  }));

  items.push(addStatus(svg, 512, 320, [
    [0, 'Generic code calls leaf operations with several paths'],
    [labelStarts[0], 'Pick a backend, and every leaf resolves to one path'],
    [labelStarts[1], 'A different backend picks a different path in each leaf'],
    [labelStarts[2], 'The shared nodes and edges never change'],
    [labelStarts[3], 'EmulatedScalar takes the portable path everywhere'],
    [reset, 'Generic code calls leaf operations with several paths'],
  ]));

  return items;
}

// Modular SIMD helpers monomorphize, inline into one function, and get interleaved by LLVM.

const SOUP_HEIGHT = 240;
// Phase 1 tile metrics (separate helpers) and merged tile metrics (one wide function).
const SOUP_TILE_W = 48;
const SOUP_TILE_GAP = 6;
const SOUP_MERGED_W = 60;
const SOUP_MERGED_GAP = 8;
const SOUP_TILE_H = 28;
const SOUP_PAD = 12;
const SOUP_BOX_GAP = 32;
const SOUP_BOX_Y = 20;
const SOUP_BOX_H = 106;
const SOUP_TILE_Y = SOUP_BOX_Y + 64;
const SOUP_BIG_PAD = 16;
// Vertical lane offsets used while reordering, so moving tiles never overlap.
const SOUP_LANE = { K: -32, B: 0, G: 32 };
// Extra merged-box height while tiles use the lower lane.
const SOUP_GROW = 30;

// Each helper lists its instructions in source order: B = left chain, G = right chain,
// K = shared constant.
const SOUP_FUNCS = [
  { name: 'load', ops: ['B', 'B', 'G', 'G'] },
  { name: 'rounds4', ops: ['B', 'B', 'G', 'G'] },
  { name: 'schedule4', ops: ['K', 'B', 'G'] },
  { name: 'add_state', ops: ['K', 'B', 'G'] },
];

function buildSoup(mount) {
  const svg = makeSvg(mount, SOUP_HEIGHT);
  const colorOf = op => (op === 'B' ? BLUE : op === 'G' ? GREEN : GRAY);
  const step = SOUP_MERGED_W + SOUP_MERGED_GAP;
  const boxWidth = (count, w, gap) => 2 * SOUP_PAD + count * w + (count - 1) * gap;

  // Phase 1 layout: separate boxes centered across the width.
  const totalSmall =
    SOUP_FUNCS.reduce((sum, fn) => sum + boxWidth(fn.ops.length, SOUP_TILE_W, SOUP_TILE_GAP), 0) +
    (SOUP_FUNCS.length - 1) * SOUP_BOX_GAP;
  // Merged layout: one contiguous row of wider tiles spanning the figure.
  const tileCount = SOUP_FUNCS.reduce((sum, fn) => sum + fn.ops.length, 0);
  const rowWidth = tileCount * SOUP_MERGED_W + (tileCount - 1) * SOUP_MERGED_GAP;
  const rowX = (WIDTH - rowWidth) / 2;

  // Final schedule: constants hoisted first, then left and right alternate.
  let blueRank = 0;
  let greenRank = 0;
  let grayRank = 0;
  const grayTotal = SOUP_FUNCS.reduce((sum, fn) => sum + fn.ops.filter(op => op === 'K').length, 0);

  const bigBox = addRect(svg, rowX - SOUP_BIG_PAD, SOUP_BOX_Y, rowWidth + 2 * SOUP_BIG_PAD, SOUP_BOX_H, {
    rx: 4,
    opacity: 0,
  });

  const boxes = [];
  const tiles = [];
  let smallX = (WIDTH - totalSmall) / 2;
  let sourceIndex = 0;
  SOUP_FUNCS.forEach(fn => {
    const count = fn.ops.length;
    const startWidth = boxWidth(count, SOUP_TILE_W, SOUP_TILE_GAP);
    const endWidth = boxWidth(count, SOUP_MERGED_W, SOUP_MERGED_GAP);
    const startX = smallX;
    const endX = rowX + sourceIndex * step - SOUP_PAD;
    const group = svgEl('g');
    svg.appendChild(group);
    const rect = addRect(group, 0, SOUP_BOX_Y, startWidth, SOUP_BOX_H, { rx: 4 });
    const name = addText(group, SOUP_PAD, SOUP_BOX_Y + 26, fn.name, { 'font-weight': 700 });
    const generic = addText(group, SOUP_PAD, SOUP_BOX_Y + 48, 'S::U32x4', { 'font-size': 14, fill: GRAY });
    const native = addText(group, SOUP_PAD, SOUP_BOX_Y + 48, '__m128i', {
      'font-size': 14,
      fill: GRAY,
      opacity: 0,
    });
    boxes.push({ group, rect, name, generic, native, startX, endX, startWidth, endWidth });

    fn.ops.forEach((op, local) => {
      let finalIndex;
      if (op === 'K') finalIndex = grayRank++;
      else if (op === 'B') finalIndex = grayTotal + 2 * blueRank++;
      else finalIndex = grayTotal + 1 + 2 * greenRank++;
      tiles.push({
        op,
        startX: startX + SOUP_PAD + local * (SOUP_TILE_W + SOUP_TILE_GAP),
        mergedX: rowX + sourceIndex * step,
        finalX: rowX + finalIndex * step,
        el: null,
      });
      sourceIndex += 1;
    });
    smallX += startWidth + SOUP_BOX_GAP;
  });

  // Merged labels sit above the helper boxes so the fade-in is never hidden.
  const bigTitle = addText(svg, rowX, SOUP_BOX_Y + 26, 'hash::<NativeX86V4C>', {
    'font-weight': 700,
    opacity: 0,
  });
  const bigNote = addText(svg, rowX + rowWidth, SOUP_BOX_Y + 26, 'one function, every value in a register', {
    'font-size': 14,
    fill: GRAY,
    'text-anchor': 'end',
    opacity: 0,
  });

  // Tiles are drawn last so they stay above every box.
  tiles.forEach(tile => {
    tile.el = addRect(svg, tile.startX, SOUP_TILE_Y, SOUP_TILE_W, SOUP_TILE_H, {
      rx: 3,
      fill: colorOf(tile.op),
    });
  });

  // Legend.
  const legend = [
    [BLUE, 'left message'],
    [GREEN, 'right message'],
    [GRAY, 'shared constant'],
  ];
  const legendY = 188;
  const legendWidths = legend.map(([, label]) => 22 + label.length * 9.6);
  const legendGap = 36;
  let legendX = (WIDTH - (legendWidths.reduce((a, b) => a + b, 0) + legendGap * (legend.length - 1))) / 2;
  legend.forEach(([color, label], index) => {
    addRect(svg, legendX, legendY - 12, 14, 14, { rx: 2, fill: color });
    addText(svg, legendX + 22, legendY, label);
    legendX += legendWidths[index] + legendGap;
  });

  const status = addStatus(svg, WIDTH / 2, 224, [
    [0, 'Small generic helpers, each a few instructions'],
    [0.13, 'Monomorphized: S::U32x4 becomes the __m128i register type'],
    [0.29, 'Inlined: the helpers dissolve into one function'],
    [0.6, 'Scheduled: LLVM interleaves the independent chains'],
  ]);

  const SWAP_OUT = [0.14, 0.2];
  const SWAP_IN = [0.2, 0.26];
  const SLIDE = [0.3, 0.5];
  const FADE_SMALL_TEXT = [0.32, 0.4];
  const FADE_BIG_BOX = [0.44, 0.52];
  const HIDE_SMALL_BOX = 0.53;
  const FADE_BIG_TEXT = [0.48, 0.58];
  const REORDER = [0.62, 0.92];

  return [
    status,
    addFn(progress => {
      const swapOut = phase(progress, ...SWAP_OUT);
      const swapIn = phase(progress, ...SWAP_IN);
      const slide = ease(phase(progress, ...SLIDE));
      const fadeSmallText = phase(progress, ...FADE_SMALL_TEXT);
      const fadeBigBox = phase(progress, ...FADE_BIG_BOX);
      const fadeBigText = phase(progress, ...FADE_BIG_TEXT);
      // Reorder in three overlapping steps: leave the row, slide, settle back.
      const reorderT = phase(progress, ...REORDER);
      const lift = ease(phase(reorderT, 0, 0.25)) * (1 - ease(phase(reorderT, 0.75, 1)));
      const reorder = ease(phase(reorderT, 0.2, 0.8));

      boxes.forEach(box => {
        const x = lerp(box.startX, box.endX, slide);
        box.group.setAttribute('transform', 'translate(' + x + ' 0)');
        box.rect.setAttribute('width', lerp(box.startWidth, box.endWidth, slide));
        box.rect.setAttribute('opacity', progress < HIDE_SMALL_BOX ? 1 : 0);
        box.name.setAttribute('opacity', 1 - fadeSmallText);
        box.generic.setAttribute('opacity', 1 - swapOut);
        box.native.setAttribute('opacity', swapIn * (1 - fadeSmallText));
      });
      bigBox.setAttribute('opacity', fadeBigBox);
      bigBox.setAttribute('height', SOUP_BOX_H + SOUP_GROW * lift);
      bigTitle.setAttribute('opacity', fadeBigText);
      bigNote.setAttribute('opacity', fadeBigText);

      const width = lerp(SOUP_TILE_W, SOUP_MERGED_W, slide);
      tiles.forEach(tile => {
        const mergedX = lerp(tile.startX, tile.mergedX, slide);
        const x = lerp(mergedX, tile.finalX, reorder);
        const moves = tile.finalX !== tile.mergedX;
        const y = SOUP_TILE_Y + (moves ? SOUP_LANE[tile.op] * lift : 0);
        tile.el.setAttribute('x', x);
        tile.el.setAttribute('y', y);
        tile.el.setAttribute('width', width);
      });
    }),
  ];
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
    clamp01((elapsed - startHoldMs) / (loopMs - startHoldMs - endHoldMs));

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
  .mtm-svg {
    background: white;
    display: block;
    height: auto;
    width: 100%;
  }

  .mtm-loop[role="button"] .mtm-svg {
    cursor: pointer;
  }
`;
document.head.appendChild(style);


const figures = [
  ['mtm-fig-autovec', buildAutovec, 8600, 900, 900, 1],
  ['mtm-fig-spill', buildSpill, 9600, 900, 900, 1],
  ['mtm-fig-compose', buildCompose, 9000, 900, 900, 1],
  ['mtm-fig-tree', buildTree, 10000, 900, 900, 0.23],
  ['mtm-fig-soup', buildSoup, 9000, 900, 900, 1],
];
for (const [id, builder, loopMs, startHoldMs, endHoldMs, staticProgress] of figures) {
  const mount = document.getElementById(id);
  if (mount) run(mount, builder, loopMs, startHoldMs, endHoldMs, staticProgress);
}

