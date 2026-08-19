// Dependency-free SVG lifecycle loops for the clearing article. The palette, 1024-unit
// canvas, progressive arrows, opening/final holds, and visibility behavior
// follow the Multimmit launch diagrams.

const SVG_NS = 'http://www.w3.org/2000/svg';
const DESIGN_W = 1024;
const DESIGN_H = 576;

const RED = '#d9251c';
const GREEN = '#087a32';
const BLUE = '#1f1fd1';
const GRAY = '#666666';
const FAINT = '#8a8a8a';
const GOLD = '#806600';
const GRID = '#e4e4e4';
const ROW_LINE = '#cfcfcf';

const STYLES = {
  tx: { stroke: 'black', width: 2.4, opacity: 1 },
  bad: { stroke: RED, width: 2.4, opacity: 1 },
  bat: { stroke: GREEN, width: 3.4, opacity: 0.95 },
  ctl: { stroke: BLUE, width: 2, opacity: 0.9 },
  bg: { stroke: FAINT, width: 1.8, opacity: 1 },
};

const START_HOLD = 0.6;
const ACTIVE_END = 5.7;
const END_HOLD = 1.7;
const DURATION = START_HOLD + ACTIVE_END + END_HOLD;
const FADE_S = 0.45;

const clamp = (v, min, max) => Math.min(max, Math.max(min, v));

const STYLE_ID = 'clearing-loops-style';

function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .clearing-loop-svg {
      background: white;
      cursor: pointer;
      display: block;
      height: auto;
      width: 100%;
    }

    .clearing-loop-svg text {
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

function textEl(x, y, value, attrs = {}) {
  const el = svgEl('text', {
    x,
    y,
    fill: 'black',
    'font-size': 15,
    ...attrs,
  });
  el.textContent = value;
  return el;
}

function multiline(layer, x, y, lines, attrs = {}, lineHeight = 17) {
  const group = svgEl('g');
  lines.forEach((line, index) => {
    group.appendChild(textEl(x, y + index * lineHeight, line, attrs));
  });
  layer.appendChild(group);
  return group;
}

function setOpacity(el, visible, opacity = 1) {
  el.setAttribute('opacity', visible ? opacity : 0);
}

function makeLine(x0, y0, x1, y1, styleName) {
  const style = STYLES[styleName];
  const length = Math.hypot(x1 - x0, y1 - y0);
  const line = svgEl('line', {
    x1: x0,
    y1: y0,
    x2: x1,
    y2: y1,
    stroke: style.stroke,
    'stroke-width': style.width,
    'stroke-linecap': 'round',
    'stroke-dasharray': length,
    'stroke-dashoffset': length,
    opacity: 0,
  });
  const ux = (x1 - x0) / (length || 1);
  const uy = (y1 - y0) / (length || 1);
  const size = style.width >= 3 ? 11 : 8.5;
  const bx = x1 - ux * size;
  const by = y1 - uy * size;
  const half = size * 0.42;
  const points =
    x1 + ',' + y1 + ' ' +
    (bx - uy * half) + ',' + (by + ux * half) + ' ' +
    (bx + uy * half) + ',' + (by - ux * half);
  const head = svgEl('polygon', { points, fill: style.stroke, opacity: 0 });
  return {
    line,
    head,
    length,
    set(frac) {
      line.setAttribute('opacity', frac === 0 ? 0 : style.opacity);
      line.setAttribute('stroke-dashoffset', length * (1 - frac));
      head.setAttribute('opacity', frac > 0.97 ? style.opacity : 0);
    },
  };
}

function makeStroke(x0, y0, x1, y1, styleName) {
  const style = STYLES[styleName];
  const length = Math.hypot(x1 - x0, y1 - y0);
  const line = svgEl('line', {
    x1: x0,
    y1: y0,
    x2: x1,
    y2: y1,
    stroke: style.stroke,
    'stroke-width': style.width,
    'stroke-linecap': 'round',
    'stroke-dasharray': length,
    'stroke-dashoffset': length,
    opacity: 0,
  });
  return {
    line,
    length,
    set(frac) {
      line.setAttribute('opacity', frac === 0 ? 0 : style.opacity);
      line.setAttribute('stroke-dashoffset', length * (1 - frac));
    },
  };
}

class Scene {
  constructor(svg, title) {
    this.svg = svg;
    this.staticLayer = svgEl('g');
    this.dynamicLayer = svgEl('g');
    this.svg.append(this.staticLayer, this.dynamicLayer);
    this.updaters = [];

    const titleNode = textEl(24, 30, title, {
      'font-size': 18,
      'font-weight': 700,
    });
    this.staticLayer.appendChild(titleNode);
  }

  guide(x1, y1, x2, y2, attrs = {}) {
    this.staticLayer.appendChild(svgEl('line', {
      x1,
      y1,
      x2,
      y2,
      stroke: ROW_LINE,
      'stroke-width': 1.2,
      ...attrs,
    }));
  }

  label(x, y, value, attrs = {}) {
    this.staticLayer.appendChild(textEl(x, y, value, attrs));
  }

  event(x, y, options = {}) {
    const size = options.size || 15;
    const stroke = options.stroke || 'black';
    const fill = options.fill || stroke;
    const group = svgEl('g', { opacity: 0 });
    const shape = options.shape === 'circle'
      ? svgEl('circle', {
        cx: x,
        cy: y,
        r: size / 2,
        fill,
        stroke,
        'stroke-width': options.strokeWidth || 1.2,
      })
      : svgEl('rect', {
        x: x - size / 2,
        y: y - size / 2,
        width: size,
        height: size,
        fill,
        stroke,
        'stroke-width': options.strokeWidth || 1.2,
      });
    group.appendChild(shape);
    if (options.label) {
      group.appendChild(textEl(
        options.labelX === undefined ? x : options.labelX,
        options.labelY === undefined ? y - size / 2 - 10 : options.labelY,
        options.label,
        {
          'text-anchor': options.labelAnchor || 'middle',
          'font-size': options.labelSize || 13.5,
          'font-weight': options.weight || 600,
          fill: options.labelFill || stroke,
        },
      ));
    }
    if (options.sub) {
      group.appendChild(textEl(
        options.subX === undefined ? x : options.subX,
        options.subY === undefined ? y + size / 2 + 18 : options.subY,
        options.sub,
        {
          'text-anchor': options.subAnchor || 'middle',
          'font-size': options.subSize || 11.5,
          fill: options.subFill || GRAY,
        },
      ));
    }
    this.dynamicLayer.appendChild(group);
    const at = options.at || 0;
    this.updaters.push(tau => setOpacity(group, tau >= at));
    return { group, shape };
  }

  pair(x, y, options = {}) {
    const group = svgEl('g', { opacity: 0 });
    const size = options.size || 17;
    const gap = 3;
    const left = x - size - gap / 2;
    const right = x + gap / 2;
    group.appendChild(svgEl('rect', {
      x: left,
      y: y - size / 2,
      width: size,
      height: size,
      fill: GREEN,
      stroke: 'black',
      'stroke-width': 1,
    }));
    group.appendChild(svgEl('rect', {
      x: right,
      y: y - size / 2,
      width: size,
      height: size,
      fill: GOLD,
      stroke: 'black',
      'stroke-width': 1,
    }));
    group.appendChild(textEl(left + size / 2, y + 4, 'S', {
      'text-anchor': 'middle',
      'font-size': 9.5,
      'font-weight': 700,
      fill: 'white',
    }));
    group.appendChild(textEl(right + size / 2, y + 4, 'R', {
      'text-anchor': 'middle',
      'font-size': 9.5,
      'font-weight': 700,
      fill: 'white',
    }));
    if (options.retained) {
      group.insertBefore(svgEl('rect', {
        x: left - 4,
        y: y - size / 2 - 4,
        width: size * 2 + gap + 8,
        height: size + 8,
        fill: 'none',
        stroke: GOLD,
        'stroke-width': 2,
      }), group.firstChild);
    }
    if (options.label) {
      group.appendChild(textEl(
        options.labelX === undefined ? x : options.labelX,
        options.labelY || y - size / 2 - 11,
        options.label,
        {
          'text-anchor': options.labelAnchor || 'middle',
          'font-size': options.labelSize || 13,
          'font-weight': 600,
          fill: options.labelFill || BLUE,
        },
      ));
    }
    if (options.sub) {
      group.appendChild(textEl(
        options.subX === undefined ? x : options.subX,
        options.subY || y + size / 2 + 19,
        options.sub,
        {
          'text-anchor': options.subAnchor || 'middle',
          'font-size': options.subSize || 11.5,
          fill: options.subFill || GRAY,
        },
      ));
    }
    this.dynamicLayer.appendChild(group);
    const at = options.at || 0;
    this.updaters.push(tau => setOpacity(group, tau >= at));
    return group;
  }

  edge(x0, y0, x1, y1, options = {}) {
    const at = options.at || 0;
    const duration = options.duration || 0.55;
    const edge = makeStroke(x0, y0, x1, y1, options.style || 'bg');
    this.dynamicLayer.appendChild(edge.line);
    this.updaters.push(tau => {
      edge.set(clamp((tau - at) / duration, 0, 1));
    });
    return edge;
  }

  note(x, y, lines, options = {}) {
    const group = multiline(
      this.dynamicLayer,
      x,
      y,
      lines,
      {
        'text-anchor': options.anchor || 'middle',
        'font-size': options.size || 13,
        'font-weight': options.weight || 400,
        fill: options.fill || GRAY,
      },
      options.lineHeight || 16,
    );
    group.setAttribute('opacity', 0);
    const at = options.at || 0;
    this.updaters.push(tau => setOpacity(group, tau >= at));
    return group;
  }

  arrow(x0, y0, x1, y1, options = {}) {
    const at = options.at || 0;
    const duration = options.duration || 0.7;
    const arrow = makeLine(x0, y0, x1, y1, options.style || 'tx');
    this.dynamicLayer.append(arrow.line, arrow.head);
    let label = null;
    if (options.label) {
      const lx = options.labelX === undefined ? (x0 + x1) / 2 : options.labelX;
      const ly = options.labelY === undefined ? (y0 + y1) / 2 - 9 : options.labelY;
      label = textEl(lx, ly, options.label, {
        'text-anchor': options.labelAnchor || 'middle',
        'font-size': options.labelSize || 12.5,
        fill: STYLES[options.style || 'tx'].stroke,
      });
      label.setAttribute('opacity', 0);
      this.dynamicLayer.appendChild(label);
    }
    this.updaters.push(tau => {
      const frac = clamp((tau - at) / duration, 0, 1);
      arrow.set(frac);
      if (label) setOpacity(label, frac > 0.15);
    });
    return arrow;
  }

  revealText(x, y, value, options = {}) {
    const el = textEl(x, y, value, {
      'text-anchor': options.anchor || 'middle',
      'font-size': options.size || 14,
      'font-weight': options.weight || 400,
      fill: options.fill || 'black',
    });
    el.setAttribute('opacity', 0);
    this.dynamicLayer.appendChild(el);
    const at = options.at || 0;
    this.updaters.push(tau => setOpacity(el, tau >= at));
    return el;
  }

  render(tau) {
    for (const update of this.updaters) update(tau);
  }
}

function baseSvg(mount) {
  const svg = svgEl('svg', {
    viewBox: '0 0 ' + DESIGN_W + ' ' + DESIGN_H,
    class: 'clearing-loop-svg',
    role: 'img',
  });
  const ariaLabel = mount.getAttribute('aria-label');
  if (ariaLabel) svg.setAttribute('aria-label', ariaLabel);
  svg.appendChild(svgEl('rect', {
    x: 0,
    y: 0,
    width: DESIGN_W,
    height: DESIGN_H,
    fill: 'white',
  }));
  mount.textContent = '';
  mount.appendChild(svg);
  return svg;
}

function buildPaymentMinimal(mount) {
  const svg = baseSvg(mount);
  const s = new Scene(
    svg,
    'The Payment Lifecycle',
  );

  // Multimmit-style message-sequence timeline: rows are participants and the
  // x-axis is time in message delays δ. The operator's verify/commit/sign all
  // happen at one instant, so the round trip is exactly two message delays.
  const X0 = 170;
  const X1 = 1014;
  const T_MIN = -0.4;
  const T_MAX = 3.6;
  const xOf = t => X0 + ((t - T_MIN) / (T_MAX - T_MIN)) * (X1 - X0);
  const PAYER_Y = 150;
  const OP_Y = 300;
  const RCPT_Y = 450;

  for (let t = 0; t <= 3; t++) {
    s.guide(xOf(t), 54, xOf(t), 510, { stroke: GRID, 'stroke-width': 1 });
    s.label(xOf(t), 538, String(t), {
      'text-anchor': 'middle',
      'font-size': 14,
      fill: GRAY,
    });
  }
  s.label(24, 538, 'time in message delays (δ)', {
    'text-anchor': 'start',
    'font-size': 12.5,
    fill: GRAY,
  });
  const rows = [
    ['Payer a', PAYER_Y],
    ['Operator', OP_Y],
    ['Recipient b', RCPT_Y],
  ];
  for (const [label, y] of rows) {
    s.label(X0 - 18, y + 5, label, {
      'text-anchor': 'end',
      'font-size': 17,
      'font-weight': label === 'Operator' ? 600 : 400,
    });
    s.guide(X0 - 6, y, X1, y, { stroke: ROW_LINE, 'stroke-width': 1.2 });
  }

  s.event(xOf(0), PAYER_Y, {
    at: 0.3,
    size: 13,
    stroke: 'black',
    fill: GREEN,
    label: 'S(a→b, 20)',
    labelY: PAYER_Y - 15,
    labelSize: 13.5,
    labelFill: GREEN,
  });
  s.arrow(xOf(0), PAYER_Y, xOf(1), OP_Y, {
    at: 0.4,
    duration: 1.05,
    style: 'tx',
  });

  // One local instant: the request lands and the response leaves at the same
  // tick. The step list reveals in order beneath the commit point.
  s.event(xOf(1), OP_Y, {
    at: 1.5,
    size: 15,
    stroke: 'black',
    fill: GREEN,
  });
  const stepX = xOf(1) - 14;
  s.revealText(stepX, OP_Y + 22, 'verify S', {
    at: 1.75,
    anchor: 'end',
    size: 12.5,
    weight: 700,
    fill: BLUE,
  });
  s.revealText(stepX, OP_Y + 39, 'commit', {
    at: 1.95,
    anchor: 'end',
    size: 12.5,
    weight: 700,
    fill: GREEN,
  });
  s.revealText(stepX, OP_Y + 56, 'sign R', {
    at: 2.15,
    anchor: 'end',
    size: 12.5,
    weight: 700,
    fill: GOLD,
  });
  s.revealText(stepX, OP_Y + 76, 'a: 100→80 • b/κ₀: (0,0)→(20,1)', {
    at: 2.35,
    anchor: 'end',
    size: 12,
    weight: 600,
    fill: GREEN,
  });

  s.arrow(xOf(1), OP_Y, xOf(1.93), PAYER_Y + 13, {
    at: 2.55,
    duration: 1.05,
    style: 'ctl',
    label: 'R',
    labelX: xOf(1.5) + 10,
    labelY: (PAYER_Y + OP_Y) / 2 + 22,
    labelAnchor: 'start',
    labelSize: 13.5,
  });

  // The operator already holds both S and R, so it could hand the pair to b
  // directly, landing at 2δ: one hop sooner than the payer-forward path. A
  // dashed whole-line fade (no progressive draw) marks it as optional.
  const dx1 = xOf(1) + 8;
  const dy1 = OP_Y + 10;
  const dx2 = xOf(2) - 8;
  const dy2 = RCPT_Y - 10;
  const dLen = Math.hypot(dx2 - dx1, dy2 - dy1);
  const dux = (dx2 - dx1) / dLen;
  const duy = (dy2 - dy1) / dLen;
  const direct = svgEl('g', { opacity: 0 });
  direct.appendChild(svgEl('line', {
    x1: dx1,
    y1: dy1,
    x2: dx2 - dux * 6,
    y2: dy2 - duy * 6,
    stroke: GREEN,
    'stroke-width': 2,
    'stroke-linecap': 'round',
    'stroke-dasharray': '3 7',
    opacity: 0.85,
  }));
  direct.appendChild(svgEl('polygon', {
    points: dx2 + ',' + dy2 + ' ' +
      (dx2 - dux * 9 - duy * 3.8) + ',' + (dy2 - duy * 9 + dux * 3.8) + ' ' +
      (dx2 - dux * 9 + duy * 3.8) + ',' + (dy2 - duy * 9 - dux * 3.8),
    fill: GREEN,
    opacity: 0.85,
  }));
  s.dynamicLayer.appendChild(direct);
  s.updaters.push(tau => setOpacity(direct, tau >= 2.7));

  // A ghost pair rides the dashed path, landing at 2δ as the response reaches
  // the payer, then settles translucent: b could already hold the pair here.
  const ghost = svgEl('g', { opacity: 0 });
  const gSize = 15;
  const gGap = 2.5;
  ghost.appendChild(svgEl('rect', {
    x: -gSize - gGap / 2,
    y: -gSize / 2,
    width: gSize,
    height: gSize,
    fill: GREEN,
    stroke: 'black',
    'stroke-width': 1,
  }));
  ghost.appendChild(svgEl('rect', {
    x: gGap / 2,
    y: -gSize / 2,
    width: gSize,
    height: gSize,
    fill: GOLD,
    stroke: 'black',
    'stroke-width': 1,
  }));
  ghost.appendChild(textEl(-(gSize + gGap) / 2, 3.5, 'S', {
    'text-anchor': 'middle',
    'font-size': 8.5,
    'font-weight': 700,
    fill: 'white',
  }));
  ghost.appendChild(textEl((gSize + gGap) / 2, 3.5, 'R', {
    'text-anchor': 'middle',
    'font-size': 8.5,
    'font-weight': 700,
    fill: 'white',
  }));
  s.dynamicLayer.appendChild(ghost);
  const ghostEndX = dx2 - dux * 10;
  const ghostEndY = dy2 - duy * 10;
  s.updaters.push(tau => {
    if (tau < 2.75) {
      ghost.setAttribute('opacity', 0);
      return;
    }
    const frac = clamp((tau - 2.75) / 1.0, 0, 1);
    const gx = dx1 + (ghostEndX - dx1) * frac;
    const gy = dy1 + (ghostEndY - dy1) * frac;
    ghost.setAttribute('transform', 'translate(' + gx + ' ' + gy + ')');
    ghost.setAttribute('opacity', frac < 1 ? 0.9 : 0.55);
  });

  s.revealText(xOf(1.7), 360, 'optional: relay to recipient', {
    at: 2.85,
    anchor: 'start',
    size: 12.5,
    weight: 600,
    fill: GREEN,
  });
  s.pair(xOf(2), PAYER_Y, {
    at: 3.65,
    retained: true,
    label: '(S,R)',
    labelY: PAYER_Y - 24,
    labelSize: 13,
  });
  s.arrow(xOf(2.08), PAYER_Y + 12, xOf(3.06), RCPT_Y - 16, {
    at: 3.8,
    duration: 1.05,
    style: 'bat',
  });
  s.pair(xOf(3.1), RCPT_Y, {
    at: 4.87,
    retained: true,
  });

  return { svg, scene: s };
}

function buildRolloverMinimal(mount) {
  const svg = baseSvg(mount);
  const s = new Scene(
    svg,
    'Closing e While Spending in e+1',
  );

  s.label(191, 77, 'epoch e', {
    'text-anchor': 'end',
    'font-size': 13.5,
    'font-weight': 700,
  });
  s.label(219, 77, 'epoch e+1', {
    'text-anchor': 'start',
    'font-size': 13.5,
    'font-weight': 700,
  });
  s.guide(205, 64, 205, 470, {
    stroke: ROW_LINE,
    'stroke-width': 1.2,
    'stroke-dasharray': '5 5',
  });
  s.label(205, 490, 'published boundary', {
    'text-anchor': 'middle',
    'font-size': 11.5,
    fill: GRAY,
  });
  s.label(383, 215, 'exact close for e', {
    'text-anchor': 'end',
    'font-size': 13,
    'font-weight': 700,
    fill: GOLD,
  });
  s.label(383, 410, 'live head in e+1', {
    'text-anchor': 'end',
    'font-size': 13,
    'font-weight': 700,
    fill: BLUE,
  });
  s.guide(390, 210, 852, 210, {
    stroke: GRID,
    'stroke-width': 1.6,
  });
  s.guide(390, 405, 895, 405, {
    stroke: GRID,
    'stroke-width': 1.6,
  });

  s.pair(100, 305, {
    at: 0.35,
    retained: true,
    label: 'a→b 20',
    labelY: 260,
    labelSize: 13.5,
    sub: 'head 100→80',
    subY: 345,
    subSize: 11.5,
  });
  s.arrow(123, 305, 264, 305, {
    at: 0.78,
    duration: 0.58,
    style: 'ctl',
    label: 'rotate the head',
    labelY: 285,
    labelSize: 12.5,
  });

  function balanceNode(x, y, value, at, options = {}) {
    const size = options.size || 50;
    s.event(x, y, {
      at,
      shape: 'circle',
      size,
      stroke: options.stroke || BLUE,
      fill: 'white',
      strokeWidth: 2.2,
    });
    s.revealText(x, y + 6, String(value), {
      at,
      size: 16,
      weight: 700,
      fill: options.textFill || BLUE,
    });
    if (options.label) {
      s.revealText(x, y + size / 2 + 24, options.label, {
        at,
        size: 11.8,
        weight: 600,
        fill: options.labelFill || GRAY,
      });
    }
  }

  balanceNode(290, 305, 80, 1.2, { label: 'preserved head' });
  s.edge(310, 289, 395, 222, {
    at: 1.42,
    duration: 0.45,
    style: 'bg',
  });
  s.edge(310, 321, 395, 393, {
    at: 1.5,
    duration: 0.45,
    style: 'bg',
  });
  balanceNode(410, 210, 80, 1.82, { size: 38 });
  balanceNode(410, 405, 80, 1.9, { size: 38 });

  s.arrow(429, 405, 530, 405, {
    at: 2.05,
    duration: 0.48,
    style: 'bad',
    label: '−20',
    labelY: 380,
    labelSize: 13,
  });
  balanceNode(555, 405, 60, 2.45);

  s.edge(650, 174, 650, 441, {
    at: 2.55,
    duration: 0.55,
    style: 'bat',
  });
  s.revealText(668, 303, 'ρₐ = +5', {
    at: 2.68,
    anchor: 'start',
    size: 14,
    weight: 700,
    fill: GREEN,
  });
  s.event(650, 210, {
    at: 2.72,
    shape: 'circle',
    size: 12,
    stroke: GREEN,
    fill: GREEN,
  });
  s.event(650, 405, {
    at: 2.72,
    shape: 'circle',
    size: 12,
    stroke: GREEN,
    fill: GREEN,
  });

  s.arrow(429, 210, 825, 210, {
    at: 2.76,
    duration: 0.62,
    style: 'bat',
  });
  balanceNode(850, 210, 85, 3.25, {
    stroke: GOLD,
    textFill: GOLD,
  });
  s.arrow(580, 405, 700, 405, {
    at: 2.84,
    duration: 0.5,
    style: 'bat',
  });
  balanceNode(725, 405, 65, 3.28);

  s.arrow(750, 405, 845, 405, {
    at: 3.55,
    duration: 0.48,
    style: 'bad',
    label: '−15',
    labelY: 380,
    labelSize: 13,
  });
  balanceNode(870, 405, 50, 3.98);

  s.revealText(570, 520, 'reconcile: live ← live + ρₐ', {
    at: 4.3,
    size: 13.5,
    weight: 700,
    fill: GREEN,
  });
  s.revealText(860, 520, 'never: live ← 85', {
    at: 4.3,
    size: 13.5,
    weight: 700,
    fill: RED,
  });

  return { svg, scene: s };
}

const BUILDERS = {
  'clearing-fig-payment': buildPaymentMinimal,
  'clearing-fig-rollover': buildRolloverMinimal,
};

function renderInstance(instance, seconds) {
  const into = ((seconds % DURATION) + DURATION) % DURATION;
  const tau = clamp(into - START_HOLD, 0, ACTIVE_END + 0.011);
  instance.scene.render(tau);
  const fadeIn = clamp(into / 0.3, 0, 1);
  const fadeOut = clamp((DURATION - into) / FADE_S, 0, 1);
  instance.scene.dynamicLayer.setAttribute('opacity', Math.min(fadeIn, fadeOut));
}

function initLive(mount, instance) {
  let epoch = performance.now();
  let paused = false;
  let pausedAt = 0;
  let visible = false;
  let rafId = 0;

  function frame(now) {
    rafId = 0;
    renderInstance(instance, (now - epoch) / 1000);
    if (visible && !paused) rafId = requestAnimationFrame(frame);
  }

  function start() {
    if (!rafId && visible && !paused) rafId = requestAnimationFrame(frame);
  }

  instance.svg.addEventListener('click', () => {
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

  const title = svgEl('title');
  title.textContent = 'Click to pause';
  instance.svg.appendChild(title);

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
}

function initAll() {
  injectStyles();
  for (const [id, builder] of Object.entries(BUILDERS)) {
    const mount = document.getElementById(id);
    if (!mount) continue;
    const instance = builder(mount);
    renderInstance(instance, 0);
    initLive(mount, instance);
  }
}

initAll();
