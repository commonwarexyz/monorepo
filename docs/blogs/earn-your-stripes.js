const SVG_NS = 'http://www.w3.org/2000/svg';
const DESIGN_W = 800;

const RED = '#d9251c';
const BLUE = '#1f1fd1';
const PURPLE = '#7427a8';
const GREEN = '#087a35';
const GRAY = '#6b7280';
const PALE_BLUE = '#eeeeff';
const PALE_GREEN = '#e9f5ec';
const PALE_RED = '#fff1ef';
const CHART_FONT_SCALE = 0.7;

const chartFontSize = size => size * CHART_FONT_SCALE;

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
const range = (time, start, end) => clamp((time - start) / (end - start), 0, 1);
const ease = value => 1 - Math.pow(1 - value, 3);

function svgEl(name, attrs = {}) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, value);
  return element;
}

function addText(parent, x, y, value, attrs = {}) {
  const element = svgEl('text', {
    x,
    y,
    fill: '#111111',
    'font-size': 17,
    ...attrs,
  });
  element.textContent = value;
  parent.appendChild(element);
  return element;
}

function addLines(parent, x, y, lines, attrs = {}) {
  const element = svgEl('text', {
    x,
    y,
    fill: '#111111',
    'font-size': 16,
    'text-anchor': 'middle',
    ...attrs,
  });
  lines.forEach((line, index) => {
    const span = svgEl('tspan', { x, dy: index === 0 ? 0 : 19 });
    span.textContent = line;
    element.appendChild(span);
  });
  parent.appendChild(element);
  return element;
}

function addPatterns(svg, prefix) {
  const defs = svgEl('defs');
  const checked = svgEl('pattern', {
    id: `${prefix}-checked`,
    width: 9,
    height: 9,
    patternUnits: 'userSpaceOnUse',
    patternTransform: 'rotate(45)',
  });
  checked.appendChild(svgEl('rect', { width: 9, height: 9, fill: '#fff7f6' }));
  checked.appendChild(svgEl('line', {
    x1: 0,
    y1: 0,
    x2: 0,
    y2: 9,
    stroke: RED,
    'stroke-width': 3,
  }));

  const restored = svgEl('pattern', {
    id: `${prefix}-restored`,
    width: 9,
    height: 9,
    patternUnits: 'userSpaceOnUse',
    patternTransform: 'rotate(45)',
  });
  restored.appendChild(svgEl('rect', { width: 9, height: 9, fill: '#fbf6fd' }));
  restored.appendChild(svgEl('line', {
    x1: 0,
    y1: 0,
    x2: 0,
    y2: 9,
    stroke: PURPLE,
    'stroke-width': 3,
  }));

  defs.append(checked, restored);
  svg.appendChild(defs);
  return {
    checked: `url(#${prefix}-checked)`,
    restored: `url(#${prefix}-restored)`,
  };
}

function createSvg(mount, height) {
  const svg = svgEl('svg', {
    viewBox: `0 0 ${DESIGN_W} ${height}`,
    class: 'cw-rs-svg',
    role: 'img',
  });
  if (mount.getAttribute('aria-label')) {
    svg.setAttribute('aria-label', mount.getAttribute('aria-label'));
  }
  return svg;
}

function makeArrow(parent, x0, y0, x1, y1, color = BLUE, width = 2.6) {
  const length = Math.hypot(x1 - x0, y1 - y0);
  const line = svgEl('line', {
    x1: x0,
    y1: y0,
    x2: x1,
    y2: y1,
    stroke: color,
    'stroke-width': width,
    'stroke-linecap': 'round',
    'stroke-dasharray': length,
    'stroke-dashoffset': length,
    opacity: 0,
  });
  const unitX = (x1 - x0) / (length || 1);
  const unitY = (y1 - y0) / (length || 1);
  const size = 9;
  const backX = x1 - unitX * size;
  const backY = y1 - unitY * size;
  const half = size * 0.45;
  const head = svgEl('polygon', {
    points: `${x1},${y1} ${backX - unitY * half},${backY + unitX * half} ${backX + unitY * half},${backY - unitX * half}`,
    fill: color,
    opacity: 0,
  });
  parent.append(line, head);
  return {
    set(value) {
      const fraction = clamp(value, 0, 1);
      line.setAttribute('stroke-dashoffset', length * (1 - fraction));
      line.setAttribute('opacity', fraction > 0 ? 1 : 0);
      head.setAttribute('opacity', fraction > 0.98 ? 1 : 0);
    },
  };
}

const legendItemWidth = label => 36 + label.length * 8.4;

function addLegendItem(parent, x, y, fill, stroke, dash, label) {
  parent.appendChild(svgEl('rect', {
    x,
    y: y - 13,
    width: 28,
    height: 16,
    fill,
    stroke,
    'stroke-width': 1.7,
    'stroke-dasharray': dash,
  }));
  addText(parent, x + 36, y, label, { 'font-size': 14, fill: GRAY });
  return legendItemWidth(label);
}

function makeShardRow(parent, patterns, x, y, width, label, provided, options = {}) {
  if (options.showLabel ?? true) {
    addText(parent, x - 20, y + 16, label, {
      'font-size': 15,
      'font-weight': 600,
      'text-anchor': 'end',
    });
  }
  const segmentCount = options.segmentCount ?? 12;
  const segmentGap = 2.5;
  const segmentWidth = (width - segmentGap * (segmentCount - 1)) / segmentCount;
  const bases = [];
  const fills = [];

  for (let index = 0; index < segmentCount; index++) {
    const segmentX = x + index * (segmentWidth + segmentGap);
    const base = svgEl('rect', {
      x: segmentX,
      y,
      width: segmentWidth,
      height: 22,
      rx: 1,
      fill: provided ? patterns.checked : 'white',
      stroke: provided ? RED : GRAY,
      'stroke-width': 1.6,
      'stroke-dasharray': provided ? 'none' : '5 3',
    });
    parent.appendChild(base);
    bases.push(base);

    if (!provided) {
      const fill = svgEl('rect', {
        x: segmentX,
        y,
        width: 0,
        height: 22,
        rx: 1,
        fill: patterns.restored,
      });
      parent.appendChild(fill);
      fills.push(fill);
    }
  }

  if (provided) return { set() {} };

  return {
    set(value) {
      const fraction = clamp(value, 0, 1);
      fills.forEach((fill, index) => {
        const progress = clamp(fraction * segmentCount - index, 0, 1);
        fill.setAttribute('width', segmentWidth * progress);
        bases[index].setAttribute('stroke', progress >= 1 ? PURPLE : GRAY);
        bases[index].setAttribute('stroke-dasharray', progress >= 1 ? 'none' : '5 3');
        bases[index].setAttribute('stroke-width', progress >= 1 ? 1.8 : 1.6);
      });
    },
  };
}

const chartLegendWidth = label => 39 + label.length * 6;

function addChartLegend(parent, x, y, label, color) {
  parent.appendChild(svgEl('line', {
    x1: x,
    y1: y,
    x2: x + 20,
    y2: y,
    stroke: color,
    'stroke-width': 2.5,
    'stroke-linecap': 'round',
  }));
  parent.appendChild(svgEl('circle', {
    cx: x + 10,
    cy: y,
    r: 2.5,
    fill: 'white',
    stroke: color,
    'stroke-width': 1.5,
  }));
  addText(parent, x + 27, y + 4, label, {
    'font-size': chartFontSize(14),
    'font-weight': 600,
    fill: GRAY,
  });
  return chartLegendWidth(label);
}

function buildBenchmarkChart(mount, config) {
  const width = 500;
  const height = 310;
  const svg = svgEl('svg', {
    viewBox: `0 0 ${width} ${height}`,
    class: 'cw-rs-svg',
    role: 'img',
  });
  if (mount.getAttribute('aria-label')) {
    svg.setAttribute('aria-label', mount.getAttribute('aria-label'));
  }
  const layer = svgEl('g');
  svg.appendChild(layer);

  layer.appendChild(svgEl('rect', {
    x: 5,
    y: 5,
    width: 490,
    height: 300,
    rx: 8,
    fill: '#fcfcfc',
    stroke: '#e5e7eb',
  }));
  const plotLeft = 45;
  const plotRight = 472;
  const plotTop = 26;
  const plotBottom = 208;
  const xInset = 32;
  const xMin = Math.min(...config.workers);
  const xMax = Math.max(...config.workers);
  const xScale = worker => plotLeft + xInset
    + ((worker - xMin) / (xMax - xMin)) * (plotRight - plotLeft - xInset * 2);
  const yScale = value => plotBottom - (value / config.yMax) * (plotBottom - plotTop);

  config.yTicks.forEach(value => {
    const y = yScale(value);
    layer.appendChild(svgEl('line', {
      x1: plotLeft,
      y1: y,
      x2: plotRight,
      y2: y,
      stroke: value === 0 ? '#9ca3af' : '#e5e7eb',
      'stroke-width': value === 0 ? 1.4 : 1,
    }));
    addText(layer, plotLeft - 12, y + 5, `${value}`, {
      'font-size': chartFontSize(12),
      fill: GRAY,
      'text-anchor': 'end',
    });
  });

  config.workers.forEach(worker => {
    const x = xScale(worker);
    layer.appendChild(svgEl('line', {
      x1: x,
      y1: plotBottom,
      x2: x,
      y2: plotBottom + 5,
      stroke: '#9ca3af',
      'stroke-width': 1.4,
    }));
    addText(layer, x, plotBottom + 23, `${worker}`, {
      'font-size': chartFontSize(12),
      'font-weight': 600,
      fill: GRAY,
      'text-anchor': 'middle',
    });
  });
  addText(layer, (plotLeft + plotRight) / 2, 252, 'Workers', {
    'font-size': chartFontSize(12),
    'font-weight': 600,
    fill: GRAY,
    'text-anchor': 'middle',
  });

  const legendWidth = config.series.reduce(
    (total, series) => total + chartLegendWidth(series.label),
    0,
  );
  let legendX = (width - legendWidth) / 2;
  config.series.forEach(series => {
    legendX += addChartLegend(layer, legendX, 276, series.label, series.color);
  });
  addText(layer, width / 2, 298, 'End-to-end latency (ms) · lower is better', {
    'font-size': chartFontSize(13),
    fill: GRAY,
    'text-anchor': 'middle',
  });

  const points = config.series.map(series => series.values.map((value, index) => ({
    value,
    x: xScale(config.workers[index]),
    y: yScale(value),
  })));
  const bandPoints = [
    ...points[0],
    ...[...points[1]].reverse(),
  ].map(point => `${point.x},${point.y}`).join(' ');
  layer.appendChild(svgEl('polygon', {
    points: bandPoints,
    fill: config.bandFill,
    opacity: 0.82,
  }));

  config.series.forEach((series, seriesIndex) => {
    const seriesPoints = points[seriesIndex];
    layer.appendChild(svgEl('polyline', {
      points: seriesPoints.map(point => `${point.x},${point.y}`).join(' '),
      fill: 'none',
      stroke: series.color,
      'stroke-width': 3,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
    }));
    seriesPoints.forEach((point, pointIndex) => {
      layer.appendChild(svgEl('circle', {
        cx: point.x,
        cy: point.y,
        r: 3.75,
        fill: 'white',
        stroke: series.color,
        'stroke-width': 2.25,
      }));
      const firstImprovedPoint = seriesIndex === 1 && pointIndex === 0;
      const firstPointHasBadge = firstImprovedPoint
        && (config.badges ?? []).some(badge => badge.index === 0);
      let labelX = point.x;
      let labelOffsetY = -12;
      let labelAnchor = 'middle';
      if (seriesIndex === 1) {
        labelX = point.x - 7;
        labelOffsetY = firstImprovedPoint ? 26 : 15;
        labelAnchor = 'end';
        if (firstImprovedPoint && !firstPointHasBadge) {
          labelX = plotLeft + 3;
          labelOffsetY = 34;
          labelAnchor = 'start';
        }
      }
      addText(
        layer,
        labelX,
        point.y + labelOffsetY,
        `${point.value.toFixed(2)} ms`,
        {
          'font-size': chartFontSize(12),
          'font-weight': 700,
          fill: series.color,
          'text-anchor': labelAnchor,
        },
      );
    });
  });

  (config.badges ?? []).forEach(badge => {
    const first = points[0][badge.index];
    const improved = points[1][badge.index];
    const separation = Math.abs(first.y - improved.y);
    const width = 64;
    const y = separation >= 28
      ? (first.y + improved.y) / 2 - 12
      : Math.min(plotBottom - 26, Math.max(first.y, improved.y) + 32);
    addPill(
      layer,
      clamp(improved.x - width / 2, plotLeft + 2, plotRight - width - 2),
      y,
      width,
      badge.label,
      GREEN,
      PALE_GREEN,
      chartFontSize(12),
    );
  });

  return svg;
}

function buildStripingFigure(mount) {
  const height = 570;
  const svg = createSvg(mount, height);
  const patterns = addPatterns(svg, 'cw-rs-striping');
  const layer = svgEl('g');
  svg.appendChild(layer);

  layer.appendChild(svgEl('rect', {
    x: 10, y: 10, width: 780, height: 220, rx: 8,
    fill: '#fcfcfc', stroke: '#e5e7eb',
  }));
  layer.appendChild(svgEl('rect', {
    x: 10, y: 245, width: 780, height: 315, rx: 8,
    fill: '#fcfcfc', stroke: '#e5e7eb',
  }));

  addPanelLabel(layer, 25, 10, 'BEFORE', RED);

  const states = [true, false, true, true];
  const labels = ['D0', 'D1', 'D2', 'R0'];
  const gridX = 100;
  const gridWidth = 600;
  const beforeJob = svgEl('rect', {
    x: 86, y: 53, width: 628, height: 146, rx: 10,
    fill: '#fcfcfc', stroke: BLUE, 'stroke-width': 1.6,
  });
  layer.appendChild(beforeJob);
  addPill(layer, 314, 48, 172, '1 RS job · full width', BLUE, PALE_BLUE);
  const beforeRows = labels.map((label, index) =>
    makeShardRow(layer, patterns, gridX, 76 + index * 29, gridWidth, label, states[index])
  );

  const playhead = svgEl('line', {
    x1: gridX, y1: 72, x2: gridX, y2: 190,
    stroke: BLUE, 'stroke-width': 3, opacity: 0,
  });
  layer.appendChild(playhead);
  addPanelLabel(layer, 25, 245, 'AFTER', GREEN);
  const gridY = 318;
  const jobGap = 14;
  const jobWidth = gridWidth / 3;
  const afterLabels = ['D0', 'D1', 'D2', 'R0'];
  const afterStates = [true, false, true, true];

  const jobLayer = svgEl('g', { opacity: 0 });
  layer.appendChild(jobLayer);
  const jobRects = [];
  for (let index = 0; index < 3; index++) {
    const start = gridX + index * (jobWidth + jobGap);
    const rect = svgEl('rect', {
      x: start - 5, y: 287, width: jobWidth + 10, height: 143, rx: 8,
      fill: '#fcfcfc', stroke: BLUE, 'stroke-width': 1.5,
    });
    jobLayer.appendChild(rect);
    jobRects.push(rect);
    addPill(
      jobLayer,
      start + jobWidth / 2 - 49,
      290,
      98,
      `RS job ${index}`,
      BLUE,
      PALE_BLUE,
    );
  }
  const afterRows = [];
  const recoveredStripes = [];
  const stripeLabels = [];
  for (let job = 0; job < 3; job++) {
    const start = gridX + job * (jobWidth + jobGap);
    afterLabels.forEach((label, row) => {
      const rowLayer = row === 1 ? svgEl('g') : jobLayer;
      if (row === 1) jobLayer.appendChild(rowLayer);
      afterRows.push(makeShardRow(
        rowLayer,
        patterns,
        start,
        gridY + row * 26,
        jobWidth,
        label,
        afterStates[row],
        { segmentCount: 4, showLabel: job === 0 },
      ));
      if (row === 1) {
        const stripeLabel = addText(
          rowLayer,
          start + jobWidth / 2,
          gridY + row * 26 + 16,
          job === 2 ? 'D1 · final stripe' : `D1 · stripe ${job}`,
          {
            'font-size': 11,
            'font-weight': 700,
            'text-anchor': 'middle',
            opacity: 0,
          },
        );
        recoveredStripes.push({
          group: rowLayer,
          dx: gridX + job * jobWidth - start,
        });
        stripeLabels.push(stripeLabel);
      }
    });
  }

  const stripedPlayheads = Array.from({ length: 3 }, (_, job) => {
    const start = gridX + job * (jobWidth + jobGap);
    const line = svgEl('line', {
      x1: start,
      y1: gridY - 4,
      x2: start,
      y2: gridY + 104,
      stroke: BLUE,
      'stroke-width': 3,
      opacity: 0,
    });
    layer.appendChild(line);
    return { line, start };
  });

  const equalityLabel = addText(layer, DESIGN_W / 2, 526, 'same full-width D1', {
    'font-size': 11,
    'font-weight': 700,
    fill: GREEN,
    'text-anchor': 'middle',
    opacity: 0,
  });

  const legendItems = [
    [patterns.checked, RED, 'none', 'checked'],
    ['white', GRAY, '6 4', 'missing'],
    [patterns.restored, PURPLE, 'none', 'recovered'],
  ];
  const legendGap = 20;
  const legendWidth = legendItems.reduce(
    (total, item) => total + legendItemWidth(item[3]),
    legendGap * (legendItems.length - 1),
  );
  let legendX = (DESIGN_W - legendWidth) / 2;
  legendItems.forEach(([fill, stroke, dash, label]) => {
    legendX += addLegendItem(layer, legendX, 548, fill, stroke, dash, label);
    legendX += legendGap;
  });

  function render(time) {
    const before = ease(range(time, 0.5, 2.4));
    beforeRows.forEach(row => row.set(before));
    beforeJob.setAttribute('fill', before > 0 && before < 1 ? PALE_BLUE : '#fcfcfc');
    beforeJob.setAttribute('stroke-width', before > 0 && before < 1 ? 2.6 : 1.6);
    playhead.setAttribute('x1', gridX + gridWidth * before);
    playhead.setAttribute('x2', gridX + gridWidth * before);
    playhead.setAttribute('opacity', before > 0 && before < 1 ? 0.85 : 0);

    const reveal = ease(range(time, 2.7, 3.35));
    jobLayer.setAttribute('opacity', reveal);

    const striped = ease(range(time, 3.45, 5.05));
    afterRows.forEach(row => row.set(striped));
    stripedPlayheads.forEach(({ line, start }) => {
      line.setAttribute('x1', start + jobWidth * striped);
      line.setAttribute('x2', start + jobWidth * striped);
      line.setAttribute('opacity', striped > 0 && striped < 1 ? 0.85 : 0);
    });
    jobRects.forEach(rect => {
      rect.setAttribute('fill', striped > 0 && striped < 1 ? PALE_BLUE : '#fcfcfc');
      rect.setAttribute('stroke-width', striped > 0 && striped < 1 ? 2.5 : 1.5);
    });

    const output = ease(range(time, 4.75, 5.15));
    stripeLabels.forEach(label => label.setAttribute('opacity', output));

    const assembly = ease(range(time, 5.15, 5.9));
    recoveredStripes.forEach(stripe => {
      stripe.group.setAttribute(
        'transform',
        `translate(${stripe.dx * assembly} ${144 * assembly})`,
      );
    });
    const equal = ease(range(time, 5.75, 6.05));
    equalityLabel.setAttribute('opacity', equal);
  }

  render(0);
  return { svg, duration: 6.1, render };
}

function addShardChip(parent, x, y, label, patterns, state, options = {}) {
  const width = options.width ?? 31;
  const height = options.height ?? 31;
  const styles = {
    checked: { fill: patterns.checked, stroke: RED, dash: 'none', opacity: 1 },
    recovered: { fill: patterns.restored, stroke: PURPLE, dash: 'none', opacity: 1 },
    hidden: { fill: patterns.restored, stroke: GRAY, dash: '5 3', opacity: 0.55 },
  }[state];
  const group = svgEl('g', { opacity: styles.opacity });
  group.appendChild(svgEl('rect', {
    x,
    y,
    width,
    height,
    rx: 3,
    fill: styles.fill,
    stroke: styles.stroke,
    'stroke-width': 1.7,
    'stroke-dasharray': styles.dash,
  }));
  if (state === 'hidden') {
    group.appendChild(svgEl('line', {
      x1: x + 4,
      y1: y + 4,
      x2: x + width - 4,
      y2: y + height - 4,
      stroke: GRAY,
      'stroke-width': 2,
    }));
  }
  addText(group, x + width / 2, y + height / 2 + 5, label, {
    'font-size': options.fontSize ?? 13,
    'font-weight': 700,
    'text-anchor': 'middle',
  });
  parent.appendChild(group);
  return group;
}

function addShardSet(parent, x, y, patterns, items, options = {}) {
  const group = svgEl('g', { opacity: options.opacity ?? 1 });
  const width = options.width ?? 31;
  const height = options.height ?? 31;
  const gap = options.gap ?? 4;
  const totalWidth = items.length * width + (items.length - 1) * gap;
  if (options.label) {
    addText(group, x + totalWidth / 2, y - 9, options.label, {
      'font-size': options.labelSize ?? 12,
      fill: options.labelFill ?? GRAY,
      'text-anchor': 'middle',
    });
  }
  items.forEach((item, index) => {
    addShardChip(
      group,
      x + index * (width + gap),
      y,
      item.label,
      patterns,
      item.state,
      { width, height, fontSize: options.fontSize },
    );
  });
  parent.appendChild(group);
  return group;
}

function makeTransformNode(parent, cx, cy, lines, color, activeFill) {
  const group = svgEl('g');
  const core = svgEl('circle', {
    cx,
    cy,
    r: 35,
    fill: 'white',
    stroke: color,
    'stroke-width': 2,
  });
  const ring = svgEl('circle', {
    cx,
    cy,
    r: 40,
    fill: 'none',
    stroke: color,
    'stroke-width': 2.5,
    'stroke-dasharray': '20 9',
    opacity: 0.28,
  });
  group.append(core, ring);
  const lineGap = 19;
  addLines(group, cx, cy - ((lines.length - 1) * lineGap) / 2 + 4, lines, {
    'font-size': lines.length > 2 ? 11 : 12,
    'font-weight': 700,
    'text-anchor': 'middle',
  });
  parent.appendChild(group);
  return {
    setActive(value) {
      const progress = clamp(value, 0, 1);
      const active = progress > 0 && progress < 1;
      core.setAttribute('fill', active ? activeFill : 'white');
      ring.setAttribute('opacity', active ? 0.95 : 0.28);
      ring.setAttribute('transform', `rotate(${progress * 300} ${cx} ${cy})`);
    },
  };
}

function makeRootNode(parent, cx, cy) {
  const group = svgEl('g', { opacity: 0 });
  const circle = svgEl('circle', {
    cx,
    cy,
    r: 32,
    fill: 'white',
    stroke: GREEN,
    'stroke-width': 2.2,
  });
  const check = svgEl('path', {
    d: `M ${cx - 14} ${cy} l 9 9 l 19 -21`,
    fill: 'none',
    stroke: GREEN,
    'stroke-width': 4,
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
  });
  group.append(circle, check);
  addLines(group, cx, cy + 48, ['root matches', 'commitment'], {
    'font-size': 11,
    'font-weight': 700,
    fill: GREEN,
    'text-anchor': 'middle',
  });
  parent.appendChild(group);
  return {
    setActive(value) {
      const progress = clamp(value, 0, 1);
      group.setAttribute('opacity', progress <= 0 ? 0 : Math.min(1, progress * 4));
      circle.setAttribute('fill', progress > 0 && progress < 1 ? PALE_GREEN : 'white');
      circle.setAttribute('stroke-width', progress > 0 && progress < 1 ? 3 : 2.2);
    },
  };
}

function addPanelLabel(parent, x, y, label, color) {
  const width = 16 + label.length * 8;
  parent.appendChild(svgEl('line', {
    x1: x - 6,
    y1: y,
    x2: x + width,
    y2: y,
    stroke: '#fcfcfc',
    'stroke-width': 5,
  }));
  addText(parent, x, y + 5, label, {
    'font-size': 13,
    'font-weight': 700,
    fill: color,
  });
}

function addPill(parent, x, y, width, label, color, fill, fontSize = 12) {
  parent.appendChild(svgEl('rect', {
    x,
    y,
    width,
    height: 24,
    rx: 12,
    fill,
    stroke: color,
    'stroke-width': 1.4,
  }));
  addText(parent, x + width / 2, y + 17, label, {
    'font-size': fontSize,
    'font-weight': 700,
    fill: color,
    'text-anchor': 'middle',
  });
}

function buildRevealFigure(mount) {
  const height = 415;
  const svg = createSvg(mount, height);
  svg.setAttribute('viewBox', `0 55 ${DESIGN_W} ${height}`);
  const patterns = addPatterns(svg, 'cw-rs-reveal');
  const layer = svgEl('g');
  svg.appendChild(layer);

  layer.appendChild(svgEl('rect', {
    x: 10, y: 65, width: 780, height: 190, rx: 8,
    fill: '#fcfcfc', stroke: '#e5e7eb',
  }));
  layer.appendChild(svgEl('rect', {
    x: 10, y: 270, width: 780, height: 190, rx: 8,
    fill: '#fcfcfc', stroke: '#e5e7eb',
  }));

  addPanelLabel(layer, 25, 65, 'BEFORE', RED);
  addShardSet(layer, 25, 144, patterns, [
    { label: 'D0', state: 'checked' },
    { label: 'D2', state: 'checked' },
    { label: 'R0', state: 'checked' },
  ], { width: 29, height: 32, gap: 3, label: 'checked inputs' });
  const oldInputArrow = makeArrow(layer, 119, 160, 175, 160);
  const oldDecode = makeTransformNode(layer, 220, 160, ['decode', 'D1 + R1'], BLUE, PALE_BLUE);

  addText(layer, 345, 135, 'D1 returned', {
    'font-size': 12,
    fill: PURPLE,
    'text-anchor': 'middle',
  });
  addText(layer, 320, 219, 'R1 not returned', {
    'font-size': 10,
    fill: GRAY,
    'text-anchor': 'middle',
  });
  const oldR1Arrow = makeArrow(layer, 249, 181, 300, 192);
  const oldD1Arrow = makeArrow(layer, 258, 151, 415, 151);
  const oldHiddenR1 = svgEl('g', { opacity: 0 });
  addShardChip(oldHiddenR1, 305, 176, 'R1', patterns, 'hidden', {
    width: 30, height: 32, fontSize: 12,
  });
  layer.appendChild(oldHiddenR1);

  addText(layer, 460, 118, 'D0 · D1 · D2', {
    'font-size': 11,
    fill: GRAY,
    'text-anchor': 'middle',
  });
  const oldEncode = makeTransformNode(
    layer,
    460,
    160,
    ['encode', 'R0 + R1'],
    RED,
    PALE_RED,
  );
  addText(layer, 460, 214, 'compare checked R0', {
    'font-size': 10,
    fill: GRAY,
    'text-anchor': 'middle',
  });
  const oldEncodeArrow = makeArrow(layer, 500, 160, 525, 160);
  const oldCodeword = svgEl('g');
  addText(oldCodeword, 598, 135, 'all 5 · checked + recovered', {
    'font-size': 10,
    fill: GRAY,
    'text-anchor': 'middle',
  });
  addShardChip(oldCodeword, 530, 144, 'D0', patterns, 'checked', {
    width: 25, height: 32, fontSize: 11,
  });
  addShardChip(oldCodeword, 586, 144, 'D2', patterns, 'checked', {
    width: 25, height: 32, fontSize: 11,
  });
  addShardChip(oldCodeword, 614, 144, 'R0', patterns, 'checked', {
    width: 25, height: 32, fontSize: 11,
  });
  layer.appendChild(oldCodeword);
  const oldD1Position = svgEl('g', { opacity: 0 });
  addShardChip(oldD1Position, 558, 144, 'D1', patterns, 'recovered', {
    width: 25, height: 32, fontSize: 11,
  });
  layer.appendChild(oldD1Position);
  const oldDerivedRecovery = svgEl('g', { opacity: 0 });
  addShardChip(oldDerivedRecovery, 642, 144, 'R1', patterns, 'recovered', {
    width: 25, height: 32, fontSize: 11,
  });
  layer.appendChild(oldDerivedRecovery);
  const oldRootArrow = makeArrow(layer, 671, 160, 695, 160, GREEN);
  const oldRoot = makeRootNode(layer, 735, 160);

  addPanelLabel(layer, 25, 270, 'AFTER', GREEN);
  addShardSet(layer, 25, 349, patterns, [
    { label: 'D0', state: 'checked' },
    { label: 'D2', state: 'checked' },
    { label: 'R0', state: 'checked' },
  ], { width: 29, height: 32, gap: 3, label: 'checked inputs' });
  const newInputArrow = makeArrow(layer, 119, 365, 175, 365);
  const newDecode = makeTransformNode(layer, 220, 365, ['decode', 'D1 + R1'], BLUE, PALE_BLUE);

  const newRevealArrow = makeArrow(layer, 258, 365, 450, 365);
  const codeword = svgEl('g');
  addText(codeword, 536, 340, 'all 5 · checked + recovered', {
    'font-size': 12,
    fill: GRAY,
    'text-anchor': 'middle',
  });
  addShardChip(codeword, 455, 349, 'D0', patterns, 'checked', {
    width: 30, height: 32, fontSize: 11,
  });
  addShardChip(codeword, 521, 349, 'D2', patterns, 'checked', {
    width: 30, height: 32, fontSize: 11,
  });
  addShardChip(codeword, 554, 349, 'R0', patterns, 'checked', {
    width: 30, height: 32, fontSize: 11,
  });
  layer.appendChild(codeword);
  const revealedPositions = svgEl('g', { opacity: 0 });
  addShardChip(revealedPositions, 488, 349, 'D1', patterns, 'recovered', {
    width: 30, height: 32, fontSize: 11,
  });
  addShardChip(revealedPositions, 587, 349, 'R1', patterns, 'recovered', {
    width: 30, height: 32, fontSize: 11,
  });
  layer.appendChild(revealedPositions);
  const newRootArrow = makeArrow(layer, 621, 365, 660, 365, GREEN);
  const newRoot = makeRootNode(layer, 700, 365);

  function render(time) {
    const oldDecodeProgress = ease(range(time, 0.35, 1.0));
    oldInputArrow.set(oldDecodeProgress);
    oldDecode.setActive(oldDecodeProgress);
    const oldRevealProgress = ease(range(time, 0.9, 1.55));
    oldD1Arrow.set(oldRevealProgress);
    oldR1Arrow.set(oldRevealProgress);
    oldD1Position.setAttribute('opacity', oldRevealProgress);
    oldHiddenR1.setAttribute('opacity', oldRevealProgress);

    const oldEncodeProgress = ease(range(time, 1.55, 2.25));
    oldEncode.setActive(oldEncodeProgress);
    const oldOutputProgress = ease(range(time, 2.15, 2.8));
    oldEncodeArrow.set(oldOutputProgress);
    oldDerivedRecovery.setAttribute('opacity', oldOutputProgress);
    const oldVerifyProgress = ease(range(time, 2.75, 3.35));
    oldRootArrow.set(oldVerifyProgress);
    oldRoot.setActive(oldVerifyProgress);

    const newDecodeProgress = ease(range(time, 3.65, 4.3));
    newInputArrow.set(newDecodeProgress);
    newDecode.setActive(newDecodeProgress);
    const newRevealProgress = ease(range(time, 4.2, 4.85));
    newRevealArrow.set(newRevealProgress);
    revealedPositions.setAttribute('opacity', newRevealProgress);
    const newVerifyProgress = ease(range(time, 4.8, 5.45));
    newRootArrow.set(newVerifyProgress);
    newRoot.setActive(newVerifyProgress);
  }

  render(0);
  return { svg, duration: 6.1, render };
}

function injectStyles() {
  const style = document.createElement('style');
  style.textContent = `
    .cw-rs-svg {
      background: white;
      cursor: pointer;
      display: block;
      height: auto;
      width: 100%;
    }

    .cw-rs-svg text {
      font-family: monospace;
      user-select: none;
    }

    .cw-rs-chart .cw-rs-svg {
      cursor: default;
    }
  `;
  document.head.appendChild(style);
}

function animateFigure(mount, build) {
  const figure = build(mount);
  mount.textContent = '';
  mount.appendChild(figure.svg);

  const freezeValue = new URLSearchParams(window.location.search).get('freeze');
  const freeze = freezeValue === null ? null : Number(freezeValue);
  if (Number.isFinite(freeze)) {
    figure.render(clamp(freeze, 0, figure.duration));
    return;
  }

  const startHold = 0.45;
  const endHold = 1.1;
  const cycle = startHold + figure.duration + endHold;
  let epoch = performance.now();
  let frameId = 0;
  let visible = false;
  let paused = false;
  let pausedAt = 0;

  function frame(now) {
    frameId = 0;
    const into = ((now - epoch) / 1000) % cycle;
    figure.render(clamp(into - startHold, 0, figure.duration));
    if (visible && !paused) frameId = requestAnimationFrame(frame);
  }

  function start() {
    if (!frameId && visible && !paused) frameId = requestAnimationFrame(frame);
  }

  function togglePaused() {
    paused = !paused;
    if (paused) {
      pausedAt = performance.now();
      if (frameId) cancelAnimationFrame(frameId);
      frameId = 0;
    } else {
      epoch += performance.now() - pausedAt;
      start();
    }
  }

  figure.svg.addEventListener('click', togglePaused);
  const tooltip = svgEl('title');
  tooltip.textContent = 'Click to pause';
  figure.svg.appendChild(tooltip);

  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      const wasVisible = visible;
      visible = entry.isIntersecting;
      if (visible && !wasVisible) {
        epoch = performance.now();
        paused = false;
        figure.render(0);
        start();
      }
      if (!visible && frameId) {
        cancelAnimationFrame(frameId);
        frameId = 0;
      }
    }
  }, { threshold: 0.25 });
  observer.observe(mount);
}

function init() {
  injectStyles();
  const charts = [
    ['earn-your-stripes-chart-recovery-gap', {
      workers: [1, 8, 16],
      yMax: 60,
      yTicks: [0, 15, 30, 45, 60],
      bandFill: PALE_RED,
      series: [
        { label: 'Full recovery', color: RED, values: [51.19, 26.85, 25.94] },
        { label: 'All originals', color: BLUE, values: [34.96, 9.45, 7.90] },
      ],
    }],
    ['earn-your-stripes-chart-striping', {
      workers: [1, 8, 16],
      yMax: 60,
      yTicks: [0, 15, 30, 45, 60],
      bandFill: PALE_GREEN,
      series: [
        { label: 'Before striping', color: RED, values: [51.19, 26.85, 25.94] },
        { label: 'After striping', color: BLUE, values: [51.79, 10.22, 7.67] },
      ],
      badges: [
        { index: 1, label: '2.63×' },
        { index: 2, label: '3.38×' },
      ],
    }],
    ['earn-your-stripes-chart-reveal', {
      workers: [8, 16],
      yMax: 12,
      yTicks: [0, 3, 6, 9, 12],
      bandFill: PALE_GREEN,
      series: [
        { label: 'Decode + encode', color: RED, values: [10.20, 7.64] },
        { label: 'Decode + reveal', color: BLUE, values: [9.09, 6.87] },
      ],
      badges: [
        { index: 0, label: '1.12×' },
        { index: 1, label: '1.11×' },
      ],
    }],
    ['earn-your-stripes-chart-final', {
      workers: [1, 8, 16],
      yMax: 60,
      yTicks: [0, 15, 30, 45, 60],
      bandFill: PALE_GREEN,
      series: [
        { label: 'Baseline', color: RED, values: [51.19, 26.85, 25.94] },
        { label: 'Final', color: BLUE, values: [47.14, 8.91, 6.51] },
      ],
      badges: [
        { index: 0, label: '1.09×' },
        { index: 1, label: '3.01×' },
        { index: 2, label: '3.99×' },
      ],
    }],
  ];
  charts.forEach(([id, config]) => {
    const mount = document.getElementById(id);
    if (!mount) return;
    mount.appendChild(buildBenchmarkChart(mount, config));
  });
  const figures = [
    ['earn-your-stripes-fig-striping', buildStripingFigure],
    ['earn-your-stripes-fig-reveal', buildRevealFigure],
  ];
  figures.forEach(([id, build]) => {
    const mount = document.getElementById(id);
    if (mount) animateFigure(mount, build);
  });
}

init();
