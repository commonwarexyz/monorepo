const figure = document.querySelector("#multimmit-pay-latency");
const chart = figure.querySelector(".latency-chart");
const table = figure.querySelector("table");
const regions = Array.from(table.tBodies, group => {
    const [header, ...rows] = group.rows;
    return {
        name: header.cells[0].textContent.trim(),
        max: Number(group.dataset.axisMax),
        step: Number(group.dataset.axisStep),
        medians: new Map(rows.map(({ cells }) => [
            cells[0].textContent.trim(),
            [Number(cells[1].textContent), Number(cells[3].textContent)],
        ])),
    };
});
const conditions = [...regions[0].medians.keys()];

const svgNS = "http://www.w3.org/2000/svg";
const receipt = "#1f1fd1";
const placement = "#b89b37";

function add(parent, tag, attrs, text) {
    const node = document.createElementNS(svgNS, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    if (text !== undefined) node.textContent = text;
    parent.append(node);
    return node;
}

function marker(parent, x, y, isReceipt) {
    if (isReceipt) {
        add(parent, "circle", { cx: x, cy: y, r: 4, fill: receipt });
    } else {
        add(parent, "path", { d: `M ${x} ${y - 5} l 5 5 -5 5 -5 -5 Z`, fill: placement });
    }
}

let lastWidth;

function render(width) {
    width = Math.max(300, Math.floor(width));
    if (width === lastWidth) return;
    lastWidth = width;
    const narrow = width < 620;
    const scenarioWidth = narrow ? 0 : 144;
    const gap = narrow ? 14 : 24;
    const panelWidth = (width - scenarioWidth - gap) / 2;
    // Narrow layouts put the scenario above both plots to keep their axes side by side.
    const rowY = index => (narrow ? 72 + 41 * index : 59 + 29 * index);
    const axisY = rowY(conditions.length - 1) + 14;
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${axisY + 23}`);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Median receipt and placement latency by condition. Expand the table for all measurements.");

    marker(svg, 5, 9, true);
    add(svg, "text", { x: 16, y: 13 }, "Receipt");
    marker(svg, 85, 9, false);
    add(svg, "text", { x: 97, y: 13 }, "Placement");

    conditions.forEach((condition, index) => {
        add(svg, "text", { x: 0, y: rowY(index) + (narrow ? -13 : 4) }, condition);
    });

    regions.forEach((region, index) => {
        const left = scenarioWidth + (panelWidth + gap) * index;
        const minX = left + 12;
        const maxX = left + panelWidth - 30;
        const x = value => minX + (maxX - minX) * value / region.max;
        const panel = add(svg, "g", { "data-region": region.name });
        add(panel, "text", { x: left, y: 32, "font-weight": "bold" }, region.name + " (ms)");
        add(panel, "line", { x1: minX, x2: maxX, y1: axisY, y2: axisY, stroke: "#999" });
        for (let tick = 0; tick <= region.max; tick += region.step) {
            const tickX = x(tick);
            const gridline = (top, bottom) => add(panel, "line", {
                x1: tickX, x2: tickX, y1: top, y2: bottom, stroke: "#ddd",
            });
            if (narrow) {
                conditions.forEach((_, row) => gridline(rowY(row) - 10, rowY(row) + 12));
            } else {
                gridline(43, axisY);
            }
            add(panel, "text", {
                x: tickX, y: axisY + 15, "text-anchor": "middle", "font-size": 11, fill: "#555",
            }, tick);
        }

        conditions.forEach((condition, row) => {
            const [receiptMedian, placementMedian] = region.medians.get(condition);
            const rx = x(receiptMedian);
            const px = x(placementMedian);
            const y = rowY(row);
            const pair = add(panel, "g", { "data-condition": condition });
            add(pair, "line", { x1: rx, x2: px, y1: y, y2: y, stroke: "#999" });
            marker(pair, rx, y, true);
            marker(pair, px, y, false);
            add(pair, "text", { x: rx - 8, y: y + 4, "text-anchor": "end", fill: receipt }, receiptMedian);
            add(pair, "text", { x: px + 8, y: y + 4, fill: "#635117" }, placementMedian);
        });
    });

    chart.replaceChildren(svg);
}

render(figure.clientWidth);
chart.hidden = false;
new ResizeObserver(([entry]) => render(entry.contentRect.width)).observe(chart);
