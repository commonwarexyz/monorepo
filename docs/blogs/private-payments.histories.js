'use strict';

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

const MAX_TX = 14;           // bound on log length
const FULL_LEVELS = 6;        // levels drawn in full (t1..t6); the rest show counts
const MAX_DRAWN_LEAVES = 256; // safety cap on the widest level drawn
const ACCOUNTS = ['A', 'B', 'C', 'D', 'E', 'F'];

// Number of accounts in play; the active accounts are the first `numAccts`.
let numAccts = 4;
function active() {
    return ACCOUNTS.slice(0, numAccts);
}

// A transaction is {acct, op: 'send', to} or {acct, op: 'recv', claims} where
// `claims` is the index of the send whose receipt is consumed.
let log = [];

// Whether an account may pay itself, i.e. claim a receipt it published. The
// send relation permits Rec = Sen.
let allowSelf = true;

// Leakage functions.
//   unl:  (op, account).  Our basic construction.
//   ind:  (account).      Our operation-hiding construction.
const LEAKS = ['unl', 'ind'];

// Receipts published by sends to `acct` that no receive in the log has consumed.
function claimable(acct) {
    const consumed = new Set(log.filter(t => t.op === 'recv').map(t => t.claims));
    const out = [];
    log.forEach((t, i) => {
        if (t.op === 'send' && t.to === acct && !consumed.has(i)) out.push(i);
    });
    return out;
}

function maySend(j, leak) {
    return leak !== 'unl' || log[j].op === 'send';
}
function mayRecv(j, leak) {
    return leak !== 'unl' || log[j].op === 'recv';
}
// Both leakage functions reveal the acting account.
function actorsFor(j) {
    return [log[j].acct];
}

// ---------------------------------------------------------------------------
// Counting consistent histories
// ---------------------------------------------------------------------------
//
// A history assigns each transaction an actor (fixed unless the leakage hides
// it) and a role: a send, or a receive claiming a specific unclaimed receipt. A
// receipt may be claimed only after it is published, at most once, and (unless
// self-payments are allowed) not by its creator.
//
// For counting, the relevant state is the number of unclaimed receipts per
// creator, since any two unclaimed receipts of the same creator offer the same
// future options. A receive that claims one of the c_Y receipts created by Y
// has c_Y distinct realizations, so it carries multiplicity c_Y.

function countHistories(leak) {
    const accts = active();
    const idx = new Map(accts.map((a, i) => [a, i]));
    let dist = new Map([[accts.map(() => 0).join(','), 1n]]);
    const counts = [];
    const bump = (m, s, c) => { const k = s.join(','); m.set(k, (m.get(k) || 0n) + c); };
    for (let j = 0; j < log.length; j++) {
        const next = new Map();
        for (const [key, c] of dist) {
            const state = key.split(',').map(Number);
            for (const X of actorsFor(j)) {
                if (maySend(j, leak)) {
                    const s = state.slice();
                    s[idx.get(X)]++;
                    bump(next, s, c);
                }
                if (mayRecv(j, leak)) {
                    accts.forEach((Y, yi) => {
                        if (state[yi] > 0 && (allowSelf || Y !== X)) {
                            const s = state.slice();
                            s[yi]--;
                            bump(next, s, c * BigInt(state[yi]));
                        }
                    });
                }
            }
        }
        dist = next;
        let total = 0n;
        for (const c of dist.values()) total += c;
        counts.push(total);
    }
    return counts;
}

// ---------------------------------------------------------------------------
// Explicit enumeration for drawing
// ---------------------------------------------------------------------------
//
// Nodes carry the set of unclaimed receipts (as a bitmask over transaction
// indices) and who created each receipt in that history.

function optionsFor(j, node, leak) {
    const opts = [];
    for (const X of actorsFor(j)) {
        if (maySend(j, leak)) {
            opts.push({ actor: X, role: 'S', ref: -1, mask: node.mask | (1 << j) });
        }
        if (mayRecv(j, leak)) {
            for (let i = 0; i < j; i++) {
                if (!(node.mask & (1 << i))) continue;
                if (!allowSelf && node.owners[i] === X) continue;
                opts.push({ actor: X, role: 'R', ref: i, mask: node.mask & ~(1 << i) });
            }
        }
    }
    return opts;
}

function nodeLabel(n) {
    return n.role === 'S' ? 'S' : `R${n.ref + 1}`;
}

// Returns {levels, drawn}: levels[j] are the nodes at depth j for the first
// `drawn` levels, i.e. the first FULL_LEVELS levels, stopping early only if a
// level would exceed MAX_DRAWN_LEAVES nodes.
function buildTree(leak, counts) {
    let drawn = 0;
    while (drawn < Math.min(log.length, FULL_LEVELS) && counts[drawn] <= BigInt(MAX_DRAWN_LEAVES)) drawn++;
    const levels = [];
    let prev = [{ mask: 0, owners: [], onTrue: true, path: [] }];
    for (let j = 0; j < drawn; j++) {
        const level = [];
        for (const p of prev) {
            for (const o of optionsFor(j, p, leak)) {
                const actual = log[j];
                const matches = o.actor === actual.acct && (
                    o.role === 'S' ? actual.op === 'send'
                        : (actual.op === 'recv' && actual.claims === o.ref));
                const owners = p.owners.slice();
                if (o.role === 'S') owners[j] = o.actor;
                const n = {
                    parent: p, depth: j, actor: o.actor, role: o.role, ref: o.ref, mask: o.mask,
                    owners, onTrue: p.onTrue && matches, children: [],
                };
                n.path = p.path.concat(nodeLabel(n));
                level.push(n);
            }
        }
        for (const n of level) if (n.parent.children) n.parent.children.push(n);
        levels.push(level);
        prev = level;
    }
    return { levels, drawn };
}

// ---------------------------------------------------------------------------
// Rendering: tree as SVG
// ---------------------------------------------------------------------------

const SVG_NS = 'http://www.w3.org/2000/svg';
const LEVEL_H = 46;
const LEFT_W = 44;
const TOP_PAD = 14;
const BOTTOM_PAD = 12;
const TRUE_COLOR = '#0000ee';
const EDGE_COLOR = '#999';

function el(name, attrs, text) {
    const e = document.createElementNS(SVG_NS, name);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
}

function labelText(x, y, n, font) {
    const t = el('text', {
        x, y, 'text-anchor': 'middle', 'dominant-baseline': 'middle', 'font-size': String(font),
    });
    t.appendChild(el('tspan', {}, n.role));
    if (n.role === 'R') {
        t.appendChild(el('tspan', { 'font-size': String(Math.round(font * 0.7)), dy: String(font * 0.3) }, String(n.ref + 1)));
    }
    return t;
}

function treeHeight() {
    return TOP_PAD + 10 + log.length * LEVEL_H + BOTTOM_PAD;
}

// The shared time axis for the row of trees.
function renderAxis() {
    const height = treeHeight();
    const axis = el('svg', { width: LEFT_W, height, viewBox: `0 0 ${LEFT_W} ${height}` });
    for (let j = 0; j < log.length; j++) {
        const y = TOP_PAD + 10 + j * LEVEL_H;
        const t = el('text', {
            x: LEFT_W - 14, y, 'text-anchor': 'end', 'dominant-baseline': 'middle',
            'font-size': '12', fill: 'gray',
        });
        t.appendChild(el('tspan', {}, 't'));
        t.appendChild(el('tspan', { 'font-size': '9', dy: '3' }, String(j + 1)));
        axis.appendChild(t);
    }
    axis.appendChild(el('line', {
        x1: LEFT_W - 8, y1: TOP_PAD, x2: LEFT_W - 8, y2: height - BOTTOM_PAD,
        stroke: '#ccc', 'stroke-width': 1,
    }));
    return axis;
}

// Draws the tree of histories under `leak` to fit a column `width` pixels wide:
// the whole drawn tree is always visible, so leaves shrink as the level widens,
// down to bare dots when there is no room for labels.
function renderTree(leak, counts, width) {
    const { levels, drawn } = buildTree(leak, counts);
    const baseLeafW = 34;
    const remaining = log.length - drawn;
    const leaves = levels[drawn - 1];
    const leafW = Math.min(baseLeafW, (width - 16) / leaves.length);

    // Layout: leaves of the last drawn level are spaced evenly and centred in the
    // column; parents sit at the midpoint of their children.
    const x0 = (width - leaves.length * leafW) / 2 + leafW / 2;
    leaves.forEach((n, i) => { n.x = x0 + i * leafW; });
    for (let j = drawn - 2; j >= 0; j--) {
        for (const n of levels[j]) {
            const xs = n.children.map(c => c.x);
            n.x = (Math.min(...xs) + Math.max(...xs)) / 2;
        }
    }
    levels.forEach((level, j) => level.forEach(n => { n.y = TOP_PAD + 10 + j * LEVEL_H; }));

    // Each level is labelled if its nodes are far enough apart, else drawn as dots;
    // labels shrink with the spacing. `half` is the vertical clearance of a node.
    const style = levels.map(level => {
        let gap = baseLeafW;
        for (let i = 1; i < level.length; i++) gap = Math.min(gap, level[i].x - level[i - 1].x);
        const dots = gap < 13;
        const font = Math.max(8, Math.round(13 * gap / baseLeafW));
        return { dots, font, gap, half: dots ? 3 : font * 0.7 };
    });
    const st = n => style[n.depth];

    const height = treeHeight();
    const svg = el('svg', { width, height, viewBox: `0 0 ${width} ${height}` });

    // Edges first so labels sit on top.
    for (let j = 1; j < drawn; j++) {
        for (const n of levels[j]) {
            const p = n.parent;
            svg.appendChild(el('line', {
                x1: p.x, y1: p.y + st(p).half, x2: n.x, y2: n.y - st(n).half,
                stroke: n.onTrue ? TRUE_COLOR : EDGE_COLOR,
                'stroke-width': n.onTrue ? 2 : st(n).dots ? 0.5 : 1,
            }));
        }
    }
    // Continuation stubs below leaves when levels are collapsed.
    if (remaining > 0) {
        for (const n of leaves) {
            if (!st(n).dots || n.onTrue) svg.appendChild(el('line', {
                x1: n.x, y1: n.y + st(n).half, x2: n.x, y2: n.y + 24,
                stroke: n.onTrue ? TRUE_COLOR : EDGE_COLOR, 'stroke-dasharray': '2 3',
            }));
        }
        for (let k = 0; k < remaining; k++) {
            const j = drawn + k;
            const y = TOP_PAD + 10 + j * LEVEL_H;
            svg.appendChild(el('text', {
                x: width / 2, y, 'text-anchor': 'middle', 'dominant-baseline': 'middle',
                'font-size': '12', fill: 'gray',
            }, `${fmt(counts[j])} consistent ${counts[j] === 1n ? 'history' : 'histories'}`));
        }
    }
    // Nodes.
    for (const level of levels) {
        for (const n of level) {
            const g = el('g', {});
            const { dots, font, gap, half } = st(n);
            if (dots) {
                g.appendChild(el('circle', {
                    cx: n.x, cy: n.y, r: n.onTrue ? 3 : 2, fill: n.onTrue ? TRUE_COLOR : '#555',
                }));
            } else {
                g.appendChild(el('rect', {
                    x: n.x - gap / 2 + 1, y: n.y - half, width: gap - 2, height: 2 * half, fill: 'white',
                }));
                const label = labelText(n.x, n.y, n, font);
                label.setAttribute('fill', n.onTrue ? TRUE_COLOR : 'black');
                if (n.onTrue) label.setAttribute('font-weight', 'bold');
                g.appendChild(label);
            }
            g.appendChild(el('title', {}, n.path.join(', ')));
            svg.appendChild(g);
        }
    }
    return svg;
}

// The two trees side by side on one time axis, each scaled to fit its column.
// L_unl is usually a path, so it gets the narrower column.
const TREE_HEAD = { unl: '<code>L_unl</code>: operation revealed', ind: '<code>L_ind</code>: operation hidden' };
function renderTrees(counts) {
    const row = document.getElementById('trees');
    row.innerHTML = '';
    if (log.length === 0) {
        const d = document.createElement('div');
        d.className = 'empty';
        d.textContent = 'Add a transaction to the log.';
        row.appendChild(d);
        return;
    }
    const axisCol = document.createElement('div');
    axisCol.className = 'tree-col axis';
    axisCol.appendChild(document.createElement('div')).className = 'tree-head';
    axisCol.appendChild(renderAxis());
    row.appendChild(axisCol);
    // Lay the columns out first, then draw each tree to its measured width.
    const cols = LEAKS.map(leak => {
        const col = document.createElement('div');
        col.className = 'tree-col' + (leak === 'unl' ? ' narrow' : '');
        const head = document.createElement('div');
        head.className = 'tree-head';
        head.innerHTML = TREE_HEAD[leak];
        col.appendChild(head);
        row.appendChild(col);
        return col;
    });
    LEAKS.forEach((leak, i) => cols[i].appendChild(renderTree(leak, counts[leak], cols[i].clientWidth)));
}

// ---------------------------------------------------------------------------
// Rendering: log, counts, controls
// ---------------------------------------------------------------------------

function fmt(n) {
    return n.toLocaleString('en-US');
}

function describe(t) {
    return t.op === 'send'
        ? `${t.acct} sends to ${t.to}`
        : `${t.acct} receives receipt from t${t.claims + 1}`;
}

// One row per transaction: what happened, then for each observer what it sees
// and how many histories are consistent with the transcript so far.
function renderLog(counts) {
    const tbody = document.querySelector('#log tbody');
    tbody.innerHTML = '';
    const cell = (tr, text, cls) => {
        const td = document.createElement('td');
        td.textContent = text;
        if (cls) td.className = cls;
        tr.appendChild(td);
        return td;
    };
    log.forEach((t, i) => {
        const tr = document.createElement('tr');
        cell(tr, String(i + 1));
        cell(tr, describe(t));
        cell(tr, `(${t.op}, ${t.acct})`);
        cell(tr, fmt(counts.unl[i]), 'num');
        cell(tr, t.acct);
        cell(tr, fmt(counts.ind[i]), 'num');
        tbody.appendChild(tr);
    });
    if (log.length === 0) {
        const tr = document.createElement('tr');
        const td = cell(tr, 'empty', 'muted');
        td.colSpan = 6;
        tbody.appendChild(tr);
    }
}

function renderSummary(counts) {
    const summary = document.getElementById('summary');
    if (log.length === 0) {
        summary.textContent = '';
        return;
    }
    const last = leak => counts[leak][log.length - 1];
    const u = last('unl'), i = last('ind');
    summary.innerHTML =
        `The ${log.length}-transaction transcript is consistent with <b>${fmt(u)}</b> ` +
        `${u === 1n ? 'history' : 'histories'} under <code>L_unl</code> and ` +
        `<b>${fmt(i)}</b> under <code>L_ind</code>` +
        (u > 1n ? ` (${fmt(i / u)}&times; more)` : '') + '.';
}

function renderControls() {
    const acctSel = document.getElementById('acct');
    const opSel = document.getElementById('op');
    const targetSel = document.getElementById('target');
    const accts = active();
    // Rebuild the account menu over the active accounts, keeping the selection.
    const prev = acctSel.value;
    acctSel.innerHTML = '';
    accts.forEach(a => {
        const o = document.createElement('option');
        o.value = a;
        o.textContent = a;
        acctSel.appendChild(o);
    });
    acctSel.value = accts.includes(prev) ? prev : accts[0];
    const acct = acctSel.value;
    targetSel.innerHTML = '';
    if (opSel.value === 'send') {
        const others = accts.filter(a => a !== acct);
        const targets = allowSelf ? others.concat([acct]) : others;
        targets.forEach(a => {
            const o = document.createElement('option');
            o.value = a;
            o.textContent = a;
            targetSel.appendChild(o);
        });
    } else {
        const cl = claimable(acct);
        if (cl.length === 0) {
            const o = document.createElement('option');
            o.value = '';
            o.textContent = 'nothing to claim';
            targetSel.appendChild(o);
        } else {
            cl.forEach(i => {
                const o = document.createElement('option');
                o.value = String(i);
                o.textContent = `receipt t${i + 1} from ${log[i].acct}`;
                targetSel.appendChild(o);
            });
        }
    }
    const full = log.length >= MAX_TX;
    document.getElementById('add').disabled = full || targetSel.value === '';
    document.getElementById('undo').disabled = log.length === 0;
    document.getElementById('clear').disabled = log.length === 0;
    document.getElementById('status').textContent = full
        ? `log is at its maximum length of ${MAX_TX} transactions`
        : `${log.length} / ${MAX_TX} transactions`;
}

function renderAll() {
    const counts = {};
    for (const leak of LEAKS) counts[leak] = countHistories(leak);
    renderLog(counts);
    renderSummary(counts);
    renderTrees(counts);
    renderControls();
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function addTx() {
    if (log.length >= MAX_TX) return;
    const acct = document.getElementById('acct').value;
    const op = document.getElementById('op').value;
    const target = document.getElementById('target').value;
    if (target === '') return;
    if (op === 'send') log.push({ acct, op, to: target });
    else log.push({ acct, op, claims: Number(target) });
    renderAll();
}

function loadExample() {
    // The same three payments as the paper: (A->B), (B->A), (C->D). Sends
    // land first so several receipts are outstanding when the receives
    // begin; L_unl then has a real tree, not a single path.
    log = [
        { acct: 'A', op: 'send', to: 'B' },
        { acct: 'B', op: 'send', to: 'A' },
        { acct: 'C', op: 'send', to: 'D' },
        { acct: 'B', op: 'recv', claims: 0 },
        { acct: 'A', op: 'recv', claims: 1 },
        { acct: 'D', op: 'recv', claims: 2 },
    ];
    if (numAccts < 4) setNumAccts(4);
    renderAll();
}

function setNumAccts(k) {
    numAccts = Math.min(ACCOUNTS.length, Math.max(2, k || 4));
    document.getElementById('num-accts').value = String(numAccts);
    // Drop transactions involving accounts that are no longer active, and
    // everything after them, by truncating at the first offender.
    const accts = new Set(active());
    const bad = log.findIndex(t => !accts.has(t.acct) || (t.op === 'send' && !accts.has(t.to)));
    if (bad >= 0) log = log.slice(0, bad);
}

function randomLog() {
    const n = Math.min(MAX_TX, Math.max(1, Number(document.getElementById('rand-n').value) || 6));
    const accts = active();
    const k = accts.length;
    log = [];
    for (let j = 0; j < n; j++) {
        const acct = accts[Math.floor(Math.random() * k)];
        const cl = claimable(acct);
        if (cl.length > 0 && Math.random() < 0.55) {
            log.push({ acct, op: 'recv', claims: cl[Math.floor(Math.random() * cl.length)] });
        } else {
            const targets = accts.filter(a => allowSelf || a !== acct);
            log.push({ acct, op: 'send', to: targets[Math.floor(Math.random() * targets.length)] });
        }
    }
    renderAll();
}

function init() {
    document.getElementById('acct').addEventListener('change', renderControls);
    const kInput = document.getElementById('num-accts');
    kInput.value = String(numAccts);
    kInput.addEventListener('change', () => {
        setNumAccts(Number(kInput.value));
        renderAll();
    });
    document.getElementById('op').addEventListener('change', renderControls);
    document.getElementById('add').addEventListener('click', addTx);
    document.getElementById('undo').addEventListener('click', () => { log.pop(); renderAll(); });
    document.getElementById('clear').addEventListener('click', () => { log = []; renderAll(); });
    document.getElementById('random').addEventListener('click', randomLog);
    const selfBox = document.getElementById('allow-self');
    selfBox.checked = allowSelf;
    selfBox.addEventListener('change', () => {
        allowSelf = selfBox.checked;
        if (!allowSelf) {
            // Drop any self-payments that are no longer expressible, and the
            // receives that depended on them, by truncating at the first offender.
            const bad = log.findIndex(t => t.op === 'send' && t.to === t.acct);
            if (bad >= 0) log = log.slice(0, bad);
        }
        renderAll();
    });
    loadExample();
}

document.addEventListener('DOMContentLoaded', init);

// Live counter in the introduction: what a ledger at 1M TPS would have accumulated since the
// page was opened, assuming a 32-byte nullifier per transaction.
(function () {
    const TPS = 1e6, BYTES_PER_TX = 32;
    function fmtBytes(b) {
        if (b < 1e9) return (b / 1e6).toFixed(0) + ' MB';
        if (b < 1e12) return (b / 1e9).toFixed(2) + ' GB';
        return (b / 1e12).toFixed(3) + ' TB';
    }
    function start() {
        const bytesEl = document.getElementById('live-bytes');
        const txEl = document.getElementById('live-txs');
        if (!bytesEl || !txEl) return;
        const t0 = performance.now();
        function tick() {
            const s = (performance.now() - t0) / 1000;
            const txs = Math.floor(s * TPS);
            bytesEl.textContent = fmtBytes(txs * BYTES_PER_TX);
            txEl.textContent = txs.toLocaleString('en-US');
        }
        tick();
        setInterval(tick, 100);
    }
    document.addEventListener('DOMContentLoaded', start);
})();
