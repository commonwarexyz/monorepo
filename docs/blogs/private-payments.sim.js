'use strict';

// A running simulation of a small payment system, stepped through eight designs
// from a traditional bank to our construction. The same stream of payments
// drives every panel: the network (who hands what to whom), the balances, the
// public ledger (what is published), and storage (what validators and users
// must keep, drawn as the actual data structures). Changing the step changes
// the rules, not the payments, so the panels compare directly.
//
// The SVG viewBox is 800 units wide, the same as the page column, so text sizes
// here are the sizes the reader sees.

(function () {
    const MOUNT_ID = 'sim';
    const SOURCE_ID = 'sim-source';
    const SVG_NS = 'http://www.w3.org/2000/svg';
    const W = 800, H = 620;

    const ACCOUNTS = ['A', 'B', 'C', 'D'];
    const RED = '#d9251c';
    const BLUE = '#1f1fd1';
    const GRAY = '#c8c8c8';

    // Timing (simulation milliseconds).
    const PAY_EVERY = 1500;    // a new payment starts about this often
    const TOKEN_MS = 520;      // travel time of a token to the ledger
    const HANDOFF_AT = 620;    // sender hands the coin/receipt to the receiver
    const HANDOFF_MS = 720;
    const RECV_MIN = 3000;     // receivers claim after a random delay
    const RECV_MAX = 12000;
    const EPOCH_MS = 15000;    // epoch length, for the last step

    const START_BALANCE = 1000;
    const AMOUNT_MIN = 10, AMOUNT_MAX = 200;

    const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
    const lerp = (a, b, t) => a + (b - a) * t;
    const ease = t => 1 - Math.pow(1 - t, 3);

    // Deterministic PRNG so every visit sees the same payments.
    function mulberry32(seed) {
        return function () {
            seed |= 0; seed = seed + 0x6D2B79F5 | 0;
            let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
            t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
            return ((t ^ t >>> 14) >>> 0) / 4294967296;
        };
    }

    // -----------------------------------------------------------------------
    // Layout: top row = network | balances | ledger; bottom row = storage.
    // -----------------------------------------------------------------------

    const HEAD_Y = 26;
    const NET = { cx: 112, cy: 172, off: 60, box: 32 };
    const NODE_POS = {
        A: { x: NET.cx - NET.off, y: NET.cy - NET.off },
        B: { x: NET.cx + NET.off, y: NET.cy - NET.off },
        C: { x: NET.cx + NET.off, y: NET.cy + NET.off },
        D: { x: NET.cx - NET.off, y: NET.cy + NET.off },
    };
    const BAL = { x: 236, w: 160, base: 262, barW: 26, maxH: 140 };
    const LEDGER = { x: 416, w: 372, top: 44, rowH: 28, rows: 9 };
    const ROW_SPLIT = 306;                      // horizontal divider between the rows
    const STORE = { x: 16, y: ROW_SPLIT + 26, right: 784 };
    const V_DIVIDERS = [226, 404];

    // -----------------------------------------------------------------------
    // Rules per step
    // -----------------------------------------------------------------------
    //  0 traditional bank      4 hide the operation
    //  1 ecash                 5 receipts off validators
    //  2 decentralize          6 nullifiers off validators
    //  3 commitments + proofs  7 users prune by epoch

    const DIRECT = step => step === 0;   // one instruction through the bank, no handoff
    const EPOCHS = step => step >= 7;
    const BALANCES_PUBLIC = step => step <= 2;

    function recordText(step, ev) {
        const p = ev.pay, X = ev.actor;
        if (ev.type === 'send') {
            switch (step) {
                case 0: return `${X} pays ${p.to} ${p.v}`;
                case 1: case 2: return `${X} sends ${p.v}`;
                case 3: return `${X}: new commitment, receipt ${p.rho}, proof`;
                case 4: return `${X}: commitment, receipt, nullifier, proof`;
                case 5: return `${X}: commitment, receipt, nullifier, root, proof`;
                default: return `${X}: commitment, receipt, root, proof`;
            }
        }
        switch (step) {
            case 1: case 2: return `${X} receives ${p.v}, nullifier ${p.nf}`;
            case 3: return `${X}: new commitment, nullifier ${p.nf}, proof`;
            case 4: return `${X}: commitment, receipt, nullifier, proof`;
            case 5: return `${X}: commitment, receipt, nullifier, root, proof`;
            default: return `${X}: commitment, receipt, root, proof`;
        }
    }

    // The three boxes under the stage. `hl` marks what changed at this step.
    const BOXES = [
        {
            store: { v: 'one balance per account', n: 'fixed; nothing per payment' },
            work: { v: 'the bank applies every payment' },
            learn: { v: 'everything: who paid whom, how much, every balance', n: 'the bank is inside every payment', hl: true },
        },
        {
            store: { v: 'balances, plus every nullifier', n: '0.5 PB a year at 1M TPS, never pruned', hl: true },
            work: { v: 'the bank signs every coin, checks every nullifier' },
            learn: { v: 'who sent, who received, amounts', n: 'not who paid whom: the blind signature breaks the link', hl: true },
        },
        {
            store: { v: 'balances, plus every nullifier' },
            work: { v: 'the committee signs every coin, checks every nullifier', n: 'a threshold signature per coin', hl: true },
            learn: { v: 'who sent, who received, amounts', n: 'now every validator sees every balance', hl: true },
        },
        {
            store: { v: 'commitments, plus every nullifier', n: 'the same list as before, now the only thing per payment' },
            work: { v: 'verify a proof per transaction, sign every receipt', hl: true },
            learn: { v: 'who sent, who received', n: 'amounts and balances hidden', hl: true },
        },
        {
            store: { v: 'commitments, plus a nullifier per send/receive', n: 'doubled: 1 PB a year; sends publish a dummy', hl: true },
            work: { v: 'verify a proof per transaction, sign every receipt' },
            learn: { v: 'who acted', n: 'send and receive are indistinguishable', hl: true },
        },
        {
            store: { v: 'commitments, a nullifier per send/receive, the frontier', n: 'receipts live with the two parties' },
            work: { v: 'verify a proof per transaction, sign one root per block', n: 'no per-receipt signature', hl: true },
            learn: { v: 'who acted' },
        },
        {
            store: { v: 'validators: commitments and frontier. users: every nullifier ever received', n: 'validators: 32 B per account + log n', hl: true },
            work: { v: 'verify proofs, in batches', n: 'ZK-Pari: a million a second on 18 cores', hl: true },
            learn: { v: 'who acted' },
        },
        {
            store: { v: 'validators: commitments and frontier. users: recent nullifiers + one root per epoch', n: 'nothing grows with lifetime activity', hl: true },
            work: { v: 'verify proofs, in batches' },
            learn: { v: 'who acted' },
        },
    ];

    // -----------------------------------------------------------------------
    // Simulation
    // -----------------------------------------------------------------------

    const rand = mulberry32(20260903);
    const zero = () => Object.fromEntries(ACCOUNTS.map(a => [a, 0]));
    const state = {
        time: 0,
        nextPay: 900,
        payments: [],      // {k, from, to, v, tSend, tRecv, epoch, rho, nf}
        events: [],        // {t, type, actor, pay, balance}
        balances: Object.fromEntries(ACCOUNTS.map(a => [a, START_BALANCE])),
        counts: {
            sends: 0, recvs: 0, unclaimed: zero(), recvBy: zero(),
            recvByClaimEpoch: Object.fromEntries(ACCOUNTS.map(a => [a, {}])),   // by the epoch of the claim
        },
        // Nullifier values, in insertion order, for each set that some design keeps.
        nf: {
            recv: [],                                                        // global set, one per receive
            tx: [],                                                          // global set, one per transaction (dummies for sends)
            by: Object.fromEntries(ACCOUNTS.map(a => [a, []])),              // per user, lifetime
            byEpoch: Object.fromEntries(ACCOUNTS.map(a => [a, {}])),         // per user, per claim epoch
        },
        com: {},           // current account commitment per account (random-looking)
        k: 0,
    };
    const epochOf = t => Math.floor(t / EPOCH_MS);
    const hex4 = () => Math.floor(rand() * 0xffff).toString(16).padStart(4, '0');
    for (const a of ACCOUNTS) state.com[a] = hex4();

    function schedulePayments() {
        while (state.nextPay <= state.time) {
            const from = ACCOUNTS[Math.floor(rand() * ACCOUNTS.length)];
            let to = ACCOUNTS[Math.floor(rand() * ACCOUNTS.length)];
            if (to === from) to = ACCOUNTS[(ACCOUNTS.indexOf(from) + 1 + Math.floor(rand() * 3)) % ACCOUNTS.length];
            const cap = Math.max(AMOUNT_MIN, Math.min(AMOUNT_MAX, Math.floor(state.balances[from] / 3)));
            const v = AMOUNT_MIN + Math.floor(rand() * (cap - AMOUNT_MIN + 1));
            const t0 = state.nextPay;
            if (state.balances[from] >= v) {
                state.k += 1;
                state.payments.push({
                    k: state.k, from, to, v, tSend: t0, epoch: epochOf(t0),
                    rho: hex4(), nf: hex4(), dnf: hex4(),
                    tRecv: t0 + RECV_MIN + rand() * (RECV_MAX - RECV_MIN), sent: false, recvd: false,
                });
            }
            state.nextPay += PAY_EVERY * (0.6 + 0.8 * rand());
        }
    }

    function fireEvents() {
        const c = state.counts;
        for (const p of state.payments) {
            if (!p.sent && state.time >= p.tSend + TOKEN_MS) {
                p.sent = true;
                state.balances[p.from] -= p.v;
                state.com[p.from] = hex4();
                state.nf.tx.push(p.dnf);
                c.sends += 1;
                c.unclaimed[p.to] += 1;
                state.events.push({ t: state.time, type: 'send', actor: p.from, pay: p, balance: state.balances[p.from] });
            }
            if (!p.recvd && state.time >= p.tRecv + TOKEN_MS) {
                p.recvd = true;
                state.balances[p.to] += p.v;
                c.recvs += 1;
                c.unclaimed[p.to] -= 1;
                c.recvBy[p.to] += 1;
                const ce = epochOf(state.time);
                c.recvByClaimEpoch[p.to][ce] = (c.recvByClaimEpoch[p.to][ce] || 0) + 1;
                state.nf.recv.push(p.nf);
                state.nf.tx.push(p.nf);
                state.nf.by[p.to].push(p.nf);
                (state.nf.byEpoch[p.to][ce] = state.nf.byEpoch[p.to][ce] || []).push(p.nf);
                state.com[p.to] = hex4();
                state.events.push({ t: state.time, type: 'recv', actor: p.to, pay: p, balance: state.balances[p.to] });
            }
        }
        state.payments = state.payments.filter(p => state.time < p.tRecv + TOKEN_MS + 200);
        if (state.events.length > 60) state.events.splice(0, state.events.length - 60);
    }

    // -----------------------------------------------------------------------
    // SVG helpers
    // -----------------------------------------------------------------------

    function el(name, attrs, parent) {
        const e = document.createElementNS(SVG_NS, name);
        for (const k in attrs) e.setAttribute(k, attrs[k]);
        if (parent) parent.appendChild(e);
        return e;
    }
    function text(parent, x, y, str, attrs) {
        const t = el('text', { x, y, ...attrs }, parent);
        t.textContent = str;
        return t;
    }
    function h(tag, cls, parent) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (parent) parent.appendChild(e);
        return e;
    }

    // -----------------------------------------------------------------------
    // Init
    // -----------------------------------------------------------------------

    // The step text is written in the page as a flat run of <h3> headings, each
    // followed by its paragraphs. Every heading starts a step; the nodes up to
    // the next heading are that step's body.
    function readSource() {
        const src = document.getElementById(SOURCE_ID);
        if (!src) return [];
        const steps = [];
        for (const node of src.children) {
            if (node.tagName === 'H3') steps.push({ title: node.textContent.replace(/\s+/g, ' ').trim(), nodes: [] });
            else if (steps.length) steps[steps.length - 1].nodes.push(node);
        }
        return steps;
    }

    function init() {
        const mount = document.getElementById(MOUNT_ID);
        if (!mount) return;
        const steps = readSource();
        const N = steps.length;
        if (N === 0) return;
        let step = 0;

        // Stepper.
        const bar = h('div', 'sim-stepper', mount);
        const prev = h('button', '', bar); prev.textContent = '\u2039 prev';
        const title = h('div', 'sim-title', bar);
        const dots = h('div', 'sim-dots', bar);
        const dotEls = steps.map((s, i) => {
            const d = h('span', 'sim-dot', dots);
            d.title = s.title;
            d.addEventListener('click', () => setStep(i));
            return d;
        });
        const next = h('button', '', bar); next.textContent = 'next \u203A';
        prev.addEventListener('click', () => setStep(step - 1));
        next.addEventListener('click', () => setStep(step + 1));

        // Stage.
        const stage = h('div', 'sim-stage', mount);
        const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'sim-svg' }, stage);

        // Panel headers and dividers.
        text(svg, NET.cx, HEAD_Y, 'network', { class: 'sim-h' });
        const ledgerTitle = text(svg, LEDGER.x, HEAD_Y, 'public ledger', { class: 'sim-h left' });
        const epochLabel = text(svg, LEDGER.x + LEDGER.w, HEAD_Y, '', { class: 'sim-h right sim-muted' });
        for (const x of V_DIVIDERS) el('line', { x1: x, y1: 12, x2: x, y2: ROW_SPLIT - 8, class: 'sim-divider' }, svg);
        el('line', { x1: 8, y1: ROW_SPLIT, x2: W - 8, y2: ROW_SPLIT, class: 'sim-divider' }, svg);

        // Network: spokes, ledger node, account nodes.
        const netG = el('g', {}, svg);
        for (const a of ACCOUNTS) {
            el('line', { x1: NODE_POS[a].x, y1: NODE_POS[a].y, x2: NET.cx, y2: NET.cy, class: 'sim-spoke' }, netG);
        }
        const handoffG = el('g', {}, netG);
        const ledgerNode = el('g', {}, netG);
        const bankRect = el('rect', { x: NET.cx - 32, y: NET.cy - 18, width: 64, height: 36, class: 'sim-box' }, ledgerNode);
        const bankLabel = text(ledgerNode, NET.cx, NET.cy + 5, 'bank', { class: 'sim-node-label' });
        const committee = el('g', {}, ledgerNode);
        for (let i = 0; i < 7; i++) {
            const ang = -Math.PI / 2 + i * 2 * Math.PI / 7;
            el('rect', { x: NET.cx + 22 * Math.cos(ang) - 5, y: NET.cy + 22 * Math.sin(ang) - 5, width: 10, height: 10, class: 'sim-box' }, committee);
        }
        for (const a of ACCOUNTS) {
            const p = NODE_POS[a], b = NET.box / 2;
            el('rect', { x: p.x - b, y: p.y - b, width: NET.box, height: NET.box, class: 'sim-box' }, netG);
            text(netG, p.x, p.y + 6, a, { class: 'sim-node-label bold' });
        }
        const tokenG = el('g', {}, netG);

        // Balances chart: in the account, plus in flight (sent, not yet claimed). Solid while the
        // ledger sees balances; dashed once it holds only commitments.
        const balG = el('g', {}, svg);
        const balTitle = text(balG, BAL.x, HEAD_Y, 'balances', { class: 'sim-h left' });
        const balLegend = text(balG, BAL.x, HEAD_Y + 18, '', { class: 'sim-seg-label' });   // two stacked lines
        el('line', { x1: BAL.x, x2: BAL.x + BAL.w, y1: BAL.base + 0.5, y2: BAL.base + 0.5, class: 'sim-baseline' }, balG);
        const balEls = ACCOUNTS.map((a, i) => {
            const cx = BAL.x + BAL.w * (i + 0.5) / ACCOUNTS.length;
            const acct = el('rect', { x: cx - BAL.barW / 2, width: BAL.barW, y: BAL.base, height: 0, class: 'sim-bal' }, balG);
            const flight = el('rect', { x: cx - BAL.barW / 2, width: BAL.barW, y: BAL.base, height: 0, class: 'sim-bal flight' }, balG);
            const val = text(balG, cx, BAL.base - 6, '', { class: 'sim-seg-label center dark' });
            text(balG, cx, BAL.base + 18, a, { class: 'sim-node-label' });
            return { acct, flight, val, shownA: 0, shownF: 0 };
        });

        // Ledger rows.
        const rowEls = [];
        for (let i = 0; i < LEDGER.rows; i++) {
            const g = el('g', {}, svg);
            const rec = text(g, LEDGER.x, 0, '', { class: 'sim-row' });
            const rule = el('line', { x1: LEDGER.x, x2: LEDGER.x + LEDGER.w, y1: 0, y2: 0, class: 'sim-rule' }, g);
            rowEls.push({ g, rec, rule });
        }

        // Storage: retained groups, each rebuilt only when its data key changes.
        const storeG = el('g', {}, svg);
        const cache = () => ({ g: el('g', {}, storeG), key: null, count: 0 });
        const S = {
            headings: cache(), array: cache(), grid: cache(), mmr: cache(), tree: cache(),
            users: ACCOUNTS.map(() => ({ mmr: cache(), tree: cache() })),
        };

        // Help: a [?] in the corner of each panel explains what is drawn there. The text is
        // a function of the step and the live state, refreshed while the tip is open.
        const helps = [];
        function addHelp(x, y, textFn) {
            const right = `${(W - x) / W * 100}%`, top = `${y / H * 100}%`;
            const btn = h('button', 'sim-help', stage);
            btn.type = 'button'; btn.textContent = '?'; btn.setAttribute('aria-label', 'What is drawn here?');
            btn.style.right = right; btn.style.top = top;
            const tip = h('div', 'sim-tip', stage);
            // Tips under markers in the left half open to the right so they are not squeezed.
            if (x < W / 2) tip.style.left = '8px'; else tip.style.right = right;
            tip.style.top = `calc(${top} + 22px)`;
            let pinned = false, hover = false;
            const update = () => {
                const on = pinned || hover;
                tip.classList.toggle('show', on);
                btn.classList.toggle('open', on);
                if (on) { const t = textFn(); if (tip.textContent !== t) tip.textContent = t; }
            };
            btn.addEventListener('mouseenter', () => { hover = true; update(); });
            btn.addEventListener('mouseleave', () => { hover = false; update(); });
            btn.addEventListener('focus', () => { hover = true; update(); });
            btn.addEventListener('blur', () => { hover = false; update(); });
            btn.addEventListener('click', () => { pinned = !pinned; update(); });
            document.addEventListener('click', ev => { if (pinned && ev.target !== btn) { pinned = false; update(); } });
            helps.push(update);
        }
        addHelp(V_DIVIDERS[0] - 10, 10, () => {
            if (step === 0) return 'A payment instruction travels from the sender to the bank (solid dot); the bank applies it and forwards the credit to the receiver.';
            const item = step === 1 ? 'coin' : 'receipt', to = step === 1 ? 'bank' : 'ledger';
            return `Solid dots are messages to the ${to} (send/receive). The hollow dot on the dashed arc is the ${item} opening from sender to receiver via an external channel.`;
        });
        addHelp(W - 8, ROW_SPLIT + 8, () => {
            switch (step) {
                case 0: return 'The bank keeps one balance per account and nothing per payment.';
                case 1: case 2: return `Each square is one nullifier the ${step === 1 ? 'bank' : 'committee'} has seen. The set is append-only: a coin issued long ago is still valid, so no entry can ever be removed.`;
                case 3: return 'Balances are replaced by commitments (the hex tags), each rewritten when its account acts. The nullifier set is unchanged: one entry per receive.';
                case 4: return 'One nullifier per send or receive now, real for receives and a dummy for sends, so the set grows twice as fast.';
                case 5: return `Left: the receipt MMR. Receipts accumulate in perfect binary trees and validators only need to store the peaks (dots) to extend the tree. Right: the nullifier set as an indexed Merkle tree.`;
                case 6: return `Validators only store the MMR frontier and delegate nullifier storage to users. Each user maintains an indexed merkle tree of nullifiers of every receipt it has claimed.`;
                default: return `Users periodically prune nullifiers by adding the current epochs's nullifier tree root to an MMR (left, one leaf per epoch) and only maintain a tree of nullifiers claimed in the current epoch (right).`;
            }
        });

        // Boxes and copy.
        const boxes = h('div', 'sim-counters', mount);
        const boxEls = ['storage', 'validator work', 'validators learn'].map(k => {
            const b = h('div', 'sim-counter', boxes);
            const key = h('span', 'k', b); key.textContent = k;
            const v = h('div', 'v', b);
            const n = h('div', 'n', b);
            return { b, v, n };
        });
        const copy = h('div', 'sim-copy', mount);

        function setStep(i) {
            step = clamp(i, 0, N - 1);
            title.textContent = `${step}. ${steps[step].title}`;
            dotEls.forEach((d, j) => d.classList.toggle('on', j === step));
            prev.disabled = step === 0;
            next.disabled = step === N - 1;
            copy.replaceChildren(...steps[step].nodes.map(n => n.cloneNode(true)));
            const spec = BOXES[Math.min(step, BOXES.length - 1)];
            [spec.store, spec.work, spec.learn].forEach((s, j) => {
                boxEls[j].v.textContent = s.v;
                boxEls[j].n.textContent = s.n || '';
                boxEls[j].b.classList.toggle('hl', !!s.hl);
            });
            bankRect.style.opacity = step <= 1 ? 1 : 0;
            bankLabel.style.opacity = step <= 1 ? 1 : 0;
            committee.style.opacity = step <= 1 ? 0 : 1;
            ledgerTitle.textContent = step <= 1 ? "bank's internal ledger" : 'public ledger';
            if (/^#step-/.test(location.hash) || i !== 0) history.replaceState(null, '', `#step-${step}`);
            helps.forEach(u => u());
        }

        // -------------------------------------------------------------------
        // Network
        // -------------------------------------------------------------------

        function token(g, x, y, hollow) {
            el('circle', { cx: x, cy: y, r: 6, class: hollow ? 'sim-token hollow' : 'sim-token' }, g);
        }

        function drawTokens() {
            tokenG.innerHTML = '';
            handoffG.innerHTML = '';
            for (const p of state.payments) {
                const from = NODE_POS[p.from], to = NODE_POS[p.to];
                // Sender to ledger.
                let t = (state.time - p.tSend) / TOKEN_MS;
                if (t >= 0 && t <= 1) {
                    const e = ease(t);
                    token(tokenG, lerp(from.x, NET.cx, e), lerp(from.y, NET.cy, e));
                }
                if (DIRECT(step)) {
                    // The bank forwards the payment to the receiver.
                    t = (state.time - p.tSend - TOKEN_MS) / TOKEN_MS;
                    if (t >= 0 && t <= 1) {
                        const e = ease(t);
                        token(tokenG, lerp(NET.cx, to.x, e), lerp(NET.cy, to.y, e));
                    }
                    continue;
                }
                // Off-ledger handoff, sender to receiver, bowed away from the ledger node.
                t = (state.time - p.tSend - HANDOFF_AT) / HANDOFF_MS;
                if (t >= 0 && t <= 1) {
                    const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
                    let cx, cy;
                    if (from.x === to.x || from.y === to.y) {
                        const dx = mx - NET.cx, dy = my - NET.cy, d = Math.hypot(dx, dy) || 1;
                        cx = mx + dx / d * 44; cy = my + dy / d * 44;
                    } else {
                        const dx = to.x - from.x, dy = to.y - from.y, d = Math.hypot(dx, dy) || 1;
                        cx = mx - dy / d * 66; cy = my + dx / d * 66;
                    }
                    el('path', { d: `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`, class: 'sim-handoff' }, handoffG);
                    const e = ease(t), a = (1 - e) * (1 - e), b = 2 * (1 - e) * e, cc = e * e;
                    token(tokenG, a * from.x + b * cx + cc * to.x, a * from.y + b * cy + cc * to.y, true);
                }
                // Receiver to ledger.
                t = (state.time - p.tRecv) / TOKEN_MS;
                if (t >= 0 && t <= 1) {
                    const e = ease(t);
                    token(tokenG, lerp(to.x, NET.cx, e), lerp(to.y, NET.cy, e));
                }
            }
        }

        // -------------------------------------------------------------------
        // Ledger and balances
        // -------------------------------------------------------------------

        function drawLedger() {
            const all = DIRECT(step) ? state.events.filter(e => e.type === 'send') : state.events;
            const evs = all.slice(-LEDGER.rows);
            const offset = LEDGER.rows - evs.length;
            rowEls.forEach((r, i) => {
                const ev = evs[i - offset];
                if (!ev) { r.g.style.opacity = 0; return; }
                const y = LEDGER.top + i * LEDGER.rowH;
                const age = state.time - ev.t;
                const isLast = i === LEDGER.rows - 1 || !evs[i - offset + 1];
                r.g.style.opacity = isLast ? clamp(age / 250, 0, 1) : 1;
                r.rec.setAttribute('y', y + 14);
                r.rule.setAttribute('y1', y + LEDGER.rowH - 7);
                r.rule.setAttribute('y2', y + LEDGER.rowH - 7);
                r.rec.textContent = recordText(step, ev);
            });
            epochLabel.textContent = EPOCHS(step) ? `epoch ${epochOf(state.time)}` : '';
        }

        function drawBalances(dt) {
            const k = 1 - Math.pow(0.001, dt / 600);
            const pub = BALANCES_PUBLIC(step);
            balTitle.textContent = pub ? 'balances (public)' : 'balances (private)';
            // In flight: sent but not yet claimed. The bank applies payments atomically, so in
            // step 0 that money already sits in the receiver's account.
            const inFlight = zero();
            for (const p of state.payments) if (p.sent && !p.recvd) inFlight[p.to] += p.v;
            const total = a => state.balances[a] + inFlight[a];
            const maxBal = Math.max(START_BALANCE, ...ACCOUNTS.map(total));
            const unit = BAL.maxH / maxBal;
            ACCOUNTS.forEach((a, i) => {
                const b = balEls[i];
                const acctT = (DIRECT(step) ? total(a) : state.balances[a]) * unit;
                const flightT = (DIRECT(step) ? 0 : inFlight[a]) * unit;
                b.shownA += (acctT - b.shownA) * k;
                b.shownF += (flightT - b.shownF) * k;
                b.acct.setAttribute('y', BAL.base - b.shownA);
                b.acct.setAttribute('height', Math.max(b.shownA, 0));
                b.flight.setAttribute('y', BAL.base - b.shownA - b.shownF);
                b.flight.setAttribute('height', Math.max(b.shownF, 0));
                b.acct.classList.toggle('hidden', !pub);
                b.flight.classList.toggle('hidden', !pub);
                b.val.classList.toggle('sim-muted', !pub);
                b.val.setAttribute('y', BAL.base - b.shownA - b.shownF - 6);
                b.val.textContent = total(a);
            });
            // Swatches match the bars: solid while public, faded once private.
            const legendKey = (DIRECT(step) ? 'acct' : 'acct|flight') + (pub ? '|pub' : '|priv');
            if (balLegend.dataset.key !== legendKey) {
                balLegend.dataset.key = legendKey;
                balLegend.innerHTML = '';
                const t1 = el('tspan', { fill: pub ? GRAY : '#e2e2e2' }, balLegend); t1.textContent = '\u25A0';
                const t1l = el('tspan', { fill: '#555', dx: 3 }, balLegend); t1l.textContent = 'in account';
                if (!DIRECT(step)) {
                    const t2 = el('tspan', { fill: pub ? BLUE : '#c9c9f0', x: BAL.x, dy: 16 }, balLegend); t2.textContent = '\u25A0';
                    const t2l = el('tspan', { fill: '#555', dx: 3 }, balLegend); t2l.textContent = 'in flight';
                }
            }
        }

        // -------------------------------------------------------------------
        // Storage structures
        // -------------------------------------------------------------------

        const STEP_MS = 140;   // per-level delay of the insertion ripple

        function rebuild(c, key, fn) {
            if (c.key === key) return;
            c.key = key;
            c.g.innerHTML = '';
            fn(c.g);
        }
        function clearAll(list) { for (const c of list) rebuild(c, 'empty', () => {}); }
        function flash(g, attrs, delayMs) {
            // A highlight that fades out; marks something just written. An optional delay
            // lets a sequence of flashes ripple.
            const e = el(attrs.r ? 'circle' : 'rect', { ...attrs, class: 'sim-flash' }, g);
            if (delayMs) e.style.animationDelay = `${delayMs}ms`;
            return e;
        }
        function label(g, x, y, str, cls) { return text(g, x, y, str, { class: cls || 'sim-seg-label' }); }

        // Four account cells showing balances (public) or commitments (hex).
        function drawArray(c, x, y, w, mode) {
            const vals = ACCOUNTS.map(a => mode === 'bal' ? String(state.balances[a]) : state.com[a]);
            const key = `${mode}|${x}|${vals.join(',')}`;
            const prev = c.prev || [];
            rebuild(c, key, g => {
                const gap = 6, cw = (w - gap * 3) / 4, ch = 30;
                ACCOUNTS.forEach((a, i) => {
                    const cx = x + i * (cw + gap);
                    if (prev.length && prev[i] !== vals[i]) flash(g, { x: cx - 3, y: y - 3, width: cw + 6, height: ch + 6 });
                    el('rect', { x: cx, y, width: cw, height: ch, class: 'sim-cell' }, g);
                    label(g, cx + 4, y + 11, a, 'sim-tiny');
                    text(g, cx + cw / 2, y + 21, vals[i], { class: 'sim-cell-val' + (mode === 'bal' ? '' : ' hex') });
                });
            });
            c.prev = vals;
        }

        // A growing grid of cells, one per nullifier, filling the space row by row.
        function drawGrid(c, x0, x1, y0, y1, count) {
            const pitch = 15, size = 12, cols = Math.max(1, Math.floor((x1 - x0 + 3) / pitch)), rows = Math.max(0, Math.floor((y1 - y0) / pitch));
            const shown = Math.min(count, cols * rows);
            const key = `grid|${x0}|${y0}`;
            if (c.count > shown || c.key !== key) { c.g.innerHTML = ''; c.count = 0; c.key = key; }
            const fresh = c.count > 0;   // do not flash when repopulating after a step change
            for (let i = c.count; i < shown; i++) {
                const x = x0 + (i % cols) * pitch, y = y0 + Math.floor(i / cols) * pitch;
                if (fresh) flash(c.g, { x: x - 2, y: y - 2, width: size + 4, height: size + 4 });
                el('rect', { x, y, width: size, height: size, class: 'sim-nf' }, c.g);
            }
            c.count = shown;
        }

        // A Merkle Mountain Range with n leaves: one perfect tree per set bit. The tree bodies
        // are not stored (dashed); the peaks are (solid). Fit into x, y, w, h.
        //
        // The layout is sized for the maximum-peaks case at the current bit length (n' = 2^L - 1,
        // every bit set), and each peak of size 2^k is drawn in the slot it would occupy there.
        // So the picture is stable: peaks stay put as smaller ones merge to their left, and the
        // range cannot outgrow its box until n crosses a power of two.
        function drawMMR(c, x, y, w, h, n, opts) {
            const key = `mmr|${n}|${x}|${y}|${w}|${h}`;
            const prevN = c.n || 0;
            rebuild(c, key, g => {
                if (n === 0) {
                    if (opts.empty !== '') label(g, x, y + h / 2, opts.empty || 'empty', 'sim-seg-label sim-muted');
                    return;
                }
                const L = Math.floor(Math.log2(n)) + 1;
                const unit = 11, gap = 12;
                const width = k => 20 + unit * k, height = k => 14 + unit * k;
                let totalW = gap * (L - 1);
                for (let k = 0; k < L; k++) totalW += width(k);
                const scale = Math.min(1, w / totalW, h / height(L - 1));
                // Slot origins for k = L-1 .. 0, left to right.
                const slot = {};
                let cx = x;
                for (let k = L - 1; k >= 0; k--) { slot[k] = cx; cx += (width(k) + gap) * scale; }
                let lowest = -1;
                for (let k = 0; k < L; k++) if (n >> k & 1) { lowest = k; break; }
                for (let k = L - 1; k >= 0; k--) {
                    if (!(n >> k & 1)) continue;
                    const pw = width(k) * scale, ph = height(k) * scale, x0 = slot[k];
                    const apexX = x0 + pw / 2, apexY = y + h - ph;
                    el('path', { d: `M ${x0} ${y + h} L ${apexX} ${apexY} L ${x0 + pw} ${y + h} Z`, class: 'sim-mmr-body' }, g);
                    // The lowest peak is the one the last append created or merged into.
                    if (k === lowest && n > prevN) flash(g, { cx: apexX, cy: apexY, r: 10 });
                    el('circle', { cx: apexX, cy: apexY, r: 4.5, class: 'sim-peak' }, g);
                    if (opts.sizes && pw > 26) label(g, apexX, y + h - 5, String(1 << k), 'sim-tiny center');
                }
            });
            c.n = n;
        }

        // An indexed Merkle tree over the nullifiers a party has inserted. Leaves are appended
        // in insertion order, left to right, and threaded into a linked list sorted by value:
        // each leaf also stores the next larger value. Inserting x therefore rewrites two
        // leaves, the appended one and the "low leaf" holding the largest value below x, whose
        // pointer now names x. That second path can land anywhere in the tree, which is why the
        // whole tree is kept (every node solid), unlike the receipt MMR that keeps only its
        // peaks. When the tree is full its depth grows by one.
        //
        // `d` is the minimum depth. The drawn depth D is capped by the width; beyond it each
        // drawn leaf stands for 2^(d-D) consecutive leaves and the frontier leaf is shaded by
        // how far it is filled. The depth and group size are recorded on the cache entry for
        // the panel's help text.
        function drawTree(c, x, y, w, h, values, d, opts) {
            opts = opts || {};
            const maxD = Math.max(d, Math.floor(Math.log2(w / (opts.pitch || 1.7))));
            while (d < 16 && (1 << d) < values.length) d++;
            const D = Math.min(d, maxD), LD = 1 << D, group = 1 << (d - D);
            c.depth = d; c.group = group;
            // Switching to another set (a different user) is not an insertion.
            if (c.who !== opts.who) { c.who = opts.who; c.n = values.length; }
            const n = values.length;
            const key = `tree|${opts.who || ''}|${d}|${D}|${n}|${values[n - 1] || ''}|${x}|${y}|${w}|${h}`;
            const prevN = c.n || 0;
            rebuild(c, key, g => {
                const inserted = n > prevN && n > 0;
                // The low leaf: the position of the largest earlier value below the new one.
                let low = -1;
                if (inserted) {
                    for (let i = 0; i < n - 1; i++) {
                        if (values[i] < values[n - 1] && (low < 0 || values[i] > values[low])) low = i;
                    }
                }
                const r = Math.min(4.5, Math.max(1.1, w / LD / 2.6));
                const labelRoom = opts.labels && group === 1 && w / LD >= 20;
                // The bottom strip holds the sorted list; the tree proper sits above it.
                const LIST = 38;
                const th = (labelRoom ? h - 26 : h) - LIST;
                const pos = (lvl, i) => ({ x: x + (i + 0.5) * w / (1 << lvl), y: y + r + lvl * (th - 2 * r) / D });
                for (let lvl = 0; lvl < D; lvl++) {
                    for (let i = 0; i < (1 << lvl); i++) {
                        const p = pos(lvl, i), a = pos(lvl + 1, 2 * i), b = pos(lvl + 1, 2 * i + 1);
                        el('path', { d: `M ${a.x} ${a.y} L ${p.x} ${p.y} L ${b.x} ${b.y}`, class: 'sim-edge' }, g);
                    }
                }
                const leafOf = i => i >> (d - D);                       // drawn leaf of the i-th value
                const newLeaf = inserted ? leafOf(n - 1) : -1, lowLeaf = low >= 0 ? leafOf(low) : -1;
                // Both rewritten leaves ripple to the root; the two paths merge on the way up.
                const ripple = (leaf, p, lvl) => {
                    const delay = (D - lvl) * STEP_MS;
                    flash(g, { cx: p.x, cy: p.y, r: r + 6 }, delay);
                    if (lvl > 0) {
                        const q = pos(lvl - 1, leaf >> (D - lvl + 1));
                        const hot = el('path', { d: `M ${p.x} ${p.y} L ${q.x} ${q.y}`, class: 'sim-edge-hot' }, g);
                        hot.style.animationDelay = `${delay + STEP_MS / 2}ms`;
                    }
                };
                for (let lvl = 0; lvl <= D; lvl++) {
                    for (let i = 0; i < (1 << lvl); i++) {
                        const p = pos(lvl, i);
                        const span = 1 << (D - lvl), first = i * span;
                        // Values occupy a prefix of the leaves, so a node is live iff its
                        // leftmost leaf holds something.
                        const occ = Math.max(0, Math.min(span * group, n - first * group));
                        const live = occ > 0;
                        let cls = lvl === D ? (live ? 'sim-leaf' : 'sim-leaf empty') : (live ? 'sim-inner' : 'sim-inner empty');
                        const onNew = inserted && i === (newLeaf >> (D - lvl));
                        const onLow = lowLeaf >= 0 && i === (lowLeaf >> (D - lvl));
                        if (onNew) ripple(newLeaf, p, lvl);
                        if (onLow && !onNew) ripple(lowLeaf, p, lvl);
                        if (onNew && lvl === D && occ === 1) cls += ' pop';
                        const node = el('circle', { cx: p.x, cy: p.y, r, class: cls }, g);
                        // The frontier leaf of an aggregated tree is shaded by how full it is.
                        if (lvl === D && live && group > 1 && occ < group) node.style.fillOpacity = (0.15 + 0.85 * occ / group).toFixed(2);
                        if (lvl === D && labelRoom && i < n) {
                            label(g, p.x, y + h - LIST - (i % 2 ? 2 : 14), values[i], 'sim-tiny center' + (i === newLeaf ? ' hot' : ''));
                        }
                    }
                }
                // The sorted linked list, as a row of dots beneath the tree. The new value takes
                // its place in sorted order: the dots to its right slide over to make room, then
                // it pops in. Thin lines tie the new dot to the appended leaf and the dot to its
                // left, the low leaf, to the leaf it lives in.
                const sorted = values.map((v, i) => i).sort((i, j) => values[i] < values[j] ? -1 : values[i] > values[j] ? 1 : 0);
                const ly = y + h - 20;
                const pitch = w / Math.max(n, LD), lr = Math.min(r, Math.max(1, pitch / 2.6));
                const lx = k => x + (k + 0.5) * pitch;
                const newAt = inserted ? sorted.indexOf(n - 1) : -1, lowAt = newAt - 1;
                if (n > 0) label(g, x + w / 2, ly + 15, 'sorted nullifiers', 'sim-tiny center');
                const SLIDE = 350;
                sorted.forEach((i, k) => {
                    const cls = 'sim-leaf' + (i === n - 1 && inserted ? ' pop' : '');
                    const dot = el('circle', { cx: lx(k), cy: ly, r: lr, class: cls }, g);
                    if (!inserted) return;
                    if (i === n - 1) {
                        dot.style.animationDelay = `${SLIDE}ms`;
                    } else if (k > newAt) {
                        // Start one slot to the left (its old place) and slide right.
                        dot.style.transform = `translateX(${-pitch}px)`;
                        dot.style.transition = `transform ${SLIDE}ms ease-in-out`;
                        requestAnimationFrame(() => requestAnimationFrame(() => { dot.style.transform = 'translateX(0)'; }));
                    }
                });
                if (inserted) {
                    // The gap opening in the list.
                    flash(g, { cx: lx(newAt), cy: ly, r: lr + 5 });
                    const tie = (k, leaf, delay) => {
                        const p = pos(D, leaf);
                        const line = el('path', { d: `M ${lx(k)} ${ly - lr} L ${p.x} ${p.y + r}`, class: 'sim-link' }, g);
                        line.style.animationDelay = `${delay}ms`;
                    };
                    tie(newAt, newLeaf, SLIDE);
                    if (lowAt >= 0 && lowLeaf >= 0) tie(lowAt, lowLeaf, SLIDE);
                }
            });
            c.n = n;
        }

        function drawStorage() {
            const c = state.counts;
            const nTx = c.sends + c.recvs;
            const epoch = epochOf(state.time);
            const peaks = nTx.toString(2).split('1').length - 1;
            const X0 = STORE.x, XR = STORE.right, Y0 = STORE.y;
            const arrayMode = step <= 2 ? 'bal' : 'com';
            const arrayW = 300;
            const bottom = H - 12;

            // Left column: validator storage, always starting with the account array.
            drawArray(S.array, X0, Y0 + 14, arrayW, arrayMode);

            if (step <= 4) {
                const nfCount = step === 0 ? 0 : step <= 3 ? c.recvs : nTx;
                rebuild(S.headings, `h|${step}|${nfCount}`, g => {
                    label(g, X0, Y0, step <= 1 ? 'bank storage' : 'validator storage', 'sim-h left');
                    label(g, X0, Y0 + 62, step <= 2 ? 'balances: one per account' : 'commitments: one per account', 'sim-seg-label');
                    const gx = X0 + arrayW + 36;
                    if (step === 0) label(g, gx, Y0 + 14 + 21, 'nothing per payment', 'sim-seg-label sim-muted');
                    else {
                        label(g, gx, Y0, `nullifiers: ${nfCount}`, 'sim-h left red');
                        label(g, gx, Y0 + 18, step <= 3 ? 'one per receive, never pruned' : 'one per send/receive, never pruned', 'sim-seg-label sim-muted');
                    }
                });
                drawGrid(S.grid, X0 + arrayW + 36, XR, Y0 + 32, bottom, nfCount);
                clearAll([S.mmr, S.tree, ...S.users.flatMap(u => [u.mmr, u.tree])]);
                return;
            }
            drawGrid(S.grid, 0, 0, 0, 0, 0);

            // Steps 5 to 7: the validators' column is the account array with the receipt MMR
            // beneath it; the right-hand column holds the nullifiers, wherever this step keeps them.
            const ux = X0 + arrayW + 48, uw = XR - ux;
            const perUser = step >= 6;
            rebuild(S.headings, `h|${step}|${nTx}|${peaks}|${epoch}|${perUser ? ACCOUNTS.map(a => c.recvBy[a] + ':' + (c.recvByClaimEpoch[a][epoch] || 0)).join(',') : ''}`, g => {
                label(g, X0, Y0, 'validator storage', 'sim-h left');
                label(g, X0, Y0 + 62, 'commitments: one per account', 'sim-seg-label');
                label(g, X0, Y0 + 112, `receipt MMR: ${nTx}`, 'sim-h left blue');
                label(g, X0, Y0 + 130, `kept: the ${peaks} peaks only`, 'sim-seg-label sim-muted');
                el('line', { x1: ux - 24, y1: Y0 - 14, x2: ux - 24, y2: bottom, class: 'sim-divider' }, g);
                if (!perUser) {
                    label(g, ux, Y0, `nullifier tree: ${nTx}`, 'sim-h left red');
                    label(g, ux, Y0 + 18, 'nullifiers committed via indexed Merkle tree', 'sim-seg-label sim-muted');
                    return;
                }
                label(g, ux, Y0, 'users keep', 'sim-h left');
                // One cell per user, in a 2x2 grid, each with its own heading.
                ACCOUNTS.forEach((a, i) => {
                    const cell = userCell(ux, uw, Y0, bottom, i);
                    if (i % 2 === 1) el('line', { x1: cell.x - 8, y1: cell.y, x2: cell.x - 8, y2: cell.y + cell.h, class: 'sim-divider' }, g);
                    if (i >= 2) el('line', { x1: ux, y1: cell.y - 6, x2: ux + uw, y2: cell.y - 6, class: 'sim-divider' }, g);
                    label(g, cell.x, cell.y + 11, a, 'sim-seg-label dark bold');
                    if (step === 6) {
                        label(g, cell.x + cell.w, cell.y + 11, `nullifier tree: ${c.recvBy[a]}`, 'sim-seg-label right red');
                    } else {
                        // The MMR of closed-epoch roots is captioned beneath itself; the header
                        // carries only the count for the open epoch, so the two never collide.
                        label(g, cell.x + cell.w, cell.y + 11, `this epoch: ${c.recvByClaimEpoch[a][epoch] || 0}`, 'sim-seg-label right red');
                        label(g, cell.x + MMR_PAD + (epochStrip(cell) - MMR_PAD) / 2, cell.y + cell.h - 4, `${epoch} epoch root${epoch === 1 ? '' : 's'}`, 'sim-tiny center blue');
                    }
                });
            });
            drawMMR(S.mmr, X0, Y0 + 140, arrayW, bottom - Y0 - 150, nTx, { sizes: true });

            if (!perUser) {
                drawTree(S.tree, ux + 4, Y0 + 36, uw - 8, bottom - Y0 - 44, state.nf.tx, 5, { pitch: 3.4 });
                clearAll(S.users.flatMap(u => [u.mmr, u.tree]));
                return;
            }
            clearAll([S.tree]);
            ACCOUNTS.forEach((a, i) => {
                const cell = userCell(ux, uw, Y0, bottom, i), U = S.users[i];
                const ty = cell.y + 22, th = cell.h - 26;
                if (step === 6) {
                    clearAll([U.mmr]);
                    drawTree(U.tree, cell.x, ty, cell.w, th, state.nf.by[a], 4, { who: a });
                } else {
                    // The cell splits in half: the epoch-root MMR on the left, this epoch's
                    // nullifier tree on the right.
                    const strip = epochStrip(cell), tx = cell.x + strip + 16, tw = cell.w - strip - 16;
                    drawMMR(U.mmr, cell.x + MMR_PAD, ty + 10, strip - MMR_PAD, th - 20, epoch, { empty: '' });
                    drawTree(U.tree, tx, ty, tw, th, state.nf.byEpoch[a][epoch] || [], 3, { who: `${a}|${epoch}` });
                }
            });
        }

        // Width of the epoch-root strip at the left of a step-7 user cell, and the gap that keeps
        // its MMR off the cell's left edge (the divider, for the right-hand column).
        const MMR_PAD = 10;
        function epochStrip(cell) {
            return Math.round((cell.w - 16) / 2);
        }

        // Geometry of the i-th cell of the 2x2 grid of per-user panels.
        function userCell(ux, uw, Y0, bottom, i) {
            const top = Y0 + 20, gap = 16;
            const w = (uw - gap) / 2, h = (bottom - top - gap) / 2;
            return { x: ux + (i % 2) * (w + gap), y: top + Math.floor(i / 2) * (h + gap), w, h };
        }

        // -------------------------------------------------------------------
        // Frame loop
        // -------------------------------------------------------------------

        let last = performance.now();
        let running = true;
        function frame(now) {
            const dt = clamp(now - last, 0, 50);
            last = now;
            if (running) {
                state.time += dt;
                schedulePayments();
                fireEvents();
            }
            drawTokens();
            drawLedger();
            drawBalances(dt);
            drawStorage();
            helps.forEach(u => u());
            requestAnimationFrame(frame);
        }

        // Pause when off screen to save work.
        if ('IntersectionObserver' in window) {
            new IntersectionObserver(entries => { running = entries[0].isIntersecting; }, { threshold: 0 }).observe(stage);
        }

        // Keyboard: arrows step when the widget is in view and no form control has focus.
        window.addEventListener('keydown', ev => {
            if (ev.altKey || ev.ctrlKey || ev.metaKey || ev.shiftKey) return;
            if (!running) return;
            if (/^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(ev.target.tagName)) return;
            if (ev.key === 'ArrowRight') { setStep(step + 1); ev.preventDefault(); }
            if (ev.key === 'ArrowLeft') { setStep(step - 1); ev.preventDefault(); }
        });

        // Deep link: #step-N opens the widget at step N; ?t=MS fast-forwards the simulation.
        const m = /^#step-(\d+)$/.exec(location.hash);
        setStep(m ? Number(m[1]) : 0);
        const ff = Number(new URLSearchParams(location.search).get('t')) || 0;
        for (let t = 50; t <= ff; t += 50) { state.time = t; schedulePayments(); fireEvents(); }
        requestAnimationFrame(frame);
    }

    document.addEventListener('DOMContentLoaded', init);
})();
