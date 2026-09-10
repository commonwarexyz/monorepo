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
    const HANDOFF_AT = 620;    // sender hands the coin/receipt opening to the receiver
    const HANDOFF_MS = 720;
    const RECV_MIN = 3000;     // receivers claim after a random delay
    const RECV_MAX = 12000;
    const HOT_W = 4;           // largest claimed positions a user keeps hot, for the last step

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
    //  3 commitments + proofs  7 users prune by position

    const DIRECT = step => step === 0;   // one instruction through the bank, no handoff
    const BALANCES_PUBLIC = step => step <= 2;
    const OP_VISIBLE = step => step <= 3;   // the ledger can tell a send from a receive

    function recordText(step, ev) {
        const p = ev.pay, X = ev.actor;
        if (ev.type === 'send') {
            switch (step) {
                case 0: return `${X} pays ${p.to} ${p.v}`;
                case 1: case 2: return `${X} sends ${p.v}`;
                case 3: return `${X}: commitment, receipt, proof`;
                case 4: return `${X}: commitment, receipt, nullifier, proof`;
                case 5: return `${X}: commitment, receipt, nullifier, root, proof`;
                default: return `${X}: commitment, receipt, root, proof`;
            }
        }
        switch (step) {
            case 1: case 2: return `${X} receives ${p.v}`;
            case 3: return `${X}: commitment, nullifier, proof`;
            case 4: return `${X}: commitment, receipt, nullifier, proof`;
            case 5: return `${X}: commitment, receipt, nullifier, root, proof`;
            default: return `${X}: commitment, receipt, root, proof`;
        }
    }

    // The three stage summaries. `hl` marks what changed at this step.
    const BOXES = [
        {
            store: { v: 'bank: one balance per account', n: 'nothing per payment' },
            work: { v: 'the bank applies every payment' },
            learn: { v: 'who paid whom, how much', hl: true },
        },
        {
            store: { v: 'bank: balances + a nullifier for every transfer', n: '~1 PB/year @1M TPS, never pruned', hl: true },
            work: { v: 'signature for every transfer' },
            learn: { v: 'who sent, who received, amounts', n: 'not who paid whom', hl: true },
        },
        {
            store: { v: 'validators: balances + a nullifier for every transfer' },
            work: { v: 'signature for every transfer', n: '(threshold signature)', hl: true },
            learn: { v: 'who sent, who received, amounts', n: 'visible to anyone (not just the bank)', hl: true },
        },
        {
            store: { v: 'validators: commitments + a nullifier per receive, a receipt per send', hl: true },
            work: { v: 'verify a proof per transaction, signature per transaction', hl: true },
            learn: { v: 'who sent, who received', n: 'amounts and balances hidden', hl: true },
        },
        {
            store: { v: 'validators: commitments + a nullifier and receipt per send/receive', hl: true },
            work: { v: 'verify a proof per transaction, signature per send/receive' },
            learn: { v: 'who acted', n: 'send/receive are indistinguishable', hl: true },
        },
        {
            store: { v: 'validators: commitments + MMR frontier + bounded recent roots + a nullifier per send/receive', hl: true },
            work: { v: 'verify a proof per transaction, sign one root per block', hl: true },
            learn: { v: 'who acted' },
        },
        {
            store: { v: 'validators: commitments + MMR frontier + bounded recent roots\nusers: every claimed receipt position', hl: true },
            work: { v: 'verify a proof per transaction, sign one root per block' },
            learn: { v: 'who acted' },
        },
        {
            store: { v: `validators: commitments + MMR frontier + bounded recent roots\nusers: nullifier tree frontier + ${HOT_W} largest claimed positions`, n: 'smaller claimed positions in cold storage', hl: true },
            work: { v: 'verify a proof per transaction, sign one root per block' },
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
        payments: [],      // {k, from, to, v, tSend, tRecv, pid}
        events: [],        // {t, type, actor, pay, balance}
        balances: Object.fromEntries(ACCOUNTS.map(a => [a, START_BALANCE])),
        counts: { sends: 0, recvs: 0, unclaimed: zero(), recvBy: zero() },
        // Nullifiers are receipt positions. The simulation schedules each user
        // to claim in position order, so these arrays are increasing.
        nf: Object.fromEntries(ACCOUNTS.map(a => [a, []])),
        com: {},           // current account commitment per account (random-looking)
        hit: {},           // last balance change per account: {t, type}, for the flash on its bar
        fwd: {},           // credit forwarded by the bank, used instead of the claim in step 0
        k: 0,
    };
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
                // A receiver works through its inbox in position order, so this claim
                // waits for any earlier receipt addressed to the same account.
                let tRecv = t0 + RECV_MIN + rand() * (RECV_MAX - RECV_MIN);
                for (const q of state.payments) if (q.to === to && !q.recvd) tRecv = Math.max(tRecv, q.tRecv + 400);
                state.payments.push({ k: state.k, from, to, v, tSend: t0, tRecv, pid: -1, sent: false, recvd: false });
            }
            state.nextPay += PAY_EVERY * (0.6 + 0.8 * rand());
        }
    }

    function fireEvents() {
        const c = state.counts;
        for (const p of state.payments) {
            if (!p.sent && state.time >= p.tSend + TOKEN_MS) {
                p.sent = true;
                // The receipt lands at the next position of the receipt log, which every
                // send and receive extends once the operation is hidden.
                p.pid = c.sends + c.recvs;
                state.balances[p.from] -= p.v;
                state.com[p.from] = hex4();
                state.hit[p.from] = { t: state.time, type: 'send' };
                // With a bank in the middle the credit lands one hop later (step 0 only).
                state.fwd[p.to] = { t: state.time + TOKEN_MS, type: 'recv' };
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
                state.nf[p.to].push(p.pid);
                state.com[p.to] = hex4();
                state.hit[p.to] = { t: state.time, type: 'recv' };
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

        const copy = h('div', 'sim-copy', mount);
        const boxes = h('div', 'sim-counters', mount);
        const boxEls = ['storage', 'validator work', 'validators learn'].map(k => {
            const b = h('div', 'sim-counter', boxes);
            const key = h('span', 'k', b); key.textContent = k;
            const v = h('div', 'v', b);
            const n = h('div', 'n', b);
            return { b, v, n };
        });

        // Stage.
        const stage = h('div', 'sim-stage', mount);
        const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'sim-svg' }, stage);

        // Panel headers and dividers.
        text(svg, NET.cx, HEAD_Y, 'network', { class: 'sim-h' });
        const ledgerTitle = text(svg, LEDGER.x, HEAD_Y, 'public ledger', { class: 'sim-h left' });
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
            const hit = el('rect', { x: cx - BAL.barW / 2 - 3, width: BAL.barW + 6, y: BAL.base, height: 0, class: 'sim-bal-hit' }, balG);
            text(balG, cx, BAL.base + 18, a, { class: 'sim-node-label' });
            return { acct, flight, val, hit, shownA: 0, shownF: 0 };
        });

        // Ledger rows. Each carries a marker: colored by operation while the ledger can tell a
        // send from a receive, gray once it cannot.
        const rowEls = [];
        for (let i = 0; i < LEDGER.rows; i++) {
            const g = el('g', {}, svg);
            const mark = el('circle', { cx: LEDGER.x + 4, cy: 0, r: 3.5, class: 'sim-row-mark' }, g);
            const rec = text(g, LEDGER.x + 14, 0, '', { class: 'sim-row' });
            const rule = el('line', { x1: LEDGER.x, x2: LEDGER.x + LEDGER.w, y1: 0, y2: 0, class: 'sim-rule' }, g);
            rowEls.push({ g, mark, rec, rule });
        }

        // Storage: retained groups, each rebuilt only when its data key changes.
        const storeG = el('g', {}, svg);
        const cache = () => ({ g: el('g', {}, storeG), key: null, count: 0 });
        const S = {
            headings: cache(), array: cache(), grid: cache(), mmr: cache(),
            users: ACCOUNTS.map(() => cache()),
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
                case 5: return `Left: the receipt MMR. Receipts accumulate in perfect binary trees and validators only need to store the peaks (dots) to extend the tree. Right: the nullifier set, still held by validators and still growing with every transaction.`;
                case 6: return `Validators keep commitments, the MMR frontier, and bounded recent roots, and delegate nullifier storage to users. Each user keeps a sparse Merkle tree keyed by receipt position (leaf labels): a leaf is set once the receipt at that position is claimed. In this example, users claim receipts in position order.`;
                default: return `Each user freezes its tree below a threshold: the frozen prefix is summarized by its frontier (blue), only the ${HOT_W} largest claimed positions stay hot (red), and everything else moves to cold storage (faded). Nothing changes for the ledger.`;
            }
        });

        function setStep(i) {
            step = clamp(i, 0, N - 1);
            title.textContent = `${step}. ${steps[step].title}`;
            dotEls.forEach((d, j) => d.classList.toggle('on', j === step));
            prev.disabled = step === 0;
            next.disabled = step === N - 1;
            copy.classList.remove('changed');
            void copy.offsetWidth;
            copy.replaceChildren(...steps[step].nodes.map(n => n.cloneNode(true)));
            copy.classList.add('changed');
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

        // Dots to the ledger: red send, blue receive, purple once the operation is hidden.
        function tokenKind(kind) {
            return OP_VISIBLE(step) ? kind : 'hidden';
        }
        function token(g, x, y, kind) {
            el('circle', { cx: x, cy: y, r: 6, class: kind === 'handoff' ? 'sim-token hollow' : `sim-token ${kind}` }, g);
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
                    token(tokenG, lerp(from.x, NET.cx, e), lerp(from.y, NET.cy, e), tokenKind('send'));
                }
                if (DIRECT(step)) {
                    // The bank forwards the payment to the receiver.
                    t = (state.time - p.tSend - TOKEN_MS) / TOKEN_MS;
                    if (t >= 0 && t <= 1) {
                        const e = ease(t);
                        token(tokenG, lerp(NET.cx, to.x, e), lerp(NET.cy, to.y, e), tokenKind('recv'));
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
                    token(tokenG, a * from.x + b * cx + cc * to.x, a * from.y + b * cy + cc * to.y, 'handoff');
                }
                // Receiver to ledger.
                t = (state.time - p.tRecv) / TOKEN_MS;
                if (t >= 0 && t <= 1) {
                    const e = ease(t);
                    token(tokenG, lerp(to.x, NET.cx, e), lerp(to.y, NET.cy, e), tokenKind('recv'));
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
                r.mark.setAttribute('cy', y + 10);
                r.mark.setAttribute('class', 'sim-row-mark ' + (OP_VISIBLE(step) ? ev.type : 'hidden'));
                r.rule.setAttribute('y1', y + LEDGER.rowH - 7);
                r.rule.setAttribute('y2', y + LEDGER.rowH - 7);
                r.rec.textContent = recordText(step, ev);
            });
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
                // Outline the bar briefly when a debit or credit lands on it, in the color of
                // the token that caused it.
                let hit = state.hit[a];
                const fwd = state.fwd[a];
                if (DIRECT(step) && fwd && fwd.t <= state.time && (!hit || fwd.t > hit.t)) hit = fwd;
                const age = hit ? state.time - hit.t : Infinity;
                const HIT_MS = 900;
                b.hit.setAttribute('class', 'sim-bal-hit' + (hit ? ' ' + hit.type : ''));
                b.hit.style.opacity = age < HIT_MS ? (1 - age / HIT_MS).toFixed(2) : 0;
                b.hit.setAttribute('y', BAL.base - b.shownA - b.shownF - 3);
                b.hit.setAttribute('height', Math.max(b.shownA + b.shownF + 3, 0));
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
        function clearAll(list) { for (const c of list) rebuild(c, 'empty', () => { }); }
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

        // A user's nullifier tree: a sparse Merkle tree keyed by receipt position. The leaf of
        // position p is set once the user has claimed the receipt at p. The tree spans every
        // position the log has issued so far (`space`), so its depth grows with the log, not
        // with the user's activity. The simulation claims receipts in position order, so each
        // insertion lands to the right of every earlier one and touches a single
        // root-to-leaf path, which ripples upward.
        // Nodes are solid when the user stores them and hollow when their subtree is empty
        // (a default hash anyone can recompute).
        //
        // With `opts.hot` set to a threshold L, the prefix [0, L) is frozen: the maximal
        // subtrees covering it are summarized by their roots (the frontier, in blue), their
        // bodies move to cold storage (faded), and only the paths of positions >= L stay hot.
        //
        // `d` is the minimum depth. The drawn depth D is capped by the width; beyond it each
        // drawn leaf stands for 2^(d-D) consecutive positions and nodes below that resolution
        // (including frontier and hot nodes) cannot be drawn, so a note flags the coarsening.
        function drawSMT(c, x, y, w, h, positions, space, d, opts) {
            opts = opts || {};
            const maxD = Math.max(d, Math.floor(Math.log2(w / 1.7)));
            while (d < 30 && (1 << d) < space) d++;
            const D = Math.min(d, maxD), LD = 1 << D;
            const L = opts.hot || 0;
            // Switching to another set (a different user) is not an insertion.
            if (c.who !== opts.who) { c.who = opts.who; c.n = positions.length; }
            const n = positions.length;
            const key = `smt|${opts.who || ''}|${d}|${D}|${n}|${L}|${x}|${y}|${w}|${h}`;
            const prevN = c.n || 0;
            rebuild(c, key, g => {
                const inserted = n > prevN && n > 0;
                const r = Math.min(4.5, Math.max(1.1, w / LD / 2.6));
                const labelRoom = D === d && w / LD >= 6;
                const coarse = D < d;
                const th = labelRoom || coarse ? h - 22 : h;
                if (coarse) label(g, x + w / 2, y + h - 4, `${1 << (d - D)} positions per drawn leaf`, 'sim-tiny center');
                const pos = (lvl, i) => ({ x: x + (i + 0.5) * w / (1 << lvl), y: y + r + lvl * (th - 2 * r) / D });
                // The range of positions under the i-th drawn node at level lvl.
                const lo = (lvl, i) => i << (d - lvl), hi = (lvl, i) => (i + 1) << (d - lvl);
                const frozen = (lvl, i) => L > 0 && hi(lvl, i) <= L;
                const leafOf = p => p >> (d - D);
                const held = new Set(positions.map(leafOf));
                const holds = (lvl, i) => {
                    const a = i << (D - lvl), b = (i + 1) << (D - lvl);
                    for (const leaf of held) if (leaf >= a && leaf < b) return true;
                    return false;
                };
                for (let lvl = 0; lvl < D; lvl++) {
                    for (let i = 0; i < (1 << lvl); i++) {
                        const p = pos(lvl, i), a = pos(lvl + 1, 2 * i), b = pos(lvl + 1, 2 * i + 1);
                        el('path', { d: `M ${a.x} ${a.y} L ${p.x} ${p.y} L ${b.x} ${b.y}`, class: frozen(lvl, i) ? 'sim-edge cold' : 'sim-edge' }, g);
                    }
                }
                const newLeaf = inserted ? leafOf(positions[n - 1]) : -1;
                const ripple = (p, lvl) => {
                    const delay = (D - lvl) * STEP_MS;
                    flash(g, { cx: p.x, cy: p.y, r: r + 6 }, delay);
                    if (lvl > 0) {
                        const q = pos(lvl - 1, newLeaf >> (D - lvl + 1));
                        const hot = el('path', { d: `M ${p.x} ${p.y} L ${q.x} ${q.y}`, class: 'sim-edge-hot' }, g);
                        hot.style.animationDelay = `${delay + STEP_MS / 2}ms`;
                    }
                };
                for (let lvl = 0; lvl <= D; lvl++) {
                    for (let i = 0; i < (1 << lvl); i++) {
                        const p = pos(lvl, i);
                        const base = lvl === D ? 'sim-leaf' : 'sim-inner';
                        let cls;
                        if (frozen(lvl, i)) {
                            // The frontier is the frozen nodes whose parent is not frozen.
                            cls = lvl === 0 || !frozen(lvl - 1, i >> 1) ? 'sim-frontier' : base + ' cold';
                        } else {
                            cls = holds(lvl, i) ? base : base + ' empty';
                        }
                        const onNew = inserted && i === (newLeaf >> (D - lvl));
                        if (onNew) ripple(p, lvl);
                        if (onNew && lvl === D) cls += ' pop';
                        el('circle', { cx: p.x, cy: p.y, r: cls === 'sim-frontier' ? r + 1 : r, class: cls }, g);
                        if (lvl === D && labelRoom && held.has(i)) {
                            label(g, p.x, y + h - (i % 2 ? 0 : 11), String(i), 'sim-tiny center' + (i === newLeaf ? ' hot' : lo(D, i) < L ? ' cold' : ''));
                        }
                    }
                }
            });
            c.n = n;
        }

        // The threshold below which a user freezes its tree: keep the HOT_W largest
        // claimed positions hot, so the frontier summarizes everything below them.
        function hotThreshold(positions) {
            return positions.length > HOT_W ? positions[positions.length - HOT_W] : 0;
        }
        const popcount = n => n.toString(2).split('1').length - 1;

        function drawStorage() {
            const c = state.counts;
            const nTx = c.sends + c.recvs;
            const peaks = popcount(nTx);
            const X0 = STORE.x, XR = STORE.right, Y0 = STORE.y;
            const arrayMode = step <= 2 ? 'bal' : 'com';
            const arrayW = 300;
            const bottom = H - 12;

            // Who keeps what. Through step 5 everything in this row belongs to one party (the
            // bank, then the validators), so one header spans the row and there is no divider.
            // From step 6 the row splits: validators on the left, users on the right.
            const ownerHead = step <= 1 ? 'bank storage' : 'validator storage';
            const ownerPoss = step <= 1 ? "bank's" : "validators'";
            const perUser = step >= 6;
            const ux = X0 + arrayW + 48, uw = XR - ux;
            // A rule under the header marks its extent: the whole row, or each half.
            const headRule = (g, x1, x2) => el('line', { x1, y1: Y0 + 8, x2, y2: Y0 + 8, class: 'sim-headrule' }, g);

            // Left column: the owner's storage, always starting with the account array.
            drawArray(S.array, X0, Y0 + 14, arrayW, arrayMode);

            // Through step 5 the nullifier set sits with the owner, one square per entry.
            const nfCount = step === 0 ? 0 : step <= 3 ? c.recvs : nTx;
            const gx = X0 + arrayW + 36;
            if (step <= 4) {
                rebuild(S.headings, `h|${step}|${nfCount}`, g => {
                    label(g, X0, Y0, ownerHead, 'sim-h left');
                    headRule(g, X0, XR);
                    label(g, X0, Y0 + 62, step <= 2 ? 'balances: one per account' : 'commitments: one per account', 'sim-seg-label');
                    if (step === 0) {
                        label(g, gx, Y0 + 14 + 21, 'nothing per payment', 'sim-seg-label sim-muted');
                    } else {
                        label(g, gx, Y0 + 32, `${ownerPoss} nullifier set: ${nfCount}`, 'sim-h left red');
                        label(g, gx, Y0 + 50, step <= 3 ? 'one per receive, never pruned' : 'one per send/receive, never pruned', 'sim-seg-label sim-muted');
                    }
                });
                drawGrid(S.grid, gx, XR, Y0 + 62, bottom, nfCount);
                clearAll([S.mmr, ...S.users]);
                return;
            }

            // Steps 5 to 7: the validators' column is the account array with the receipt MMR
            // beneath it; the right-hand column holds the nullifiers, wherever this step keeps them.
            const perUserKey = perUser ? ACCOUNTS.map(a => `${c.recvBy[a]}:${step === 7 ? hotThreshold(state.nf[a]) : ''}`).join(',') : '';
            rebuild(S.headings, `h|${step}|${nTx}|${peaks}|${perUserKey}`, g => {
                label(g, X0, Y0, 'validator storage', 'sim-h left');
                label(g, X0, Y0 + 62, 'commitments: one per account', 'sim-seg-label');
                label(g, X0, Y0 + 112, `receipt MMR: ${nTx}`, 'sim-h left blue');
                label(g, X0, Y0 + 130, `only store ${peaks} peaks + recent roots`, 'sim-seg-label sim-muted');
                if (!perUser) {
                    headRule(g, X0, XR);
                    label(g, gx, Y0 + 32, `${ownerPoss} nullifier set: ${nTx}`, 'sim-h left red');
                    label(g, gx, Y0 + 50, 'one per send/receive, never pruned', 'sim-seg-label sim-muted');
                    return;
                }
                headRule(g, X0, ux - 40);
                headRule(g, ux, XR);
                el('line', { x1: ux - 24, y1: Y0 - 14, x2: ux - 24, y2: bottom, class: 'sim-divider' }, g);
                label(g, ux, Y0, 'user storage', 'sim-h left');
                // One cell per user, in a 2x2 grid, each with its own heading.
                ACCOUNTS.forEach((a, i) => {
                    const cell = userCell(ux, uw, Y0, bottom, i);
                    if (i % 2 === 1) el('line', { x1: cell.x - 8, y1: cell.y, x2: cell.x - 8, y2: cell.y + cell.h, class: 'sim-divider' }, g);
                    if (i >= 2) el('line', { x1: ux, y1: cell.y - 6, x2: ux + uw, y2: cell.y - 6, class: 'sim-divider' }, g);
                    label(g, cell.x, cell.y + 11, a, 'sim-seg-label dark bold');
                    if (step === 6) {
                        label(g, cell.x + cell.w, cell.y + 11, `nullifier tree: ${c.recvBy[a]}`, 'sim-seg-label right red');
                    } else {
                        // Hot state: the frontier of the frozen prefix plus the largest claimed positions.
                        const L = hotThreshold(state.nf[a]), hot = Math.min(c.recvBy[a], HOT_W);
                        const t = label(g, cell.x + cell.w, cell.y + 11, '', 'sim-seg-label right');
                        const f = el('tspan', { fill: BLUE }, t); f.textContent = `frontier: ${popcount(L)}`;
                        const s = el('tspan', { fill: '#555' }, t); s.textContent = ' + ';
                        const r = el('tspan', { fill: RED }, t); r.textContent = `hot: ${hot}`;
                        if (c.recvBy[a] > HOT_W) label(g, cell.x + cell.w, cell.y + 24, `${c.recvBy[a] - HOT_W} in cold storage`, 'sim-tiny right');
                    }
                });
            });
            drawMMR(S.mmr, X0, Y0 + 140, arrayW, bottom - Y0 - 150, nTx, { sizes: true });

            if (!perUser) {
                drawGrid(S.grid, gx, XR, Y0 + 62, bottom, nTx);
                clearAll(S.users);
                return;
            }
            drawGrid(S.grid, 0, 0, 0, 0, 0);
            ACCOUNTS.forEach((a, i) => {
                const cell = userCell(ux, uw, Y0, bottom, i);
                const ty = cell.y + 30, th = cell.h - 34;
                const hot = step === 7 ? hotThreshold(state.nf[a]) : 0;
                drawSMT(S.users[i], cell.x, ty, cell.w, th, state.nf[a], nTx, 4, { who: a, hot });
            });
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
