'use strict';

(function () {
    function init() {
        const mount = document.getElementById('rpc-diagram');
        if (!mount) return;

        const sources = ['A', 'B', 'A', 'C', 'B', 'A'];
        mount.innerHTML = `
            <div class="sim-stepper rpc-controls" role="group" aria-label="View as">
                <span class="sim-title">View as</span>
                <button type="button" data-view="ledger" aria-pressed="true">Ledger observer</button>
                <button type="button" data-view="rpc" aria-pressed="false">RPC operator</button>
            </div>
            <p class="rpc-status" role="status"></p>
            <div class="rpc-flow">
                <div class="rpc-node">
                    <strong>Wallet clients</strong>
                    <span class="rpc-detail">Submit their own transactions</span>
                </div>
                <span class="rpc-arrow" aria-hidden="true">&#8594;</span>
                <div class="rpc-node rpc-relay">
                    <strong>One RPC</strong>
                    <span class="rpc-detail">Forwards every submission</span>
                    <div class="rpc-groups" hidden>
                        <strong class="rpc-group-title">Private source groups</strong>
                    </div>
                    <span class="rpc-hidden rpc-detail">Submission sources hidden from this observer</span>
                </div>
                <span class="rpc-arrow" aria-hidden="true">&#8594;</span>
                <div class="rpc-node">
                    <strong>Shielded ledger</strong>
                    <span class="rpc-detail">Acting accounts hidden</span>
                    <ol class="rpc-transactions" aria-label="Transactions on the ledger"></ol>
                </div>
            </div>
            <p class="rpc-caption">The transaction numbers identify the same submissions in both views. Client labels identify submission sources, not cryptographic accounts.</p>
        `;

        const transactions = mount.querySelector('.rpc-transactions');
        sources.forEach((_, i) => {
            const transaction = document.createElement('li');
            transaction.textContent = `tx ${i + 1}`;
            transactions.appendChild(transaction);
        });

        const groups = mount.querySelector('.rpc-groups');
        for (const source of ['A', 'B', 'C']) {
            const group = document.createElement('div');
            group.className = 'rpc-group';
            const label = document.createElement('strong');
            label.textContent = `Client ${source}`;
            const submissions = document.createElement('span');
            submissions.textContent = sources.flatMap((s, i) => s === source ? [`tx ${i + 1}`] : []).join(', ');
            group.append(label, submissions);
            groups.appendChild(group);
        }

        const buttons = [...mount.querySelectorAll('.rpc-controls button')];
        function update(view) {
            const operator = view === 'rpc';
            for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.view === view));
            groups.hidden = !operator;
            mount.querySelector('.rpc-hidden').hidden = operator;
            mount.querySelector('.rpc-status').textContent = operator
                ? 'The RPC can group repeated submissions by client/session. The ledger contains no such client labels.'
                : 'The ledger reveals the ordered transactions without their submission sources.';
        }
        for (const b of buttons) b.addEventListener('click', () => update(b.dataset.view));
        update('ledger');
    }

    document.addEventListener('DOMContentLoaded', init);
})();
