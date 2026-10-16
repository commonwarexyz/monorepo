'use strict';

// Nullifier storage accumulated since the page opened at 1M transactions per
// second, assuming a 32-byte nullifier per transaction.
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
        function tick() {
            const s = performance.now() / 1000;
            const txs = Math.floor(s * TPS);
            bytesEl.textContent = fmtBytes(txs * BYTES_PER_TX);
            txEl.textContent = txs.toLocaleString('en-US');
        }
        tick();
        setInterval(tick, 100);
    }
    document.addEventListener('DOMContentLoaded', start);
})();
