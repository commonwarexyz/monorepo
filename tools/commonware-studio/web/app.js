/**
 * Commonware Studio Client Logic
 */

let isAutoConsensus = false;
let autoInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initListeners();
});

function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.toggle('active', t === tab));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${tab.dataset.tab}`));
    });
  });
}

function initListeners() {
  document.getElementById('btn-commit-block').addEventListener('click', commitBlock);

  const autoBtn = document.getElementById('btn-toggle-auto');
  autoBtn.addEventListener('click', () => {
    if (isAutoConsensus) {
      clearInterval(autoInterval);
      isAutoConsensus = false;
      autoBtn.textContent = '▶️ Start Auto-Consensus Stream (5 blocks/sec)';
      autoBtn.className = 'btn btn-gradient btn-lg';
    } else {
      isAutoConsensus = true;
      autoBtn.textContent = '⏸️ Pause Simplex BFT Stream';
      autoBtn.className = 'btn btn-secondary btn-lg';
      commitBlock();
      autoInterval = setInterval(commitBlock, 200); // 200ms per block!
    }
  });

  document.getElementById('btn-gen-dkg').addEventListener('click', async () => {
    const box = document.getElementById('dkg-json-box');
    box.textContent = '⏳ Running BLS12-381 Distributed Key Generation...';
    try {
      const res = await fetch('/api/crypto/dkg', { method: 'POST' });
      const data = await res.json();
      box.textContent = JSON.stringify(data.keyPair, null, 2);
    } catch (e) {
      box.textContent = `Error: ${e.message}`;
    }
  });
}

async function commitBlock() {
  try {
    const res = await fetch('/api/simplex/commit', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      appendBlockRow(data.block);
    }
  } catch (e) {
    console.warn(e);
  }
}

function appendBlockRow(block) {
  const container = document.getElementById('blocks-container');
  const empty = container.querySelector('.empty-state');
  if (empty) container.innerHTML = '';

  const row = document.createElement('div');
  row.className = 'ledger-row';
  row.innerHTML = `
    <div>
      <div style="font-weight: 700; color: #fff;">View Round #v${block.view}</div>
      <div class="mono text-muted" style="font-size: 0.72rem;">Leader: ${block.leader.slice(0, 14)}...</div>
    </div>
    <div style="text-align: right;">
      <div style="color: #f97316; font-weight: 700; font-family: var(--font-mono);">${block.finalityLatencyMs} Finality</div>
      <div class="mono text-muted" style="font-size: 0.72rem;">${block.quorumVotes}</div>
    </div>
  `;
  container.insertBefore(row, container.firstChild);
}
