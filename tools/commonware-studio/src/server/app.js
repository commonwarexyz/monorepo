/**
 * Commonware Studio Web Server
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { COMMONWARE_CONFIG } from '../config.js';
import { defaultSimplexEngine } from '../core/simplex-consensus.js';
import { defaultBlsEngine } from '../core/bls-dkg.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WEB_ROOT = path.join(__dirname, '../../web');

const app = express();
const PORT = process.env.PORT || 3419;

app.use(cors());
app.use(express.json());
app.use(express.static(WEB_ROOT));

// 1. Get Architecture & Primitives Info
app.get('/api/config', (req, res) => {
  res.json({
    architecture: COMMONWARE_CONFIG.architecture,
    simplexRounds: COMMONWARE_CONFIG.simplexRounds,
    primitives: COMMONWARE_CONFIG.cryptoPrimitives,
  });
});

// 2. Propose & Commit Simplex BFT Block
app.post('/api/simplex/commit', (req, res) => {
  const block = defaultSimplexEngine.proposeAndCommitBlock();
  res.json({ success: true, block });
});

// 3. Simplex Blocks Ledger
app.get('/api/simplex/blocks', (req, res) => {
  res.json(defaultSimplexEngine.getCommittedBlocks());
});

// 4. Generate BLS12-381 Threshold Key Pair
app.post('/api/crypto/dkg', (req, res) => {
  const keyPair = defaultBlsEngine.generateThresholdKeyPair();
  res.json({ success: true, keyPair });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`🛠️  Commonware Modular Primitives & Simplex BFT Studio Running!`);
    console.log(`🌐 Web Dashboard: http://localhost:${PORT}`);
    console.log(`⚡ Finality: ~200ms Simplex BFT Consensus`);
    console.log(`======================================================\n`);
  });
}

export default app;
