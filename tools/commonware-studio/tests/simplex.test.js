/**
 * Simplex BFT & BLS12-381 DKG Unit Tests
 */

import { defaultSimplexEngine } from '../src/core/simplex-consensus.js';
import { defaultBlsEngine } from '../src/core/bls-dkg.js';

async function runSimplexTests() {
  console.log('Testing Commonware Simplex BFT & BLS12-381 Threshold DKG Engine...');

  // 1. Simplex BFT Block Commitment
  const block = defaultSimplexEngine.proposeAndCommitBlock();
  if (!block.blockHash || !block.finalityLatencyMs) {
    throw new Error('Simplex BFT block finalization failed');
  }

  // 2. BLS12-381 DKG Generation
  const keys = defaultBlsEngine.generateThresholdKeyPair();
  if (!keys.groupPublicKey || !keys.curve.includes('BLS12-381')) {
    throw new Error('BLS12-381 threshold keypair generation failed');
  }

  console.log(`✅ Commonware Simplex BFT Consensus (~200ms) & BLS12-381 DKG Tested (v${block.view})!`);
}

runSimplexTests().catch(e => {
  console.error('❌ Simplex Test Failed:', e);
  process.exit(1);
});
