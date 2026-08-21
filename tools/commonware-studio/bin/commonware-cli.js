#!/usr/bin/env node

/**
 * Commonware Primitives CLI
 */

import { defaultSimplexEngine } from '../src/core/simplex-consensus.js';
import { defaultBlsEngine } from '../src/core/bls-dkg.js';

const args = process.argv.slice(2);
const command = args[0] || 'help';

async function main() {
  switch (command.toLowerCase()) {
    case 'commit': {
      console.log('\n⚡ Proposing & Finalizing Block via Simplex BFT (~200ms)...');
      const block = defaultSimplexEngine.proposeAndCommitBlock();
      console.log(`  View Round:        v${block.view}`);
      console.log(`  Block Hash:        ${block.blockHash}`);
      console.log(`  Threshold Sig:     ${block.thresholdSig.slice(0, 18)}...`);
      console.log(`  Finality Latency:  ${block.finalityLatencyMs}`);
      console.log(`  Quorum:            ${block.quorumVotes}\n`);
      break;
    }

    case 'dkg': {
      console.log('\n🔐 Generating BLS12-381 Threshold DKG Keys...');
      const keys = defaultBlsEngine.generateThresholdKeyPair();
      console.log(`  Curve:             ${keys.curve}`);
      console.log(`  Threshold:         ${keys.threshold}`);
      console.log(`  Group Public Key:  ${keys.groupPublicKey.slice(0, 24)}...`);
      console.log(`  DKG Status:        ${keys.dkgStatus}\n`);
      break;
    }

    case 'studio': {
      console.log('\n🌐 Launching Commonware Studio on :3419...');
      await import('../src/server/app.js');
      break;
    }

    default: {
      console.log(`
╔══════════════════════════════════════════════════════════════════╗
║               🛠️ COMMONWARE PRIMITIVES CLI                      ║
║     Simplex BFT Consensus & BLS12-381 Threshold DKG Suite        ║
╚══════════════════════════════════════════════════════════════════╝

Commands:
  commonware-cli commit                 Commit block via Simplex BFT (~200ms)
  commonware-cli dkg                    Generate BLS12-381 DKG threshold keys
  commonware-cli studio                 Launch Interactive Web Studio on :3419
      `);
      break;
    }
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
