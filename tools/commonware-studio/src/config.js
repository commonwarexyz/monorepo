/**
 * Commonware Modular Primitives & Simplex BFT Configuration
 */

export const COMMONWARE_CONFIG = {
  architecture: {
    philosophy: 'Anti-Framework Composability (Unbundled Primitives)',
    consensusProtocol: 'consensus::simplex (Sub-second BFT Consensus)',
    targetFinalityMs: 220,
    cryptoSuite: 'BLS12-381 Threshold DKG & Ed25519 P2P Auth',
    storageEngine: 'commonware-storage (QMDB Merkleized KV Store)',
  },
  simplexRounds: {
    viewDurationMs: 200,
    quorumThreshold: '2f + 1 (Supermajority Threshold)',
    leaderElection: 'VRF-Based Pseudo-Random Rotational Leader',
  },
  cryptoPrimitives: [
    {
      id: 'dkg_bls12_381',
      name: 'BLS12-381 Threshold DKG',
      type: 'Distributed Key Generation',
      description: 'Public-board-less DKG for non-interactive threshold signature aggregation.',
    },
    {
      id: 'qmdb_merkle_store',
      name: 'QMDB Merkleized Storage',
      type: 'State DB',
      description: 'Zero-overhead concurrent Merkle proof key-value state engine.',
    },
  ],
};
