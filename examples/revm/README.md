# commonware-revm

[![Crates.io](https://img.shields.io/crates/v/commonware-revm.svg)](https://crates.io/crates/commonware-revm)

REVM-based example chain driven by threshold-simplex (`commonware_consensus::simplex`) and executed with `alloy-evm`.

## What This Demonstrates

- Threshold-simplex orders opaque 32-byte digests; full blocks are disseminated and backfilled by `commonware_consensus::marshal` over `commonware_p2p::simulated`.
- Blocks carry a batch of EVM transactions plus an advertised 32-byte `state_root` commitment.
- Validators re-execute proposed blocks with `alloy-evm` / `revm` and reject proposals whose `state_root` mismatches.
- State is persisted in QMDB and exposed to REVM via `WrapDatabaseAsync` + `CacheDB` (QMDB is the base store; CacheDB is the speculative overlay).
- The `state_root` is derived from authenticated QMDB partition roots (accounts, storage, code).
- Seed plumbing: threshold-simplex certificate seed signatures are hashed to 32 bytes and injected as `block.prevrandao` (EIP-4399).
- Bonus: a stateful precompile at `0x00000000000000000000000000000000000000ff` returns the current block's `prevrandao` (32 bytes).

## Components

- `src/domain/`: canonical block/tx types, commitment mapping, and deterministic state-change encoding.
- `src/application/`: proposal/verification logic (marshaled), shared state (mempool + DB snapshots), reporters, and query handle.
- `src/application/execution.rs`: EVM execution (`EthEvmBuilder`) and the seed precompile.
- `src/qmdb/`: QMDB-backed persistence and REVM database adapter.
- `src/simulation/`: tokio, single-process simulation harness (N nodes, simulated P2P).

## How It Works

This example is intentionally "digest-first":

- Simplex agrees on a `ConsensusDigest` for each height (32 bytes).
- The application maps `ConsensusDigest <-> Block` and ensures a digest is only accepted if the
  corresponding block re-executes to the advertised `state_root`.

### Block Lifecycle (One Height)

1. Genesis: the application creates the genesis block and prefunds accounts in the EVM DB.
2. Propose: when Simplex asks a leader to propose, the application builds a child block, executes
   its txs, stores the block + resulting DB snapshot locally, and returns the full block to the
   `commonware_consensus::application::marshaled::Marshaled` wrapper (consensus still orders only
   the block commitment digest).
3. Disseminate: marshal broadcasts the full block and serves backfill requests for missing ancestors.
4. Verify: validators re-execute the block on the parent snapshot and accept only if the computed
   `state_root` matches the advertised `state_root` (the wrapper notifies marshal on success).
5. Finalize: marshal delivers finalized blocks to the node, the simulation records the digest, and stops after the configured
   number of finalizations per node.

The main glue points are `src/application/node/start.rs` (wiring) and `src/application/` (application logic).

### Seed Lifecycle

- On notarization/finalization, threshold-simplex emits a seed signature.
- This example hashes that seed signature to 32 bytes and stores it alongside the finalized digest.
- The next block uses the parent digest's stored seed hash as `prevrandao` (EIP-4399).
- The seed precompile returns the current block's `prevrandao` so contracts can read it.

### State Root Semantics

- Block headers publish the pre-commit QMDB root computed after merkleization but before durability is enforced.
- QMDB commit operations append to the authenticated log, so the post-commit root can differ even when state does not.
- Treat the header `state_root` as the consensus commitment and do not compare it to the post-commit QMDB root.

## Run (Tokio Simulation)

```sh
cargo run -p commonware-revm --release -- --nodes 4 --blocks 5 --seed 1
```

Flags:

- `--nodes`: number of validators (default: 4)
- `--blocks`: number of finalized blocks to wait for per node (default: 3)
- `--seed`: seeded DKG + demo inputs (default: 1)

Expected output is consistent for a given `--seed` and includes:

- Finalized head digest (agreed by consensus)
- Final `state_root` commitment
- Final balances for the example accounts
- Latest tracked threshold seed (32 bytes) and the current block's `prevrandao`

## Test

```sh
cargo test -p commonware-revm
```

## Notes and Next Steps

- This is intentionally minimal and does not implement an Ethereum trie; `state_root` comes from authenticated QMDB partition roots.
- Transactions are built directly as EVM call environments (no signature/fee market modeling); gas price is set to 0.
- The demo block stream is minimal (a single transfer is injected early); extend `src/application/` to add more tx generation.
- The example now uses a QMDB-backed persistence layer with per-finalized-block batch commits.
