# commonware-revm-chain

[![Crates.io](https://img.shields.io/crates/v/commonware-revm-chain.svg)](https://crates.io/crates/commonware-revm-chain)

REVM-based example chain driven by threshold-simplex (`commonware_consensus::simplex`) and executed with `alloy-evm`.

## What This Demonstrates

- Threshold-simplex orders opaque 32-byte digests; full blocks are delivered out-of-band over `commonware_p2p::simulated`.
- Blocks carry a batch of EVM transactions plus an advertised 32-byte `state_root` commitment.
- Validators re-execute proposed blocks with `alloy-evm` / `revm` and reject proposals whose `state_root` mismatches.
- State is kept in REVM's in-memory DB (`alloy_evm::revm::database::InMemoryDB`) behind the `Database + DatabaseCommit` seam.
- State commitment is deterministic and does not require iterating the whole DB:
  - `delta = keccak256(Encode(StateChanges))`
  - `new_root = keccak256(prev_root || delta)`
- Seed plumbing: threshold-simplex certificate seed signatures are hashed to 32 bytes and injected as `block.prevrandao` (EIP-4399).
- Bonus: a stateful precompile at `0x00000000000000000000000000000000000000ff` returns the current block's `prevrandao` (32 bytes).

## Components

- `src/consensus/`: glue implementing Simplex `Automaton` / `Relay` / `Reporter` over a mailbox.
- `src/application/`: block store, proposal/verification logic, out-of-band block gossip, and query handle.
- `src/execution.rs`: EVM execution (`EthEvmBuilder`) and the seed precompile.
- `src/commitment.rs`: canonical `StateChanges` encoding and rolling `StateRoot` commitment.
- `src/sim/`: deterministic, single-process simulation harness (N nodes, simulated P2P).

## Run (Deterministic Simulation)

```sh
cargo run -p commonware-revm-chain --release -- --nodes 4 --blocks 5 --seed 1
```

Flags:

- `--nodes`: number of validators (default: 4)
- `--blocks`: number of finalized blocks to wait for per node (default: 3)
- `--seed`: deterministic simulation seed (default: 1)

Expected output is deterministic for a given `--seed` and includes:

- Finalized head digest (agreed by consensus)
- Final `state_root` commitment
- Final balances for the example accounts
- Latest tracked threshold seed (32 bytes) and the current block's `prevrandao`

## Test

```sh
cargo test -p commonware-revm-chain
```

## Notes and Next Steps

- This is intentionally minimal and does not implement an Ethereum trie or block syncing; `state_root` is a rolling commitment over per-tx state deltas.
- The demo block stream is minimal (a single transfer is injected early); extend `src/application/` to add more tx generation.
- A future persistent backend can be implemented by adapting a Commonware storage primitive to the `Database` / `DatabaseCommit` seam (note the async/sync impedance mismatch).
