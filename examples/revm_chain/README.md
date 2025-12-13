# commonware-revm-chain

Educational example showing how to wire:

`consensus::simplex` (threshold-simplex via `bls12381_threshold`) -> block production/verification -> EVM execution (`alloy-evm` + `revm`) -> 32-byte state commitment.

This example intentionally keeps the storage backend in-memory and focuses on:

- Consensus proposals are `BlockId` (a hash/commitment); full blocks are gossiped separately.
- Validators verify proposals by re-executing the block and checking the advertised `state_root`.
- A per-finalization threshold seed is tracked and made available to execution via `block.prevrandao` (EIP-4399).
- Bonus: a custom precompile exposes the current block's `prevrandao` to contracts.

## Run

```sh
cargo run -p commonware-revm-chain --release -- --nodes 4 --blocks 5 --seed 1
```

Expected output is deterministic for a given `--seed` and includes:

- Produced/finalized block count
- Final state commitment
- Final balances for the example accounts
- Latest threshold seed (hashed to 32 bytes) and the current block's `prevrandao`

## Test

```sh
cargo test -p commonware-revm-chain
```

## Notes

- This uses `alloy-evm` as the integration layer above `revm`, while keeping the state backend swappable (generic over the `Database` trait).
- The demo DB is REVM's in-memory `CacheDB` (via `alloy_evm::revm::database::InMemoryDB`).
- The "state root" is a deterministic 32-byte commitment (not an Ethereum Merkle-Patricia trie). The example uses a rolling commitment so it does not require iterating all accounts from the DB.
- The "threshold seed" is derived from the threshold-simplex certificate seed signature and hashed to 32 bytes with Keccak-256 (`B256`).
- The seed precompile address is `0x00000000000000000000000000000000000000ff` and returns 32 bytes (the current block's `prevrandao`).
