# REVM Example Docs

These docs describe the REVM-based example chain in this repository. They are written for multiple
audiences and multiple depths so you can choose how far to go.

## Who should read what

- If you want to run the example or understand what it demonstrates, start here and then read
  ARCHITECTURE.md.
- If you want to contribute code or review logic, read ARCHITECTURE.md and DOMAIN_MODEL.md.
- If you want to reason about invariants and failure handling, focus on the "Safety and invariants"
  sections in ARCHITECTURE.md and DOMAIN_MODEL.md.

## Quickstart

From the repository root:

```
cargo run -p commonware-revm --release -- --nodes 4 --blocks 5 --seed 1
```

You should see:
- A finalized head digest
- The state root commitment
- Final balances for the demo accounts
- The latest seed hash and the current block prevrandao

## Document map

| Doc | Purpose | Read when |
| --- | --- | --- |
| ARCHITECTURE.md | System overview, flows, and runtime boundaries | You want to understand how the example works end to end |
| DOMAIN_MODEL.md | Domain terms, aggregates, invariants, and events | You want to modify logic or review correctness |

## Key ideas in one page

- Digest first: consensus orders a 32-byte digest, not the full block.
- Full blocks are disseminated by marshal and verified by re-execution.
- State roots are QMDB partition roots (pre-commit), not an Ethereum trie.
- QMDB writes are batched on finalization for persistence.
- The example uses tokio because REVM requires a tokio runtime to bridge async QMDB to sync REVM.

## Diagrams

The docs reference three diagrams. The PNGs are checked in, and the DOT files are the sources.

- revm_architecture.png (source: revm_architecture.dot)
- revm_block_lifecycle.png (source: revm_block_lifecycle.dot)
- revm_persistence_flow.png (source: revm_persistence_flow.dot)

To regenerate the PNGs:

```
cd examples/revm/docs
for f in revm_architecture revm_block_lifecycle revm_persistence_flow; do
  dot -Tpng "$f.dot" -o "$f.png"
done
```

## Scope and non-goals

This is an example chain. It intentionally omits many Ethereum features (signatures, fee market,
MPT state root, etc.). The goal is to demonstrate how Commonware primitives can drive a minimal
EVM execution pipeline with authenticated persistence.
