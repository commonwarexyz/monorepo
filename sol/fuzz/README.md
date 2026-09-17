# commonware-sol-fuzz

Generate and verify Commonware inputs for Solidity differential tests.
Commands print one hex-encoded ABI value. Run from the repository root.

```sh
cargo build --release --locked -p commonware-sol-fuzz
cargo test --release --locked -p commonware-sol-fuzz
target/release/commonware-sol-fuzz bmt --help
target/release/commonware-sol-fuzz merkle --help
target/release/commonware-sol-fuzz simplex --help
```

`bmt` generates and checks binary Merkle tree proofs.
`merkle` generates and checks MMR and MMB proofs.
`simplex` recovers seeded 3-of-4 threshold signatures, hashes messages to curve
points, and checks signatures. Its ABI formats are documented in `src/simplex.rs`.
