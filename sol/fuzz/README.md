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

- `bmt`: Generate and check binary Merkle tree proofs.
- `merkle`: Generate and check MMR and MMB proofs.
- `simplex`: Recover seeded 3-of-4 threshold signatures, hash messages to curve
  points, and check signatures. Its ABI formats are documented in [src/simplex.rs](src/simplex.rs).

`bmt` and `merkle` use Keccak256 by default. Pass `--hash sha256` to use SHA-256.
