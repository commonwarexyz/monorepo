# commonware-sol-fuzz

Generate and verify Commonware inputs for Solidity differential tests.
Commands print one hex-encoded ABI value. Run from the repository root.

```sh
cargo build --release --locked -p commonware-sol-fuzz
cargo test --release --locked -p commonware-sol-fuzz
target/release/commonware-sol-fuzz bmt --help
target/release/commonware-sol-fuzz certificate --help
target/release/commonware-sol-fuzz merkle --help
target/release/commonware-sol-fuzz qmdb --help
target/release/commonware-sol-fuzz simplex --help
```

- `bmt`: Generate and check binary Merkle tree proofs.
- `certificate`: Generate and check BLS12-381 certificates, or hash namespaced messages
  to curve points.
- `merkle`: Generate and check MMR and MMB proofs.
- `qmdb`: Generate QMDB operation and exclusion proofs.
- `simplex`: Generate Simplex signatures.
