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
- `qmdb` generates QMDB operation and exclusion proofs. Its subcommands are listed below.
- `simplex`: Generate Simplex signatures.

`qmdb` uses Keccak256 by default. Pass `--hash sha256` to use SHA-256.

QMDB commands use MMB by default. Pass `--family mmr` for MMR proofs.
Range and sparse commands accept `--encoding variable` for variable-length values.

- `qmdb current` generates active operation proofs for current QMDBs.
- `qmdb lifecycle` generates proofs from committed, pruned, and reopened ordered current databases.
- `qmdb any` generates ordered operation proofs, including overwrite and deletion histories.
- `qmdb keyless` generates append and commit proofs with fixed or variable encodings.
- `qmdb unordered` generates fixed or variable operation proofs. Add `--current`
  to include activity authentication.
- `qmdb immutable` generates set and commit proofs.
- `qmdb exclude` generates ordered exclusion proofs with 32-byte keys and values.
- `qmdb exclude-variable` generates ordered exclusion proofs with Vec keys and values
  by default. `--key-size` and `--value-size` select fixed widths of 0, 1, 4, or 32 bytes.
- `qmdb range` generates range proofs. Add `--current` to authenticate bitmap state.
- `qmdb multi` generates sparse proofs. Add `--current` to authenticate historical
  operations against a current QMDB root.
