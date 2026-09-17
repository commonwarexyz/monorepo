# commonware-sol-fuzz

Generate and verify Commonware inputs for Solidity differential tests.
Commands print one hex-encoded ABI value. Run from the repository root.

```sh
cargo build --release --locked -p commonware-sol-fuzz
cargo test --release --locked -p commonware-sol-fuzz
target/release/commonware-sol-fuzz bmt --help
target/release/commonware-sol-fuzz certificate --help
target/release/commonware-sol-fuzz merkle --help
target/release/commonware-sol-fuzz simplex --help
```

Certificate commands accept `minsig` or `minpk` as the variant:

```text
certificate generate <variant> <namespace_hex> <message_hex> <seed>
certificate hash <variant> <namespace_hex> <message_hex>
certificate check <variant> <public_key_hex> <namespace_hex> <message_hex> <signature_hex>
```

- `bmt`: Generate and check binary Merkle tree proofs.
- `certificate`: Recover seeded 3-of-4 BLS12-381 threshold certificates, hash
  namespace-framed messages to curve points, and check recovered signatures. Its ABI
  formats are documented in [src/certificate.rs](src/certificate.rs).
- `merkle`: Generate and check MMR and MMB proofs.
- `simplex`: Recover seeded 3-of-4 threshold signatures for encoded Simplex voting
  subjects. It delegates certificate framing and cryptography to `certificate`.

`bmt` and `merkle` use Keccak256 by default. Pass `--hash sha256` to use SHA-256.
