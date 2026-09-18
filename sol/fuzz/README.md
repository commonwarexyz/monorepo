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

```text
certificate threshold generate <variant> <namespace_hex> <message_hex> <seed>
certificate threshold check <variant> <public_key_hex> <namespace_hex> <message_hex> <signature_hex>
certificate multisig generate <variant> <namespace_hex> <message_hex> <participants> <signers_hex> <seed>
certificate multisig check <variant> <public_keys_hex> <signers_hex> <quorum> <namespace_hex> <message_hex> <signature_hex>
certificate hash <variant> <namespace_hex> <message_hex>
simplex generate <scheme> <variant> <kind> <namespace_hex> <epoch> <view> <parent> <payload_hex> <seed> [--participants <n>] [--signers-hex <bitmap>]
```

- `bmt`: Generate and check binary Merkle tree proofs.
- `certificate`: Generate and check BLS12-381 certificates, or hash namespaced messages
  to curve points.
- `merkle`: Generate and check MMR and MMB proofs.
- `simplex`: Generate Simplex signatures. `--participants` and `--signers-hex` apply
  to `multisig` and default to `4` and `0x07`.
