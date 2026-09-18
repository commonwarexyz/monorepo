# commonware-sol-fuzz

Generate and verify Commonware inputs for Solidity differential tests.
Commands print one hex-encoded ABI value. Run from the repository root.

```sh
cargo build --release --locked -p commonware-sol-fuzz
cargo test --release --locked -p commonware-sol-fuzz
target/release/commonware-sol-fuzz bmt --help
target/release/commonware-sol-fuzz certificate --help
target/release/commonware-sol-fuzz merkle --help
target/release/commonware-sol-fuzz multisig --help
target/release/commonware-sol-fuzz simplex --help
```

Certificate commands accept `minsig` or `minpk` as the variant:

```text
certificate generate <variant> <namespace_hex> <message_hex> <seed>
certificate hash <variant> <namespace_hex> <message_hex>
certificate check <variant> <public_key_hex> <namespace_hex> <message_hex> <signature_hex>
multisig generate <variant> <namespace_hex> <message_hex> <participants> <signers_hex> <seed>
multisig check <variant> <public_keys_hex> <signers_hex> <quorum> <namespace_hex> <message_hex> <signature_hex>
simplex generate-multisig <variant> <kind> <namespace_hex> <epoch> <view> <parent> <payload_hex> <seed> [--participants <n>] [--signers-hex <bitmap>]
```

- `bmt`: Generate and check binary Merkle tree proofs.
- `certificate`: Recover seeded 3-of-4 BLS12-381 threshold certificates, hash
  namespace-framed messages to curve points, and check recovered signatures. Its ABI
  formats are documented in [src/certificate.rs](src/certificate.rs).
- `merkle`: Generate and check MMR and MMB proofs.
- `multisig`: Generate seeded BLS12-381 keys and aggregate signatures, or verify
  an aggregate against a caller-selected quorum. Public keys are concatenated EIP-2537
  padded points in authenticated participant order. Signers are a raw, unframed bitmap,
  exactly `ceil(participants / 8)` bytes, with participant `i` at LSB-first bit `i`.
  Generated subsets may be below an N3f1 quorum so cryptographic validity and quorum
  policy can be tested independently.
- `simplex`: Recover seeded 3-of-4 threshold signatures or generate seeded BLS
  multi-signatures for encoded Simplex voting subjects. `generate-multisig` defaults to
  four participants and `0x07` (participants 0, 1, and 2), and accepts custom
  `--participants` and `--signers-hex` values.

Aggregate verification is secure only when the caller authenticated the participant ordering,
verified a proof of possession for every registered BLS public key, and rejected duplicate keys.
The generator validates proofs of possession for all fixture keys before producing output; the
`check` command assumes registration performed the authentication and PoP checks because proofs
are not part of its input.

`bmt` and `merkle` use Keccak256 by default. Pass `--hash sha256` to use SHA-256.
