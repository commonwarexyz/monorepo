# commonware-sol

Verify proofs and certificates in Solidity.

BLS12-381 certificates support both MinSig (G1 signatures and G2 public keys) and
MinPk (G2 signatures and G1 public keys). `LibBLS12381Threshold` verifies recovered
threshold signatures. `LibBLS12381Multisig` verifies an aggregate signature against
the selected members of an authenticated committee and a required quorum.
`LibSimplex` supplies vote domains, subject encoding, and the Simplex multisig
quorum.

The BLS libraries require the EIP-2537 precompiles. Signatures use uncompressed
48-byte field elements; public keys use 64-byte padded field elements. G2 points
place the real component before the imaginary component. Convert Rust's compressed
points before calling these libraries.

Multisig signer bitmaps use one bit per committee member, least significant bit
first within each byte, without Rust's encoded bitmap length prefix. Supply exactly
`ceil(committee size / 8)` bytes with unused high bits cleared. The caller must
authenticate the committee's order and identity-to-key bindings, require distinct
BLS public keys, validate each nonzero subgroup key and its proof of possession at
registration, and select the required quorum from trusted protocol context.
Simplex callers must authenticate
the committee for the subject's epoch.

## Status

ALPHA. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
