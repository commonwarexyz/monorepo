# commonware-cryptography-curve25519

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-curve25519.svg)](https://crates.io/crates/commonware-cryptography-curve25519)
[![Docs.rs](https://docs.rs/commonware-cryptography-curve25519/badge.svg)](https://docs.rs/commonware-cryptography-curve25519)

Perform Curve25519 field/group arithmetic, Ed25519 signing and verification, and X25519 key exchange.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

The `batch` module is BETA and verifies Ed25519 signatures over already-framed payloads
using ZIP215 rules. The `signing` and `key_exchange` modules remain ALPHA.

Batch verification selects AVX-512F/IFMA on supported x86-64 CPUs, NEON on AArch64, and
portable arithmetic elsewhere. `batch::is_accelerated()` reports whether a SIMD backend was
selected.
