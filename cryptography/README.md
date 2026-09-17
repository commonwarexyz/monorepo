# commonware-cryptography

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography.svg)](https://crates.io/crates/commonware-cryptography)
[![Docs.rs](https://docs.rs/commonware-cryptography/badge.svg)](https://docs.rs/commonware-cryptography)

Generate keys, sign arbitrary messages, and deterministically verify untrusted signatures.

Native arithmetic implementations are available in [curve25519](curve25519) and
[bls](bls). The BLS crate uses the shared [vroom](vroom) prime-field core.

## Status 

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
