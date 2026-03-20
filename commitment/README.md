# commonware-commitment

[![Crates.io](https://img.shields.io/crates/v/commonware-commitment.svg)](https://crates.io/crates/commonware-commitment)
[![Docs.rs](https://docs.rs/commonware-commitment/badge.svg)](https://docs.rs/commonware-commitment)

Commit to polynomials with compact proofs and efficient verification.

Implements the [Ligerito](https://angeris.github.io/papers/ligerito.pdf) polynomial
commitment scheme over binary extension fields (GF(2^32), GF(2^128)). Produces
~130 KB proofs for polynomials of 2^20 elements with sub-millisecond verification.

## Status

`ALPHA`: Breaking changes expected. No migration path provided.

## Performance

Benchmarked on AMD Ryzen 9 7945HX, 8 physical cores, SMT disabled,
`RUSTFLAGS="-C target-cpu=native"`:

| Operation | 2^20 polynomial |
|-----------|----------------|
| Prove     | 62 ms          |
| Verify    | 411 us         |
| Proof size | 130 KB        |

## Usage

```rust
use commonware_commitment::{
    field::{BinaryElem128, BinaryElem32},
    prover_config_for_log_size, verifier_config_for_log_size,
    transcript::Sha256Transcript,
};

// Configure for 2^20 polynomial
let prover_cfg = prover_config_for_log_size::<BinaryElem32, BinaryElem128>(20);
let verifier_cfg = verifier_config_for_log_size(20);

let poly = vec![BinaryElem32::from(42u32); 1 << 20];

// Prove
let mut pt = Sha256Transcript::new(0);
let proof = commonware_commitment::prove(&prover_cfg, &poly, &mut pt).unwrap();

// Verify
let mut vt = Sha256Transcript::new(0);
let valid = commonware_commitment::verify(&verifier_cfg, &proof, &mut vt).unwrap();
assert!(valid);
```
