//! MAYO implementations of the [crate::Verifier] and [crate::Signer] traits.
//!
//! MAYO is a multivariate quadratic signature scheme based on the Oil and Vinegar
//! trapdoor and is a candidate in the NIST post-quantum signature standardization
//! process. This module wraps the reference MAYO-C implementation via the
//! [sriracha_mayo] bindings, which build the C library at compile time (a C
//! toolchain and CMake are required). The module is unavailable on `wasm32`
//! targets.
//!
//! # Parameter Sets
//!
//! Each parameter set is exposed as its own submodule with concrete key and
//! signature types:
//!
//! | Module    | NIST Level | Secret Seed | Public Key | Signature |
//! |-----------|------------|-------------|------------|-----------|
//! | [mayo1]   | 1          | 24 bytes    | 1420 bytes | 454 bytes |
//! | [mayo2]   | 1          | 24 bytes    | 4912 bytes | 186 bytes |
//! | [mayo3]   | 3          | 32 bytes    | 2986 bytes | 681 bytes |
//! | [mayo5]   | 5          | 40 bytes    | 5554 bytes | 964 bytes |
//!
//! MAYO-2 trades a much larger public key for the smallest signatures. A
//! private key serializes as its secret seed; the public key is re-derived
//! on decode.
//!
//! # Randomized Signatures
//!
//! MAYO signing draws a fresh salt (from the operating system, inside MAYO-C)
//! for every signature, so signing the same message twice produces different
//! signatures. Verification is deterministic.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{mayo::mayo1, PrivateKey, PublicKey, Signature, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let signer = mayo1::PrivateKey::random(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

mod scheme;
pub use scheme::{mayo1, mayo2, mayo3, mayo5};
