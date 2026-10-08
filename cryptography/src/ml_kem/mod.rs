//! ML-KEM-768 (FIPS 203) key encapsulation.
//!
//! Decapsulation uses implicit rejection: a modified ciphertext produces an unrelated shared
//! secret. A protocol must confirm possession of the shared secret before accepting an exchange.
//!
//! Seeds, expanded decapsulation keys, and wrapper-owned secret buffers zeroize on drop.
//! The upstream implementation does not zeroize all of its internal temporary values.
//!
//! # Examples
//!
//! ```
//! use commonware_cryptography::{Kem as _, ml_kem::MlKem768};
//! use commonware_utils::sys_rng;
//!
//! let mut rng = sys_rng();
//! let kem = MlKem768;
//! let (dk, ek) = kem.generate(&mut rng);
//! let (ct, sent) = kem.encapsulate(&mut rng, &ek).unwrap();
//! let received = kem.decapsulate(dk, &ct).unwrap();
//! assert_eq!(sent, received);
//! ```

mod kem;

pub use kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768, SharedSecret};

#[cfg(test)]
mod tests;
