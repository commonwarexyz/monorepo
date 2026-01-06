//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `minimmit`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.
//!
//! This scheme produces compact aggregate signatures, reducing certificate size compared to
//! schemes that store individual signatures.

use crate::minimmit::types::Subject;
use commonware_cryptography::impl_certificate_bls12381_multisig;

impl_certificate_bls12381_multisig!(Subject<'a, D>);
