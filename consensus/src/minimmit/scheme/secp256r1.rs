//! Secp256r1 (P-256/NIST P-256) implementation of the [`Scheme`] trait for `minimmit`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.
//!
//! This scheme supports HSM (Hardware Security Module) integration for key management.

use crate::minimmit::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_secp256r1;

impl_certificate_secp256r1!(Subject<'a, D>, Namespace);
