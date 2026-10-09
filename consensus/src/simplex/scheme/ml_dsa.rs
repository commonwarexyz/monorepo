//! ML-DSA-65 implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside individual signatures,
//! enabling secure per-validator activity tracking and fault detection.
//!
//! ML-DSA has no batch verification, so the batcher verifies signatures immediately as they
//! arrive rather than waiting to batch them. Signatures are post-quantum secure but large
//! (3309 bytes), so certificates grow quickly with the quorum size.

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_ml_dsa;
use commonware_utils::N3f1;

impl_certificate_ml_dsa!(Subject<'a, D>, Namespace, N3f1);
