//! FN-DSA (Falcon) implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside individual signatures,
//! enabling secure per-validator activity tracking and fault detection.
//!
//! FN-DSA has no batch verification, so the batcher verifies signatures immediately as they
//! arrive rather than waiting to batch them. Signatures are post-quantum secure and much smaller
//! than ML-DSA signatures (666 bytes for [`FnDsa512`](commonware_cryptography::fn_dsa::FnDsa512),
//! 1280 bytes for [`FnDsa1024`](commonware_cryptography::fn_dsa::FnDsa1024)).
//!
//! [`EllipsoidalFalcon512`](commonware_cryptography::fn_dsa::EllipsoidalFalcon512) uses the same
//! individual-signature certificate flow with a distinct experimental signing profile. It is
//! not standard FN-DSA and is not assigned a NIST security category.
//!
//! **Experimental**: FIPS 206 is unpublished and the signature and key encodings may change
//! (see [commonware_cryptography::fn_dsa]).

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_fn_dsa;
use commonware_utils::N3f1;

impl_certificate_fn_dsa!(Subject<'a, D>, Namespace, N3f1);
