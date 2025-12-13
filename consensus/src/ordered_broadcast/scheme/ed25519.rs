//! Ed25519 implementation of the [`Scheme`] trait for `ordered_broadcast`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.

use crate::{ordered_broadcast::types::AckContext, scheme::impl_ed25519_scheme};
use commonware_cryptography::ed25519;

impl_ed25519_scheme!(AckContext<'a, ed25519::PublicKey, D>);
