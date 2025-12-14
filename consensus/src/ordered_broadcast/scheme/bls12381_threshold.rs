//! BLS12-381 threshold implementation of the [`Scheme`] trait for `ordered_broadcast`.
//!
//! [`Scheme`] is **non-attributable**: exposing partial signatures
//! as evidence of either liveness or of committing a fault is not safe. With threshold signatures,
//! any `t` valid partial signatures can be used to forge a partial signature for any other player,
//! enabling equivocation attacks. Because peer connections are authenticated, evidence can be used locally
//! (as it must be sent by said participant) but can't be used by an external observer.

use crate::ordered_broadcast::types::AckContext;
use commonware_cryptography::impl_bls12381_threshold_certificate;

impl_bls12381_threshold_certificate!(AckContext<'a, P, D>);
