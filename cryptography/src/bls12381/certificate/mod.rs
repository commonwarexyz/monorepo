//! BLS12-381 certificate scheme implementations.
//!
//! This module provides two signing scheme implementations:
//!
//! - [`multisig`]: Multi-signature scheme with attributable signatures
//! - [`threshold`]: Threshold signature scheme with non-attributable signatures

pub mod multisig;
pub mod threshold;

use crate::{
    bls12381::primitives::{sharing::Sharing, variant::Variant},
    certificate::{AssemblyError, Signers},
};
use commonware_utils::Participant;

/// Builds [`Signers`] using the sharing's participant bound and recovery threshold.
impl<'a, V, I> TryFrom<(&'a Sharing<V>, I)> for Signers
where
    V: Variant,
    I: IntoIterator<Item = Participant>,
{
    type Error = AssemblyError;

    fn try_from((quorum, signers): (&'a Sharing<V>, I)) -> Result<Self, Self::Error> {
        Self::new(quorum.total().get(), signers)?.require(quorum.required())
    }
}
