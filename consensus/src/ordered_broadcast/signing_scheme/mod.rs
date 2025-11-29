//! Signing schemes for ordered broadcast.

use super::types::AckContext;
use crate::signing_scheme::Scheme;
use commonware_cryptography::{Digest, PublicKey};

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;

pub trait OrderedBroadcastScheme<P: PublicKey, D: Digest>:
    for<'a> Scheme<Context<'a, D> = AckContext<'a, P, D>, PublicKey = P>
{
}

impl<P: PublicKey, D: Digest, S> OrderedBroadcastScheme<P, D> for S where
    S: for<'a> Scheme<Context<'a, D> = AckContext<'a, P, D>, PublicKey = P>
{
}
