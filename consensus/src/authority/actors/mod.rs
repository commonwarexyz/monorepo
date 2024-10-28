pub mod resolver;
pub mod voter;

use crate::authority::{wire, Height, View};
use commonware_cryptography::Digest;

#[derive(Clone)]
pub(crate) enum Proposal {
    Reference(View, Height, Digest),
    Populated(Digest, wire::Proposal),
    Null(View),
}
