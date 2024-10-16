pub mod resolver;
pub mod voter;

use crate::{authority::wire, Hash, Height, View};

#[derive(Clone)]
pub(crate) enum Proposal {
    Reference(View, Height, Hash),
    Populated(Hash, wire::Proposal),
}
