//! DKG participant actor
use commonware_cryptography::bls12381::primitives::sharing::ModeVersion;

/// Highest sharing mode this example can decode/use.
pub const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v0();

mod state;

mod actor;
pub use actor::{Actor, Config};

mod ingress;
pub use ingress::{Mailbox, Message};

mod egress;
pub use egress::{ContinueOnUpdate, PostUpdate, Update, UpdateCallBack};
