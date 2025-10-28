//! DKG participant actor

mod actor;
pub use actor::{Actor, Config};

mod ingress;
pub use ingress::{Mailbox, Message};
