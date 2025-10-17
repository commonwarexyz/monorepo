//! DKG participant actor

mod actor;
pub use actor::{Actor, Config};

mod ingress;
pub use ingress::{Mailbox, Message};

mod types;
pub use types::{DealOutcome, Dkg, Payload};

mod manager;
pub use manager::DkgManager;
