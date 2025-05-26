//! This crate contains application-specific logic.
//! For the broadcast example, this includes a simplified ApplicationActor
//! and its communication channel (ActorMailbox).

// Hasher and Array are no longer needed for the simplified Config.
// use commonware_cryptography::Hasher;
// use commonware_utils::Array;

mod actor;
pub use actor::ApplicationActor; // Updated from Application to ApplicationActor
mod ingress;
pub use ingress::ActorMailbox; // Exporting ActorMailbox as it's returned by ApplicationActor::new
mod supervisor; // Remains as a module, though supervisor.rs is now a placeholder

/// Configuration for the ApplicationActor.
// Generics P and H removed. Fields hasher and participants removed.
pub struct Config {
    /// Number of messages the actor's mailbox can hold before blocking.
    pub mailbox_size: usize,
}
