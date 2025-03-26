//! Mock implementations for testing.

mod automaton;
pub use automaton::Automaton;
mod committer;
pub use committer::{Committer, Mailbox as CommitterMailbox};
mod monitor;
pub use monitor::Monitor;
mod sequencers;
pub use sequencers::Sequencers;
mod validators;
pub use validators::Validators;
