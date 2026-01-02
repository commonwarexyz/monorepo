//! Mock implementations for testing.

mod automaton;
pub use automaton::Automaton;
mod drop_first_automaton;
pub use drop_first_automaton::DropFirstAutomaton;
mod monitor;
pub use monitor::Monitor;
mod reporter;
pub use reporter::{Mailbox as ReporterMailbox, Reporter};
mod sequencers;
pub use sequencers::Sequencers;
mod provider;
pub use provider::Provider;
