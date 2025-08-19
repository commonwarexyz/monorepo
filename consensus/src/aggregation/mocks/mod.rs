//! Mock implementations for testing.

mod application;
pub use application::{Application, Strategy};
mod reporter;
pub use reporter::{Mailbox as ReporterMailbox, Reporter};
mod monitor;
pub use monitor::Monitor;
mod supervisor;
pub use supervisor::Supervisor;
