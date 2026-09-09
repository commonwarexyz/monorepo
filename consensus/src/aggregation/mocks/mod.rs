//! Mock implementations for testing.

mod application;
pub use application::{Application, Strategy};
mod reporter;
pub use reporter::{Mailbox as ReporterMailbox, Reporter};
pub mod scheme;
