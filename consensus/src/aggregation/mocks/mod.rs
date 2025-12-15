//! Mock implementations for testing.

mod application;
pub use application::{Application, Strategy};
pub mod fixtures;
mod monitor;
pub use monitor::Monitor;
mod reporter;
pub use reporter::{Mailbox as ReporterMailbox, Reporter};
mod scheme_provider;
pub use scheme_provider::Provider;
