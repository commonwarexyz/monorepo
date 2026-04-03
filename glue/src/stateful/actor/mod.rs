mod core;
pub use core::{Config, StartupMode, Stateful};

mod mailbox;
pub use mailbox::Mailbox;

mod bootstrap;

mod metrics;

mod processor;
