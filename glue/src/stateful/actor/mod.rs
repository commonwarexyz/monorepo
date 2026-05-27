mod core;
pub use core::{Config, Mailbox, Stateful};

mod syncer;
pub use syncer::SyncPlan;

mod processor;
