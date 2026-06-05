mod core;
pub use core::{Config, Mailbox, MaintenanceInterval, Stateful};

mod syncer;
pub use syncer::SyncPlan;

mod processor;
