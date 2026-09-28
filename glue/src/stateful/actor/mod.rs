use crate::stateful::{Application, db::DatabaseSet};
use commonware_cryptography::Digestible;

mod core;
pub use core::{Config, Mailbox, PruneConfig, Stateful};

mod durability;

mod metrics;

mod syncer;
pub use syncer::SyncPlan;

mod processor;

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type SyncTargets<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;

pub(super) mod ordered;
