//! QMDB-backed storage adapter for the REVM example.
//!
//! This module wires a QMDB-backed key/value model into REVM's database
//! interfaces. QMDB provides persistence and authenticated structure, while
//! REVM executes against a synchronous in-memory overlay via `CacheDB`.
//!
//! Design at a glance:
//! - Accounts, storage, and code live in separate QMDB partitions.
//! - Reads go through `DatabaseAsyncRef` and are bridged into sync REVM calls
//!   via `WrapDatabaseAsync` (Tokio runtime required).
//! - Writes are staged in the REVM overlay and applied to QMDB in batches when
//!   the example decides a block is finalized.

mod adapter;
mod changes;
mod config;
mod error;
mod keys;
mod model;
mod service;
mod state;
mod store;
mod types;

pub(crate) use adapter::QmdbRefDb;
pub(crate) use changes::{AccountUpdate, QmdbChangeSet};
pub(crate) use config::QmdbConfig;
pub(crate) use error::Error;
pub(crate) use service::QmdbLedger;
pub(crate) use state::{state_root_from_roots, QmdbState, RevmDb};
pub(crate) use store::{QmdbInner, Stores};
pub(crate) use types::{
    AccountStore, AccountStoreDirty, CodeStore, CodeStoreDirty, StorageStore, StorageStoreDirty,
};
