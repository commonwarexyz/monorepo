//! Shared compact QMDB helpers.
//!
//! # What compact dbs store
//!
//! A compact db's only persistent state is its witness journal ([`witness`]), whose entries
//! each snapshot one committed state as the commit operation, the committed leaf count, and
//! the pinned nodes one operation below it. The in-memory compact Merkle
//! ([`crate::merkle::compact`]) is rebuilt from the journal tip on reopen. Without the
//! witness, a compact db could recover its root and continue appending, but it could not
//! serve compact sync to another node.
//!
//! # When compact state changes
//!
//! The servable compact state advances only when a commit is persisted. A db-local commit
//! appends one witness entry during `commit`, `sync`, or `start_sync`. An entry appended by
//! `start_sync` is servable when the call returns and is proven durable only when its handle
//! completes. `rewind` restores the witness from the target journal entry. Unpersisted
//! in-memory mutations are therefore intentionally not servable. `target()` and served
//! responses lag behind `apply_batch()` until the db's next persist.

pub(crate) mod batch;
pub(crate) mod witness;
