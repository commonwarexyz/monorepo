//! Read views over an Any QMDB.
//!
//! A [`View`] is a read capability pinned to the database's applied state at a
//! generation. The owner keeps applying batches; a view's reads are incapable of
//! observing anything newer. It is a generation coordinate, a copy-on-write capture of
//! the in-memory Merkle state, and a read protocol over the live index and undo
//! window -- not a frozen copy: it pins no journal data and costs a few `Arc` clones
//! to create.
//!
//! A view survives any number of concurrent applies, including pruning (physical GC).
//! It goes [`Stale`] only when the database begins a new incarnation (rewind, sync
//! handoff) or when its undo records are evicted past the retention window.
//!
//! [`Stale`]: crate::qmdb::Stale

use super::operation::update::Update;
use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::Contiguous,
    merkle::{Family, Location, mem::Mem},
    qmdb::{
        any::{db::Db, operation::Operation},
        applied::{Generation, Resolution},
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use std::sync::Arc;

/// A read capability over the database's applied state at a fixed generation.
pub struct View<F: Family, D: Digest> {
    pub(crate) generation: Generation,
    /// Journal size at mint; reads never observe locations at or beyond it.
    pub(crate) size: Location<F>,
    /// The in-memory Merkle state as of this view. Batches merkleize against this
    /// capture, never the live tree.
    pub(crate) mem: Arc<Mem<F, D>>,
}

impl<F: Family, D: Digest> Clone for View<F, D> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            size: self.size,
            mem: Arc::clone(&self.mem),
        }
    }
}

impl<F: Family, D: Digest> View<F, D> {
    /// The generation this view is pinned to.
    pub const fn generation(&self) -> Generation {
        self.generation
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// A view of the database's current applied state.
    pub fn view(&self) -> View<F, H::Digest> {
        View {
            generation: self.applied.generation(),
            size: self.last_commit_loc + 1,
            mem: self.log.mem(),
        }
    }

    /// Get the value of `key` as of `view`, or None if it had no value there.
    ///
    /// Exact under concurrent applies. Returns [`crate::qmdb::Error::Stale`] if the view
    /// can no longer answer (new incarnation, or its undo records were evicted), and a
    /// journal `ItemPruned` error if the answering operation was since pruned.
    pub async fn get_at(
        &self,
        view: &View<F, H::Digest>,
        key: &U::Key,
    ) -> Result<Option<U::Value>, crate::qmdb::Error<F>> {
        let locs = match self.applied.resolve(view.generation, *view.size, key)? {
            Resolution::Exact(None) => return Ok(None),
            Resolution::Exact(Some(loc)) => vec![loc],
            Resolution::Candidates(locs) => locs,
        };
        for loc in locs {
            let op = self.log.read(*loc).await?;
            let Operation::Update(data) = op else {
                panic!("location does not reference update operation. loc={loc}");
            };
            if data.key() == key {
                return Ok(Some(data.value().clone()));
            }
        }
        Ok(None)
    }
}
