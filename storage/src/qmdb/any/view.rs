//! Read views over an Any QMDB.
//!
//! A [`View`] is a read capability pinned to the database's applied state at a
//! generation. The owner keeps applying batches; a view's reads are incapable of
//! observing anything newer. It is a generation coordinate plus a read protocol over
//! the live index and undo window (see [`crate::qmdb::applied`]), not a frozen copy:
//! it pins no journal data and costs a few `Arc` clones to create.
//!
//! A view survives any number of concurrent applies. It goes [`Stale`] only when the
//! database begins a new incarnation (rewind, prune, sync handoff) or when its undo
//! records are evicted past the retention floor.

use super::operation::update::Update;
use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::Contiguous,
    merkle::{Family, Location},
    qmdb::{
        any::{db::Db, operation::Operation},
        applied::{Applied, Generation, Resolution},
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;

/// A read capability over the database's applied state at a fixed generation.
pub struct View<F: Family, I, const N: usize> {
    generation: Generation,
    /// Journal size at mint; reads never observe locations at or beyond it.
    size: Location<F>,
    applied: Applied<F, I, N>,
}

impl<F: Family, I, const N: usize> Clone for View<F, I, N> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            size: self.size,
            applied: self.applied.clone(),
        }
    }
}

impl<F: Family, I, const N: usize> View<F, I, N> {
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
    pub fn view(&self) -> View<F, I, N> {
        View {
            generation: self.applied.generation(),
            size: self.last_commit_loc + 1,
            applied: self.applied.clone(),
        }
    }

    /// Get the value of `key` as of `view`, or None if it had no value there.
    ///
    /// Exact under concurrent applies. Returns [`crate::qmdb::Error::Stale`] if the view
    /// can no longer answer (new incarnation, or its undo records were evicted).
    pub async fn get_at(
        &self,
        view: &View<F, I, N>,
        key: &U::Key,
    ) -> Result<Option<U::Value>, crate::qmdb::Error<F>> {
        let locs = match view.applied.resolve(view.generation, *view.size, key)? {
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
