//! Defines the abstraction allowing MMRs with differing backends and representations to be
//! uniformly accessed.

use crate::mmr::{
    bitmap::Bitmap,
    hasher::{source_pos, Hasher, Standard},
    iterator::{pos_to_height, PeakIterator},
    journaled::Mmr as JournaledMmr,
    mem::Mmr as MemMmr,
    Error,
};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use futures::future::try_join_all;
use std::future::Future;

/// A trait for accessing MMR digests from storage.
pub trait Storage<D: Digest>: Send + Sync {
    /// Return the number of elements in the MMR.
    fn size(&self) -> u64;

    /// Return the specified node of the MMR if it exists & hasn't been pruned.
    fn get_node(&self, position: u64) -> impl Future<Output = Result<Option<D>, Error>> + Send;
}

impl<H: CHasher> Storage<H::Digest> for MemMmr<H>
where
    H: CHasher,
{
    fn size(&self) -> u64 {
        self.size()
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        Ok(MemMmr::get_node(self, position))
    }
}

impl<E: RStorage + Clock + Metrics, H: CHasher> Storage<H::Digest> for JournaledMmr<E, H> {
    fn size(&self) -> u64 {
        self.size()
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        self.get_node(position).await
    }
}

impl<H: CHasher, const N: usize> Storage<H::Digest> for Bitmap<H, N> {
    fn size(&self) -> u64 {
        self.size()
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        Ok(self.get_node(position))
    }
}

/// A [Storage] implementation that makes grafted trees look like a single MMR for conveniently
/// generating inclusion proofs.
pub struct Grafting<'a, H: CHasher, S1: Storage<H::Digest>, S2: Storage<H::Digest>> {
    peak_tree: &'a S1,
    base_mmr: &'a S2,
    height: u32,

    _marker: std::marker::PhantomData<H>,
}

impl<'a, H: CHasher, S1: Storage<H::Digest>, S2: Storage<H::Digest>> Grafting<'a, H, S1, S2> {
    /// Creates a new [Grafting] Storage instance.
    pub fn new(peak_tree: &'a S1, base_mmr: &'a S2, height: u32) -> Self {
        Self {
            peak_tree,
            base_mmr,
            height,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn root(&self, hasher: &mut Standard<H>) -> Result<H::Digest, Error> {
        let size = self.size();
        let peak_futures = PeakIterator::new(size).map(|(peak_pos, _)| self.get_node(peak_pos));
        let peaks = try_join_all(peak_futures).await?;
        let unwrapped_peaks = peaks.iter().map(|p| p.as_ref().unwrap());
        let digest = hasher.root_digest(self.base_mmr.size(), unwrapped_peaks);

        Ok(digest)
    }
}

impl<H: CHasher, S1: Storage<H::Digest>, S2: Storage<H::Digest>> Storage<H::Digest>
    for Grafting<'_, H, S1, S2>
{
    fn size(&self) -> u64 {
        self.base_mmr.size()
    }

    async fn get_node(&self, pos: u64) -> Result<Option<H::Digest>, Error> {
        let height = pos_to_height(pos);
        if height < self.height {
            return self.base_mmr.get_node(pos).await;
        }

        let source_pos = source_pos(pos, self.height);
        let Some(source_pos) = source_pos else {
            return Ok(None);
        };

        self.peak_tree.get_node(source_pos).await
    }
}
