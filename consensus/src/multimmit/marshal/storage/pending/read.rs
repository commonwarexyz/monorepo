//! Immutable body reads planned against pending custody.
//!
//! A read plan names body locations in one segment. Planned reads own the segment snapshot
//! they read (or the inputs to open one), so they may run after the store moves on.

use crate::multimmit::{
    marshal::storage::Error,
    types::{BlockRef, Body, TransactionBlock},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{Context, journal::segmented::glob};
use std::{collections::BTreeSet, marker::PhantomData, num::NonZeroUsize, sync::Arc};

/// A frozen view of one segment's body storage.
pub(super) type BodySnapshot<E, H, B> =
    glob::Reader<<E as commonware_runtime::Storage>::Blob, Arc<TransactionBlock<H, B>>>;

/// The location of one stored body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyLocator<D: Digest> {
    /// Global append position of the body.
    pub(super) position: u64,
    /// Block stored at the position.
    pub(super) reference: BlockRef<D>,
    /// Encoded length of the complete block.
    pub(super) encoded_len: u64,
    /// Offset of the body frame in its segment's value blob.
    pub(super) offset: u64,
    /// Size of the body frame, including its checksum.
    pub(super) size: u32,
}

/// The inputs needed to open one shared snapshot for a segment without a resident reader.
pub(crate) struct ColdSource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    pub(super) context: E,
    pub(super) config: glob::Config<B::Cfg>,
    pub(super) segment: u64,
    pub(super) segment_capacity: u64,
    pub(super) _marker: PhantomData<H>,
}

/// An immutable segment source: a snapshot already open, or the inputs to open one on demand.
pub(crate) enum BodySource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    /// A cloned snapshot of a resident reader.
    Ready(BodyReader<E, H, B>),
    /// A segment with no resident reader.
    Cold(ColdSource<E, H, B>),
}

/// A shareable snapshot reader for one segment's bodies.
pub(crate) struct BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    pub(super) segment: u64,
    pub(super) segment_capacity: u64,
    pub(super) reader: BodySnapshot<E, H, B>,
    /// Whether the segment accepts no further appends and may enter the advisory reader cache.
    pub(super) immutable: bool,
}

/// One owned, single-segment materialization job and the source it reads.
pub(crate) struct BodyReadGroup<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    /// Snapshot or open inputs for the segment.
    pub(crate) source: BodySource<E, H, B>,
    /// Locations to read.
    pub(crate) read: BodyRead<H>,
}

/// A batch of locations in one segment, read through any snapshot of that segment.
///
/// Entries keep their requested output indexes and are sorted by storage position so one
/// deduplicated batch of value reads serves them.
pub(crate) struct BodyRead<H: Hasher> {
    pub(super) segment: u64,
    pub(super) entries: Vec<(usize, BodyLocator<H::Digest>)>,
    pub(super) encoded_bytes: u64,
    pub(super) prefetch: NonZeroUsize,
}

impl<E, H, B> ColdSource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Opens an immutable value blob without replaying indexes or changing storage.
    pub(crate) async fn open(self) -> Result<BodyReader<E, H, B>, Error> {
        let reader = glob::Reader::open(&self.context, self.config, 0).await?;
        Ok(BodyReader::new(
            self.segment,
            self.segment_capacity,
            reader,
            true,
        ))
    }
}

impl<E, H, B> Clone for BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            segment: self.segment,
            segment_capacity: self.segment_capacity,
            reader: self.reader.clone(),
            immutable: self.immutable,
        }
    }
}

impl<E, H, B> BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    pub(super) const fn new(
        segment: u64,
        segment_capacity: u64,
        reader: BodySnapshot<E, H, B>,
        immutable: bool,
    ) -> Self {
        Self {
            segment,
            segment_capacity,
            reader,
            immutable,
        }
    }

    /// Returns the segment this reader serves.
    pub(crate) const fn segment(&self) -> u64 {
        self.segment
    }

    /// Returns the segment-local position of a global append position in this segment.
    pub(super) const fn local_position(&self, position: u64) -> Result<u64, Error> {
        if position / self.segment_capacity != self.segment {
            return Err(Error::Inconsistent(
                "pending body locator names another segment",
            ));
        }
        Ok(position % self.segment_capacity)
    }

    /// Returns whether this snapshot covers `locator`.
    pub(super) fn contains(&self, locator: BodyLocator<H::Digest>) -> bool {
        self.local_position(locator.position).is_ok()
            && locator
                .offset
                .checked_add(u64::from(locator.size))
                .is_some_and(|end| end <= self.reader.size())
    }
}

impl<E, H, B> BodyReadGroup<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    /// Returns the segment this group reads.
    pub(crate) const fn segment(&self) -> u64 {
        self.read.segment
    }

    /// Returns every block this group reads.
    pub(crate) fn references(&self) -> impl Iterator<Item = BlockRef<H::Digest>> + '_ {
        self.read
            .entries
            .iter()
            .map(|(_, locator)| locator.reference)
    }

    /// Keeps only entries for `references` and returns whether any remain.
    pub(crate) fn retain_references(
        &mut self,
        references: &BTreeSet<BlockRef<H::Digest>>,
    ) -> Result<bool, Error> {
        self.read
            .entries
            .retain(|(_, locator)| references.contains(&locator.reference));
        self.read.encoded_bytes = total_encoded_bytes(&self.read.entries)?;
        Ok(!self.read.entries.is_empty())
    }
}

impl<H: Hasher> BodyRead<H> {
    /// Creates a read of `entries`, which must lie in `segment` in position order.
    pub(super) fn new(
        segment: u64,
        entries: Vec<(usize, BodyLocator<H::Digest>)>,
        prefetch: NonZeroUsize,
    ) -> Result<Self, Error> {
        let encoded_bytes = total_encoded_bytes(&entries)?;
        Ok(Self {
            segment,
            entries,
            encoded_bytes,
            prefetch,
        })
    }

    /// Returns the encoded bytes this read materializes.
    pub(crate) const fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    /// Returns the segment this read covers.
    pub(crate) const fn segment(&self) -> u64 {
        self.segment
    }

    /// Reads every entry through `reader` and returns blocks by requested output index.
    pub(crate) async fn read<E, B>(
        self,
        reader: BodyReader<E, H, B>,
    ) -> Result<Vec<(usize, Arc<TransactionBlock<H, B>>)>, Error>
    where
        E: Context,
        B: Body<H>,
    {
        let requests = self
            .entries
            .chunk_by(|(_, left), (_, right)| left.position == right.position);
        let locations = requests
            .clone()
            .map(|requests| {
                let locator = requests[0].1;
                reader.local_position(locator.position)?;
                Ok((locator.offset, locator.size))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let stored = reader.reader.get_many(&locations, self.prefetch).await?;
        let mut results = Vec::new();
        for (requests, block) in requests.zip(stored) {
            for (output, locator) in requests {
                validate_body(&block, *locator)?;
                results.push((*output, Arc::clone(&block)));
            }
        }
        results.sort_unstable_by_key(|(output, _)| *output);
        Ok(results)
    }
}

fn total_encoded_bytes<D: Digest>(entries: &[(usize, BodyLocator<D>)]) -> Result<u64, Error> {
    entries.iter().try_fold(0u64, |total, (_, locator)| {
        total
            .checked_add(locator.encoded_len)
            .ok_or(Error::Inconsistent("pending body read bytes overflow"))
    })
}

/// Checks that a stored body is the block its locator names.
pub(super) fn validate_body<H, B>(
    block: &TransactionBlock<H, B>,
    locator: BodyLocator<H::Digest>,
) -> Result<(), Error>
where
    H: Hasher,
    B: Body<H>,
{
    let encoded_len = u64::try_from(block.encode_size())
        .map_err(|_| Error::Inconsistent("encoded block length exceeds u64"))?;
    if block.reference() != locator.reference || encoded_len != locator.encoded_len {
        return Err(Error::Inconsistent(
            "pending body does not match its locator",
        ));
    }
    Ok(())
}
