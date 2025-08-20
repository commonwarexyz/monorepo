use crate::{adb::sync, journal::variable, store::operation::Variable};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::{Array, NZUsize};
use futures::{pin_mut, StreamExt};
use std::num::NonZeroU64;

/// Wraps a [variable::Journal] to provide a sync-compatible interface for Immutable databases.
/// Namely, it provides a `size` method that returns the number of operations in the journal,
/// and an `append` method that appends an operation to the journal. These are used by the
/// sync engine to populate the journal with data from the target database.
pub struct Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    /// Underlying variable journal storing the operations.
    inner: variable::Journal<E, Variable<K, V>>,

    /// Logical operations per storage section.
    items_per_section: NonZeroU64,

    /// Logical next append location (number of ops present).
    /// Invariant: computed by caller so `lower_bound <= size <= upper_bound + 1`.
    size: u64,
}

impl<E, K, V> Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    /// Create a new sync-compatible [ImmutableJournal].
    ///
    /// Arguments:
    /// - `inner`: The wrapped [variable::Journal], whose logical last operation location is `size - 1`.
    /// - `items_per_section`: Operations per section.
    /// - `size`: Logical next append location to report.
    pub fn new(
        inner: variable::Journal<E, Variable<K, V>>,
        items_per_section: NonZeroU64,
        size: u64,
    ) -> Self {
        Self {
            inner,
            items_per_section,
            size,
        }
    }

    /// Return the inner [variable::Journal].
    pub fn into_inner(self) -> variable::Journal<E, Variable<K, V>> {
        self.inner
    }
}

impl<E, K, V> sync::Journal for Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    type Op = Variable<K, V>;
    type Error = crate::journal::Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        Ok(self.size)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        let section = self.size / self.items_per_section;
        self.inner.append(section, op).await?;
        self.size += 1;
        Ok(())
    }

    async fn close(self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

/// Compute the next append location (size) by scanning the variable journal and
/// counting only items whose logical location is within [lower_bound, upper_bound].
pub async fn compute_size<E, K, V>(
    journal: &variable::Journal<E, Variable<K, V>>,
    items_per_section: NonZeroU64,
    lower_bound: u64,
    upper_bound: u64,
) -> Result<u64, crate::journal::Error>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    let items_per_section = items_per_section.get();
    let mut size = lower_bound;
    let mut current_section: Option<u64> = None;
    let mut index_in_section: u64 = 0;
    let stream = journal.replay(NZUsize!(1024)).await?;
    pin_mut!(stream);
    while let Some(item) = stream.next().await {
        match item {
            Ok((section, _offset, _size, _op)) => {
                if current_section != Some(section) {
                    current_section = Some(section);
                    index_in_section = 0;
                }
                let loc = section
                    .saturating_mul(items_per_section)
                    .saturating_add(index_in_section);
                if loc < lower_bound {
                    index_in_section = index_in_section.saturating_add(1);
                    continue;
                }
                if loc > upper_bound {
                    return Ok(size);
                }
                size = loc.saturating_add(1);
                index_in_section = index_in_section.saturating_add(1);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(size)
}
