//! Contiguous trait implementation for fixed-length journals.

use super::{Contiguous, ContiguousRead};
use crate::journal::{fixed, Error};
use commonware_codec::CodecFixed;
use commonware_runtime::{Metrics, Storage};
use futures::Stream;
use std::num::NonZeroUsize;

impl<E: Storage + Metrics, A: CodecFixed<Cfg = ()> + Send + Sync> Contiguous
    for fixed::Journal<E, A>
{
    type Item = A;

    async fn append(&mut self, item: Self::Item) -> Result<u64, Error> {
        fixed::Journal::append(self, item).await
    }

    async fn size(&self) -> Result<u64, Error> {
        fixed::Journal::size(self).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        fixed::Journal::prune(self, min_position).await
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error> {
        fixed::Journal::replay(self, buffer, start_pos).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        fixed::Journal::sync(self).await
    }

    async fn close(self) -> Result<(), Error> {
        fixed::Journal::close(self).await
    }
}

// Implement ContiguousRead for fixed::Journal
impl<E: Storage + Metrics, A: CodecFixed<Cfg = ()> + Send + Sync> ContiguousRead
    for fixed::Journal<E, A>
{
    async fn read(&self, position: u64) -> Result<Self::Item, Error> {
        fixed::Journal::read(self, position).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::{Contiguous, ContiguousRead};
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};

    #[test]
    fn test_fixed_journal_implements_contiguous() {
        // Test that we can use a fixed journal through the Contiguous trait
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal: fixed::Journal<_, u64> = fixed::Journal::init(
                context,
                fixed::Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(10),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Use through trait methods
            let pos1 = Contiguous::append(&mut journal, 42u64).await.unwrap();
            let pos2 = Contiguous::append(&mut journal, 100u64).await.unwrap();
            assert_eq!(pos1, 0);
            assert_eq!(pos2, 1);

            let size = Contiguous::size(&journal).await.unwrap();
            assert_eq!(size, 2);

            // Use ContiguousRead trait
            let item = ContiguousRead::read(&journal, 0).await.unwrap();
            assert_eq!(item, 42u64);

            journal.close().await.unwrap();
        });
    }

    #[test]
    fn test_fixed_journal_replay_through_trait() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal: fixed::Journal<_, u64> = fixed::Journal::init(
                context,
                fixed::Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(10),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append some items
            for i in 0..5u64 {
                Contiguous::append(&mut journal, i * 10).await.unwrap();
            }

            // Replay through trait
            use futures::StreamExt;
            {
                let stream = Contiguous::replay(&journal, 0, NZUsize!(1024))
                    .await
                    .unwrap();
                futures::pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    items.push(result.unwrap());
                }

                assert_eq!(items.len(), 5);
                for (i, (pos, value)) in items.iter().enumerate() {
                    assert_eq!(*pos, i as u64);
                    assert_eq!(*value, (i as u64) * 10);
                }
            }

            journal.close().await.unwrap();
        });
    }

    #[test]
    fn test_fixed_journal_prune_through_trait() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal: fixed::Journal<_, u64> = fixed::Journal::init(
                context,
                fixed::Config {
                    partition: "test".to_string(),
                    items_per_blob: NZU64!(10),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append items
            for i in 0..20u64 {
                Contiguous::append(&mut journal, i).await.unwrap();
            }

            // Prune first 10 items
            let pruned = Contiguous::prune(&mut journal, 10).await.unwrap();
            assert!(pruned);

            // Size should still be 20
            let size = Contiguous::size(&journal).await.unwrap();
            assert_eq!(size, 20);

            // Reading pruned item should fail
            let result = ContiguousRead::read(&journal, 5).await;
            assert!(result.is_err());

            // Reading non-pruned item should work
            let item = ContiguousRead::read(&journal, 15).await.unwrap();
            assert_eq!(item, 15);

            journal.close().await.unwrap();
        });
    }
}
