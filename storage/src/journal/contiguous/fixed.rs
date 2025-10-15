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
    use crate::journal::contiguous::tests::run_contiguous_tests;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use futures::FutureExt as _;

    #[test]
    fn test_fixed_generic_suite() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            run_contiguous_tests(move |test_name: String| {
                let context = context.clone();
                async move {
                    fixed::Journal::init(
                        context,
                        fixed::Config {
                            partition: format!("generic_test_{}", test_name),
                            items_per_blob: NZU64!(10),
                            buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                            write_buffer: NZUsize!(1024),
                        },
                    )
                    .await
                }
                .boxed()
            })
            .await;
        });
    }
}
