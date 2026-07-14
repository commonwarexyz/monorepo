//! Storage conformance helpers.

use crate::{deterministic, Runner, Supervisor as _};
use commonware_conformance::Conformance;
use core::{fmt::Debug, marker::PhantomData};
use std::future::Future;

/// Deterministic storage workload for conformance testing.
pub trait StorageWorkload: Send + Sync {
    /// Error returned by the workload.
    type Error: Debug + Send + 'static;

    /// Run the workload against a deterministic runtime context.
    fn run(
        context: deterministic::Context,
        seed: u64,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Conformance wrapper that commits a deterministic runtime storage audit.
pub struct StorageConformance<W>(PhantomData<W>);

impl<W> Conformance for StorageConformance<W>
where
    W: StorageWorkload,
{
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|context| async move {
            W::run(context.child("workload"), seed)
                .await
                .unwrap_or_else(|err| panic!("storage workload failed: {err:?}"));

            context.storage_audit().to_vec()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{StorageConformance, StorageWorkload};
    use crate::{Blob as _, Storage as _};
    use commonware_conformance::Conformance as _;
    use futures::executor::block_on;

    struct SyncedWrite;

    impl StorageWorkload for SyncedWrite {
        type Error = crate::Error;

        async fn run(context: crate::deterministic::Context, seed: u64) -> Result<(), Self::Error> {
            let (blob, _) = context
                .open("storage-conformance", &seed.to_be_bytes())
                .await?;
            blob.write_at(0, vec![seed as u8, 1, 2, 3]).await?;
            blob.sync().await
        }
    }

    struct DifferentWrite;

    impl StorageWorkload for DifferentWrite {
        type Error = crate::Error;

        async fn run(context: crate::deterministic::Context, seed: u64) -> Result<(), Self::Error> {
            let (blob, _) = context
                .open("storage-conformance", &seed.to_be_bytes())
                .await?;
            blob.write_at(0, vec![seed as u8, 4, 5, 6]).await?;
            blob.sync().await
        }
    }

    struct EmptyWorkload;

    impl StorageWorkload for EmptyWorkload {
        type Error = crate::Error;

        async fn run(_: crate::deterministic::Context, _: u64) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn synced_writes_affect_audit() {
        let empty = block_on(StorageConformance::<EmptyWorkload>::commit(0));
        let written = block_on(StorageConformance::<SyncedWrite>::commit(0));

        assert_ne!(empty, written);
    }

    #[test]
    fn identical_workloads_produce_identical_audits() {
        let first = block_on(StorageConformance::<SyncedWrite>::commit(7));
        let second = block_on(StorageConformance::<SyncedWrite>::commit(7));

        assert_eq!(first, second);
    }

    #[test]
    fn different_storage_contents_produce_different_audits() {
        let first = block_on(StorageConformance::<SyncedWrite>::commit(7));
        let second = block_on(StorageConformance::<DifferentWrite>::commit(7));

        assert_ne!(first, second);
    }
}
