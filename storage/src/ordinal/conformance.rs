//! Ordinal storage conformance tests.

use crate::ordinal::{Config, Error, Ordinal};
use commonware_conformance::conformance_tests;
use commonware_runtime::{
    Supervisor as _,
    conformance::{StorageConformance, StorageWorkload},
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
use rand::RngExt as _;

struct OrdinalWorkload;

impl StorageWorkload for OrdinalWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let cfg = Config {
            partition: format!("ordinal-conformance-{seed}"),
            items_per_blob: NZU64!(16),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        };
        let mut ordinal =
            Ordinal::<_, FixedBytes<32>>::init(context.child("ordinal"), cfg, None).await?;

        let items = context.random_range(16..80);
        for i in 0..items {
            let index = i as u64 * 3 + (seed % 3);
            let mut value = [0; 32];
            context.fill(&mut value);
            ordinal = ordinal.put(index, FixedBytes::new(value)).await?;
        }
        ordinal = ordinal.sync().await?;

        if items > 32 {
            ordinal = ordinal.prune(32).await?;
            ordinal.sync().await?;
        }

        Ok(())
    }
}

conformance_tests! {
    StorageConformance<OrdinalWorkload> => 256,
}
