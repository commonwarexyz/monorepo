//! Metadata storage conformance tests.

use crate::metadata::{Config, Error, Metadata};
use commonware_codec::RangeCfg;
use commonware_conformance::conformance_tests;
use commonware_runtime::{
    Supervisor as _,
    conformance::{StorageConformance, StorageWorkload},
};
use commonware_utils::sequence::U64;
use rand::RngExt as _;

struct MetadataWorkload;

impl StorageWorkload for MetadataWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let cfg = Config {
            partition: format!("metadata-conformance-{seed}"),
            codec_config: (RangeCfg::new(0..512), ()),
        };
        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.child("metadata"), cfg).await?;

        let items = context.random_range(16..64);
        for i in 0..items {
            let mut value = vec![0; context.random_range(0..512)];
            context.fill(value.as_mut_slice());
            metadata.put(U64::new(i), value);
        }
        metadata = metadata.sync().await?;

        for i in (0..items).step_by(3) {
            let mut value = vec![0; context.random_range(0..512)];
            context.fill(value.as_mut_slice());
            metadata.put(U64::new(i), value);
        }
        metadata.sync().await?;
        Ok(())
    }
}

conformance_tests! {
    StorageConformance<MetadataWorkload> => 256,
}
