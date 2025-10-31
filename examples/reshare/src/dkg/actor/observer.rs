use std::collections::BTreeMap;

use commonware_codec::RangeCfg;
use commonware_cryptography::{
    bls12381::{
        dkg2::{DealerLog, RoundInfo, SignedDealerLog},
        primitives::variant::Variant,
    },
    PrivateKey,
};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;

type Data<V, P> = BTreeMap<P, DealerLog<V, P>>;

/// The observer stores the logs produced by dealers, in durable storage.
///
/// This allows recovering them, in case we crash after already processing
/// blocks where they were posted.
pub struct Observer<E, V, S>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    S: PrivateKey,
{
    key: U64,
    storage: Metadata<E, U64, Data<V, S::PublicKey>>,
}

impl<E, V, S> Observer<E, V, S>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    S: PrivateKey,
{
    /// Load the storage from disk.
    pub async fn load(ctx: E, partition_prefix: &str, round: u64, max_read_size: usize) -> Self {
        let mut storage = Metadata::<E, U64, Data<V, S::PublicKey>>::init(
            ctx,
            metadata::Config {
                partition: format!("{partition_prefix}_observer"),
                codec_config: (RangeCfg::new(0..=max_read_size), ((), max_read_size)),
            },
        )
        .await
        .expect("should be able to create observer storage");
        let key: U64 = round.into();
        if storage.get(&key).is_none() {
            storage
                .put_sync(key.clone(), BTreeMap::new())
                .await
                .expect("should be able to update observer storage");
        }
        Self { key, storage }
    }

    /// Get the current map of logs.
    pub fn logs(&self) -> &BTreeMap<S::PublicKey, DealerLog<V, S::PublicKey>> {
        self.storage
            .get(&self.key)
            .expect("observer storage should be initialized")
    }

    /// Insert a new log.
    ///
    /// This will do nothing if that dealer has already posted a log, or
    /// if this log's signature fails to verify.
    pub async fn put_log(
        &mut self,
        round_info: &RoundInfo<V, S::PublicKey>,
        log: SignedDealerLog<V, S>,
    ) {
        let Some((dealer, log)) = log.check(round_info) else {
            return;
        };
        let logs = self
            .storage
            .get_mut(&self.key)
            .expect("observer storage should be initialized");
        if logs.contains_key(&dealer) {
            return;
        }
        logs.insert(dealer, log);
        self.storage
            .sync()
            .await
            .expect("should be able to update observer storage");
    }
}
