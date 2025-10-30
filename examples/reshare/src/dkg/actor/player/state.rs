use commonware_codec::RangeCfg;
use commonware_cryptography::{
    bls12381::{
        dkg2::{DealerPrivMsg, DealerPubMsg},
        primitives::variant::Variant,
    },
    PublicKey,
};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use std::num::NonZeroUsize;

type Data<V, P> = Vec<(P, DealerPubMsg<V>, DealerPrivMsg)>;

/// A handle over the state maintained by the player.
pub struct State<E, V, P>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    P: PublicKey,
{
    key: U64,
    storage: Metadata<E, U64, Data<V, P>>,
}

impl<E, V, P> State<E, V, P>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    P: PublicKey,
{
    /// Load the state from storage.
    ///
    /// `round` identifies the round, with each state given a different round.
    /// `max_read_size` is a parameter governing read sizes. This should correspond
    /// with the number of players we might acknowledge.
    pub async fn load(ctx: E, partition: String, round: u64, max_read_size: NonZeroUsize) -> Self {
        let mut storage = Metadata::<E, U64, Data<V, P>>::init(
            ctx,
            metadata::Config {
                partition,
                codec_config: (
                    RangeCfg::new(0..=max_read_size.get()),
                    ((), max_read_size, ()),
                ),
            },
        )
        .await
        .expect("should be able to create player storage");
        let key: U64 = round.into();
        if storage.get(&key).is_none() {
            storage
                .put_sync(key.clone(), Vec::with_capacity(max_read_size.get()))
                .await
                .expect("should be able to update player storage");
        }
        Self { key, storage }
    }

    fn get(&self) -> &Data<V, P> {
        self.storage
            .get(&self.key)
            .expect("data should be initialized")
    }

    fn get_mut(&mut self) -> &mut Data<V, P> {
        self.storage
            .get_mut(&self.key)
            .expect("data should be initialized")
    }

    async fn sync(&mut self) {
        self.storage
            .sync()
            .await
            .expect("failed to update dealer storage");
    }

    /// Return the messages we've received so far
    pub fn msgs(&self) -> &[(P, DealerPubMsg<V>, DealerPrivMsg)] {
        self.get().as_slice()
    }

    /// Remember an additional message.
    pub async fn put_msg(&mut self, dealer: P, pub_msg: DealerPubMsg<V>, priv_msg: DealerPrivMsg) {
        self.get_mut().push((dealer, pub_msg, priv_msg));
        self.sync().await;
    }
}
