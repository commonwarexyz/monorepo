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
use commonware_utils::sequence::FixedBytes;

type Key = FixedBytes<4>;

type Data<V: Variant, P: PublicKey> = Vec<(P, DealerPubMsg<V>, DealerPrivMsg)>;

/// A handle over the state maintained by the player.
pub struct State<E, V, P>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    P: PublicKey,
{
    key: Key,
    max_read_size: usize,
    storage: Metadata<E, Key, Data<V, P>>,
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
    pub async fn load(ctx: E, partition: String, round: u32, max_read_size: usize) -> Self {
        let storage = Metadata::<E, Key, Data<V, P>>::init(
            ctx,
            metadata::Config {
                partition,
                codec_config: (RangeCfg::new(0..=max_read_size), ((), max_read_size, ())),
            },
        )
        .await
        .expect("should be able to create dealer storage");
        Self {
            key: round.to_le_bytes().into(),
            max_read_size,
            storage,
        }
    }

    fn get(&self) -> Option<&Data<V, P>> {
        self.storage.get(&self.key)
    }

    fn get_mut(&mut self) -> Option<&mut Data<V, P>> {
        self.storage.get_mut(&self.key)
    }

    async fn put_sync(&mut self, data: Data<V, P>) {
        self.storage
            .put_sync(self.key.clone(), data)
            .await
            .expect("failed to update dealer storage");
    }

    async fn sync(&mut self) {
        self.storage
            .sync()
            .await
            .expect("failed to update dealer storage");
    }

    /// Return the messages we've received so far
    pub fn msgs(&self) -> &[(P, DealerPubMsg<V>, DealerPrivMsg)] {
        self.get().map(|x| x.as_slice()).unwrap_or(&[])
    }

    /// Remember an additional message.
    pub async fn put_msg(&mut self, dealer: P, pub_msg: DealerPubMsg<V>, priv_msg: DealerPrivMsg) {
        let data = self.get_mut();
        match data {
            Some(x) => {
                x.push((dealer, pub_msg, priv_msg));
                self.storage
                    .sync()
                    .await
                    .expect("failed to update dealer storage");
            }
            None => {
                let mut msgs = Vec::with_capacity(self.max_read_size);
                msgs.push((dealer, pub_msg, priv_msg));
                self.put_sync(msgs).await;
            }
        }
    }
}
