use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::{DealerPrivMsg, DealerPubMsg},
        primitives::variant::Variant,
    },
    PublicKey,
};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use std::num::NonZeroUsize;

struct PlayerData<V: Variant, P: PublicKey> {
    messages: Vec<(P, DealerPubMsg<V>, DealerPrivMsg)>,
}

impl<V, P> EncodeSize for PlayerData<V, P>
where
    V: Variant,
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.messages.encode_size()
    }
}

impl<V, P> Write for PlayerData<V, P>
where
    V: Variant,
    P: PublicKey,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.messages.write(buf);
    }
}

impl<V, P> Read for PlayerData<V, P>
where
    V: Variant,
    P: PublicKey,
{
    type Cfg = <Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            messages: Vec::<(P, DealerPubMsg<V>, DealerPrivMsg)>::read_cfg(buf, cfg)?,
        })
    }
}

/// A handle over the state maintained by the player.
pub struct State<E, V, P>
where
    E: Clock + Storage + Metrics,
    V: Variant,
    P: PublicKey,
{
    key: U64,
    storage: Metadata<E, U64, PlayerData<V, P>>,
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
        let mut storage = Metadata::<E, U64, PlayerData<V, P>>::init(
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
                .put_sync(
                    key.clone(),
                    PlayerData {
                        messages: Vec::with_capacity(max_read_size.get()),
                    },
                )
                .await
                .expect("should be able to update player storage");
        }
        Self { key, storage }
    }

    fn get(&self) -> &PlayerData<V, P> {
        self.storage
            .get(&self.key)
            .expect("data should be initialized")
    }

    fn get_mut(&mut self) -> &mut PlayerData<V, P> {
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
        self.get().messages.as_slice()
    }

    /// Remember an additional message.
    pub async fn put_msg(&mut self, dealer: P, pub_msg: DealerPubMsg<V>, priv_msg: DealerPrivMsg) {
        self.get_mut().messages.push((dealer, pub_msg, priv_msg));
        self.sync().await;
    }
}
