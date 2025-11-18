use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{bls12381::dkg::PlayerAck, transcript::Summary, Digest, PublicKey};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use rand_core::CryptoRngCore;

struct DealerData<P: PublicKey> {
    seed: Option<Summary>,
    acks: Vec<(P, PlayerAck<P>)>,
}

impl<P> EncodeSize for DealerData<P>
where
    P: PublicKey,
{
    fn encode_size(&self) -> usize {
        self.seed.encode_size() + self.acks.encode_size()
    }
}

impl<P> Write for DealerData<P>
where
    P: PublicKey,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.write(buf);
        self.acks.write(buf);
    }
}

impl<P> Read for DealerData<P>
where
    P: PublicKey,
{
    type Cfg = (
        <Option<Summary> as Read>::Cfg,
        <Vec<(P, PlayerAck<P>)> as Read>::Cfg,
    );

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            seed: Option::<Summary>::read_cfg(buf, &cfg.0)?,
            acks: Vec::<(P, PlayerAck<P>)>::read_cfg(buf, &cfg.1)?,
        })
    }
}

/// A handle over the state maintained by the dealer.
pub struct State<E, P>
where
    E: Clock + Storage + Metrics,
    P: PublicKey,
{
    key: U64,
    max_read_size: usize,
    storage: Metadata<E, U64, DealerData<P>>,
}

impl<E, P> State<E, P>
where
    E: Clock + Storage + Metrics,
    P: PublicKey,
{
    /// Load the state from storage.
    ///
    /// `round` identifies the round, with each state given a different round.
    /// `max_read_size` is a parameter governing read sizes. This should correspond
    /// with the number of players we might acknowledge.
    pub async fn load(ctx: E, partition: String, round: u64, max_read_size: usize) -> Self {
        let storage = Metadata::<E, U64, DealerData<P>>::init(
            ctx,
            metadata::Config {
                partition,
                codec_config: ((), (RangeCfg::new(0..=max_read_size), ((), ()))),
            },
        )
        .await
        .expect("should be able to create dealer storage");
        Self {
            key: round.into(),
            max_read_size,
            storage,
        }
    }

    fn get(&self) -> Option<&DealerData<P>> {
        self.storage.get(&self.key)
    }

    fn get_mut(&mut self) -> Option<&mut DealerData<P>> {
        self.storage.get_mut(&self.key)
    }

    async fn put_sync(&mut self, data: DealerData<P>) {
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

    /// Get the seed to be used for dealer randomness.
    ///
    /// This takes an RNG, to initialize the seed if it hasn't been created yet.
    pub async fn seed(&mut self, rng: &mut impl CryptoRngCore) -> Summary {
        let data = self.get_mut();
        match data {
            Some(DealerData {
                seed: Some(seed), ..
            }) => *seed,
            Some(entry) => {
                let seed = Summary::random(rng);
                entry.seed = Some(seed);
                self.sync().await;
                seed
            }
            None => {
                let seed = Summary::random(rng);
                self.put_sync(DealerData {
                    seed: Some(seed),
                    acks: Vec::with_capacity(self.max_read_size),
                })
                .await;
                seed
            }
        }
    }

    /// Return the acks we've received so far.
    pub fn acks(&self) -> &[(P, PlayerAck<P>)] {
        self.get().map(|data| data.acks.as_slice()).unwrap_or(&[])
    }

    /// Remember an additional ack.
    pub async fn put_ack(&mut self, player: P, ack: PlayerAck<P>) {
        let data = self.get_mut();
        match data {
            Some(x) => {
                x.acks.push((player, ack));
                self.storage
                    .sync()
                    .await
                    .expect("failed to update dealer storage");
            }
            None => {
                let mut acks = Vec::with_capacity(self.max_read_size);
                acks.push((player, ack));
                self.put_sync(DealerData { seed: None, acks }).await;
            }
        }
    }
}
