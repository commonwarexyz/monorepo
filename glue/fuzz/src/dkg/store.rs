//! The secret store each engine is given.
//!
//! The store is held by the harness outside the engine, so the oracle can read
//! the shares an engine holds. The two halves of the compromised identity
//! never share one, which is what makes them deal differently under one key.
//!
//! A paced store may hold a write before it is applied or after it is applied
//! and before its future resolves (see [`pacing`](super::pacing)). A write is
//! one change of the store made under its lock, so it is durable when its
//! future resolves, and a write whose future is dropped first is either in
//! place as a whole or absent. Reads are never held.
//!
//! The store is the harness's code and the tasks of an engine call it. What
//! it does to its contents runs as belonging to no engine, so that a panic in
//! it is reported as the harness's.

use super::pacing::{EnginePacing, Operation, Secret};
use crate::stateful::runner::unattributed;
use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg},
        primitives::{group::Share, variant::Variant},
    },
    transcript::Summary,
};
use commonware_glue::dkg::SecretStore;
use commonware_utils::sync::Mutex;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Default)]
struct Inner {
    shares: BTreeMap<Epoch, Share>,
    seeds: BTreeMap<Epoch, Summary>,
    /// Private dealings keyed by epoch, encoded dealer key, and the encoded
    /// public message each came with, since a dealer can deal more than once
    /// in an epoch.
    dealings: BTreeMap<(Epoch, Vec<u8>, Bytes), DealerPrivMsg>,

    /// Every distinct share ever stored, in the order stored. Pruning does
    /// not shorten it.
    held: Vec<(Epoch, Share)>,
}

impl Inner {
    fn put_share(&mut self, epoch: Epoch, share: Share) {
        let stored = (epoch, share);
        if !self.held.contains(&stored) {
            self.held.push(stored.clone());
        }
        self.shares.insert(stored.0, stored.1);
    }
}

/// An in-memory [`SecretStore`] whose writes are durable when their futures
/// resolve.
#[derive(Clone, Default)]
pub(super) struct Secrets {
    inner: Arc<Mutex<Inner>>,
    /// The pacing of the store's writes, or none if they are not paced.
    pacing: Option<EnginePacing>,
}

impl Secrets {
    /// This store with its writes paced by `pacing`.
    ///
    /// An engine's storage is paced like the store the engine is given (see
    /// [`Self::pacing`]), so this is all a driver does to pace an engine,
    /// across every restart.
    pub(super) fn paced(mut self, pacing: EnginePacing) -> Self {
        self.pacing = Some(pacing);
        self
    }

    /// The pacing of the store's writes, if they are paced. The stack gives
    /// it to the context of the engine it starts on this store.
    pub(super) fn pacing(&self) -> Option<EnginePacing> {
        self.pacing.clone()
    }

    /// Read the store's contents with `read`.
    fn read<T>(&self, read: impl FnOnce(&Inner) -> T) -> T {
        unattributed(|| read(&self.inner.lock()))
    }

    /// Make the one write `secret`: apply `change` to the store, held if the
    /// store is paced and the tape says so.
    async fn write(&self, secret: Secret, change: impl FnOnce(&mut Inner)) {
        let apply = async { unattributed(|| change(&mut self.inner.lock())) };
        match &self.pacing {
            Some(pacing) => pacing.write(Operation::Secret(secret), apply).await,
            None => apply.await,
        }
    }

    /// A store that already holds `share` for `epoch`, as a node handed its
    /// share of a trusted deal does.
    pub(super) fn holding(epoch: Epoch, share: Share) -> Self {
        let store = Self::default();
        store.inner.lock().put_share(epoch, share);
        store
    }

    /// The store an identity starts a reshare run with: it holds `share`,
    /// the identity's share of the first output, if the identity was dealt
    /// one.
    pub(super) fn dealt(share: Option<Share>) -> Self {
        share.map_or_else(Self::default, |share| Self::holding(Epoch::zero(), share))
    }

    /// Give the store `share` for `epoch` at once, as a fault a test plants
    /// from outside the engine does.
    #[cfg(test)]
    pub(super) fn plant(&self, epoch: Epoch, share: Share) {
        self.inner.lock().put_share(epoch, share);
    }

    /// The share held for `epoch`, if any.
    pub(super) fn share(&self, epoch: Epoch) -> Option<Share> {
        self.read(|inner| inner.shares.get(&epoch).cloned())
    }

    /// Whether a dealer seed is held for `epoch`.
    #[cfg(test)]
    pub(super) fn seeded(&self, epoch: Epoch) -> bool {
        self.read(|inner| inner.seeds.contains_key(&epoch))
    }

    /// How many private dealings are held for `epoch`.
    #[cfg(test)]
    pub(super) fn dealings(&self, epoch: Epoch) -> usize {
        self.read(|inner| {
            inner
                .dealings
                .keys()
                .filter(|(dealt, _, _)| *dealt == epoch)
                .count()
        })
    }

    /// Give `copy` at once the private dealings held for `epoch` from
    /// `dealer`, each under the public message it came with.
    #[cfg(test)]
    pub(super) fn copy_dealings<P: PublicKey>(&self, copy: &Self, epoch: Epoch, dealer: &P) {
        let dealer = dealer.encode().to_vec();
        let held: Vec<_> = self.read(|inner| {
            inner
                .dealings
                .iter()
                .filter(|((dealt, from, _), _)| *dealt == epoch && *from == dealer)
                .map(|(key, private)| (key.clone(), private.clone()))
                .collect()
        });
        copy.inner.lock().dealings.extend(held);
    }

    /// Every distinct share the engine ever stored, with the epoch it was
    /// stored for, in the order stored. The engine prunes the shares of old
    /// epochs; the oracle reads them from here.
    pub(super) fn held(&self) -> Vec<(Epoch, Share)> {
        self.read(|inner| inner.held.clone())
    }

    /// Every distinct share the engine ever stored for `epoch`, in the order
    /// stored.
    pub(super) fn held_for(&self, epoch: Epoch) -> Vec<Share> {
        self.read(|inner| {
            inner
                .held
                .iter()
                .filter(|(stored, _)| *stored == epoch)
                .map(|(_, share)| share.clone())
                .collect()
        })
    }
}

impl SecretStore for Secrets {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.write(Secret::Share, |inner| inner.put_share(epoch, share))
            .await;
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        self.share(epoch)
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.write(Secret::Seed, |inner| {
            inner.seeds.insert(epoch, seed);
        })
        .await;
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.read(|inner| inner.seeds.get(&epoch).cloned())
    }

    async fn put_dealing<V: Variant, P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        public: &DealerPubMsg<V>,
        private: DealerPrivMsg,
    ) {
        let key = (epoch, dealer.encode().to_vec(), public.encode());
        self.write(Secret::Dealing, |inner| {
            // A player stores only a dealing it verified, and one public
            // message fixes the private dealing each player can verify.
            let replaced = inner.dealings.insert(key, private.clone());
            assert!(
                replaced.is_none_or(|replaced| replaced == private),
                "stored private dealing must not change"
            );
        })
        .await;
    }

    async fn get_dealing<V: Variant, P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
        public: &DealerPubMsg<V>,
    ) -> Option<DealerPrivMsg> {
        let key = (epoch, dealer.encode().to_vec(), public.encode());
        self.read(|inner| inner.dealings.get(&key).cloned())
    }

    async fn prune(&mut self, min: Epoch) {
        self.write(Secret::Prune, |inner| {
            inner.shares.retain(|epoch, _| *epoch >= min);
            inner.seeds.retain(|epoch, _| *epoch >= min);
            inner.dealings.retain(|(epoch, _, _), _| *epoch >= min);
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            MockGroup, RESHARE_NAMESPACE,
            context::EngineContext,
            fixtures::{committee, described},
            identities,
            pacing::{PacedCounts, Pacing, Stage},
        },
        stateful::runner::tolerating,
    };
    use commonware_cryptography::{
        bls12381::{
            dkg::feldman_desmedt::{Dealer, Info as Round, Reveal},
            primitives::sharing::Mode,
        },
        ed25519,
    };
    use commonware_math::algebra::Random as _;
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{N3f1, TestRng};
    use std::time::Duration;

    /// When the one crash of every schedule here is due, how far back its
    /// window reaches, and a moment inside that window.
    const CRASH: Duration = Duration::from_millis(200);
    const REACH: Duration = Duration::from_millis(50);
    const INSIDE: Duration = Duration::from_millis(175);

    const EPOCH: Epoch = Epoch::zero();

    fn seed() -> Summary {
        Summary::random(TestRng::new(7))
    }

    /// The share a trusted deal gives the first identity.
    fn share() -> Share {
        described(1, EPOCH).1.remove(0)
    }

    /// The public message of the first identity's dealing when it reshares
    /// the output of the trusted deal.
    fn public() -> DealerPubMsg<MockGroup> {
        let (info, _) = described(1, EPOCH);
        let round = Round::new::<N3f1>(
            RESHARE_NAMESPACE,
            EPOCH.get(),
            Some(info.output.clone()),
            Mode::NonZeroCounter,
            Reveal::V1,
            info.output.players().clone(),
            info.players,
        )
        .expect("a reshare among the dealt committee is valid");
        let (_, public, _) = Dealer::<MockGroup, ed25519::PrivateKey>::start::<N3f1>(
            TestRng::new(7),
            round,
            identities().remove(0),
            Some(share()),
        )
        .expect("the first identity deals");
        public
    }

    /// What a store holds for [`EPOCH`] after a crash, how the held writes
    /// ended, and the held writes the crash dropped.
    struct Crashed {
        seed: Option<Summary>,
        share: Option<Share>,
        held: Vec<(Epoch, Share)>,
        counts: PacedCounts,
        dropped: Vec<(Operation, Stage)>,
    }

    /// Run an engine that, inside the window of its crash, starts `write` on
    /// a paced store, which is held at `stage`, and crash it there. The
    /// store holds a share, and a seed if `seeded`.
    fn crashed_in_a_write<W, Fut>(stage: Stage, seeded: bool, write: W) -> Crashed
    where
        W: FnOnce(Secrets) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, stage, CRASH, REACH);
            let mut secrets = Secrets::holding(EPOCH, share()).paced(pacing.engine(0));
            if seeded {
                secrets.put_seed(EPOCH, seed()).await;
            }
            let store = secrets.clone();
            let handle = context.child("engine").spawn(move |context| async move {
                context.sleep(INSIDE).await;
                write(store).await;
                unreachable!("the crash comes while the write is held");
            });
            context.sleep(CRASH).await;
            pacing.crashing(0);
            handle.abort();
            let _ = handle.await;
            let trace = pacing.trace();
            Crashed {
                seed: secrets.get_seed(EPOCH).await,
                share: secrets.get_share(EPOCH).await,
                held: secrets.held(),
                counts: trace.counts(),
                dropped: trace.dropped(0),
            }
        })
    }

    #[test]
    fn write_dropped_before_it_is_applied_leaves_no_trace() {
        let crashed = crashed_in_a_write(Stage::Before, false, |mut store| async move {
            store.put_seed(EPOCH, seed()).await;
        });
        assert_eq!(crashed.seed, None);
        assert_eq!(
            crashed.counts,
            PacedCounts {
                crashes: 1,
                before: 1,
                dkg_before: 1,
                ..PacedCounts::default()
            }
        );
        assert_eq!(
            crashed.dropped,
            vec![(Operation::Secret(Secret::Seed), Stage::Before)]
        );
    }

    #[test]
    fn write_dropped_after_it_is_applied_is_durable() {
        let crashed = crashed_in_a_write(Stage::After, false, |mut store| async move {
            store.put_seed(EPOCH, seed()).await;
        });
        assert_eq!(crashed.seed, Some(seed()));
        assert_eq!(
            crashed.counts,
            PacedCounts {
                crashes: 1,
                durable: 1,
                dkg_durable: 1,
                ..PacedCounts::default()
            }
        );
        assert_eq!(
            crashed.dropped,
            vec![(Operation::Secret(Secret::Seed), Stage::After)]
        );
    }

    /// A write that changes several entries is made as a whole or not at
    /// all.
    #[test]
    fn dropped_write_is_never_applied_in_part() {
        for (stage, kept) in [(Stage::Before, true), (Stage::After, false)] {
            let crashed = crashed_in_a_write(stage, true, |mut store| async move {
                store.prune(EPOCH.next()).await;
            });
            assert_eq!(crashed.share.is_some(), kept, "{stage:?}");
            assert_eq!(crashed.seed.is_some(), kept, "{stage:?}");
            assert_eq!(
                crashed.dropped,
                vec![(Operation::Secret(Secret::Prune), stage)]
            );

            // What the oracle reads of the shares ever held is not pruned.
            assert_eq!(crashed.held, vec![(EPOCH, share())]);
        }
    }

    /// A write is in place when its future resolves: at once outside the
    /// window of a crash and on a store that is not paced, and after its
    /// hold inside the window.
    #[test]
    fn resolved_write_is_durable() {
        deterministic::Runner::default().start(|context| async move {
            let pacing = Pacing::holding(&context, Stage::Before, CRASH, REACH);
            let mut secrets = Secrets::default().paced(pacing.engine(0));
            let mut unpaced = Secrets::default();
            let dealer = committee().remove(0);

            let started = context.current();
            secrets.put_share(EPOCH, share()).await;
            assert_eq!(secrets.get_share(EPOCH).await, Some(share()));
            assert_eq!(context.current(), started);

            context.sleep(INSIDE).await;
            let started = context.current();
            unpaced.put_seed(EPOCH, seed()).await;
            assert_eq!(unpaced.get_seed(EPOCH).await, Some(seed()));
            assert_eq!(secrets.get_seed(EPOCH).await, None);
            assert_eq!(secrets.get_dealing(EPOCH, &dealer, &public()).await, None);
            assert_eq!(context.current(), started);

            secrets.put_seed(EPOCH, seed()).await;
            assert_eq!(secrets.get_seed(EPOCH).await, Some(seed()));
            assert!(context.current() > started + (CRASH - INSIDE));
            assert_eq!(
                pacing.trace().counts(),
                PacedCounts {
                    resumed: 1,
                    ..PacedCounts::default()
                }
            );
        });
    }

    /// A panic in the store's own code, raised while a task of an engine
    /// reads or writes it, is attributed to no engine.
    #[test]
    fn panic_in_the_store_is_attributed_to_no_engine() {
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, panics) = tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let (reader, writer) = (Secrets::default(), Secrets::default());
                let engine = EngineContext::new(context.child("engine"), 2);
                drop(engine.child("reader").spawn(move |_| async move {
                    reader.read(|_| panic!("reading"));
                }));
                drop(engine.child("writer").spawn(move |_| async move {
                    writer.write(Secret::Seed, |_| panic!("writing")).await;
                }));
                context.sleep(Duration::from_millis(10)).await;
            })
        });
        result.expect("the root task returns");
        let engines: Vec<_> = panics.iter().map(|panic| panic.engine).collect();
        assert_eq!(engines, vec![None, None]);
    }
}
