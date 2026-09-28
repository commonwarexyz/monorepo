//! Per-epoch driver for the reshare ceremony.
//!
//! See the [reshare docs](crate::dkg::reshare) for the protocol, application
//! contract, and recovery rules this actor implements.
//!
//! # Architecture
//!
//! Each iteration of the run loop handles the epoch containing the first height
//! the actor has not applied:
//!
//! - `setup` is responsible for loading the epoch's [`EpochInfo`], registering
//!   its scheme, and restoring this node's dealer and player state.
//! - `dealing` is responsible for exchanging private dealings and
//!   acknowledgements during the first half of the epoch.
//! - `inclusion` is responsible for offering this node's dealer log, recording
//!   finalized logs, and deriving the next [`EpochInfo`].
//! - `follower` is responsible for following the chain without participating
//!   until the next final block of an epoch is applied.
//! - `dkg` is responsible for the one-shot DKG mode used by
//!   [`bootstrap`](crate::dkg::bootstrap).

use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    fence::Fence,
    network::{Directory, Manager},
    reshare::{Mailbox, Message, metrics::Metrics as ReshareMetrics, store::Store},
    state_sync::{self, Plan as StateSyncPlan},
    types::EpochInfo,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver as MailboxReceiver};
use commonware_consensus::{
    Heightable as _,
    marshal::core::{CommitmentFallback, Mailbox as MarshalMailbox, Variant as MarshalVariant},
    simplex::scheme::Scheme as SimplexScheme,
    types::{EpochPhase, FixedEpocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::Reveal,
        primitives::{sharing::Mode as SharingMode, variant::Variant as BlsVariant},
    },
    certificate::Scheme,
};
use commonware_p2p::{Blocker, Receiver, Sender, utils::mux::Muxer};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
    spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact, ordered::Set};
use rand_core::CryptoRng;
use std::{
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
};

type DkgCompletion<V, P, D> = Box<dyn FnOnce(Option<EpochInfo<V, P, D>>) + Send>;

/// Height and digest of the latest finalized block the actor has applied.
#[derive(Clone, Copy)]
struct FinalizedTip<D> {
    height: Height,
    digest: D,
}

mod dealing;
mod dkg;
mod follower;
mod inclusion;
mod setup;
#[cfg(test)]
mod utils;
use setup::{Setup, StateSyncStart, startup};

/// Configuration for the one-shot DKG mode used by [`bootstrap`](crate::dkg::bootstrap).
pub(crate) struct DkgConfig<V, P, D>
where
    V: BlsVariant,
    P: PublicKey,
    D: Directory<P>,
{
    pub(crate) participants: Set<P>,
    /// Transport directory for the one-shot ceremony's participants, embedded
    /// verbatim in the emitted epoch-zero artifact. Every participant must
    /// configure the same directory.
    pub(crate) directory: D,
    pub(crate) completion: DkgCompletion<V, P, D>,
}

enum Mode<V, P, D>
where
    V: BlsVariant,
    P: PublicKey,
    D: Directory<P>,
{
    Reshare,
    Dkg {
        participants: Set<P>,
        directory: D,
        completion: Option<DkgCompletion<V, P, D>>,
    },
}

/// Configuration for [`Actor`].
pub struct Config<C, M, X, P, SS, T, BV, S, MV, R>
where
    C: Signer,
    X: Blocker<PublicKey = C::PublicKey>,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock,
    <MV::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = C::PublicKey>,
    R: Registrar<PublicKey = C::PublicKey>,
{
    /// Signer for player acknowledgements and dealer logs.
    pub signer: C,

    /// P2P manager used to track peers during one-shot DKG.
    ///
    /// Continuous reshare peer tracking is owned by
    /// [`orchestrator`](crate::dkg::orchestrator).
    pub manager: M,

    /// Blocker used to block peers that send invalid protocol messages.
    pub blocker: X,

    /// Source of future participant sets and transport directories.
    pub participants_provider: P,

    /// Store for shares, private dealings, and dealer RNG seeds.
    pub secret_store: SS,

    /// Parallel strategy for cryptographic verification.
    pub strategy: T,

    /// Receives each epoch's signer or verifier scheme.
    pub registrar: R,

    /// Marshal mailbox used to read finalized blocks.
    pub marshal: MarshalMailbox<S, MV>,

    /// State-sync recovery plan shared with the orchestrator.
    pub state_sync: StateSyncPlan<
        S,
        MV::Commitment,
        R::Variant,
        <MV::ApplicationBlock as ReshareBlock>::Directory,
    >,

    /// Fence marked after each epoch's scheme is registered.
    pub fence: Fence,

    /// Application namespace for transcript separation.
    pub namespace: &'static [u8],

    /// Sharing mode used for newly generated threshold outputs.
    pub sharing_mode: SharingMode,

    /// Revealed-share calculation used for each newly prepared ceremony.
    pub reveal: Reveal,

    /// Actor mailbox capacity.
    pub mailbox_size: NonZeroUsize,

    /// Prefix of the recovery journal's storage partition.
    pub partition_prefix: String,

    /// Page cache for the recovery journal.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob in the recovery journal.
    pub write_buffer: NonZeroUsize,

    /// Number of bytes to buffer when replaying the recovery journal during startup.
    pub replay_buffer: NonZeroUsize,

    /// Maximum entries accepted in each decoded or provider-supplied
    /// participant set.
    pub max_participants: NonZeroU32,

    /// Epoch schedule used to interpret finalized block heights.
    pub blocks_per_epoch: NonZeroU64,

    /// Batch verifier used to verify dealer logs.
    pub batch_verifier: PhantomData<BV>,
}

/// Reshare actor for one node.
///
/// See the [module docs](crate::dkg::reshare) for the protocol it runs.
pub struct Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A = Exact>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey, Directory = B::Directory>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey, Directory = B::Directory>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    context: ContextCell<E>,
    mailbox: MailboxReceiver<Message<B, V, C, A>>,
    signer: C,
    manager: M,
    blocker: X,
    participants_provider: P,
    secret_store: Option<SS>,
    strategy: T,
    registrar: R,
    marshal: MarshalMailbox<S, MV>,
    state_sync: StateSyncPlan<S, MV::Commitment, V, B::Directory>,
    fence: Fence,
    namespace: &'static [u8],
    sharing_mode: SharingMode,
    reveal: Reveal,
    partition_prefix: String,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,
    replay_buffer: NonZeroUsize,
    max_participants: NonZeroU32,
    blocks_per_epoch: NonZeroU64,
    epocher: FixedEpocher,
    metrics: ReshareMetrics<C::PublicKey>,
    mode: Mode<V, C::PublicKey, B::Directory>,
    tip: Option<FinalizedTip<B::Digest>>,
    batch_verifier: PhantomData<BV>,
}

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey, Directory = B::Directory>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey, Directory = B::Directory>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    /// Creates an actor from `config` and returns it with its [`Mailbox`].
    pub fn new(
        context: E,
        config: Config<C, M, X, P, SS, T, BV, S, MV, R>,
    ) -> (Self, Mailbox<B, V, C, A>) {
        let epocher = FixedEpocher::new(config.blocks_per_epoch);
        let (sender, mailbox) = actor_mailbox::new(context.child("mailbox"), config.mailbox_size);
        let metrics = ReshareMetrics::new(&context);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                signer: config.signer,
                manager: config.manager,
                blocker: config.blocker,
                participants_provider: config.participants_provider,
                secret_store: Some(config.secret_store),
                strategy: config.strategy,
                registrar: config.registrar,
                marshal: config.marshal,
                state_sync: config.state_sync,
                fence: config.fence,
                namespace: config.namespace,
                sharing_mode: config.sharing_mode,
                reveal: config.reveal,
                partition_prefix: config.partition_prefix,
                page_cache: config.page_cache,
                write_buffer: config.write_buffer,
                replay_buffer: config.replay_buffer,
                max_participants: config.max_participants,
                blocks_per_epoch: config.blocks_per_epoch,
                epocher,
                metrics,
                mode: Mode::Reshare,
                tip: None,
                batch_verifier: config.batch_verifier,
            },
            Mailbox::new(sender),
        )
    }

    pub(crate) fn new_dkg(
        context: E,
        config: Config<C, M, X, P, SS, T, BV, S, MV, R>,
        dkg: DkgConfig<V, C::PublicKey, B::Directory>,
    ) -> (Self, Mailbox<B, V, C, A>) {
        let (mut actor, mailbox) = Self::new(context, config);
        actor.mode = Mode::Dkg {
            participants: dkg.participants,
            directory: dkg.directory,
            completion: Some(dkg.completion),
        };
        (actor, mailbox)
    }

    /// Spawns the actor with its P2P channel `chan`.
    ///
    /// The task exits when the runtime stops, when the mailbox closes, or when
    /// `chan` closes during a dealing window. See the
    /// [module docs](crate::dkg::reshare#failures) for the conditions under
    /// which it panics.
    pub fn start<SE, RE>(mut self, chan: (SE, RE)) -> Handle<()>
    where
        SE: Sender<PublicKey = C::PublicKey>,
        RE: Receiver<PublicKey = C::PublicKey>,
    {
        spawn_cell!(self.context, self.run(chan))
    }

    async fn run<SE, RE>(mut self, (sender, receiver): (SE, RE))
    where
        SE: Sender<PublicKey = C::PublicKey>,
        RE: Receiver<PublicKey = C::PublicKey>,
    {
        let secret_store = self
            .secret_store
            .take()
            .expect("secret store must be available when actor starts");
        let mut store = Store::init(
            self.context.child("store"),
            &self.partition_prefix,
            self.max_participants,
            self.page_cache.clone(),
            self.write_buffer,
            self.replay_buffer,
            secret_store,
        )
        .await;

        let (mux, mut dealing_mux) = Muxer::new(self.context.child("mux"), sender, receiver, 128);
        mux.start();

        let recovered_epoch = state_sync::recovered_epoch(&self.marshal, &self.epocher).await;
        let state_sync = self
            .state_sync
            .resolve(
                self.context.as_present().child("state_sync"),
                recovered_epoch,
            )
            .await;

        // Register the synced epoch, then resolve its floor height. Setup uses
        // the floor to decide whether the epoch's dealer-log window is complete.
        let (mut state_sync, floor) = if let Some(state_sync) = state_sync {
            let share = self.recovered_share(&mut store, &state_sync.info).await;
            self.register_epoch(&state_sync.info, share).await;
            let floor = self
                .marshal
                .subscribe_by_commitment(
                    state_sync.floor.proposal.payload,
                    CommitmentFallback::Wait,
                )
                .await
                .expect("marshal must yield state sync floor block");
            let start = StateSyncStart {
                info: state_sync.info,
                floor: floor.height(),
            };
            (Some(start), Some(floor))
        } else {
            (None, None)
        };

        self.tip = startup(self.marshal.get_anchor().await, floor);

        if matches!(self.mode, Mode::Dkg { .. }) {
            self.run_dkg(&mut store, &mut dealing_mux).await;
            return;
        }

        loop {
            let Some(prepared) = self.setup(&mut store, state_sync.take()).await else {
                return;
            };
            let Setup::Participate(prepared) = prepared else {
                if self.follow(&mut store).await.is_break() {
                    return;
                }
                continue;
            };
            let mut prepared = *prepared;

            let chan = dealing_mux
                .register(prepared.epoch.get())
                .await
                .expect("failed to register reshare epoch channel");

            if prepared.phase == EpochPhase::Early {
                let dealer = prepared.dealer.as_mut();
                let player = prepared.player.as_mut();
                if self
                    .dealing(prepared.epoch, &mut store, dealer, player, chan)
                    .await
                    .is_break()
                {
                    return;
                }
            }

            if self
                .inclusion(
                    prepared.epoch,
                    &prepared.info,
                    &mut store,
                    prepared.dealer.as_mut(),
                )
                .await
                .is_break()
            {
                return;
            }
        }
    }

    /// Returns whether the actor has already applied `block`, either at startup
    /// or by completing its effects.
    ///
    /// A block at or below the tip is a redelivery. A block above the tip must
    /// be at the height after it. Without a tip, returns `false` and checks
    /// nothing.
    ///
    /// # Panics
    ///
    /// Panics if `block` conflicts with the tip at the same height or skips
    /// heights above the tip.
    fn covered(&self, block: &B) -> bool {
        self.tip.is_some_and(|tip| {
            if block.height() == tip.height {
                assert_eq!(block.digest(), tip.digest, "conflicting finalized block");
            } else if block.height() > tip.height {
                assert_eq!(
                    block.height(),
                    tip.height.next(),
                    "finalized block skips unapplied heights"
                );
            }
            block.height() <= tip.height
        })
    }

    /// Records `block` as the tip after its effects complete.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not above the tip.
    fn advance(&mut self, block: &B) {
        assert!(
            self.tip.is_none_or(|tip| block.height() > tip.height),
            "completed block must advance the tip"
        );
        self.tip = Some(FinalizedTip {
            height: block.height(),
            digest: block.digest(),
        });
    }
}
