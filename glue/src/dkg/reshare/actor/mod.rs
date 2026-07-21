//! Drive per-epoch BLS resharing from finalized marshal state.
//!
//! The actor bridges finalized epoch metadata, the Feldman-Desmedt reshare
//! protocol, P2P dealer traffic, and certificate-scheme registration. Each loop
//! iteration derives the active epoch from marshal's processed height, loads the
//! epoch's public [`EpochInfo`] from the finalized
//! boundary block, and either participates in the ceremony or follows until the
//! next boundary is finalized.
//!
//! # Epoch Lifecycle
//!
//! A participating epoch has three states:
//!
//! 1. **Setup** reads the canonical boundary block, replays durable recovery
//!    state, opens the epoch peer set, registers the current scheme with the
//!    [`Registrar`], and prepares optional dealer/player state for this node.
//! 2. **Dealing** runs during the early half of the epoch. Dealers send private
//!    shares to players over P2P and players return signed acknowledgements.
//! 3. **Inclusion** runs from the midpoint through the final block. The actor
//!    offers one finalized dealer log to the application, observes finalized
//!    logs on-chain, computes the next [`EpochInfo`],
//!    and registers the next epoch once that boundary block finalizes.
//!
//! ```text
//! finalized boundary for epoch N
//!        |
//!        v
//! setup: load EpochInfo(N), share, seed, recovery journal
//!        |
//!        +-- no boundary info and already inside epoch --> follower mode
//!        |
//!        v
//! early blocks
//!        |
//!        v
//! dealing: dealer shares <--> player acknowledgements
//!        |
//!        v
//! midpoint
//!        |
//!        v
//! inclusion: propose/observe dealer logs
//!        |
//!        v
//! final block carries EpochInfo(N + 1)
//!        |
//!        v
//! register scheme for epoch N + 1
//! ```
//!
//! # Payload Flow
//!
//! Consensus asks the actor for an optional payload before proposing each block,
//! and reports finalized blocks after marshal processes them:
//!
//! ```text
//! application --Next(height)-----------> Actor --Payload?----------> application
//! marshal     --Finalized(block)-------> Actor --acknowledge-------> marshal
//! peer        --Dealer/Ack(epoch)------> Actor --Ack/Dealer(epoch)-> peer
//! ```
//!
//! During dealing, `Next` never returns a payload. During inclusion, `Next`
//! returns at most one dealer log before the final height, and returns the
//! computed [`EpochInfo`] at the final height when
//! enough valid logs are available. Finalized blocks are the source of truth:
//! only logs and epoch info that appear in finalized blocks update durable state
//! or registered schemes.
//!
//! # Crash Recovery
//!
//! Recovery state is split by sensitivity. Public, replayable protocol messages
//! are journaled by [`Store`]: dealer public messages, player acknowledgements,
//! and finalized dealer logs. Secret material is kept only in [`SecretStore`]:
//! current shares, private dealings, and dealer RNG seeds. Public epoch info is
//! normally re-derived from finalized boundary blocks; state-sync startup
//! material is retained separately and removed on a later startup after marshal
//! has advanced beyond its epoch.
//!
//! ```text
//! restart
//!   |
//!   +--> marshal processed height determines candidate epoch
//!   |
//!   +--> boundary block supplies canonical EpochInfo
//!   |
//!   +--> Store replays public journal
//!   |
//!   +--> SecretStore supplies share, private dealings, and seed
//!   |
//!   v
//! resume as dealer/player/observer when enough state is available
//! ```
//!
//! Reusing the persisted dealer seed makes regenerated dealer shares identical
//! after a restart. Persisted acknowledgements and finalized logs let a player or
//! observer rebuild the same outcome even though P2P messages and finalized-block
//! notifications are not replayed by the runtime. If the node lacks a valid share
//! for a dealer role, it simply observes or plays instead of manufacturing local
//! state.
//!
//! # Follower Mode
//!
//! The actor follows instead of participating when setup cannot read the boundary
//! [`EpochInfo`] for the epoch containing marshal's next unprocessed height. This can occur during
//! state-sync handoff because marshal may not retain the preceding boundary block.
//!
//! ```text
//! processed height + 1 = H
//!        |
//!        v
//! H is in epoch N
//!        |
//!        v
//! boundary EpochInfo(N) unavailable locally
//!        |
//!        v
//! follower mode until final(N)
//!        |
//!        v
//! final(N) carries EpochInfo(N + 1)
//!        |
//!        +--> failed ceremony and prior share held -> register signer
//!        |
//!        +--> otherwise -> register verifier
//!        |
//!        v
//! setup again
//! ```
//!
//! While following, `Next` always returns no payload and finalized blocks are
//! acknowledged without mutation until the final block of the current epoch. The
//! final block's epoch info is used as the next loop's boundary state. When a
//! failed ceremony carries the previous threshold output forward, the actor also
//! carries forward a locally held share and registers as a signer. Otherwise, it
//! commits without a share and registers as a verifier.

use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    fence::Fence,
    reshare::{Mailbox, Message, metrics::Metrics as ReshareMetrics, store::Store},
    state_sync::{self, Plan as StateSyncPlan},
    types::EpochInfo,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver as MailboxReceiver};
use commonware_consensus::{
    marshal::core::{CommitmentFallback, Mailbox as MarshalMailbox, Variant as MarshalVariant},
    simplex::scheme::Scheme as SimplexScheme,
    types::{EpochPhase, FixedEpocher},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::primitives::{sharing::Mode as SharingMode, variant::Variant as BlsVariant},
    certificate::Scheme,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender, utils::mux::Muxer};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact, ordered::Set};
use rand_core::CryptoRng;
use std::{
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
};

type DkgCompletion<V, P> = Box<dyn FnOnce(Option<EpochInfo<V, P>>) + Send>;

mod dealing;
mod dkg;
mod follower;
mod inclusion;
mod setup;
use setup::Setup;

/// Configuration for the crate-private one-shot DKG mode.
pub(crate) struct DkgConfig<V, P>
where
    V: BlsVariant,
    P: PublicKey,
{
    pub(crate) participants: Set<P>,
    pub(crate) completion: DkgCompletion<V, P>,
}

enum Mode<V, P>
where
    V: BlsVariant,
    P: PublicKey,
{
    Reshare,
    Dkg {
        participants: Set<P>,
        completion: Option<DkgCompletion<V, P>>,
    },
}

/// Configuration for [`Actor`].
pub struct Config<C, M, X, P, SS, T, BV, S, MV, R>
where
    C: Signer,
    X: Blocker<PublicKey = C::PublicKey>,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant,
    R: Registrar<PublicKey = C::PublicKey>,
{
    /// Signer for player acknowledgments and dealer logs.
    pub signer: C,

    /// P2P manager used to track peers during one-shot DKG.
    ///
    /// Continuous reshare peer tracking is owned by
    /// [`orchestrator`](crate::dkg::orchestrator).
    pub manager: M,

    /// Blocker used to block peers that send invalid protocol messages.
    pub blocker: X,

    /// Provider of participant policy.
    pub participants_provider: P,

    /// Store for private share material.
    pub secret_store: SS,

    /// Parallel strategy for cryptographic verification.
    pub strategy: T,

    /// Registrar for configuring signing scheme providers.
    pub registrar: R,

    /// Marshal mailbox used to read canonical public epoch state from finalized
    /// boundary blocks.
    pub marshal: MarshalMailbox<S, MV>,

    /// Shared DKG state-sync startup recovery plan.
    pub state_sync: StateSyncPlan<S, MV::Commitment, R::Variant>,

    /// Epoch readiness fence.
    pub fence: Fence,

    /// Application namespace for transcript separation.
    pub namespace: &'static [u8],

    /// Sharing mode used for newly generated threshold outputs.
    pub sharing_mode: SharingMode,

    /// Actor mailbox capacity.
    pub mailbox_size: NonZeroUsize,

    /// Runtime-storage partition prefix.
    pub partition_prefix: String,

    /// Maximum participants accepted in decoded protocol values and
    /// provider-supplied future participant sets.
    pub max_participants: NonZeroU32,

    /// Epoch schedule used to interpret finalized block heights.
    pub blocks_per_epoch: NonZeroU64,

    /// Batch verifier marker.
    pub batch_verifier: PhantomData<BV>,
}

pub struct Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A = Exact>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
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
    state_sync: StateSyncPlan<S, MV::Commitment, V>,
    fence: Fence,
    namespace: &'static [u8],
    sharing_mode: SharingMode,
    partition_prefix: String,
    max_participants: NonZeroU32,
    blocks_per_epoch: NonZeroU64,
    epocher: FixedEpocher,
    metrics: ReshareMetrics<C::PublicKey>,
    mode: Mode<V, C::PublicKey>,
    batch_verifier: PhantomData<BV>,
}

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
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
                partition_prefix: config.partition_prefix,
                max_participants: config.max_participants,
                blocks_per_epoch: config.blocks_per_epoch,
                epocher,
                metrics,
                mode: Mode::Reshare,
                batch_verifier: config.batch_verifier,
            },
            Mailbox::new(sender),
        )
    }

    pub(crate) fn new_dkg(
        context: E,
        config: Config<C, M, X, P, SS, T, BV, S, MV, R>,
        dkg: DkgConfig<V, C::PublicKey>,
    ) -> (Self, Mailbox<B, V, C, A>) {
        let (mut actor, mailbox) = Self::new(context, config);
        actor.mode = Mode::Dkg {
            participants: dkg.participants,
            completion: Some(dkg.completion),
        };
        (actor, mailbox)
    }

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
        if let Some(state_sync) = &state_sync {
            let share = self.recovered_share(&mut store, &state_sync.info).await;
            self.register_epoch(&state_sync.info, share).await;
            self.marshal
                .subscribe_by_commitment(
                    state_sync.floor.proposal.payload,
                    CommitmentFallback::Wait,
                )
                .await
                .expect("marshal must yield state sync floor block");
        }

        if matches!(self.mode, Mode::Dkg { .. }) {
            self.run_dkg(&mut store, &mut dealing_mux).await;
            return;
        }

        let mut current_epoch = state_sync.as_ref().map(|state_sync| state_sync.info.epoch);
        let mut state_sync_info = state_sync.map(|state_sync| state_sync.info);
        loop {
            let Some(prepared) = self
                .setup(&mut store, current_epoch.take(), state_sync_info.take())
                .await
            else {
                return;
            };
            let Setup::Participate(prepared) = prepared else {
                if self.follow(&mut store).await.is_break() {
                    return;
                }
                current_epoch = store.current().map(|info| info.epoch);
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
            current_epoch = Some(prepared.epoch.next());
        }
    }
}
