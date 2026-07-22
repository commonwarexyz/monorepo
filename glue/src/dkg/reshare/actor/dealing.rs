use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    reshare::{
        Actor, EpochInfoResponse, Message as MailboxMessage,
        metrics::Phase,
        store::{Dealer, Player, Store},
    },
    types::Message,
};
use commonware_codec::{Decode, Encode};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, EpochPhase, Epocher},
};
use commonware_cryptography::{
    BatchVerifier, Signer,
    bls12381::{dkg::feldman_desmedt::Verdict, primitives::variant::Variant as BlsVariant},
    certificate::Scheme,
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Manager, Message as NetworkMessage, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::traces::TracedExt as _,
};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use rand_core::CryptoRng;
use std::ops::ControlFlow;
use tracing::{Instrument as _, debug, info, info_span, warn};

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
    /// Run the early dealing phase for `epoch`.
    ///
    /// The phase processes inbound dealer messages and acknowledgements while
    /// finalized blocks remain in [`EpochPhase::Early`]. It returns after the
    /// final early block is acknowledged.
    pub(super) async fn dealing<SE, RE>(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey>,
        mut dealer: Option<&mut Dealer<V, C>>,
        mut player: Option<&mut Player<V, C>>,
        (mut sender, mut receiver): (SE, RE),
    ) -> ControlFlow<()>
    where
        SE: Sender<PublicKey = C::PublicKey>,
        RE: Receiver<PublicKey = C::PublicKey>,
    {
        self.metrics.set_phase(Phase::Dealing);

        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return ControlFlow::Break(());
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return ControlFlow::Break(());
            } => match message {
                MailboxMessage::NextLog { span, response, .. } => {
                    let process = info_span!(parent: &span, "dkg.reshare.actor.dealing.next_log");
                    process.in_scope(|| {
                        let _ = response.send_lossy(None);
                    });
                }
                MailboxMessage::ReleaseLog { .. } => {}
                MailboxMessage::EpochInfo { span, response, .. } => {
                    let process = info_span!(parent: &span, "dkg.reshare.actor.dealing.epoch_info");
                    process.in_scope(|| {
                        let _ = response.send_lossy(EpochInfoResponse::Pending);
                    });
                }
                MailboxMessage::Finalized {
                    span,
                    block,
                    response,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.dealing.finalized",
                        height = block.height().traced()
                    );
                    let done = async {
                        let bounds = self
                            .epocher
                            .containing(block.height())
                            .expect("epocher must know of block height");
                        assert_eq!(bounds.epoch(), epoch, "dealing received future epoch block");
                        assert_eq!(
                            bounds.phase(),
                            EpochPhase::Early,
                            "dealing received block after early phase"
                        );

                        if let Some(dealer) = dealer.as_deref_mut() {
                            Self::send_dealings(
                                &self.signer.public_key(),
                                store,
                                epoch,
                                dealer,
                                player.as_deref_mut(),
                                &mut sender,
                            )
                            .await;
                        }

                        let done = self
                            .epocher
                            .midpoint(epoch)
                            .and_then(|midpoint| midpoint.previous())
                            == Some(block.height());
                        response.acknowledge();
                        done
                    }
                    .instrument(process)
                    .await;
                    if done {
                        return ControlFlow::Continue(());
                    }
                }
            },
            Ok(message) = receiver.recv() else {
                debug!("dealing channel closed, shutting down");
                return ControlFlow::Break(());
            } => {
                self.handle_message(
                    epoch,
                    store,
                    dealer.as_deref_mut(),
                    player.as_deref_mut(),
                    &mut sender,
                    message,
                )
                .await
            },
        };

        ControlFlow::Break(())
    }

    async fn handle_message<SE>(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey>,
        dealer: Option<&mut Dealer<V, C>>,
        player: Option<&mut Player<V, C>>,
        sender: &mut SE,
        (from, bytes): NetworkMessage<C::PublicKey>,
    ) where
        SE: Sender<PublicKey = C::PublicKey>,
    {
        let message =
            match Message::<V, C::PublicKey>::decode_cfg(bytes.as_ref(), &self.max_participants) {
                Ok(message) => message,
                Err(error) => {
                    commonware_p2p::block!(
                        self.blocker,
                        from,
                        ?epoch,
                        ?error,
                        "failed to decode dealing message"
                    );
                    return;
                }
            };

        match message {
            Message::Dealer(public, private) => {
                let Some(player) = player else {
                    commonware_p2p::block!(
                        self.blocker,
                        from,
                        ?epoch,
                        "dealing sent to non-player"
                    );
                    return;
                };
                let ack = match player
                    .handle(store, epoch, from.clone(), public, private)
                    .await
                {
                    Verdict::Valid(ack) => ack,
                    Verdict::Skip => return,
                    Verdict::Fault => {
                        commonware_p2p::block!(self.blocker, from, ?epoch, "invalid dealing");
                        return;
                    }
                };

                self.metrics.record_share(&from, epoch.get());
                info!(?epoch, dealer = ?from, "received dealing");
                let sent = sender.send(
                    Recipients::One(from.clone()),
                    Message::<V, C::PublicKey>::Ack(ack).encode(),
                    true,
                );
                if sent.is_empty() {
                    warn!(?epoch, dealer = ?from, "failed to send ack");
                }
            }
            Message::Ack(ack) => {
                let Some(dealer) = dealer else {
                    commonware_p2p::block!(self.blocker, from, ?epoch, "ack sent to non-dealer");
                    return;
                };
                match dealer.handle(store, epoch, from.clone(), ack).await {
                    Verdict::Valid(()) => {
                        self.metrics.record_ack(&from, epoch.get());
                        info!(?epoch, player = ?from, "received ack");
                    }
                    Verdict::Skip => {}
                    Verdict::Fault => {
                        commonware_p2p::block!(self.blocker, from, ?epoch, "invalid ack signature");
                    }
                }
            }
        }
    }

    async fn send_dealings<SE>(
        public_key: &C::PublicKey,
        store: &mut Store<E, SS, V, C::PublicKey>,
        epoch: Epoch,
        dealer: &mut Dealer<V, C>,
        mut player: Option<&mut Player<V, C>>,
        sender: &mut SE,
    ) where
        SE: Sender<PublicKey = C::PublicKey>,
    {
        for (recipient, public, private) in dealer.shares_to_distribute().collect::<Vec<_>>() {
            if recipient == *public_key {
                let Some(player) = player.as_deref_mut() else {
                    continue;
                };
                let Verdict::Valid(ack) = player
                    .handle(store, epoch, public_key.clone(), public, private)
                    .await
                else {
                    continue;
                };
                let _ = dealer.handle(store, epoch, public_key.clone(), ack).await;
                continue;
            }

            let sent = sender.send(
                Recipients::One(recipient.clone()),
                Message::<V, C::PublicKey>::Dealer(public, private).encode(),
                true,
            );
            if sent.is_empty() {
                debug!(?epoch, ?recipient, "failed to send share");
            } else {
                debug!(?epoch, ?recipient, "sent share");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        fence::Fence,
        reshare::actor::Config,
        state_sync::Plan as StateSyncPlan,
        tests::mocks::{self, MemorySecretStore},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{
        Reporter,
        marshal::{self, Start as MarshalStart, core::Actor as MarshalActor},
        types::{FixedEpocher, ViewDelta},
    };
    use commonware_cryptography::{
        bls12381::primitives::sharing::Mode, certificate::Verifier as _, ed25519,
    };
    use commonware_p2p::{
        Receiver,
        simulated::{Config as NetworkConfig, Network},
        utils::mocks::inert_channel,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        IoBuf, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        Acknowledgement, NZU16, NZU32, NZU64, NZUsize, acknowledgement::Exact, ordered::Set,
    };
    use std::{
        collections::VecDeque,
        convert::Infallible,
        marker::PhantomData,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    const TEST_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_RESHARE_DEALING_TEST";

    type TestActor = Actor<
        deterministic::Context,
        mocks::TestBlock,
        mocks::TestBlsVariant,
        mocks::TestSigner,
        mocks::TestManager,
        mocks::TestBlocker,
        StaticParticipants,
        MemorySecretStore,
        Sequential,
        ed25519::Batch,
        mocks::TestScheme,
        mocks::TestMarshalVariant,
        mocks::MockConsumer,
    >;

    #[derive(Clone)]
    struct StaticParticipants(Set<mocks::TestPublicKey>);

    impl ParticipantsProvider for StaticParticipants {
        type PublicKey = mocks::TestPublicKey;

        async fn participants(&mut self, _epoch: Epoch) -> Set<Self::PublicKey> {
            self.0.clone()
        }
    }

    #[derive(Debug)]
    struct QueuedReceiver {
        peer: mocks::TestPublicKey,
        messages: VecDeque<IoBuf>,
        received: Arc<AtomicUsize>,
    }

    impl Receiver for QueuedReceiver {
        type Error = Infallible;
        type PublicKey = mocks::TestPublicKey;

        async fn recv(&mut self) -> Result<NetworkMessage<Self::PublicKey>, Self::Error> {
            let Some(message) = self.messages.pop_front() else {
                futures::future::pending().await
            };
            self.received.fetch_add(1, Ordering::SeqCst);
            Ok((self.peer.clone(), message))
        }
    }

    async fn marshal_mailbox(
        context: deterministic::Context,
        signer: &mocks::TestSigner,
        scheme: mocks::TestScheme,
    ) -> mocks::TestMarshalMailbox {
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height =
            immutable::Archive::init(context.child("finalizations_by_height"), {
                let _: () = mocks::TestScheme::certificate_codec_config_unbounded();
                archive_config("dealing-priority", "finalizations", page_cache.clone(), ())
            })
            .await
            .expect("finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config("dealing-priority", "blocks", page_cache.clone(), ()),
        )
        .await
        .expect("blocks archive");

        let (_actor, mailbox, _) = MarshalActor::<_, _, _, _, _, _, _, Exact>::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: mocks::TestProvider::new(scheme),
                epocher: FixedEpocher::new(NZU64!(2)),
                start: MarshalStart::Genesis(mocks::genesis_block(signer.public_key())),
                partition_prefix: "dealing-priority-marshal".into(),
                mailbox_size: NZUsize!(16),
                view_retention: ViewDelta::new(8),
                prunable_items_per_section: NZU64!(10),
                page_cache,
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                block_codec_config: (),
                max_repair: NZUsize!(4),
                max_pending_acks: NZUsize!(4),
                strategy: Sequential,
            },
        )
        .await;
        mailbox
    }

    fn archive_config<C>(
        prefix: &str,
        name: &str,
        page_cache: CacheRef,
        codec_config: C,
    ) -> immutable::Config<C> {
        immutable::Config {
            metadata_partition: format!("{prefix}-{name}-metadata"),
            freezer_table_partition: format!("{prefix}-{name}-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{prefix}-{name}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{prefix}-{name}-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{prefix}-{name}-ordinal"),
            items_per_section: NZU64!(10),
            codec_config,
            replay_buffer: NZUsize!(1024),
            freezer_key_write_buffer: NZUsize!(1024),
            freezer_value_write_buffer: NZUsize!(1024),
            ordinal_write_buffer: NZUsize!(1024),
        }
    }

    #[test]
    fn finalized_message_is_acknowledged_before_ready_peer_traffic() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 1);
            let signer = ed25519::PrivateKey::from_seed(0);
            let peer = ed25519::PrivateKey::from_seed(1).public_key();
            let participants = Set::from_iter_dedup([signer.public_key(), peer.clone()]);
            let (_network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                vec![signer.public_key(), peer.clone()],
            )
            .await;
            let marshal = marshal_mailbox(
                context.child("marshal"),
                &signer,
                fixture.schemes[0].clone(),
            )
            .await;
            let (fence, _gate) = Fence::new(Epoch::zero());
            let (mut actor, mut mailbox) = TestActor::new(
                context.child("actor"),
                Config {
                    signer: signer.clone(),
                    manager: oracle.manager(),
                    blocker: oracle.control(signer.public_key()),
                    participants_provider: StaticParticipants(participants),
                    secret_store: MemorySecretStore::default(),
                    strategy: Sequential,
                    registrar: mocks::MockConsumer::default(),
                    marshal,
                    state_sync: StateSyncPlan::disabled(),
                    fence,
                    namespace: TEST_NAMESPACE,
                    sharing_mode: Mode::NonZeroCounter,
                    mailbox_size: NZUsize!(16),
                    partition_prefix: "dealing-priority-actor".into(),
                    max_participants: NZU32!(16),
                    blocks_per_epoch: NZU64!(2),
                    batch_verifier: PhantomData::<ed25519::Batch>,
                },
            );

            let mut store = Store::init(
                context.child("store"),
                "dealing-priority-store",
                NZU32!(16),
                MemorySecretStore::default(),
            )
            .await;
            let received = Arc::new(AtomicUsize::new(0));
            let receiver = QueuedReceiver {
                peer: peer.clone(),
                messages: (0..8).map(|_| IoBuf::from(vec![0xff])).collect(),
                received: received.clone(),
            };
            let (sender, _) = inert_channel([peer]);
            let block = Arc::new(mocks::genesis_block(signer.public_key()));
            let (ack, waiter) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(block, ack)),
                Feedback::Ok
            );

            let result = actor
                .dealing(Epoch::zero(), &mut store, None, None, (sender, receiver))
                .await;

            assert!(result.is_continue());
            waiter
                .await
                .expect("finalized block should be acknowledged");
            assert_eq!(received.load(Ordering::SeqCst), 0);
        });
    }
}
