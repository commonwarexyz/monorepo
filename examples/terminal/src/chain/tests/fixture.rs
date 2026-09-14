use super::*;
use crate::chain::validator::{INGRESS_BYTES, INGRESS_CAPACITY, INGRESS_LEASE};
use commonware_consensus::{Reporter as _, simplex::types::Activity};
use commonware_p2p::utils::mocks::inert_channel;
use std::net::SocketAddr;

/// Permits a finite run of empty proposals without borrowing retained ingress entries.
#[derive(Clone)]
pub(super) struct ReadProvider(pub(super) Option<ingress::Mailbox>);

impl ingress::Provider for ReadProvider {
    async fn drain(&mut self, max: usize, budget: usize) -> Vec<SettlementTx> {
        match &mut self.0 {
            Some(ingress) => ingress::Provider::drain(ingress, max, budget).await,
            None => Vec::new(),
        }
    }
}

/// A production query and stateful stack whose certified tip advances only on demand.
pub(super) struct ReadFixture {
    pub(super) identity: Genesis,
    pub(super) scheme: Threshold,
    pub(super) app: App<Threshold, ReadProvider>,
    pub(super) db: Database<deterministic::Context>,
    pub(super) ingress: ingress::Mailbox,
    pub(super) registry: RegistryView,
    pub(super) marshal: marshal::core::Mailbox<Threshold, Standard<Block>>,
    pub(super) finalized: Finalized,
    pub(super) parent: Block,
    pub(super) address: SocketAddr,
}

impl ReadFixture {
    pub(super) async fn new(context: &deterministic::Context) -> Self {
        Self::with_timing(context, Timing::DEFAULT).await
    }

    pub(super) async fn with_timing(context: &deterministic::Context, timing: Timing) -> Self {
        let native = native_for(two_deployments());
        assert!(native.validate());
        let address = SocketAddr::from(([127, 0, 0, 1], 19_874));
        let signer = ed25519::PrivateKey::from_seed(4_242);
        let leader = signer.public_key();
        let players = Set::from_iter_dedup([leader.clone()]);
        let (identity, shares) =
            deal::<MinSig, _, N3f1>(&mut test_rng(), SHARING_MODE, players).unwrap();
        let identity = Genesis::new(
            identity,
            0,
            timing,
            native.clone(),
            committee()
                .unwrap()
                .members()
                .iter()
                .map(|clearing| ValidatorEntry {
                    clearing: *clearing,
                    query: address,
                })
                .collect(),
        );
        let scheme = Threshold::signer(
            CHAIN_NAMESPACE,
            identity.players().clone(),
            identity.public().clone(),
            shares.get_value(&leader).unwrap().clone(),
        )
        .unwrap();
        Self::configured(context, "native-reads", address, identity, scheme, None).await
    }

    pub(super) async fn configured(
        context: &deterministic::Context,
        prefix: &str,
        address: SocketAddr,
        identity: Genesis,
        scheme: Threshold,
        observer: Option<node::Observer>,
    ) -> Self {
        let native = identity.native.clone();
        let timing = identity.timing();
        let leader = identity.players().iter().next().unwrap().clone();
        let (network, oracle) = commonware_p2p::simulated::Network::new_with_peers(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: MAX_MESSAGE_SIZE,
                max_peers_per_set: NZUsize!(1),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            [leader.clone()],
        )
        .await;
        network.start();
        let resolver = marshal_resolver::init(
            context.child("resolver"),
            marshal_resolver::Config {
                public_key: leader.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(leader.clone()),
                mailbox_size: NZUsize!(100),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            inert_channel::<ed25519::PublicKey>([]),
        );
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let archive_config = |name: &str| prunable::Config {
            translator: TwoCap,
            key_partition: format!("{prefix}-{name}-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{prefix}-{name}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(10),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        };
        let finalizations = prunable::Archive::init(
            context.child("finalizations"),
            archive_config("finalizations"),
        )
        .await
        .unwrap();
        let blocks = prunable::Archive::init(context.child("blocks"), archive_config("blocks"))
            .await
            .unwrap();
        let parent = Block::genesis(
            leader,
            native.chain_id(),
            0,
            initial_sync_target::<deterministic::Context>(),
        );
        let startup = context.child("startup");
        let plan = SyncPlan::init(&startup, prefix).await;
        let _ = plan.should_state_sync(false);
        let (actor, marshal, floor) = MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
            context.child("marshal"),
            finalizations,
            blocks,
            marshal::Config {
                provider: ConstantProvider::new(scheme.clone()),
                epocher: FixedEpocher::new(NZU64!(1_000)),
                start: plan.marshal_start(parent.clone()),
                partition_prefix: prefix.into(),
                mailbox_size: NZUsize!(100),
                view_retention: ViewDelta::new(10),
                prunable_items_per_section: NZU64!(10),
                page_cache,
                replay_buffer: IO_BUFFER_SIZE,
                key_write_buffer: IO_BUFFER_SIZE,
                value_write_buffer: IO_BUFFER_SIZE,
                block_codec_config: (),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                strategy: Sequential,
            },
        )
        .await;
        let registry = RegistryView::new(native.deployments.clone());
        let (ingress_actor, ingress) = ingress::Actor::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(100),
                capacity: INGRESS_CAPACITY,
                bytes: INGRESS_BYTES,
                lease: INGRESS_LEASE,
                retention: INGRESS_LEASE * 4,
            },
            registry.clone(),
        );
        let finalized = Finalized::default();
        let app = App::new(parent.clone(), timing, native.clone(), finalized.clone());
        let (stateful_actor, stateful) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application: app.clone(),
                db_config: config(prefix, context),
                provider: ReadProvider(Some(ingress.clone())),
                marshal: (marshal.clone(), floor),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: NoopResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
                prune_config: None,
            },
        );
        actor.start_unbuffered(
            Reporters::<_, _, node::Observer>::from((
                Reporters::from((stateful.clone(), ingress.clone())),
                observer,
            )),
            resolver,
        );
        stateful_actor.start();
        let db = stateful.subscribe_databases().await;
        ingress_actor.start(
            inert_channel::<ed25519::PublicKey>([]),
            db.clone(),
            finalized.clone(),
            native.clone(),
            timing,
            identity.players().clone(),
        );
        crate::chain::registry::watch(
            context.child("registry"),
            db.clone(),
            native.clone(),
            registry.clone(),
            oracle.manager(),
            identity.players().clone(),
        );
        query::start(
            context.child("query"),
            query::Config {
                address,
                db: db.clone(),
                finalized: finalized.clone(),
                marshal: marshal.clone(),
                ingress: ingress.clone(),
                sealer: None,
            },
        );
        Self {
            identity,
            scheme,
            app,
            db,
            ingress,
            registry,
            marshal,
            finalized,
            parent,
            address,
        }
    }

    pub(super) async fn seal(&mut self, context: &deterministic::Context, verify: bool) -> Block {
        self.seal_with(context, verify, ReadProvider(Some(self.ingress.clone())))
            .await
    }

    pub(super) async fn seal_with(
        &mut self,
        context: &deterministic::Context,
        verify: bool,
        provider: ReadProvider,
    ) -> Block {
        let block_context = Context {
            round: Round::new(Epoch::zero(), View::new(self.parent.height.get() + 1)),
            leader: self.parent.context.leader.clone(),
            parent: (self.parent.context.round.view(), self.parent.digest()),
        };
        let proposed = self
            .app
            .propose(
                (context.child("propose"), block_context.clone()),
                marshal::ancestry::from_iter([Arc::new(self.parent.clone())]),
                self.db.new_batches().await,
                Input {
                    upstream: (),
                    provider,
                },
            )
            .await
            .unwrap();
        let block = proposed.block;
        assert_eq!(Block::decode(block.encode()).unwrap(), block);
        if verify {
            let verified = self
                .app
                .verify(
                    (context.child("verify"), block_context),
                    marshal::ancestry::from_iter([
                        Arc::new(block.clone()),
                        Arc::new(self.parent.clone()),
                    ]),
                    self.db.new_batches().await,
                )
                .await
                .expect("production verification accepts the proposal");
            assert_eq!(verified.root(), proposed.merkleized.root());
            assert_eq!(verified.ops_root(), proposed.merkleized.ops_root());
            drop(verified);
        }
        drop(proposed.merkleized);
        self.publish(block.clone()).await;
        self.wait_applied(context, &block).await;
        self.parent = block.clone();
        block
    }

    pub(super) async fn publish(&mut self, block: Block) {
        assert!(
            self.marshal
                .verified(block.context.round, block.clone())
                .await
        );
        let finalize = Finalize::sign(
            &self.scheme,
            Proposal {
                round: block.context.round,
                parent: block.context.parent.0,
                payload: block.digest(),
            },
        )
        .unwrap();
        let finalization = Finalization::from_finalizes(
            &self.scheme,
            NonEmpty::try_new([&finalize].into_iter()).unwrap(),
            &Sequential,
        )
        .unwrap();
        assert!(finalization.verify(&mut test_rng(), &self.scheme, &Sequential));
        self.marshal.report(Activity::Finalization(finalization));
    }

    pub(super) async fn wait_applied(&self, context: &deterministic::Context, block: &Block) {
        while self
            .finalized
            .latest()
            .is_none_or(|tip| tip.height < block.height.get())
        {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(self.finalized.latest().unwrap().digest, block.digest());
    }

    /// Builds adversarial proposals through execution, bypassing advisory ingress filters.
    pub(super) async fn direct(
        &mut self,
        context: &deterministic::Context,
        transactions: Vec<SettlementTx>,
    ) -> Block {
        let height = self.parent.height.next();
        let timestamp = self
            .parent
            .timestamp
            .checked_add(1)
            .unwrap()
            .max(now(context));
        let executed = execute(
            self.db.new_batches().await,
            height,
            timestamp,
            &self.identity.timing(),
            &self.identity.native,
            &transactions,
        )
        .await
        .unwrap();
        let block = Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height.get())),
                leader: self.parent.context.leader.clone(),
                parent: (self.parent.context.round.view(), self.parent.digest()),
            },
            parent: self.parent.digest(),
            height,
            timestamp,
            state_root: executed.root(),
            ops_root: executed.ops_root(),
            range: non_empty_range!(executed.sync_boundary(), executed.bounds().tip.size),
            transactions,
        };
        assert_eq!(Block::decode(block.encode()).unwrap(), block);
        let verified = self
            .app
            .verify(
                (context.child("verify_direct"), block.context.clone()),
                marshal::ancestry::from_iter([
                    Arc::new(block.clone()),
                    Arc::new(self.parent.clone()),
                ]),
                self.db.new_batches().await,
            )
            .await
            .expect("production verification accepts the executed block");
        assert_eq!(verified.root(), executed.root());
        assert_eq!(verified.ops_root(), executed.ops_root());
        drop(verified);
        drop(executed);
        self.publish(block.clone()).await;
        self.wait_applied(context, &block).await;
        self.parent = block.clone();
        block
    }

    pub(super) async fn submit(&self, context: &deterministic::Context, tx: SettlementTx) {
        assert_eq!(SettlementTx::decode(tx.encode()).unwrap(), tx);
        let body = rpc::invoke(
            context,
            self.address,
            "query",
            query::METHOD_SUBMIT_TX,
            tx.encode(),
        )
        .await
        .unwrap();
        let submission = ingress::Submission::decode(body).unwrap();
        assert_eq!(submission, ingress::Submission::Accepted);
    }

    pub(super) async fn fetch(
        &self,
        context: &deterministic::Context,
        request: &ReadRequest,
    ) -> anyhow::Result<light::Verified> {
        let body = rpc::invoke(
            context,
            self.address,
            "query",
            query::METHOD_READ,
            request.encode(),
        )
        .await?;
        let ReadResponse::Certified(response) = ReadResponse::decode(body)? else {
            anyhow::bail!("certified tip unavailable")
        };
        Ok(light::verify_read::<deterministic::Context, Threshold>(
            &mut test_rng(),
            &self.scheme,
            request,
            &response,
        )?)
    }

    pub(super) fn client(&self, deployment: Digest) -> Client {
        Client::new(&self.identity, deployment, vec![self.address], test_rng()).unwrap()
    }

    pub(super) async fn busy(
        &mut self,
        context: &deterministic::Context,
        deployments: &[Digest],
    ) -> Block {
        let mut submitted = 0;
        let mut transactions = Vec::new();
        let mut remaining = MAX_BLOCK_BYTES;
        while remaining > 0 {
            assert!(submitted < MAX_BLOCK_TXS);
            let seed = u8::try_from(submitted).unwrap();
            let mut challenge = ChallengeRequest {
                deployment: deployments[submitted % deployments.len()],
                batch_id: BatchId::new(Sha256::hash(&[b"native-read-busy", &[seed]])),
                evidence: Bytes::from(vec![seed; 32 * 1024]),
            };
            let full_size = SettlementTx::Challenge(challenge.clone()).encode_size();
            if full_size > remaining {
                challenge
                    .evidence
                    .truncate(challenge.evidence.len() - (full_size - remaining));
            }
            let tx = SettlementTx::Challenge(challenge);
            let decoded = SettlementTx::decode(tx.encode()).unwrap();
            assert_eq!(decoded, tx);
            transactions.push(decoded);
            remaining -= tx.encode_size();
            submitted += 1;
        }
        let block = self.direct(context, transactions).await;
        assert_eq!(submitted, 126);
        assert_eq!(block.transactions.len(), submitted);
        assert_eq!(
            block
                .transactions
                .iter()
                .map(|tx| tx.encode_size())
                .sum::<usize>(),
            MAX_BLOCK_BYTES
        );
        assert!(block.encode_size() < query::MAX_READ_BYTES);
        block
    }
}
