//! The operator's follower node: a registered secondary of the validator
//! network.
//!
//! The node runs the validator stack without a consensus engine: p2p, the
//! marshal with its archives and backfill resolver, and the stateful
//! settlement application. Finalizations arrive over the certificate channel
//! (simplex broadcasts them to every connected peer), are verified against
//! the committee identity, and are reported into the marshal, which fetches
//! and dispatches the finalized blocks so the local applied state follows
//! the chain.
//!
//! [`Node`] is the local [`Chain`] backend over that state: reads come from
//! the node's own verified finalized database, and submissions go straight
//! onto the settlement transaction channel. [`Observer`] rides the marshal
//! reporter chain and surfaces each finalized block's deposit transactions
//! toward the operator's staging, holding the block's acknowledgement until
//! that staging is durable. [`Certifier`] is the close
//! pipeline actor: it disseminates per-validator dealings over the
//! settlement DA channel, collects and verifies votes, assembles the
//! exact-quorum certificate, and completes admission against the local
//! certified state. [`Pipeline`] hands the SQLite close worker a blocking
//! facade over that actor.

use crate::{
    chain::{
        app::{App, Finalized, initial_sync_target},
        client::{self, Chain, Env},
        da::{Ballot, Dealing, Message as DaMessage},
        ingress::Submission,
        light::{self, Verified},
        query::{ReadRequest, Submitted},
        setup::{NetworkConfig, OperatorConfig, read_genesis},
        tx::{AdmitRequest, SettlementTx},
        types::{Block, Database, now},
        validator::{
            BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, EPOCH_LENGTH, MAILBOX_SIZE,
            MAX_MESSAGE_SIZE, MESSAGE_RATE, NAMESPACE, NoopResolver, PAGE_CACHE_SIZE, PAGE_SIZE,
            RESOLVER_CHANNEL, SETTLEMENT_DA_CHANNEL, SETTLEMENT_TX_CHANNEL, Scheme, VOTE_CHANNEL,
            db_config, sync_config,
        },
    },
    protocol::{DepositEvent, Key, chain_id, dealt_participant, deployment_of},
};
use anyhow::{Context as _, Result, bail, ensure};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Receiver as MailboxReceiver, Sender as MailboxSender},
};
use commonware_broadcast::buffered;
use commonware_clearing::bajillion::{
    admission::{Vote, bls12381},
    commitment::VectorRoot,
    settlement::FinalizedBatch,
    transition::{Header, ProofSlice, RootBundle},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
use commonware_consensus::{
    Epochable as _, Reporter, Reporters,
    marshal::{
        self, Update,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::p2p as marshal_resolver,
        standard::Standard,
    },
    simplex::{
        scheme::Scheme as SimplexScheme,
        types::{Activity, Certificate as WireCertificate},
    },
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Signer as _,
    certificate::{ConstantProvider, Provider as _},
    ed25519,
    sha256::Digest,
};
use commonware_glue::stateful::{Config as StatefulConfig, Stateful, SyncPlan};
use commonware_macros::select;
use commonware_p2p::{
    Receiver, Recipients, Sender,
    authenticated::{self, discovery},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    ContextCell, Handle, Metrics, Spawner, Supervisor as _, buffer::paged::CacheRef, spawn_cell,
    tokio,
};
use commonware_storage::{Context as StorageContext, archive::prunable, translator::TwoCap};
use commonware_utils::{
    Acknowledgement as _, NZU64, NZUsize, Participant,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt as _, oneshot},
    ordered::Set,
};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    path::Path,
    time::Duration,
};
use tracing::{debug, info, warn};

/// Pause between dealing resends to validators that have not voted.
const RESEND: Duration = Duration::from_millis(500);

/// Attempts waiting for the finalized index to catch up to the applied
/// database before a local read fails.
const CATCHUP_ATTEMPTS: usize = 20;

/// Pause between finalized-index catchup attempts.
const CATCHUP_PAUSE: Duration = Duration::from_millis(25);

/// The operator's local chain backend: reads from its own verified finalized
/// state, submissions straight onto the settlement transaction channel.
pub(crate) struct Node<E, S>
where
    E: StorageContext + Spawner,
    S: Sender<PublicKey = ed25519::PublicKey>,
{
    /// The deployment this operator runs: every typed read is scoped to it.
    deployment: Digest,
    db: Database<E>,
    finalized: Finalized,
    sender: S,
}

impl<E, S> Clone for Node<E, S>
where
    E: StorageContext + Spawner,
    S: Sender<PublicKey = ed25519::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            deployment: self.deployment,
            db: self.db.clone(),
            finalized: self.finalized.clone(),
            sender: self.sender.clone(),
        }
    }
}

impl<E, S> Node<E, S>
where
    E: StorageContext + Spawner,
    S: Sender<PublicKey = ed25519::PublicKey>,
{
    pub(crate) const fn new(
        deployment: Digest,
        db: Database<E>,
        finalized: Finalized,
        sender: S,
    ) -> Self {
        Self {
            deployment,
            db,
            finalized,
            sender,
        }
    }

    /// One read of the node's own applied state at its finalized tip.
    ///
    /// The snapshot rule mirrors the query server: the read guard pins the
    /// applied database, the finalized index entry is resolved under it, and
    /// a root mismatch declines instead of serving a mixed snapshot.
    ///
    /// Between a block's apply and its finalized hook the applied database
    /// briefly runs ahead of the finalized index (and the index is empty
    /// until the first block finalizes). That ordering race is transient,
    /// the follower's finalized feed closes the gap, so a lagging index is
    /// awaited within a bounded budget rather than surfaced. Every attempt
    /// re-takes the snapshot, so the consistency check itself stays exact.
    async fn local<C: Env>(&self, ctx: &C, request: &ReadRequest) -> Result<Verified> {
        for _ in 0..CATCHUP_ATTEMPTS {
            if let Some(verified) = self.snapshot(request).await? {
                return Ok(verified);
            }
            ctx.sleep(CATCHUP_PAUSE).await;
        }
        bail!("the finalized index did not catch up to the applied state in time");
    }

    /// One snapshot attempt: `None` when the finalized index has not caught
    /// up to the applied database yet.
    async fn snapshot(&self, request: &ReadRequest) -> Result<Option<Verified>> {
        let guard = self.db.read().await;
        let Some(tip) = self.finalized.latest() else {
            return Ok(None);
        };
        if guard.root() != tip.root {
            return Ok(None);
        }
        let record = guard
            .get(&request.key())
            .await
            .context("read applied settlement state")?;
        Ok(Some(Verified {
            height: tip.height,
            timestamp: tip.timestamp,
            record,
        }))
    }
}

impl<E, S> Chain for Node<E, S>
where
    E: StorageContext + Spawner,
    S: Sender<PublicKey = ed25519::PublicKey>,
{
    fn deployment(&self) -> Digest {
        self.deployment
    }

    async fn read<E2: Env>(&mut self, ctx: &E2, request: &ReadRequest) -> Result<Verified> {
        self.local(ctx, request).await
    }

    /// The node's own tip is honest (it verified every finalization itself),
    /// so the shared recency gate is a stall detector here: a local tip older
    /// than [`client::RECENCY_THRESHOLD`] means the chain or the follower
    /// stalled, surfaced with the same typed error naming the observed lag.
    async fn recent<E2: Env>(&mut self, ctx: &E2, request: &ReadRequest) -> Result<Verified> {
        let verified = self.local(ctx, request).await?;
        light::recent(&verified, now(ctx), client::RECENCY_THRESHOLD)
            .context("the local finalized tip is stale")?;
        Ok(verified)
    }

    /// Submits by sending the transaction to every connected validator on
    /// the settlement transaction channel. Their ingress actors dedupe,
    /// queue, and re-gossip it. The p2p path answers no dry-run advice.
    async fn submit<E2: Env>(&mut self, _: &E2, tx: &SettlementTx) -> Result<Submitted> {
        let sent = self.sender.send(Recipients::All, tx.encode(), false);
        ensure!(!sent.is_empty(), "no validator accepted the submission");
        Ok(Submitted {
            admission: Submission::Accepted,
            advice: None,
        })
    }
}

/// One validator's dealing addressed by both identities: the clearing
/// committee participant whose vote it earns and the network peer holding
/// that dealt key.
pub(crate) struct Deal {
    pub(crate) participant: Participant,
    pub(crate) peer: ed25519::PublicKey,
    pub(crate) slices: Vec<ProofSlice<Key, Digest>>,
}

/// A message sent to the close pipeline [`Certifier`].
pub(crate) enum Message {
    /// Disseminate per-validator dealings and assemble the exact-quorum
    /// certificate from the returned votes.
    Certify {
        epoch: u64,
        header: Header<Digest>,
        roots: RootBundle<Digest>,
        dealings: Vec<Deal>,
        response: oneshot::Sender<bls12381::Certificate>,
    },
    /// Submit the certified close and complete once the local certified
    /// state finalized the exact batch.
    Admit {
        request: Box<AdmitRequest>,
        expected: FinalizedBatch<Digest>,
        change: VectorRoot<Digest>,
        response: oneshot::Sender<Result<()>>,
    },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Async handle to the close pipeline actor.
#[derive(Clone)]
pub(crate) struct Mailbox {
    sender: MailboxSender<Message>,
}

impl Mailbox {
    /// Disseminates `dealings` and completes on the exact-quorum certificate.
    pub(crate) async fn certify(
        &self,
        epoch: u64,
        header: Header<Digest>,
        roots: RootBundle<Digest>,
        dealings: Vec<Deal>,
    ) -> Result<bls12381::Certificate> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Certify {
            epoch,
            header,
            roots,
            dealings,
            response,
        });
        receiver.await.context("the close pipeline stopped")
    }

    /// Submits the certified close and completes on certified finalization.
    pub(crate) async fn admit(
        &self,
        request: AdmitRequest,
        expected: FinalizedBatch<Digest>,
        change: VectorRoot<Digest>,
    ) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Admit {
            request: Box::new(request),
            expected,
            change,
            response,
        });
        receiver.await.context("the close pipeline stopped")?
    }
}

/// Blocking close-pipeline facade for the operator's synchronous close
/// worker thread: dissemination, certification, and admission run inside the
/// node's runtime while the worker blocks on the result.
#[derive(Clone)]
pub(crate) struct Pipeline {
    mailbox: Mailbox,
    /// Network identity holding each clearing participant's dealt key, in
    /// committee participant order.
    peers: Vec<ed25519::PublicKey>,
}

impl Pipeline {
    /// Builds the pipeline facade, deriving the committee participant to
    /// network identity mapping from the setup convention that validator
    /// directory `i` holds clearing key `i`.
    pub(crate) fn new(mailbox: Mailbox, participants: &[ed25519::PublicKey]) -> Result<Self> {
        let mut peers = vec![None; participants.len()];
        for (index, peer) in participants.iter().enumerate() {
            let participant = dealt_participant(index)?;
            let slot = peers
                .get_mut(usize::from(participant))
                .context("dealt participant is out of committee bounds")?;
            ensure!(slot.is_none(), "two validators map to one clearing key");
            *slot = Some(peer.clone());
        }
        Ok(Self {
            mailbox,
            peers: peers
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .context("a clearing committee key has no network identity")?,
        })
    }

    /// Certifies one close: dealings indexed by committee participant, the
    /// assembled certificate on exact quorum.
    pub(crate) fn certify(
        &self,
        epoch: u64,
        header: Header<Digest>,
        roots: RootBundle<Digest>,
        dealings: Vec<Vec<ProofSlice<Key, Digest>>>,
    ) -> Result<bls12381::Certificate> {
        ensure!(
            dealings.len() == self.peers.len(),
            "dealings must cover the exact committee"
        );
        let dealings = dealings
            .into_iter()
            .enumerate()
            .map(|(index, slices)| Deal {
                participant: Participant::from_usize(index),
                peer: self.peers[index].clone(),
                slices,
            })
            .collect();
        futures::executor::block_on(self.mailbox.certify(epoch, header, roots, dealings))
    }

    /// Submits the certified close and blocks until the local certified
    /// state finalized the exact batch.
    pub(crate) fn admit(
        &self,
        request: AdmitRequest,
        expected: FinalizedBatch<Digest>,
        change: VectorRoot<Digest>,
    ) -> Result<()> {
        futures::executor::block_on(self.mailbox.admit(request, expected, change))
    }
}

/// One close awaiting its exact-quorum certificate.
struct Outstanding {
    epoch: u64,
    header: Header<Digest>,
    roots: RootBundle<Digest>,
    dealings: Vec<Deal>,
    votes: BTreeMap<Participant, Vote>,
    response: oneshot::Sender<bls12381::Certificate>,
}

/// Certifier configuration.
pub(crate) struct Config<C: Chain> {
    /// Verify-only clearing scheme over the fixed committee.
    pub(crate) verifier: bls12381::Scheme,
    /// The local chain backend admission completes against.
    pub(crate) chain: C,
    /// Mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
}

/// The operator's close pipeline actor: dealing dissemination, vote
/// collection, certificate assembly, and admission.
pub(crate) struct Certifier<E, C>
where
    E: Env + CryptoRng,
    C: Chain,
{
    context: ContextCell<E>,
    verifier: bls12381::Scheme,
    chain: C,
    mailbox: MailboxReceiver<Message>,
    outstanding: Option<Outstanding>,
}

impl<E, C> Certifier<E, C>
where
    E: Env + CryptoRng + Metrics,
    C: Chain,
{
    pub(crate) fn new(context: E, config: Config<C>) -> (Self, Mailbox) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                verifier: config.verifier,
                chain: config.chain,
                mailbox,
                outstanding: None,
            },
            Mailbox { sender },
        )
    }

    /// Starts the certifier on the settlement DA channel.
    pub(crate) fn start<Se, Re>(mut self, chan: (Se, Re)) -> Handle<()>
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        spawn_cell!(self.context, self.run(chan))
    }

    async fn run<Se, Re>(mut self, (mut sender, mut receiver): (Se, Re))
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        loop {
            select! {
                message = self.mailbox.recv() => {
                    let Some(message) = message else {
                        return;
                    };
                    match message {
                        Message::Certify { epoch, header, roots, dealings, response } => {
                            // A replaced certification drops the stale
                            // response: its worker observes the closed
                            // channel and fails that close.
                            self.outstanding = Some(Outstanding {
                                epoch,
                                header,
                                roots,
                                dealings,
                                votes: BTreeMap::new(),
                                response,
                            });
                            self.disseminate(&mut sender);
                        }
                        Message::Admit { request, expected, change, response } => {
                            let result = client::admit(
                                self.context.as_present(),
                                &mut self.chain,
                                *request,
                                &expected,
                                change,
                            )
                            .await;
                            response.send_lossy(result);
                        }
                    }
                },
                message = receiver.recv() => {
                    let Ok((peer, bytes)) = message else {
                        return;
                    };
                    let Ok(DaMessage::Vote(ballot)) = DaMessage::decode(bytes) else {
                        debug!(?peer, "dropping undecodable or unexpected DA message");
                        continue;
                    };
                    self.tally(ballot);
                },
                _ = self.context.sleep(RESEND) => {
                    self.disseminate(&mut sender);
                },
            }
        }
    }

    /// Sends every outstanding dealing to its validator, skipping validators
    /// that already voted. Dissemination is recoverable off-chain traffic,
    /// so delivery is retried on the resend tick until quorum.
    fn disseminate<Se>(&mut self, sender: &mut Se)
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
    {
        let Some(outstanding) = &self.outstanding else {
            return;
        };
        for deal in &outstanding.dealings {
            if outstanding.votes.contains_key(&deal.participant) {
                continue;
            }
            let message = DaMessage::Dealing(Dealing {
                epoch: outstanding.epoch,
                header: outstanding.header,
                roots: outstanding.roots,
                slices: deal.slices.clone(),
            });
            let sent = sender.send(Recipients::One(deal.peer.clone()), message.encode(), true);
            if sent.is_empty() {
                debug!(epoch = outstanding.epoch, peer = ?deal.peer, "failed to send dealing");
            }
        }
    }

    /// Verifies one returned vote and assembles the certificate on reaching
    /// exactly quorum.
    fn tally(&mut self, ballot: Ballot) {
        let Some(outstanding) = &mut self.outstanding else {
            return;
        };
        if ballot.epoch != outstanding.epoch || ballot.header != outstanding.header {
            debug!(epoch = ballot.epoch, "dropping vote for a foreign close");
            return;
        }
        if outstanding.votes.contains_key(&ballot.vote.signer) {
            return;
        }

        // The vote is externally supplied: it earns a slot only by verifying
        // against the committee member it names.
        if !self.verifier.verify_vote(&outstanding.header, &ballot.vote) {
            warn!(
                epoch = ballot.epoch,
                signer = ?ballot.vote.signer,
                "dropping invalid vote"
            );
            return;
        }
        let signer = ballot.vote.signer;
        outstanding.votes.insert(signer, ballot.vote);
        info!(
            epoch = outstanding.epoch,
            ?signer,
            votes = outstanding.votes.len(),
            "verified vote"
        );
        if outstanding.votes.len() < self.verifier.committee().quorum() {
            return;
        }
        let outstanding = self
            .outstanding
            .take()
            .expect("the outstanding close was checked above");

        // Exactly quorum distinct in-committee verified votes assemble by
        // construction, so a failure here is a bug, not an input.
        let certificate = self
            .verifier
            .assemble_exact(outstanding.votes.into_values())
            .expect("exactly quorum verified votes assemble");
        outstanding.response.send_lossy(certificate);
    }
}

/// Deposit transactions carried by one finalized block, awaiting durable
/// staging before the block is acknowledged to marshal.
pub(crate) struct Observed {
    /// Height of the finalized block that carried the transactions.
    pub(crate) height: u64,
    /// Deposit transactions in block order. Inclusion is not application: a
    /// rejected transaction is effect-free, so the observer confirms each
    /// event against the applied custody record before staging it.
    pub(crate) events: Vec<DepositEvent>,
    /// The block's marshal acknowledgement. It is fulfilled only once every
    /// applied event is durably staged, and dropped on a staging failure.
    pub(crate) ack: Exact,
}

impl Policy for Observed {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Marshal reporter surfacing each finalized block's deposit transactions to
/// the operator's deposit observer.
///
/// Deposits are chain state, so the operator learns them from its own
/// follower rather than from a wallet report: any party's deposit to a
/// configured account is credited without that party's cooperation. The
/// observer stages a block's applied deposits durably (one immediate SQLite
/// transaction per deposit-carrying block, deduplicated by deposit id)
/// BEFORE fulfilling the block's acknowledgement. Staging is
/// persist-before-externalize, and the acknowledgement is the
/// externalization: marshal advances its processed height only past
/// acknowledged blocks, so a crash between finalization and the staging
/// commit re-delivers the block on restart, where the id dedupe makes the
/// replay a no-op. A deposit the store cannot stage is never acknowledged.
/// Storage failures are fatal, so the observer drops the acknowledgement
/// instead, which stops marshal and halts the operator.
///
/// The acknowledgement gates only this operator's own follower height,
/// never validator consensus. A deposit-carrying block costs one batched
/// insert and fsync (single-digit milliseconds against second-scale blocks),
/// and a block without deposits costs a read-only scan of its transactions
/// and is acknowledged here immediately. If staging ever grew heavy enough
/// to backpressure block-following, the escalation is a durable intake
/// queue drained asynchronously. That is deliberately not built now.
#[derive(Clone)]
pub(crate) struct Observer {
    /// The deployment this operator runs: only its deposits are surfaced.
    deployment: Digest,
    sender: MailboxSender<Observed>,
}

impl Observer {
    pub(crate) const fn new(deployment: Digest, sender: MailboxSender<Observed>) -> Self {
        Self { deployment, sender }
    }
}

impl Reporter for Observer {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        let Update::Block(block, ack) = update else {
            return Feedback::Ok;
        };
        let events = block
            .transactions
            .iter()
            .filter_map(|tx| match tx {
                SettlementTx::Deposit(request) if request.deployment == self.deployment => {
                    Some(request.event.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if events.is_empty() {
            ack.acknowledge();
            return Feedback::Ok;
        }
        self.sender.enqueue(Observed {
            height: block.height.get(),
            events,
            ack,
        })
    }
}

/// Follows finalizations for a node without a consensus engine: every
/// certificate-channel broadcast is decoded, finalizations are verified
/// against the committee identity, and verified finalizations are reported
/// into the marshal, which backfills and dispatches the finalized blocks.
pub(crate) fn follow<E, S, Re>(
    context: E,
    provider: ConstantProvider<S, Epoch>,
    mut marshal: MarshalMailbox<S, Standard<Block>>,
    mut receiver: Re,
) -> Handle<()>
where
    E: Spawner + CryptoRng,
    S: SimplexScheme<Digest>,
    Re: Receiver<PublicKey = ed25519::PublicKey>,
{
    context.spawn(move |mut context| async move {
        while let Ok((peer, bytes)) = receiver.recv().await {
            let codec = S::certificate_codec_config_unbounded();
            let Ok(certificate) = WireCertificate::<S, Digest>::decode_cfg(bytes, &codec) else {
                debug!(?peer, "dropping undecodable certificate");
                continue;
            };
            let WireCertificate::Finalization(finalization) = certificate else {
                continue;
            };

            // The certificate is externally supplied: it reaches the marshal
            // only after verifying against the committee identity, because
            // the marshal reporter stream trusts its inputs.
            let Some(scoped) = provider.scoped(finalization.epoch()) else {
                continue;
            };
            if !finalization.verify(&mut context, &scoped, &Sequential) {
                warn!(?peer, "dropping invalid finalization");
                continue;
            }
            let _ = marshal.report(Activity::Finalization(finalization));
        }
    })
}

/// Drains and drops one channel's inbound traffic (gossip echoes on a
/// channel this node only sends on).
pub(crate) fn drain<E, Re>(context: E, mut receiver: Re) -> Handle<()>
where
    E: Spawner,
    Re: Receiver<PublicKey = ed25519::PublicKey>,
{
    context.spawn(move |_| async move { while receiver.recv().await.is_ok() {} })
}

/// Assembles and starts the operator's follower stack over the authenticated
/// network: the tokio counterpart of the validator assembly without a
/// consensus engine. Returns the local chain backend, the close pipeline
/// facade, the deposit observation feed, and every actor handle for
/// supervision.
pub(crate) async fn start(
    context: tokio::Context,
    node_dir: &Path,
) -> Result<(
    Node<tokio::Context, discovery::Sender<ed25519::PublicKey, tokio::Context>>,
    Pipeline,
    MailboxReceiver<Observed>,
    Vec<Handle<()>>,
)> {
    let operator = OperatorConfig::load(node_dir).context("load operator node config")?;
    let network = NetworkConfig::load(node_dir).context("load network config")?;
    network.validate().context("invalid network config")?;
    let genesis = read_genesis(node_dir).context("genesis is required")?;
    let local = operator.public_key();

    // The deployment this operator runs, derived from its clearing identity
    // and required to be configured in genesis.
    let deployment = deployment_of(&operator.clearing.public_key());
    ensure!(
        genesis
            .deployments
            .iter()
            .any(|configured| configured.digest() == &deployment),
        "the operator's clearing key names no configured deployment"
    );
    let partition_prefix = "operator";
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

    // The committee identity every followed finalization verifies against.
    let scheme = Scheme::verifier(
        NAMESPACE,
        genesis.players().clone(),
        genesis.public().clone(),
    );
    let provider = ConstantProvider::new(scheme);

    // The operator bootstraps into every validator and tracks the committee
    // as its primary peers. Its own registration as a secondary happens on
    // the validators' side.
    let bootstrappers = network
        .peers
        .iter()
        .map(|peer| (peer.public_key.clone(), peer.dial.into()))
        .collect();
    let max_peers_per_set = authenticated::peer_set_limit(&network.participants, &local);
    let mut p2p_config = discovery::Config::local(
        operator.signing_key.clone(),
        &[NAMESPACE, b"_P2P"].concat(),
        operator.listen,
        operator.dial,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, mut oracle) = discovery::Network::new(context.child("network"), p2p_config);
    let vote_network = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificate_network = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver_network = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill_network = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast_network = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let settlement_tx_network = p2p.register(SETTLEMENT_TX_CHANNEL, MESSAGE_RATE);
    let settlement_da_network = p2p.register(SETTLEMENT_DA_CHANNEL, MESSAGE_RATE);
    let _ = commonware_p2p::Manager::track(
        &mut oracle,
        0,
        Set::from_iter_dedup(network.participants.iter().cloned()),
    );
    let p2p_handle = p2p.start();

    // Marshal resolver for finalization and block backfill.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill_network,
    );

    // Buffered broadcast engine backing marshal block dissemination.
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: local.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: 16,
            priority: false,
            codec_config: (),
            peer_provider: oracle.clone(),
        },
    );
    let broadcast_handle = broadcast_engine.start(broadcast_network);

    // Prunable archives backing marshal.
    let archive_config = |name: &str| prunable::Config {
        translator: TwoCap,
        key_partition: format!("{partition_prefix}-{name}-key"),
        key_page_cache: page_cache.clone(),
        value_partition: format!("{partition_prefix}-{name}-value"),
        compression: None,
        codec_config: (),
        items_per_section: NZU64!(1_024),
        key_write_buffer: crate::chain::validator::IO_BUFFER_SIZE,
        value_write_buffer: crate::chain::validator::IO_BUFFER_SIZE,
        replay_buffer: crate::chain::validator::IO_BUFFER_SIZE,
    };
    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config("finalizations"),
    )
    .await
    .expect("failed to initialize finalizations archive");
    let finalized_blocks =
        prunable::Archive::init(context.child("finalized_blocks"), archive_config("blocks"))
            .await
            .expect("failed to initialize blocks archive");

    // Genesis block shared with every validator.
    let genesis_block = Block::genesis(
        network.participants[0].clone(),
        chain_id(&genesis.deployments),
        genesis.timestamp,
        initial_sync_target::<tokio::Context>(),
    );
    let plan = SyncPlan::init(&context.child("stateful_startup"), partition_prefix).await;
    let _ = plan.should_state_sync(false);

    // Marshal actor.
    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            start: plan.marshal_start(genesis_block.clone()),
            partition_prefix: partition_prefix.to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(1_024),
            page_cache: page_cache.clone(),
            replay_buffer: crate::chain::validator::IO_BUFFER_SIZE,
            key_write_buffer: crate::chain::validator::IO_BUFFER_SIZE,
            value_write_buffer: crate::chain::validator::IO_BUFFER_SIZE,
            block_codec_config: (),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;

    // Stateful actor wrapping the settlement application. The operator never
    // proposes, so its transaction provider is the no-op.
    let finalized = Finalized::default();
    let application: App<Scheme, ()> = App::new(
        genesis_block.clone(),
        genesis.timing(),
        genesis.deployments.clone(),
        finalized.clone(),
    );
    let (stateful_actor, stateful_mailbox) = Stateful::init(
        context.child("stateful"),
        StatefulConfig {
            application,
            db_config: db_config(partition_prefix, page_cache.clone()),
            provider: (),
            marshal: (marshal.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: NoopResolver,
            sync_config: sync_config(),
            prune_config: None,
        },
    );

    // The deposit observer joins the finalized-block reporter chain: a
    // deposit-carrying block is acknowledged to marshal only after its
    // applied events are durably staged (see [`Observer`]). It surfaces only
    // this operator's own deployment's deposit transactions.
    let (observer, observations) = mailbox::new(context.child("observations"), MAILBOX_SIZE);
    let marshal_handle = marshal_actor.start(
        Reporters::from((
            stateful_mailbox.clone(),
            Observer::new(deployment, observer),
        )),
        buffer,
        resolver,
    );
    let stateful_handle = stateful_actor.start();

    // The finalization feed replaces the consensus engine's reporter stream.
    let follow_handle = follow(
        context.child("follow"),
        provider,
        marshal.clone(),
        certificate_network.1,
    );

    // The transaction channel is submit-only here: gossip echoes drain.
    let drain_handle = drain(context.child("tx_drain"), settlement_tx_network.1);

    // Simplex broadcasts votes to every connected peer and its resolver may
    // fetch from any peer, but the secondary runs no engine. Inbound traffic
    // on an unregistered channel kills the connection, so both engine
    // channels are registered and drained.
    let vote_drain_handle = drain(context.child("vote_drain"), vote_network.1);
    let resolver_drain_handle = drain(context.child("resolver_drain"), resolver_network.1);

    // The local chain backend and the close pipeline actor.
    let db: Database<tokio::Context> = stateful_mailbox.subscribe_databases().await;
    let node = Node::new(deployment, db, finalized, settlement_tx_network.0);
    let protocol_verifier = crate::protocol::Protocol::new(NonZeroUsize::MIN)
        .context("construct protocol for the certifier")?
        .verifier();
    let (certifier, pipeline_mailbox) = Certifier::new(
        context.child("certifier"),
        Config {
            verifier: protocol_verifier,
            chain: node.clone(),
            mailbox_size: MAILBOX_SIZE,
        },
    );
    let certifier_handle = certifier.start(settlement_da_network);
    let pipeline = Pipeline::new(pipeline_mailbox, &network.participants)?;

    Ok((
        node,
        pipeline,
        observations,
        vec![
            p2p_handle,
            broadcast_handle,
            marshal_handle,
            stateful_handle,
            follow_handle,
            drain_handle,
            vote_drain_handle,
            resolver_drain_handle,
            certifier_handle,
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{light::Verified, query::ReadRequest},
        protocol::{Protocol, clearing_private, committee},
    };
    use anyhow::bail;
    use commonware_clearing::bajillion::commitment::VectorRoot;
    use commonware_cryptography::{Hasher as _, Sha256, ed25519::PrivateKey};
    use commonware_p2p::simulated::{Config as NetConfig, Link, Network};
    use commonware_runtime::{Quota, Runner as _, deterministic};
    use commonware_utils::{NZU32, NZUsize, probability};

    /// A chain backend the certifier test never reads or submits through.
    struct Stub;

    impl Chain for Stub {
        fn deployment(&self) -> Digest {
            crate::protocol::deployment()
        }

        async fn read<E: Env>(&mut self, _: &E, _: &ReadRequest) -> Result<Verified> {
            bail!("the stub backend serves no reads")
        }

        async fn recent<E: Env>(&mut self, _: &E, _: &ReadRequest) -> Result<Verified> {
            bail!("the stub backend serves no reads")
        }

        async fn submit<E: Env>(
            &mut self,
            _: &E,
            _: &crate::chain::tx::SettlementTx,
        ) -> Result<Submitted> {
            bail!("the stub backend accepts no submissions")
        }
    }

    #[test]
    fn certifier_drops_invalid_votes_and_assembles_exact_quorum() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let verifier = protocol.verifier();
            let committee = committee().unwrap();
            let quorum = committee.quorum();
            let operator_key = PrivateKey::from_seed(9_300).public_key();
            let validator_keys = (0..committee.members().len())
                .map(|index| PrivateKey::from_seed(9_301 + index as u64).public_key())
                .collect::<Vec<_>>();

            let mut peers = validator_keys.clone();
            peers.push(operator_key.clone());
            let (net, oracle) = Network::new_with_peers(
                context.child("network"),
                NetConfig {
                    max_size: 4 * 1024 * 1024,
                    max_peers_per_set: NZUsize!(peers.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                peers.clone(),
            )
            .await;
            net.start();
            let quota = Quota::per_second(NZU32!(128));
            let operator_chan = oracle
                .control(operator_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let mut validator_chans = Vec::new();
            for key in &validator_keys {
                validator_chans.push(
                    oracle
                        .control(key.clone())
                        .register(0, quota)
                        .await
                        .unwrap(),
                );
            }
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            for key in &validator_keys {
                oracle
                    .add_link(operator_key.clone(), key.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(key.clone(), operator_key.clone(), link.clone())
                    .await
                    .unwrap();
            }

            let (certifier, mailbox) = Certifier::new(
                context.child("certifier"),
                Config {
                    verifier: verifier.clone(),
                    chain: Stub,
                    mailbox_size: NZUsize!(16),
                },
            );
            certifier.start(operator_chan);

            // A synthetic close header: vote verification binds signatures to
            // it, so no real close is needed to exercise the tally.
            let header = commonware_clearing::bajillion::transition::Header::<Digest>::decode(
                Sha256::hash(&[b"certifier-header"]).as_ref(),
            )
            .unwrap();
            let roots = RootBundle {
                change: VectorRoot {
                    digest: Sha256::hash(&[b"change"]),
                },
                withdrawal_outputs: VectorRoot {
                    digest: Sha256::hash(&[b"withdrawals"]),
                },
                successor: VectorRoot {
                    digest: Sha256::hash(&[b"successor"]),
                },
                coverage: VectorRoot {
                    digest: Sha256::hash(&[b"coverage"]),
                },
            };
            let deals = validator_keys
                .iter()
                .enumerate()
                .map(|(index, key)| Deal {
                    participant: Participant::from_usize(index),
                    peer: key.clone(),
                    slices: Vec::new(),
                })
                .collect::<Vec<_>>();
            let certify = {
                let mailbox = mailbox.clone();
                context
                    .child("certify")
                    .spawn(move |_| async move { mailbox.certify(0, header, roots, deals).await })
            };

            // Every validator receives its dealing.
            let schemes = (0..committee.members().len())
                .map(|index| {
                    bls12381::Scheme::signer(committee.clone(), clearing_private(index).unwrap())
                        .unwrap()
                })
                .collect::<Vec<_>>();
            for chan in &mut validator_chans {
                let (from, _) = chan.1.recv().await.unwrap();
                assert_eq!(from, operator_key);
            }

            // Validator 0 returns a vote whose signature does not verify for
            // the signer it names, then a vote for a foreign header: both are
            // dropped without counting toward quorum.
            let silent = schemes[0].me().unwrap();
            let mut forged = schemes[1].sign(&header).unwrap();
            forged.signer = silent;
            let foreign_header =
                commonware_clearing::bajillion::transition::Header::<Digest>::decode(
                    Sha256::hash(&[b"foreign-header"]).as_ref(),
                )
                .unwrap();
            let foreign = Ballot {
                epoch: 0,
                header: foreign_header,
                vote: schemes[0].sign(&foreign_header).unwrap(),
            };
            validator_chans[0].0.send(
                Recipients::One(operator_key.clone()),
                DaMessage::Vote(Ballot {
                    epoch: 0,
                    header,
                    vote: forged,
                })
                .encode(),
                true,
            );
            validator_chans[0].0.send(
                Recipients::One(operator_key.clone()),
                DaMessage::Vote(foreign).encode(),
                true,
            );

            // The remaining validators return exactly quorum valid votes.
            for index in 1..=quorum {
                let vote = schemes[index].sign(&header).unwrap();
                validator_chans[index].0.send(
                    Recipients::One(operator_key.clone()),
                    DaMessage::Vote(Ballot {
                        epoch: 0,
                        header,
                        vote,
                    })
                    .encode(),
                    true,
                );
            }
            let certificate = certify
                .await
                .unwrap()
                .expect("quorum votes assemble the certificate");
            assert!(verifier.verify_exact(&header, &certificate));
            assert_eq!(certificate.signers.count(), quorum);
            assert!(!certificate.signers.iter().any(|signer| signer == silent));
        });
    }
}
