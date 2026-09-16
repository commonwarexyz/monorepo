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
//! pipeline actor: it disseminates signed activity over the settlement DA
//! channel, verifies matching validator-derived results, assembles their
//! exact-quorum certificate, and completes admission against the local
//! certified state. The follower retains the settlement ledger; account
//! state and its historical proofs belong to validators. [`Pipeline`] hands the SQLite close worker a blocking
//! facade over that actor.

use crate::{
    chain::{
        app::{App, Finalized, initial_sync_target},
        client::{self, Chain, Env},
        da::{Ballot, Dealing, Message as DaMessage},
        ingress::Submission,
        light::{self, Verified},
        query::ReadRequest,
        setup::{NetworkConfig, OperatorConfig, read_genesis},
        state::Record,
        tx::{AdmitRequest, SettlementTx},
        types::{Block, Database, now},
        validator::{
            BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, EPOCH_LENGTH, MAILBOX_SIZE,
            MAX_MESSAGE_SIZE, MESSAGE_RATE, NAMESPACE, NoopResolver, PAGE_CACHE_SIZE, PAGE_SIZE,
            RESOLVER_CHANNEL, SETTLEMENT_DA_CHANNEL, SETTLEMENT_TX_CHANNEL, Scheme, VOTE_CHANNEL,
            db_config, sync_config,
        },
    },
    protocol::{
        CertifiedEpoch, DepositEvent, Key, PreparedEpoch, SettlementResult, dealt_participant,
    },
};
use anyhow::{Context as _, Result, bail, ensure};
use bytes::Bytes;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Receiver as MailboxReceiver, Sender as MailboxSender},
};
use commonware_broadcast::buffered;
use commonware_clearing::bajillion::{admission::bls12381, transition::CloseContext};
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
    Sha256,
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
    net::SocketAddr,
    num::NonZeroUsize,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
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
    holders: Vec<SocketAddr>,
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
            holders: self.holders.clone(),
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
        holders: Vec<SocketAddr>,
    ) -> Self {
        Self {
            deployment,
            holders,
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
        let claimed = if matches!(request.lookup, crate::chain::query::Lookup::Claimed { .. }) {
            let proof = match &record {
                Some(record) => crate::chain::query::ReadProof::Present {
                    record: record.clone(),
                    proof: guard.key_value_proof(request.key()).await?,
                },
                None => crate::chain::query::ReadProof::Absent {
                    proof: guard.exclusion_proof(&request.key()).await?,
                },
            };
            proof.claimed(request)
        } else {
            None
        };
        let payout_tip = if request.lookup.requires_payout_tip() {
            match guard
                .get(&crate::chain::state::payout_head_key(&request.deployment))
                .await?
            {
                Some(Record::PayoutHead(head)) => Some(head),
                _ => return Ok(None),
            }
        } else {
            None
        };
        Ok(Some(Verified {
            height: tip.height,
            timestamp: tip.timestamp,
            record,
            claimed,
            payout_tip,
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

    fn holders(&self) -> Result<Vec<SocketAddr>> {
        Ok(self.holders.clone())
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
    /// the settlement transaction channel. Local send success is advisory;
    /// validators qualify the request before reserving proposal capacity.
    async fn submit<E2: Env>(&mut self, _: &E2, tx: &SettlementTx) -> Result<Submission> {
        let sent = self.sender.send(Recipients::All, tx.encode(), false);
        ensure!(!sent.is_empty(), "no validator accepted the submission");
        Ok(Submission::Accepted)
    }
}

/// The clearing participant and network peer receiving the shared dealing.
pub(crate) struct Route {
    pub(crate) participant: Participant,
    pub(crate) peer: ed25519::PublicKey,
}

/// A message sent to the close pipeline [`Certifier`].
pub(crate) enum Message {
    /// Stop certification for this operator's canonically invalidated suffix.
    Fence { first: u64 },
    /// Disseminate the complete dealing and assemble the exact-quorum
    /// certificate from the returned votes.
    Certify {
        prepared: Box<PreparedEpoch>,
        proposal: Digest,
        message: Bytes,
        routes: Vec<Route>,
        response: oneshot::Sender<Result<SettlementResult>>,
    },
    /// Submit the certified close and complete once the local certified
    /// state admitted the exact batch and roots.
    Admit {
        request: Box<(CloseContext<Key, Digest>, AdmitRequest)>,
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
    /// Encodes one shared DA packet and completes on the exact-quorum certificate.
    pub(crate) async fn certify(
        &self,
        prepared: PreparedEpoch,
        routes: Vec<Route>,
    ) -> Result<SettlementResult> {
        let context = prepared.context();
        let dealing = Dealing {
            deployment: *context.deployment(),
            epoch: context.payment().epoch(),
            context: context.clone(),
            bytes: prepared.encoded().clone(),
        };
        let proposal = dealing.id();
        let message = DaMessage::Dealing(Box::new(dealing)).encode();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Certify {
            prepared: Box::new(prepared),
            proposal,
            message,
            routes,
            response,
        });
        receiver.await.map_err(|_| PipelineStopped)?
    }

    /// Submits the certified close and completes on certified admission.
    pub(crate) async fn admit(
        &self,
        context: CloseContext<Key, Digest>,
        request: AdmitRequest,
    ) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Admit {
            request: Box::new((context, request)),
            response,
        });
        receiver.await.map_err(|_| PipelineStopped)?
    }
}

/// The pipeline owner has stopped; its durable jobs require a live owner to resume.
#[derive(Debug, thiserror::Error)]
#[error("the close pipeline stopped; restart the operator to resume")]
pub(crate) struct PipelineStopped;

/// Blocking close-pipeline facade for the operator's synchronous close
/// worker thread: dissemination, certification, and admission run inside the
/// node's runtime while the worker blocks on the result.
#[derive(Clone)]
pub(crate) struct Pipeline {
    mailbox: Mailbox,
    deployment: Digest,
    /// Network identity holding each clearing participant's dealt key, in
    /// committee participant order.
    peers: Vec<ed25519::PublicKey>,
}

impl Pipeline {
    /// Builds the pipeline facade, deriving the committee participant to
    /// network identity mapping from the setup convention that validator
    /// directory `i` holds clearing key `i`.
    pub(crate) fn new(
        mailbox: Mailbox,
        participants: &[ed25519::PublicKey],
        deployment: Digest,
    ) -> Result<Self> {
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
            deployment,
            peers: peers
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .context("a clearing committee key has no network identity")?,
        })
    }

    /// Certifies one complete close with every configured committee participant.
    pub(crate) fn certify(&self, prepared: &PreparedEpoch) -> Result<SettlementResult> {
        ensure!(
            prepared.context().deployment() == &self.deployment,
            "foreign deployment dealing"
        );
        let routes = self
            .peers
            .iter()
            .enumerate()
            .map(|(index, peer)| Route {
                participant: Participant::from_usize(index),
                peer: peer.clone(),
            })
            .collect();
        let started = Instant::now();
        let mut result =
            futures::executor::block_on(self.mailbox.certify(prepared.clone(), routes))?;
        result.deal_micros = started.elapsed().as_micros();
        Ok(result)
    }

    /// Cancels this operator's invalidated suffix, including work still preparing.
    pub(crate) fn fence(&self, first: u64) {
        let _ = self.mailbox.sender.enqueue(Message::Fence { first });
    }

    /// Submits the certified close and blocks until certified admission.
    pub(crate) fn admit(
        &self,
        context: CloseContext<Key, Digest>,
        request: AdmitRequest,
    ) -> Result<()> {
        futures::executor::block_on(self.mailbox.admit(context, request))
    }
}

/// One close awaiting its exact-quorum certificate.
struct Outstanding {
    prepared: PreparedEpoch,
    proposal: Digest,
    message: Bytes,
    routes: Vec<Route>,
    votes: BTreeMap<Participant, Ballot>,
    response: oneshot::Sender<Result<SettlementResult>>,
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
    // Preparation runs on a worker: a fence can arrive before its certification request.
    fenced_from: Option<u64>,
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
                fenced_from: None,
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
        let mut resend_at = self.context.current() + RESEND;
        loop {
            select! {
                _ = self.context.sleep_until(resend_at) => {
                    self.disseminate(&mut sender);
                    resend_at = self.context.current() + RESEND;
                },
                message = self.mailbox.recv() => {
                    let Some(message) = message else {
                        return;
                    };
                    match message {
                        Message::Fence { first } => {
                            self.fenced_from = Some(self.fenced_from.map_or(first, |old| old.min(first)));
                            if self.outstanding.as_ref().is_some_and(|close| close.prepared.context().payment().epoch() >= first) {
                                self.outstanding.take().unwrap().response.send_lossy(Err(anyhow::anyhow!("certification is canonically fenced")));
                            }
                        }
                        Message::Certify { prepared, proposal, message, routes, response } => {
                            let epoch = prepared.context().payment().epoch();
                            if self.fenced_from.is_some_and(|first| epoch >= first) {
                                response.send_lossy(Err(anyhow::anyhow!("certification is canonically fenced")));
                                continue;
                            }
                            // A replaced certification drops the stale
                            // response: its worker observes the closed
                            // channel and fails that close.
                            self.outstanding = Some(Outstanding {
                                prepared: *prepared,
                                proposal,
                                message,
                                routes,
                                votes: BTreeMap::new(),
                                response,
                            });
                            self.disseminate(&mut sender);
                            resend_at = self.context.current() + RESEND;
                        }
                        Message::Admit { request, response } => {
                            let (context, request) = *request;
                            let result = client::admit(
                                self.context.as_present(),
                                &mut self.chain,
                                &context,
                                request,
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
                    let Some(outstanding) = &self.outstanding else { continue; };
                    if !outstanding.routes.iter().any(|route| route.peer == peer)
                        || bytes.len() > 4096
                    {
                        continue;
                    }
                    let Ok(DaMessage::Vote(ballot)) = DaMessage::decode(bytes) else {
                        debug!(?peer, "dropping undecodable or unexpected DA message");
                        continue;
                    };
                    if !outstanding.routes.iter().any(|route| route.peer == peer && route.participant == ballot.vote.signer) {
                        continue;
                    }
                    self.tally(*ballot);
                },
            }
        }
    }

    /// Sends the shared packet to each validator, skipping validators
    /// that already voted. Dissemination is recoverable off-chain traffic,
    /// so delivery is retried on the resend tick until quorum, resending the
    /// same encoded allocation to every destination.
    fn disseminate<Se>(&mut self, sender: &mut Se)
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
    {
        let Some(outstanding) = &self.outstanding else {
            return;
        };
        for route in &outstanding.routes {
            if outstanding.votes.contains_key(&route.participant) {
                continue;
            }
            let sent = sender.send(
                Recipients::One(route.peer.clone()),
                outstanding.message.clone(),
                true,
            );
            if sent.is_empty() {
                debug!(epoch = outstanding.prepared.context().payment().epoch(), peer = ?route.peer, "failed to send dealing");
            }
        }
    }

    /// Counts one verified result per participant; quorum must agree on the derived header.
    fn tally(&mut self, ballot: Ballot) {
        let Some(outstanding) = &mut self.outstanding else {
            return;
        };
        if ballot.deployment != *outstanding.prepared.context().deployment()
            || ballot.epoch != outstanding.prepared.context().payment().epoch()
            || ballot.proposal != outstanding.proposal
            || ballot.context.epoch_context() != outstanding.prepared.context()
            || !ballot.header.verify::<Sha256, Key>(
                &ballot.context,
                &ballot.roots,
                ballot.withdrawal_total,
            )
        {
            debug!(
                epoch = ballot.epoch,
                "dropping vote for a foreign proposal or result"
            );
            return;
        }
        if outstanding.votes.contains_key(&ballot.vote.signer) {
            return;
        }
        if !self.verifier.verify_vote(&ballot.header, &ballot.vote) {
            warn!(epoch = ballot.epoch, signer = ?ballot.vote.signer, "dropping invalid vote");
            return;
        }
        let signer = ballot.vote.signer;
        let header = ballot.header;
        outstanding.votes.insert(signer, ballot);
        let matching = outstanding
            .votes
            .values()
            .filter(|ballot| ballot.header == header)
            .count();
        info!(
            epoch = outstanding.prepared.context().payment().epoch(),
            ?signer,
            votes = matching,
            "verified vote"
        );
        if matching < self.verifier.committee().quorum() {
            return;
        }
        let outstanding = self
            .outstanding
            .take()
            .expect("the outstanding proposal was checked above");
        let mut matching = outstanding
            .votes
            .into_values()
            .filter(|ballot| ballot.header == header);
        let result = matching.next().expect("nonempty quorum");
        let certificate = self
            .verifier
            .assemble_exact(
                std::iter::once(result.vote.clone()).chain(matching.map(|ballot| ballot.vote)),
            )
            .expect("exactly quorum verified votes assemble");
        outstanding
            .response
            .send_lossy(outstanding.prepared.certify(
                CertifiedEpoch {
                    context: result.context,
                    header: result.header,
                    roots: result.roots,
                    withdrawal_total: result.withdrawal_total,
                    certificate,
                },
                0,
                0,
            ));
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
/// canonical account is credited without that party's cooperation. The
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
                SettlementTx::Deposit(request) => Some(request),
                SettlementTx::ClaimDeposit(request) => Some(&request.deposit),
                _ => None,
            })
            .filter(|request| request.deployment == self.deployment)
            .map(|request| request.event.clone())
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
    let genesis = read_genesis(node_dir).context("genesis is required")?;
    network
        .validate(&genesis)
        .context("invalid network config")?;
    let local = operator.public_key();

    let deployment = operator.deployment;
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
        metadata_partition: format!("{partition_prefix}-{name}-metadata"),
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
        genesis.native.chain_id(),
        genesis.timestamp,
        initial_sync_target::<tokio::Context>(),
    );
    let startup = context.child("stateful_startup");
    let plan = SyncPlan::init(&startup, partition_prefix).await;

    // Marshal actor.
    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            start: plan.marshal_start(Arc::new(genesis_block.clone())),
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
        genesis.native.clone(),
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
    let node = Node::new(
        deployment,
        db,
        finalized,
        settlement_tx_network.0,
        genesis.holders()?,
    );
    let protocol_verifier = bls12381::Scheme::verifier(
        crate::protocol::committee().context("construct the certifier committee")?,
    );
    let (certifier, pipeline_mailbox) = Certifier::new(
        context.child("certifier"),
        Config {
            verifier: protocol_verifier,
            chain: node.clone(),
            mailbox_size: MAILBOX_SIZE,
        },
    );
    let certifier_handle = certifier.start(settlement_da_network);
    let pipeline = Pipeline::new(pipeline_mailbox, &network.participants, deployment)?;

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
    mod payouts;

    use super::*;
    use crate::{
        chain::{light::Verified, query::ReadRequest},
        protocol::{Protocol, clearing_private, committee},
    };
    use anyhow::bail;
    use commonware_actor::Unreliable;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519::PrivateKey};
    use commonware_p2p::{
        CheckedSender, LimitedSender,
        simulated::{Config as NetConfig, Link, Network},
    };
    use commonware_runtime::{Clock as _, IoBuf, IoBufs, Quota, Runner as _, deterministic};
    use commonware_utils::{NZU32, NZUsize, probability, sync::Mutex};
    use std::{sync::Arc, time::SystemTime};

    #[derive(Clone)]
    struct Recorded<S> {
        inner: S,
        messages: Arc<Mutex<Vec<IoBuf>>>,
    }

    impl<S: LimitedSender> LimitedSender for Recorded<S> {
        type PublicKey = S::PublicKey;
        type Checked<'a>
            = Recorded<S::Checked<'a>>
        where
            Self: 'a;

        fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            Ok(Recorded {
                inner: self.inner.check(recipients)?,
                messages: self.messages.clone(),
            })
        }
    }

    impl<S: CheckedSender> CheckedSender for Recorded<S> {
        type PublicKey = S::PublicKey;

        fn recipients(&self) -> Vec<Self::PublicKey> {
            self.inner.recipients()
        }

        fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
            let message = message.into().coalesce();
            self.messages.lock().push(message.clone());
            self.inner.send(message, priority)
        }
    }

    /// A chain backend the certifier test never reads or submits through.
    #[derive(Clone)]
    struct Stub(Vec<SocketAddr>);

    impl Chain for Stub {
        fn holders(&self) -> Result<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }

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
        ) -> Result<Submission> {
            bail!("the stub backend accepts no submissions")
        }
    }

    #[test]
    fn certifier_drops_invalid_votes_and_assembles_exact_quorum() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
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

            let accounts = crate::protocol::accounts();
            let registration = protocol
                .registration(
                    0,
                    commonware_clearing::bajillion::boundary::DepositBatch::empty(),
                    commonware_clearing::bajillion::boundary::WithdrawalBatch::empty(),
                    accounts.iter().map(|account| account.balance).sum(),
                )
                .unwrap();
            let prepared = protocol.prepare(registration, Vec::new()).unwrap();
            let result = protocol
                .fixture_complete(&accounts, &[], prepared.clone(), 91)
                .unwrap();
            let header = result.header;
            let proposal = Dealing {
                deployment: protocol.deployment(),
                epoch: 0,
                context: prepared.context().clone(),
                bytes: prepared.encoded().clone(),
            }
            .id();
            let make_ballot = |result: &SettlementResult, vote| Ballot {
                deployment: protocol.deployment(),
                epoch: 0,
                proposal,
                context: result.context.clone(),
                header: result.header,
                roots: result.roots,
                withdrawal_total: result.withdrawal_total,
                vote,
            };

            let (certifier, mailbox) = Certifier::new(
                context.child("certifier"),
                Config {
                    verifier: verifier.clone(),
                    chain: Stub(Vec::new()),
                    mailbox_size: NZUsize!(16),
                },
            );
            let messages = Arc::new(Mutex::new(Vec::new()));
            certifier.start((
                Recorded {
                    inner: operator_chan.0,
                    messages: messages.clone(),
                },
                operator_chan.1,
            ));

            let deals = validator_keys
                .iter()
                .enumerate()
                .map(|(index, key)| Route {
                    participant: dealt_participant(index).unwrap(),
                    peer: key.clone(),
                })
                .collect::<Vec<_>>();
            let certify = {
                let mailbox = mailbox.clone();
                context
                    .child("certify")
                    .spawn(move |_| async move { mailbox.certify(prepared, deals).await })
            };

            // Every recipient and retry shares one encoded allocation at the transport boundary.
            let schemes = (0..committee.members().len())
                .map(|index| {
                    bls12381::Scheme::signer(committee.clone(), clearing_private(index).unwrap())
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let mut foreign = make_ballot(&result, schemes[0].sign(&header).unwrap());
            foreign.proposal = Sha256::hash(&[b"foreign-proposal"]);
            let mut delayed_sender = validator_chans[0].0.clone();
            let target = operator_key.clone();
            let delayed = DaMessage::Vote(Box::new(foreign.clone())).encode();
            let delayed_replies =
                context
                    .child("delayed_replies")
                    .spawn(move |context| async move {
                        loop {
                            context.sleep(Duration::from_millis(100)).await;
                            delayed_sender.send(
                                Recipients::One(target.clone()),
                                delayed.clone(),
                                true,
                            );
                        }
                    });
            for round in 0..2 {
                for chan in &mut validator_chans {
                    let (from, _) = chan.1.recv().await.unwrap();
                    assert_eq!(from, operator_key);
                }
                let sent = messages.lock();
                assert_eq!(sent.len(), (round + 1) * validator_keys.len());
                assert!(
                    sent.iter()
                        .all(|message| message.as_ref().as_ptr() == sent[0].as_ref().as_ptr())
                );
            }

            delayed_replies.abort();

            // Invalid signatures and foreign proposal replies do not consume a participant's vote.
            let silent = schemes[0].me().unwrap();
            let mut forged = schemes[1].sign(&header).unwrap();
            forged.signer = silent;
            let ballot = |ballot: Ballot| {
                let message: DaMessage = DaMessage::Vote(Box::new(ballot));
                message.encode()
            };
            validator_chans[0].0.send(
                Recipients::One(operator_key.clone()),
                ballot(make_ballot(&result, forged)),
                true,
            );
            validator_chans[0]
                .0
                .send(Recipients::One(operator_key.clone()), ballot(foreign), true);

            // One validator may derive a different root. It cannot pin the result
            // that the remaining honest quorum is allowed to certify.
            let mut other_accounts = accounts.clone();
            other_accounts[0].balance += 1;
            other_accounts[1].balance -= 1;
            let other = protocol.fixture_complete(&other_accounts, &[],
                protocol.prepare(crate::protocol::EpochRegistration {
                    floors: None,
                    context: result.context.epoch_context().clone(),
                    deposits: commonware_clearing::bajillion::boundary::DepositBatch::empty(),
                    withdrawals: commonware_clearing::bajillion::boundary::WithdrawalBatch::empty(),
                }, Vec::new()).unwrap(), 92).unwrap();
            assert_ne!(other.header, header);
            validator_chans[0].0.send(
                Recipients::One(operator_key.clone()),
                ballot(make_ballot(&other, schemes[0].sign(&other.header).unwrap())),
                true,
            );
            context.sleep(Duration::from_millis(10)).await;

            // The remaining validators return exactly quorum valid votes.
            for index in 1..=quorum {
                let vote = schemes[index].sign(&header).unwrap();
                validator_chans[index].0.send(
                    Recipients::One(operator_key.clone()),
                    ballot(make_ballot(&result, vote)),
                    true,
                );
            }
            let certificate = certify
                .await
                .unwrap()
                .expect("quorum votes assemble the certificate");
            assert!(verifier.verify_exact(&header, &certificate.certificate));
            assert_eq!(certificate.certificate.signers.count(), quorum);
            assert_eq!(messages.lock().len(), 2 * validator_keys.len());
            assert!(
                !certificate
                    .certificate
                    .signers
                    .iter()
                    .any(|signer| signer == silent)
            );
        });
    }
    #[test]
    fn certifier_fence_cancels_pending_certification_and_rejects_replacement() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let prepared = protocol
                .prepare(
                    protocol
                        .registration(
                            0,
                            commonware_clearing::bajillion::boundary::DepositBatch::empty(),
                            commonware_clearing::bajillion::boundary::WithdrawalBatch::empty(),
                            400,
                        )
                        .unwrap(),
                    Vec::new(),
                )
                .unwrap();
            let dealing = Dealing {
                deployment: protocol.deployment(),
                epoch: 0,
                context: prepared.context().clone(),
                bytes: prepared.encoded().clone(),
            };
            let replacement = prepared.clone();
            let (mut certifier, mailbox) = Certifier::new(
                context.child("certifier"),
                Config {
                    verifier: protocol.verifier(),
                    chain: Stub(Vec::new()),
                    mailbox_size: NZUsize!(16),
                },
            );
            let (response, receiver) = oneshot::channel();
            certifier.outstanding = Some(Outstanding {
                prepared,
                proposal: dealing.id(),
                message: DaMessage::Dealing(Box::new(dealing)).encode(),
                routes: Vec::new(),
                votes: BTreeMap::new(),
                response,
            });
            certifier.start(commonware_p2p::utils::mocks::inert_channel::<
                ed25519::PublicKey,
            >([]));
            let _ = mailbox.sender.enqueue(Message::Fence { first: 0 });
            assert!(
                receiver
                    .await
                    .unwrap()
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("fenced")
            );
            assert!(
                mailbox
                    .certify(replacement, Vec::new())
                    .await
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("fenced")
            );
        });
    }
}
