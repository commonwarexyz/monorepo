//! Chain backend facade: the settlement operations the wallet and operator
//! roles consume, expressed once over the [`Chain`] trait so its two
//! backends cannot drift.
//!
//! [`Client`] is the remote backend the AGENTS use: an RPC client of the
//! validators' query servers where nothing guarantee-bearing trusts an
//! unverified response. Every read is a [`CertifiedRead`] verified through
//! [`light::verify_read`] against the deployment's threshold identity, so a
//! served record (or a served absence, via an exclusion proof) is exactly
//! what a finalized block committed. A client-wide monotonic height gate
//! ([`light::Latest`]) turns replayed stale certificates into typed errors.
//! The OPERATOR runs the local backend instead: its own follower node's
//! verified finalized state ([`crate::chain::node::Node`]).
//!
//! Recency policy: window-critical reads (the status height that deadline
//! decisions anchor on, and the anchor and admitted records reconciliation
//! adjudicates against) go through [`Chain::recent`]. Block timestamps are
//! certified alongside every other field, so one verified read from a single
//! validator suffices: the client compares the certified timestamp to its
//! local clock and rejects a read older than [`RECENCY_THRESHOLD`] as stale.
//! The client keeps its validator address list for failover rotation only,
//! never as a quorum. The local backend applies the same gate to its own
//! tip, where it is a stall detector.
//!
//! Mutations are submit-then-prove-by-effect: a flow submits a
//! [`SettlementTx`] through [`Chain::deliver`] and completes only on a
//! certified read of the variant's effect record (a deposit's custody
//! record, the registration record, the admitted record, a claim's release
//! record, the fault record). The advisory [`Submitted`] answer is used only
//! to fast-fail an oversized submission, pace a full queue, and decorate
//! timeout diagnostics, never as evidence. Rejections are effect-free, so an
//! effect-free rejection is indistinguishable from not-yet-included: flows
//! retry until the effect appears or a bounded budget ends, and only a
//! certified record proving the input can never land (a consumed idempotence
//! key bound to other bytes) discards a durable intent.

#[cfg(test)]
use crate::chain::query::{EvidenceLookup, EvidenceRequest, EvidenceResponse, METHOD_EVIDENCE};
use crate::{
    chain::{
        ingress::Submission,
        light::{self, Latest, Verified},
        query::{
            CertifiedRead, Lookup, METHOD_READ, METHOD_SUBMIT_TX, ReadRequest, ReadResponse,
            Submitted,
        },
        setup::Genesis,
        state::{
            AdmittedRootsResponse, Advice, ClaimPendingDepositResponse, ClaimRootsResponse,
            FaultRecord, HardFaultReleaseRecord, PayoutReleaseRecord, Record, RegistrationRecord,
            StatusRecord, WithdrawalReleaseRecord,
        },
        tx::SettlementTx,
        types::now,
        validator::{NAMESPACE, Scheme},
    },
    protocol::{DepositEvent, Key},
    rpc,
};
use anyhow::{Context as _, Result, bail, ensure};
use commonware_clearing::bajillion::{boundary::SignedWithdrawal, transition::BatchId};
#[cfg(test)]
use commonware_codec::DecodeExt as _;
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Clock, Network, Spawner};
use commonware_storage::Context as StorageContext;
use rand_core::CryptoRng;
use std::{future::Future, net::SocketAddr, time::Duration};

/// Pause between certified polls of a pending record.
pub(crate) const POLL: Duration = Duration::from_millis(200);

/// Certified effect polls before a submitted transaction is reported stuck.
pub(crate) const EFFECT_ATTEMPTS: usize = 300;

/// Submission attempts while the ingress queue is full or the server binds.
const SUBMIT_ATTEMPTS: usize = 50;

/// Passes over the configured validators before a recency shortfall is
/// surfaced. A validator briefly restarting, a connect timeout, or a lagging
/// serving path is expected in a live deployment, so a pass on which no
/// validator served a recent verified read retries after a brief pause. The
/// recency bound itself is absolute: a read never adopts a stale response,
/// only the attempt count grows.
const RECENT_ATTEMPTS: usize = 5;

/// Maximum milliseconds a certified read's block timestamp may lag the local
/// clock before the read is rejected as stale.
///
/// Justified from block cadence plus drift: a live chain finalizes a new
/// block within the leader and certification timeouts (one plus two seconds
/// in [`crate::chain::validator`]), and an honest proposer's timestamp sits
/// within [`crate::chain::app::MAX_TIMESTAMP_DRIFT`] (two seconds) of honest
/// clocks, so a certified tip more than five seconds behind the local clock
/// is not the live tip.
pub(crate) const RECENCY_THRESHOLD: u64 = 5_000;

/// Runtime capabilities every chain-client call site provides.
pub(crate) trait Env: Clock + Network + Spawner + StorageContext {}

impl<E: Clock + Network + Spawner + StorageContext> Env for E {}

/// One settlement-chain backend: authenticated reads and transaction
/// submission, plus the typed settlement helpers implemented once over them.
///
/// Backends implement the three primitives and name the one deployment they
/// are bound to. Every typed helper is a provided method reading that
/// deployment's records, so the remote client and the operator's local node
/// serve the identical settlement surface.
pub(crate) trait Chain: Send + 'static {
    /// The deployment digest this backend is bound to. Every typed helper
    /// reads that deployment's records.
    fn deployment(&self) -> Digest;

    /// One deployment-scoped read request for this backend's deployment.
    fn request(&self, lookup: Lookup) -> ReadRequest {
        ReadRequest::new(self.deployment(), lookup)
    }

    /// One authenticated read: the record at the requested key (or a proven
    /// absence as `None`), at the height it was proven against.
    fn read<E: Env>(
        &mut self,
        ctx: &E,
        request: &ReadRequest,
    ) -> impl Future<Output = Result<Verified>> + Send;

    /// One recency-bounded read: the certified block timestamp is within
    /// [`RECENCY_THRESHOLD`] of the local clock, so the served record (or a
    /// served absence) holds at a finalized tip no older than the threshold.
    fn recent<E: Env>(
        &mut self,
        ctx: &E,
        request: &ReadRequest,
    ) -> impl Future<Output = Result<Verified>> + Send;

    /// Submits one transaction, returning the advisory [`Submitted`] answer.
    /// Acceptance promises gossip and proposal attempts, never inclusion: the
    /// authoritative answer is the certified read of the variant's effect
    /// record.
    fn submit<E: Env>(
        &mut self,
        ctx: &E,
        tx: &SettlementTx,
    ) -> impl Future<Output = Result<Submitted>> + Send;

    /// Submits one transaction with bounded retries, returning the last
    /// advisory dry-run answer.
    ///
    /// Delivery is not completion: the caller completes by polling a
    /// certified read of the variant's effect record. A rejection is
    /// effect-free and therefore indistinguishable from not-yet-included, so
    /// effect polls run until the effect appears or a bounded budget ends,
    /// and the returned advice exists to decorate that timeout diagnosis.
    fn deliver<E: Env>(
        &mut self,
        ctx: &E,
        tx: &SettlementTx,
    ) -> impl Future<Output = Result<Option<Advice>>> + Send {
        async move {
            for attempt in 0..SUBMIT_ATTEMPTS {
                match self.submit(ctx, tx).await {
                    Ok(submitted) => match submitted.admission {
                        Submission::Accepted | Submission::Duplicate => {
                            return Ok(submitted.advice);
                        }
                        Submission::Oversized => {
                            bail!("the transaction exceeds the per-transaction wire bound")
                        }
                        Submission::Full if attempt + 1 < SUBMIT_ATTEMPTS => {}
                        Submission::Full => bail!("the ingress queue stayed full"),
                    },
                    Err(error) if attempt + 1 == SUBMIT_ATTEMPTS => {
                        return Err(error.context("submit settlement transaction"));
                    }
                    Err(_) => {}
                }
                ctx.sleep(POLL).await;
            }
            bail!("the transaction was never admitted for delivery")
        }
    }

    /// The certified status singleton.
    fn status<E: Env>(&mut self, ctx: &E) -> impl Future<Output = Result<StatusRecord>> + Send {
        async move {
            let request = self.request(Lookup::Status);
            let verified = self.read(ctx, &request).await?;
            extract_status(verified)
        }
    }

    /// The certified status singleton under the recency bound, for decisions
    /// anchored on the chain tip (deadline choices).
    fn recent_status<E: Env>(
        &mut self,
        ctx: &E,
    ) -> impl Future<Output = Result<StatusRecord>> + Send {
        async move {
            let request = self.request(Lookup::Status);
            let verified = self.recent(ctx, &request).await?;
            extract_status(verified)
        }
    }

    /// The registered payment anchor for `epoch`, or a proven absence.
    ///
    /// Recency-bounded: intake and reconciliation treat the absence as a
    /// verdict, so it must hold at a recent finalized tip.
    fn anchor<E: Env>(
        &mut self,
        ctx: &E,
        epoch: u64,
    ) -> impl Future<Output = Result<Option<Digest>>> + Send {
        async move {
            let request = self.request(Lookup::Anchor { epoch });
            let verified = self.recent(ctx, &request).await?;
            match verified.record {
                Some(Record::Anchor(anchor)) => Ok(Some(anchor)),
                Some(_) => bail!("certified anchor read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The admitted close record for `epoch`, or a proven absence.
    ///
    /// Recency-bounded: reconciliation adjudicates coverage and the
    /// challenge window against it.
    fn admitted<E: Env>(
        &mut self,
        ctx: &E,
        epoch: u64,
    ) -> impl Future<Output = Result<Option<AdmittedRootsResponse>>> + Send {
        async move {
            let request = self.request(Lookup::Admitted { epoch });
            let verified = self.recent(ctx, &request).await?;
            match verified.record {
                Some(Record::Admitted(admitted)) => Ok(Some(admitted)),
                Some(_) => bail!("certified admitted read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The claim roots of one finalized batch, or a proven absence (the batch
    /// has not finalized: an availability signal, never a verdict).
    fn claim_roots<E: Env>(
        &mut self,
        ctx: &E,
        batch: BatchId<Digest>,
    ) -> impl Future<Output = Result<Option<ClaimRootsResponse>>> + Send {
        async move {
            let request = self.request(Lookup::ClaimRoots {
                batch: batch.into_digest(),
            });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::ClaimRoots(roots)) => Ok(Some(roots)),
                Some(_) => bail!("certified claim-roots read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The custody record for one deposit id, or a proven exclusion.
    ///
    /// Recency-bounded: the wallet discards a staged deposit on this
    /// absence, so it must hold at a recent finalized tip.
    fn deposit<E: Env>(
        &mut self,
        ctx: &E,
        id: Digest,
    ) -> impl Future<Output = Result<Option<DepositEvent>>> + Send {
        async move {
            let request = self.request(Lookup::Deposit { id });
            let verified = self.recent(ctx, &request).await?;
            match verified.record {
                Some(Record::Deposit(event)) => Ok(Some(event)),
                Some(_) => bail!("certified deposit read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The registration singleton, or a proven absence (no live registered
    /// close).
    fn registration<E: Env>(
        &mut self,
        ctx: &E,
    ) -> impl Future<Output = Result<Option<RegistrationRecord>>> + Send {
        async move {
            let request = self.request(Lookup::Registration);
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::Registration(record)) => Ok(Some(record)),
                Some(_) => bail!("certified registration read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The queued withdrawal for `account`, or a proven absence.
    fn withdrawal<E: Env>(
        &mut self,
        ctx: &E,
        account: Key,
    ) -> impl Future<Output = Result<Option<SignedWithdrawal<Key, Digest>>>> + Send {
        async move {
            let request = self.request(Lookup::Withdrawal { account });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::Withdrawal(request)) => Ok(Some(request)),
                Some(_) => bail!("certified withdrawal read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The fault singleton, or a proven absence (no fault).
    fn fault<E: Env>(
        &mut self,
        ctx: &E,
    ) -> impl Future<Output = Result<Option<FaultRecord>>> + Send {
        async move {
            let request = self.request(Lookup::Fault);
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::Fault(fault)) => Ok(Some(fault)),
                Some(_) => bail!("certified fault read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The released withdrawal at (batch, position), if released.
    fn withdrawal_release<E: Env>(
        &mut self,
        ctx: &E,
        batch: BatchId<Digest>,
        position: u32,
    ) -> impl Future<Output = Result<Option<WithdrawalReleaseRecord>>> + Send {
        async move {
            let request = self.request(Lookup::WithdrawalRelease {
                batch: batch.into_digest(),
                position,
            });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::WithdrawalRelease(release)) => Ok(Some(release)),
                Some(_) => bail!("certified withdrawal-release read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The released external payout at (batch, position), if released.
    fn payout_release<E: Env>(
        &mut self,
        ctx: &E,
        batch: BatchId<Digest>,
        position: u32,
    ) -> impl Future<Output = Result<Option<PayoutReleaseRecord>>> + Send {
        async move {
            let request = self.request(Lookup::PayoutRelease {
                batch: batch.into_digest(),
                position,
            });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::PayoutRelease(release)) => Ok(Some(release)),
                Some(_) => bail!("certified payout-release read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The hard-fault release for `account`, if claimed.
    fn hard_fault<E: Env>(
        &mut self,
        ctx: &E,
        account: Key,
    ) -> impl Future<Output = Result<Option<HardFaultReleaseRecord>>> + Send {
        async move {
            let request = self.request(Lookup::HardFault { account });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::HardFault(release)) => Ok(Some(release)),
                Some(_) => bail!("certified hard-fault read returned a foreign record"),
                None => Ok(None),
            }
        }
    }

    /// The deposit refund for `account`, if claimed.
    fn refund<E: Env>(
        &mut self,
        ctx: &E,
        account: Key,
    ) -> impl Future<Output = Result<Option<ClaimPendingDepositResponse>>> + Send {
        async move {
            let request = self.request(Lookup::Refund { account });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::Refund(refund)) => Ok(Some(refund)),
                Some(_) => bail!("certified refund read returned a foreign record"),
                None => Ok(None),
            }
        }
    }
}

/// The remote settlement-chain backend: an RPC client of the validators'
/// certified query servers, used by the wallet agents. Bound to exactly one
/// configured deployment at construction: every typed read is scoped to it.
pub(crate) struct Client {
    scheme: Scheme,
    /// The chain genesis: the validators' evidence-serving identities, so an
    /// evidence request routes to the exact quorum holding its slice.
    genesis: Genesis,
    /// The deployment this client reads.
    deployment: Digest,
    /// Validator query addresses, kept as a list for failover rotation only:
    /// one verified recent read suffices, so no read samples a quorum.
    queries: Vec<SocketAddr>,
    latest: Latest,
    /// Preferred query address, rotated past failing validators.
    primary: usize,
    /// Certificate verification randomness, bound once at construction.
    rng: Box<dyn CryptoRng + Send + Sync>,
}

impl Client {
    /// Builds a client over the chain's genesis threshold identity and the
    /// validator query addresses, bound to the configured `deployment`.
    pub(crate) fn new(
        identity: &Genesis,
        deployment: Digest,
        queries: Vec<SocketAddr>,
        rng: impl CryptoRng + Send + Sync + 'static,
    ) -> Result<Self> {
        ensure!(
            !queries.is_empty(),
            "at least one query address is required"
        );
        ensure!(
            identity
                .deployments
                .iter()
                .any(|configured| configured.digest() == &deployment),
            "the deployment is not configured in genesis"
        );
        Ok(Self {
            scheme: Scheme::verifier(
                NAMESPACE,
                identity.players().clone(),
                identity.public().clone(),
            ),
            genesis: identity.clone(),
            deployment,
            queries,
            latest: Latest::default(),
            primary: 0,
            rng: Box::new(rng),
        })
    }

    /// The chain genesis this client was built over: the validators'
    /// evidence-serving identities that route an evidence request to the
    /// exact quorum retaining its slice.
    pub(crate) const fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// Fetches one piece of evidence for this deployment from the validators
    /// retaining the lookup's slice, asking each holder in ascending
    /// participant order until one serves it or declares it absent. Every
    /// other answer is routing advice, and the last one is returned when no
    /// holder serves.
    ///
    /// Nothing here is verified: the caller checks a served opening against
    /// the certified roots it already holds (the admitted record's roots, a
    /// requested interval root, or the genesis state root).
    ///
    /// The wallet routes through its own holder rotation (see the agent's
    /// evidence module), so this direct form serves the query tests only.
    #[cfg(test)]
    pub(crate) async fn evidence<E: Env>(
        &self,
        ctx: &E,
        lookup: EvidenceLookup,
    ) -> Result<EvidenceResponse> {
        let holders = match (&lookup, lookup.account()) {
            (EvidenceLookup::Interval { slice, .. }, _) => self.genesis.holders_for(*slice)?,
            (_, Some(account)) => self.genesis.holders_for_account(account)?,
            (_, None) => bail!("evidence lookup names neither an account nor a slice"),
        };
        let request = EvidenceRequest::new(self.deployment, lookup);
        let mut last = None;
        for holder in holders {
            let response = rpc::invoke(ctx, holder, "validator", METHOD_EVIDENCE, request.encode())
                .await
                .and_then(|body| {
                    EvidenceResponse::decode(body).context("evidence response does not decode")
                });
            match response {
                Ok(response @ (EvidenceResponse::Served(_) | EvidenceResponse::Absent)) => {
                    return Ok(response);
                }
                other => last = Some(other),
            }
        }
        last.unwrap_or_else(|| bail!("no validator holds the requested slice"))
    }

    /// Fetches one certified read from `address` without verifying it.
    async fn fetch<E: Env>(
        &self,
        ctx: &E,
        address: SocketAddr,
        request: &ReadRequest,
    ) -> Result<CertifiedRead> {
        let body = rpc::invoke(ctx, address, "query", METHOD_READ, request.encode()).await?;
        match ReadResponse::decode_cfg(body, &()).context("decode certified read")? {
            ReadResponse::Certified(read) => Ok(read),
            ReadResponse::Unavailable => bail!("no certified snapshot is available yet"),
        }
    }

    /// Verifies one fetched response without observing the monotonic gate.
    fn verify<E: Env>(
        &mut self,
        request: &ReadRequest,
        response: &CertifiedRead,
    ) -> Result<Verified> {
        let mut rng: &mut (dyn CryptoRng + Send + Sync) = self.rng.as_mut();
        light::verify_read::<E, Scheme>(&mut rng, &self.scheme, request, response)
            .map_err(|error| anyhow::anyhow!("certified read failed verification: {error}"))
    }
}

impl Chain for Client {
    fn deployment(&self) -> Digest {
        self.deployment
    }

    /// One verified certified read from a single validator, under the
    /// monotonic height gate. Failing validators are rotated past.
    async fn read<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        let mut last = None;
        for attempt in 0..self.queries.len() {
            let index = (self.primary + attempt) % self.queries.len();
            let outcome = match self.fetch(ctx, self.queries[index], request).await {
                Ok(response) => self.verify::<E>(request, &response).and_then(|verified| {
                    self.latest.observe(verified.height)?;
                    Ok(verified)
                }),
                Err(error) => Err(error),
            };
            match outcome {
                Ok(verified) => {
                    self.primary = index;
                    return Ok(verified);
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.expect("at least one query address was attempted"))
    }

    /// One recency-bounded read: a single verified response whose certified
    /// block timestamp is within [`RECENCY_THRESHOLD`] of the local clock.
    /// The timestamp is covered by the finalization certificate, so one
    /// honest-signed read proves the served tip is recent without sampling
    /// any other validator.
    ///
    /// A stale or unreachable validator is rotated past, and a pass on which
    /// no validator served a recent verified read re-dials up to
    /// [`RECENT_ATTEMPTS`] times before erroring. The error names every
    /// failing address and, for a stale read, the observed lag. No pass ever
    /// adopts a stale response.
    async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        let mut failures = Vec::new();
        for attempt in 0..RECENT_ATTEMPTS {
            if attempt > 0 {
                ctx.sleep(POLL).await;
            }
            failures.clear();
            for offset in 0..self.queries.len() {
                let index = (self.primary + offset) % self.queries.len();
                let address = self.queries[index];
                let outcome = match self.fetch(ctx, address, request).await {
                    Ok(fetched) => self.verify::<E>(request, &fetched).and_then(|verified| {
                        light::recent(&verified, now(ctx), RECENCY_THRESHOLD)?;
                        self.latest.observe(verified.height)?;
                        Ok(verified)
                    }),
                    Err(error) => Err(error),
                };
                match outcome {
                    Ok(verified) => {
                        self.primary = index;
                        return Ok(verified);
                    }
                    Err(error) => failures.push(format!("{address}: {error:#}")),
                }
            }
        }
        bail!(
            "no validator served a recent certified read after {} passes ({})",
            RECENT_ATTEMPTS,
            failures.join("; ")
        )
    }

    /// Submits one transaction to the first answering validator.
    async fn submit<E: Env>(&mut self, ctx: &E, tx: &SettlementTx) -> Result<Submitted> {
        let mut last = None;
        for attempt in 0..self.queries.len() {
            let address = self.queries[(self.primary + attempt) % self.queries.len()];
            match rpc::invoke(ctx, address, "query", METHOD_SUBMIT_TX, tx.encode()).await {
                Ok(body) => {
                    return Submitted::decode_cfg(body, &()).context("decode advisory answer");
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.expect("at least one query address was attempted"))
    }
}

fn extract_status(verified: Verified) -> Result<StatusRecord> {
    match verified.record {
        Some(Record::Status(status)) => Ok(status),
        Some(_) => bail!("certified status read returned a foreign record"),
        None => bail!("the chain has not committed a status record yet"),
    }
}

/// Certified admission polls before an admitted close is reported stuck. The
/// budget must outlast a genesis challenge window at live cadence: the
/// admitted close finalizes only past its challenge deadline, roughly the
/// genesis admission offset plus challenge duration after its registration's
/// inclusion.
pub(crate) const FINALIZE_ATTEMPTS: usize = 3_000;

/// Submits a completed close and completes once the chain certifiably
/// finalized the exact batch.
///
/// Completion is certified end to end: the admitted record naming exactly
/// `expected.batch_id` with the close's change root, its finalized flag, and
/// (while this epoch is still the finalized tip) the status root pinned to
/// the close's successor root. An admission rejection is effect-free, so a
/// close that never earns its admitted record times out here. A proven
/// challenge against the batch invalidates it and fails the close.
pub(crate) async fn admit<C: Chain, E: Env>(
    ctx: &E,
    chain: &mut C,
    request: crate::chain::tx::AdmitRequest,
    expected: &commonware_clearing::bajillion::settlement::FinalizedBatch<Digest>,
    change: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
) -> Result<()> {
    let epoch = request.epoch;
    let batch_id = expected.batch_id;
    let successor_root = expected.successor_root;
    let tx = SettlementTx::Admit(request);
    let advice = chain
        .deliver(ctx, &tx)
        .await
        .context("submit close admission")?;
    for _ in 0..FINALIZE_ATTEMPTS {
        if let Ok(Some(admitted)) = chain.admitted(ctx, epoch).await {
            ensure!(
                admitted.batch_id == batch_id && admitted.change == change,
                "the chain admitted a different close for this epoch"
            );
            if admitted.finalized {
                let status = chain
                    .status(ctx)
                    .await
                    .context("read certified finalization status")?;
                ensure!(
                    status.last_finalized.is_some_and(|last| last >= epoch),
                    "the finalized admitted record outran the status horizon"
                );
                if status.last_finalized == Some(epoch) {
                    ensure!(
                        status.state_root == successor_root,
                        "the chain finalized a different successor root"
                    );
                }
                return Ok(());
            }
        }

        // A proven challenge against this batch invalidates the admitted
        // close: it will never finalize.
        if let Ok(Some(fault)) = chain.fault(ctx).await {
            let reason = match fault {
                FaultRecord::Faulted(reason) => reason,
                FaultRecord::Settling(settlement) => settlement.reason,
            };
            if matches!(
                reason,
                crate::chain::state::HardFaultReasonResponse::ProvenChallenge {
                    batch_id: proven,
                    ..
                } if proven == batch_id
            ) {
                bail!("the admitted close was invalidated by a proven challenge");
            }
        }
        ctx.sleep(POLL).await;
    }
    bail!("the admitted close did not certifiably finalize in time (dry-run advice: {advice:?})")
}
