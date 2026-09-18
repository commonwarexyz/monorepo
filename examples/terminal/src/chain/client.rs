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
//! certified read of the effect: deposit custody, registration or admission,
//! payout inclusion plus claimed-range coverage, or fault recovery. The advisory
//! [`Submission`] answer is used only
//! to reject oversized submissions and pace a full queue. An effect-free
//! rejection is indistinguishable from not-yet-included: flows
//! retry until the effect appears or a bounded budget ends, and only a
//! certified record proving the input can never land (a consumed idempotence
//! key bound to other bytes) discards a durable intent.

use crate::{
    chain::{
        da::sync::{METHOD_NATIVE, NativeRequest, NativeResponse, Query as NativeQuery},
        ingress::Submission,
        light::{self, Latest, Verified},
        native::RegistryEntry,
        query::{
            CertifiedRead, Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse, Lookup,
            METHOD_EVIDENCE, METHOD_READ, METHOD_SUBMIT_TX, ReadRequest, ReadResponse,
        },
        setup::Genesis,
        state::{
            AdmittedRootsResponse, ClaimPendingDepositResponse, FaultRecord,
            HardFaultReleaseRecord, Record, RegistrationRecord, StatusRecord,
        },
        tx::{NativeTransferRequest, SettlementTx},
        types::now,
        validator::{NAMESPACE, Scheme},
    },
    protocol::{DepositEvent, Key},
    rpc,
};
use anyhow::{Context as _, Result, bail, ensure};
use commonware_clearing::bajillion::{
    admission::bls12381,
    boundary::SignedWithdrawal,
    logs::{LogHead, PayoutOperation},
    transition::CloseContext,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, RangeCfg};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::{Clock, Network, Spawner};
use commonware_storage::{
    Context as StorageContext,
    merkle::{Family as _, Location, mmr},
    qmdb::{
        self,
        sync::{Request as NativeSyncRequest, Response as NativeSyncResponse},
    },
};
use rand_core::CryptoRng;
use std::{future::Future, net::SocketAddr, num::NonZeroU64, time::Duration};

const PAYOUT_DISCOVERY_PAGE: u64 = 128;

async fn fetch_payout_operations_at<E: Clock + Network>(
    ctx: &E,
    address: SocketAddr,
    deployment: Digest,
    head: LogHead<Digest>,
    start: u64,
) -> Result<Vec<PayoutOperation>> {
    let size = Location::<mmr::Family>::new(head.operations);
    let start = Location::<mmr::Family>::new(start);
    ensure!(
        start < size,
        "payout discovery cursor is outside the authenticated head"
    );
    let count = (*size - *start).min(PAYOUT_DISCOVERY_PAGE);
    let request = NativeRequest {
        deployment,
        query: NativeQuery::Payouts(NativeSyncRequest::Operations {
            size,
            start,
            max_ops: NonZeroU64::new(count).expect("nonempty payout page"),
        }),
    };
    let body = rpc::invoke(
        ctx,
        address,
        "payout log custodian",
        METHOD_NATIVE,
        request.encode(),
    )
    .await?;
    let NativeResponse::Data(body) = NativeResponse::decode(body)? else {
        bail!("payout log page is unavailable")
    };
    let NativeSyncResponse::Operations { proof, operations } =
        NativeSyncResponse::<mmr::Family, PayoutOperation, Digest>::decode_cfg(
            body,
            &(
                usize::try_from(PAYOUT_DISCOVERY_PAGE).expect("payout page bound fits usize"),
                RangeCfg::new(..=crate::protocol::MAX_DESTINATION_BYTES),
            ),
        )?
    else {
        bail!("custodian returned another payout response")
    };
    ensure!(
        operations.len() == usize::try_from(count).expect("page count fits usize")
            && proof.leaves == size
            && proof.inactive_peaks == mmr::Family::inactive_peaks(size, Location::new(head.floor))
            && qmdb::verify_proof::<Sha256, mmr::Family, _>(&proof, start, &operations, &head.root,),
        "custodian returned an invalid payout-log page"
    );
    Ok(operations)
}

/// Tries each native custodian once and authenticates the requested output position and head.
pub(crate) async fn fetch_payout_proof<E: Clock + Network>(
    ctx: &E,
    holders: &[SocketAddr],
    deployment: Digest,
    head: commonware_clearing::bajillion::logs::LogHead<Digest>,
    index: u64,
) -> Result<commonware_clearing::bajillion::transition::WithdrawalClaim<Digest>> {
    let request = EvidenceRequest::new(deployment, EvidenceLookup::Payout { head, index });
    for address in holders {
        let Ok(body) = rpc::invoke(
            ctx,
            *address,
            "payout custodian",
            METHOD_EVIDENCE,
            request.encode(),
        )
        .await
        else {
            continue;
        };
        let Ok(EvidenceResponse::Served(Evidence::Payout(claim))) = EvidenceResponse::decode(body)
        else {
            continue;
        };
        if claim.position() == index && claim.verify::<Sha256>(&head).is_ok() {
            return Ok(claim);
        }
    }
    bail!("no custodian can open the payout at the authenticated head")
}

/// Pause between certified polls of a pending record.
pub(crate) const POLL: Duration = Duration::from_millis(200);

/// Certified effect polls before a submitted transaction is reported stuck.
pub(crate) const EFFECT_ATTEMPTS: usize = 300;

/// Submission attempts while the ingress queue is full or the server binds.
pub(crate) const SUBMIT_ATTEMPTS: usize = 50;

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
/// Backends implement the read and submission primitives and name the deployment they
/// are bound to. Every typed helper is a provided method reading that
/// deployment's records, so the remote client and the operator's local node
/// serve the identical settlement surface.
pub(crate) trait Chain: Send + 'static {
    /// The deployment digest this backend is bound to. Every typed helper
    /// reads that deployment's records.
    fn deployment(&self) -> Digest;

    /// Configured validator evidence endpoints for this chain.
    fn holders(&self) -> Result<Vec<SocketAddr>>;

    /// Fetches a retained payout witness from any configured custodian.
    fn payout_proof<E: Env>(
        &self,
        ctx: &E,
        head: commonware_clearing::bajillion::logs::LogHead<Digest>,
        index: u64,
    ) -> impl Future<
        Output = Result<commonware_clearing::bajillion::transition::WithdrawalClaim<Digest>>,
    > + Send {
        let deployment = self.deployment();
        let holders = self.holders();
        async move { fetch_payout_proof(ctx, &holders?, deployment, head, index).await }
    }

    /// Fetches and authenticates one bounded page of the finalized payout operation log.
    ///
    /// `start` is a logical cursor, independent of the MMR inactivity floor. A pruned or
    /// unavailable holder is skipped; its response never proves that the requested prefix is
    /// absent.
    fn payout_operations<E: Env>(
        &self,
        ctx: &E,
        head: LogHead<Digest>,
        start: u64,
    ) -> impl Future<Output = Result<(u64, Vec<PayoutOperation>)>> + Send {
        let deployment = self.deployment();
        let holders = self.holders();
        async move {
            ensure!(
                start < head.operations,
                "payout discovery cursor is outside the authenticated head"
            );
            let holders = holders?;
            for &address in &holders {
                if let Ok(operations) =
                    fetch_payout_operations_at(ctx, address, deployment, head, start).await
                {
                    return Ok((start, operations));
                }
            }

            // A checkpoint retention cut is availability advice only. It may skip an unavailable
            // prefix, but the returned suffix is still authenticated against the wallet's exact
            // certified payout head. Exhaust the exact cursor at every holder before using it.
            let mut best = None;
            for address in holders {
                let hint_request = NativeRequest {
                    deployment,
                    query: NativeQuery::Checkpoint { max_next: u64::MAX },
                };
                let Ok(body) = rpc::invoke(
                    ctx,
                    address,
                    "payout log custodian",
                    METHOD_NATIVE,
                    hint_request.encode(),
                )
                .await
                else {
                    continue;
                };
                let Ok(NativeResponse::Checkpoint(transfer)) = NativeResponse::decode(body) else {
                    continue;
                };
                let hint = transfer.checkpoint.retained.payouts;
                if transfer.checkpoint.deployment != deployment
                    || hint <= start
                    || hint >= head.operations
                {
                    continue;
                }
                if let Ok(operations) =
                    fetch_payout_operations_at(ctx, address, deployment, head, hint).await
                    && best
                        .as_ref()
                        .is_none_or(|(best_start, _)| hint < *best_start)
                {
                    best = Some((hint, operations));
                }
            }
            if let Some(page) = best {
                return Ok(page);
            }
            bail!("no custodian can authenticate the requested payout-log page")
        }
    }

    /// Opens the registration predecessor through independently verified validator evidence.
    fn predecessor_opening<E: Env>(
        &mut self,
        ctx: &E,
        epoch: u64,
        account: Key,
        genesis: commonware_clearing::bajillion::settlement::Genesis<Digest>,
    ) -> impl Future<
        Output = Result<commonware_clearing::bajillion::qmdb::StateOpening<Key, Digest>>,
    > + Send {
        async move {
            let (root, operations) = if let Some(previous) = epoch.checked_sub(1) {
                let admitted = self
                    .admitted(ctx, previous)
                    .await?
                    .context("predecessor is not admitted")?;
                (
                    admitted.roots.successor,
                    admitted.roots.successor_operations,
                )
            } else {
                (genesis.root(), genesis.operations())
            };
            let lookup = EvidenceLookup::State {
                root,
                operations,
                account: account.clone(),
            };
            for address in self.holders()? {
                let request = EvidenceRequest::new(self.deployment(), lookup.clone());
                let Ok(body) = rpc::invoke(
                    ctx,
                    address,
                    "balance custodian",
                    METHOD_EVIDENCE,
                    request.encode(),
                )
                .await
                else {
                    continue;
                };
                let Ok(EvidenceResponse::Served(evidence)) = EvidenceResponse::decode(body) else {
                    continue;
                };
                let Evidence::State(lookup) = evidence else {
                    continue;
                };
                if lookup
                    .resolve::<Sha256>(
                        &root,
                        &commonware_clearing::bajillion::qmdb::account_key(&account)?,
                    )
                    .is_err()
                {
                    continue;
                }
                if let commonware_clearing::bajillion::qmdb::StateLookup::Present(value) = lookup {
                    return Ok(commonware_clearing::bajillion::qmdb::StateOpening {
                        account: account.clone(),
                        balance: value.balance,
                        proof: value.proof,
                    });
                }
            }
            bail!("no custodian can open the registration predecessor")
        }
    }

    /// Shared native balance proven at a recent finalized block.
    fn native_balance<E: Env>(
        &mut self,
        ctx: &E,
        chain_id: Digest,
        account: Key,
    ) -> impl Future<Output = Result<u64>> + Send {
        async move {
            let request = self.request(Lookup::NativeBalance { chain_id, account });
            match self.recent(ctx, &request).await?.record {
                Some(Record::NativeBalance(balance)) => Ok(balance),
                None => Ok(0),
                Some(_) => bail!("certified native balance read returned a foreign record"),
            }
        }
    }

    /// One immutable deployment entry, or certified absence, at a recent block.
    fn registry_entry<E: Env>(
        &mut self,
        ctx: &E,
        chain_id: Digest,
        deployment: Digest,
    ) -> impl Future<Output = Result<Option<RegistryEntry>>> + Send {
        async move {
            let request = self.request(Lookup::RegistryEntry {
                chain_id,
                deployment,
            });
            match self.recent(ctx, &request).await?.record {
                Some(Record::RegistryEntry(entry)) => Ok(Some(entry)),
                None => Ok(None),
                Some(_) => bail!("certified registry entry read returned a foreign record"),
            }
        }
    }

    /// A native transfer's exact successful request, or certified absence.
    fn native_transfer<E: Env>(
        &mut self,
        ctx: &E,
        chain_id: Digest,
        from: Key,
        id: Digest,
    ) -> impl Future<Output = Result<Option<NativeTransferRequest>>> + Send {
        async move {
            let request = self.request(Lookup::NativeTransfer { chain_id, from, id });
            match self.read(ctx, &request).await?.record {
                Some(Record::NativeTransfer(transfer)) => Ok(Some(transfer)),
                None => Ok(None),
                Some(_) => bail!("certified native transfer read returned a foreign record"),
            }
        }
    }

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

    /// Submits one transaction, returning the advisory [`Submission`] answer.
    /// Acceptance promises gossip and proposal attempts, never inclusion: the
    /// authoritative answer is the certified read of the variant's effect
    /// record.
    fn submit<E: Env>(
        &mut self,
        ctx: &E,
        tx: &SettlementTx,
    ) -> impl Future<Output = Result<Submission>> + Send;

    /// Submits one transaction with bounded retries.
    ///
    /// Delivery is not completion: the caller completes by polling a
    /// certified read of the variant's effect record. A rejection is
    /// effect-free and therefore indistinguishable from not-yet-included, so
    /// effect polls run until the effect appears or a bounded budget ends.
    fn deliver<E: Env>(
        &mut self,
        ctx: &E,
        tx: &SettlementTx,
    ) -> impl Future<Output = Result<()>> + Send {
        async move {
            for attempt in 0..SUBMIT_ATTEMPTS {
                match self.submit(ctx, tx).await {
                    Ok(submitted) => match submitted {
                        Submission::Accepted | Submission::Duplicate => {
                            return Ok(());
                        }
                        Submission::Oversized => {
                            bail!("the transaction exceeds the per-transaction wire bound")
                        }
                        Submission::Full if attempt + 1 < SUBMIT_ATTEMPTS => {}
                        Submission::Full => return Ok(()),
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

    /// The finalized payout identity authenticated at one recent checkpoint.
    fn payout_checkpoint<E: Env>(
        &mut self,
        ctx: &E,
    ) -> impl Future<Output = Result<crate::protocol::PayoutTip>> + Send {
        async move {
            let request = self.request(Lookup::PayoutHead);
            let verified = self.recent(ctx, &request).await?;
            match verified.record {
                Some(Record::PayoutHead(tip)) => Ok(tip),
                Some(_) => bail!("certified payout-head read returned a foreign record"),
                None => bail!("the chain has not committed a payout head yet"),
            }
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
                None => {
                    if let Some(tip) = verified.payout_tip
                        && tip.finalized.is_some_and(|latest| epoch <= latest)
                    {
                        bail!("the epoch anchor is retired")
                    }
                    Ok(None)
                }
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
                None => {
                    if let Some(tip) = verified.payout_tip
                        && tip.finalized.is_some_and(|latest| epoch <= latest)
                    {
                        bail!("the admission is retired")
                    }
                    Ok(None)
                }
            }
        }
    }

    /// The finalized payout head and claimed coverage at one certified chain snapshot.
    fn payout_status<E: Env>(
        &mut self,
        ctx: &E,
        index: u64,
    ) -> impl Future<Output = Result<PayoutStatus>> + Send {
        async move {
            let request = self.request(Lookup::Claimed { index });
            let verified = self.recent(ctx, &request).await?;
            Ok(PayoutStatus {
                head: verified
                    .payout_tip
                    .context("payout lookup omitted its certified head")?
                    .payouts,
                claimed: verified.claimed,
            })
        }
    }

    /// The custody record for one deposit id, or a proven exclusion.
    /// A conflicting record can resolve a staged request; absence alone cannot.
    fn deposit<E: Env>(
        &mut self,
        ctx: &E,
        id: Digest,
    ) -> impl Future<Output = Result<Option<DepositEvent>>> + Send {
        async move {
            let request = self.request(Lookup::Deposit { id });
            let verified = self.read(ctx, &request).await?;
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

    /// The latest accepted withdrawal receipt for `account`, or a proven absence.
    /// The receipt survives carriage and does not establish current queue membership.
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

    /// The refund for this account and settlement phase, if claimed.
    fn refund<E: Env>(
        &mut self,
        ctx: &E,
        account: Key,
        terminal: bool,
    ) -> impl Future<Output = Result<Option<ClaimPendingDepositResponse>>> + Send {
        async move {
            let request = self.request(Lookup::Refund { account, terminal });
            let verified = self.read(ctx, &request).await?;
            match verified.record {
                Some(Record::Refund(refund)) => Ok(Some(refund)),
                Some(_) => bail!("certified refund read returned a foreign record"),
                None => Ok(None),
            }
        }
    }
}

/// A coherent certificate-backed payout state. Claimed coverage proves consumption;
/// its absence requires a separate Append opening against this exact `head` before submission.
pub(crate) struct PayoutStatus {
    pub(crate) head: commonware_clearing::bajillion::logs::LogHead<Digest>,
    pub(crate) claimed: Option<commonware_clearing::bajillion::settlement::ClaimedRange>,
}

/// The remote settlement-chain backend: an RPC client of the validators'
/// certified query servers, used by wallet agents. Clearing reads bind the selected
/// deployment; native reads share the chain identity across deployments.
pub(crate) struct Client {
    scheme: Scheme,
    /// The chain genesis and ordinary validator proof-serving identities.
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
    /// validator query addresses, bound to the selected `deployment`.
    /// Call [`Self::registered`] to authenticate its operator configuration.
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

    /// Resolves this client's deployment against the certified registry.
    pub(crate) async fn registered<E: Env>(&mut self, ctx: &E) -> Result<RegistryEntry> {
        let chain_id = self.genesis.native.chain_id();
        self.registry_entry(ctx, chain_id, self.deployment)
            .await?
            .context("the selected deployment is not registered")
    }

    /// The chain genesis this client was built over: the validators'
    /// evidence-serving identities that route a request to native replicas.
    pub(crate) const fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// Fetches one piece of evidence for this deployment from the validators
    /// retaining native proof sources, asking each holder in ascending
    /// participant order until one serves it or declares it absent. Every
    /// other answer is routing advice, and the last one is returned when no
    /// holder serves.
    ///
    /// The caller authenticates each served opening against its trusted state root
    /// or paired log heads and the corresponding source range.
    ///
    /// The wallet routes through its own holder rotation (see the agent's
    /// evidence module), so this direct form serves the query tests only.
    #[cfg(test)]
    pub(crate) async fn evidence<E: Env>(
        &self,
        ctx: &E,
        lookup: EvidenceLookup,
    ) -> Result<EvidenceResponse> {
        let holders = self.genesis.holders()?;
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
        last.unwrap_or_else(|| bail!("no validator serves the requested evidence"))
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
    fn holders(&self) -> Result<Vec<SocketAddr>> {
        self.genesis.holders()
    }

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
    async fn submit<E: Env>(&mut self, ctx: &E, tx: &SettlementTx) -> Result<Submission> {
        let mut last = None;
        for attempt in 0..self.queries.len() {
            let address = self.queries[(self.primary + attempt) % self.queries.len()];
            match rpc::invoke(ctx, address, "query", METHOD_SUBMIT_TX, tx.encode()).await {
                Ok(body) => {
                    return Submission::decode_cfg(body, &()).context("decode advisory answer");
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

/// Admission is unresolved; its durable close remains eligible for a later attempt.
#[derive(Debug, thiserror::Error)]
#[error("close admission remains pending")]
pub(crate) struct AdmissionPending;

/// Space exact admission renewals to limit repeated gossip while ingress may evict pending work.
const ADMISSION_RESUBMIT_POLLS: usize = 25;

/// Submits an exactly certified close and observes admission or FIFO finalization.
///
/// A retained admission must name the exact batch and roots. After that record
/// retires, the finalized epoch boundary authenticates the unique certified close.
/// Successor certification can proceed while an admitted close remains challengeable.
pub(crate) async fn admit<C: Chain, E: Env>(
    ctx: &E,
    chain: &mut C,
    close: &CloseContext<Key, Digest>,
    request: crate::chain::tx::AdmitRequest,
) -> Result<()> {
    let committee = crate::protocol::committee()?;
    ensure!(
        request.deployment == chain.deployment()
            && close.deployment() == &request.deployment
            && close.payment().epoch() == request.epoch
            && close.committee() == &committee.commitment::<Sha256>()
            && request
                .header
                .verify::<Sha256, _>(close, &request.roots, request.withdrawal_total),
        "certified close does not match its admission context"
    );
    ensure!(
        crate::protocol::has_consensus_quorum(&request.certificate)
            && bls12381::Scheme::verifier(committee).verify(&request.header, &request.certificate),
        "close admission lacks a valid consensus-quorum certificate"
    );
    let epoch = request.epoch;
    let batch_id = request.header.batch_id::<Sha256>();
    let roots = request.roots;
    let tx = SettlementTx::Admit(request);
    for attempt in 0..SUBMIT_ATTEMPTS {
        let read = chain.request(Lookup::Admitted { epoch });
        if let Ok(verified) = chain.recent(ctx, &read).await {
            match verified.record {
                Some(Record::Admitted(admitted)) => {
                    ensure!(
                        admitted.batch_id == batch_id && admitted.roots == roots,
                        "the chain admitted a different close for this epoch"
                    );
                    return Ok(());
                }
                None => {
                    // Consensus quorum and the fixed committee's durable vote decisions
                    // make the certified Header unique for each deployment and epoch.
                    // FIFO finality confirms that close after its admission record retires.
                    if verified
                        .payout_tip
                        .and_then(|tip| tip.finalized)
                        .is_some_and(|finalized| epoch <= finalized)
                    {
                        return Ok(());
                    }
                }
                Some(_) => bail!("certified admission read returned a foreign record"),
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
        if attempt % ADMISSION_RESUBMIT_POLLS == 0 {
            // Delivery may be ambiguous; a stalled renewal must not stop certified effect polling.
            let submitted = commonware_macros::select! {
                result = chain.submit(ctx, &tx) => Some(result),
                _ = ctx.sleep(POLL * ADMISSION_RESUBMIT_POLLS as u32) => None,
            };
            if matches!(submitted, Some(Ok(Submission::Oversized))) {
                bail!("close admission exceeds the chain wire bound");
            }
        }
        ctx.sleep(POLL).await;
    }
    Err(AdmissionPending.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    struct SubmissionBackend {
        replies: std::collections::VecDeque<std::result::Result<Submission, &'static str>>,
        submissions: usize,
    }

    impl Chain for SubmissionBackend {
        fn holders(&self) -> Result<Vec<SocketAddr>> {
            unreachable!()
        }

        fn deployment(&self) -> Digest {
            crate::protocol::deployment()
        }

        async fn read<E: Env>(&mut self, _: &E, _: &ReadRequest) -> Result<Verified> {
            unreachable!()
        }

        async fn recent<E: Env>(&mut self, _: &E, _: &ReadRequest) -> Result<Verified> {
            unreachable!()
        }

        async fn submit<E: Env>(&mut self, _: &E, _: &SettlementTx) -> Result<Submission> {
            self.submissions += 1;
            self.replies
                .pop_front()
                .expect("unexpected submission")
                .map_err(anyhow::Error::msg)
        }
    }

    #[test]
    fn delivery_retries_transient_full_before_effect_polling() {
        deterministic::Runner::default().start(|context| async move {
            let mut chain = SubmissionBackend {
                replies: [
                    Ok(Submission::Full),
                    Ok(Submission::Full),
                    Ok(Submission::Accepted),
                ]
                .into(),
                submissions: 0,
            };
            let tx = SettlementTx::BeginHardFaultSettlement(
                crate::chain::tx::BeginHardFaultSettlementRequest {
                    deployment: chain.deployment(),
                },
            );
            chain.deliver(&context, &tx).await.unwrap();
            assert_eq!(chain.submissions, 3);
        });
    }

    #[test]
    fn delivery_keeps_oversized_and_transport_failures_terminal() {
        deterministic::Runner::default().start(|context| async move {
            for (replies, expected, message) in [
                (vec![Ok(Submission::Oversized)], 1, "wire bound"),
                (
                    vec![Err("transport unavailable"); SUBMIT_ATTEMPTS],
                    SUBMIT_ATTEMPTS,
                    "transport unavailable",
                ),
            ] {
                let mut chain = SubmissionBackend {
                    replies: replies.into(),
                    submissions: 0,
                };
                let tx = SettlementTx::BeginHardFaultSettlement(
                    crate::chain::tx::BeginHardFaultSettlementRequest {
                        deployment: chain.deployment(),
                    },
                );
                let error = chain.deliver(&context, &tx).await.unwrap_err();
                assert!(format!("{error:#}").contains(message));
                assert_eq!(chain.submissions, expected);
            }
        });
    }
}
