//! Durable, context-scoped payment authorization and authenticated outcome resolution.
//!
//! Ordinary payments sign from local accepted epoch state and a verified balance floor.
//! Every body binds the root of the wallet's terminal vector in the preceding epoch.
//! A submitted intent keeps its exact bytes until receipts, a usable corrective report, or
//! settlement resolve it. A usable report re-signs a cut epoch's intent in the successor
//! epoch against the reported endpoint, so at most one copy can settle.

use super::{
    Agent,
    evidence::{check_opening, unusable_head},
    store::{ContextCache, PaymentConclusion, PendingPayment, VerifiedAcceptance},
    wallet::{ReceiptEpoch, receipt_epoch, retired, settlement_status},
};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL, SUBMIT_ATTEMPTS},
        state::{AdmittedRootsResponse, FaultRecord, HardFaultReasonResponse, StatusRecord},
        tx::{ChallengeRequest, SettlementTx},
    },
    operator::rpc as operator_rpc,
    protocol::{Acceptance, Entry, Key, MAX_BATCH_SEND_ENTRIES, MAX_SENDS_PER_BATCH},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::{AckWitness, Challenge, ChallengeKind},
    commitment::{self, VectorKind, VectorRoot},
    payment::{PaymentContext, SendAuthorization, VECTOR_ACK_SIGNATURE_NAMESPACE, VectorSendBody},
    qmdb::{StateOpening, StateRoot},
    state::AccountChange,
    vector::{OutEntry, OutVector},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_parallel::Sequential;
use std::net::SocketAddr;

/// One send in a context-scoped pending batch.
struct StagedSend {
    authorization: SendAuthorization<Key, Digest>,
    entries: Vec<Entry>,
}

/// One complete ordered payer batch exposed to the operator only after durable staging.
struct StagedBatch {
    context: PaymentContext<Key, Digest>,
    sends: Vec<StagedSend>,
}

/// One concluded payment.
#[derive(Debug)]
pub(crate) enum PaymentOutcome {
    /// The operator accepted the send and its verified receipts are held.
    Accepted(Box<operator_rpc::AcceptedBatchResponse>),
    /// Finalized activity proves the exact signed body, but operator receipts are unavailable.
    CommittedUnheld {
        /// Epoch the send committed in.
        epoch: u64,
        /// Batch total the send debited.
        total: u64,
    },
}

/// How verified receipts and settlement resolve one staged batch.
enum PendingOutcome {
    /// No admitted outcome resolves the intent, so resubmit the exact bytes.
    Live(Box<StagedBatch>),
    /// The batch, or an authenticated prefix of it, concluded.
    Resolved {
        outcomes: Vec<PaymentOutcome>,
        /// A permanently excluded suffix remains durable and must be re-signed.
        restage_suffix: bool,
    },
    /// A usable corrective report concluded the prefix at or below its endpoint, and the rest
    /// is staged again in the successor epoch.
    Resigned {
        outcomes: Vec<PaymentOutcome>,
        staged: Box<StagedBatch>,
    },
}

/// What an admitted preceding epoch decides about the pending batch.
enum Predecessor {
    /// The preceding epoch is unadmitted or retired, or it ended at the batch's predecessor.
    Open,
    /// Carried superseded copies still need receipts or finality to conclude.
    Wait,
    /// No close can carry the batch. The carried copies concluded, and every other pending
    /// intent is replaceable.
    Settled(Vec<PaymentOutcome>),
}

impl Agent {
    /// Pays a canonical batch, retaining its exact ordered authorizations until resolved.
    pub(crate) async fn pay<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        entries: &[(usize, u64)],
    ) -> Result<PaymentOutcome> {
        let mut outcomes = self
            .pay_batch(ctx, chain, operator, &[entries.to_vec()])
            .await?;
        ensure!(
            outcomes.len() == 1,
            "single payment returned another batch size"
        );
        Ok(outcomes.remove(0))
    }

    /// Pays one bounded sequence of independently signed logical sends in one wallet cycle.
    pub(crate) async fn pay_batch<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        sends: &[Vec<(usize, u64)>],
    ) -> Result<Vec<PaymentOutcome>> {
        self.observe_withdrawal(ctx, chain).await?;
        ensure!(
            !sends.is_empty() && sends.len() <= MAX_SENDS_PER_BATCH,
            "payment batch exceeds its send bound"
        );
        ensure!(
            sends
                .iter()
                .try_fold(0_usize, |sum, entries| sum.checked_add(entries.len()))
                .is_some_and(|entries| entries <= MAX_BATCH_SEND_ENTRIES),
            "payment batch exceeds its aggregate entry bound"
        );
        let requested = sends
            .iter()
            .map(|entries| self.payment_entries(entries))
            .collect::<Result<Vec<_>>>()?;
        self.pay_requested(ctx, chain, operator, requested).await
    }

    /// Resumes the durably staged pending batch, when one exists.
    ///
    /// The exact staged bytes resubmit and adjudicate through the standard
    /// pipeline, so an interrupted run's in-flight payment concludes before
    /// any new intent is staged.
    pub(crate) async fn resume_pending_payment<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<Option<Vec<PaymentOutcome>>> {
        if self.pending_payments.is_empty() {
            return Ok(None);
        }
        let requested = self
            .pending_payments
            .iter()
            .map(|pending| Ok((pending.entries.clone(), entry_total(&pending.entries)?)))
            .collect::<Result<Vec<_>>>()?;
        self.pay_requested(ctx, chain, operator, requested)
            .await
            .map(Some)
    }

    async fn pay_requested<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        mut requested: Vec<(Vec<Entry>, u64)>,
    ) -> Result<Vec<PaymentOutcome>> {
        let mut completed = Vec::new();
        let mut staged = if self.pending_payments.is_empty() {
            self.stage(ctx, chain, operator, &requested).await?
        } else if self.pending_payments[0].replaceable {
            // Superseded copies of the excluded intents must be decided before they are
            // signed again.
            if !self.superseded.is_empty() {
                if let Predecessor::Settled(outcomes) =
                    self.decide_predecessor(ctx, chain, operator).await?
                {
                    requested.drain(..outcomes.len());
                    completed.extend(outcomes);
                    if self.pending_payments.is_empty() {
                        return Ok(completed);
                    }
                }
                ensure!(
                    self.superseded.is_empty(),
                    "the excluded payment waits for its earlier epoch to be decided"
                );
            }
            self.restage_excluded(ctx, chain, operator, &requested)
                .await?
        } else {
            ensure!(
                self.pending_payments.len() == requested.len()
                    && self
                        .pending_payments
                        .iter()
                        .zip(&requested)
                        .all(|(pending, (entries, _))| pending.entries == *entries),
                "another payment retry is pending"
            );
            self.staged_batch()?
        };

        let mut attempts = 1;
        loop {
            let response = match submit_staged(ctx, operator, &staged).await {
                Ok(response) => response,
                Err(error) => {
                    // Silence is never exclusion: the exact bytes stay staged until a receipt,
                    // a usable report, or settlement resolves them.
                    return match self
                        .resolve_pending(ctx, chain, operator, staged, None, None)
                        .await
                    {
                        Ok(PendingOutcome::Resolved {
                            outcomes,
                            restage_suffix: true,
                        }) => {
                            let resolved = outcomes.len();
                            completed.extend(outcomes);
                            requested.drain(..resolved);
                            staged = self
                                .restage_excluded(ctx, chain, operator, &requested)
                                .await?;
                            attempts = 1;
                            continue;
                        }
                        Ok(PendingOutcome::Resolved {
                            outcomes,
                            restage_suffix: false,
                        }) => {
                            completed.extend(outcomes);
                            return Ok(completed);
                        }
                        Ok(PendingOutcome::Resigned {
                            outcomes,
                            staged: resigned,
                        }) => {
                            let resolved = outcomes.len();
                            completed.extend(outcomes);
                            requested.drain(..resolved);
                            staged = *resigned;
                            attempts = 1;
                            continue;
                        }
                        Ok(PendingOutcome::Live(_)) => Err(error).context("submit payment"),
                        Err(unresolved) => Err(unresolved).context(format!(
                            "payment submission failed ({error:#}); outcome unresolved"
                        )),
                    };
                }
            };
            let resolution = match response {
                operator_rpc::AcceptSendsResponse::Accepted(accepted) => {
                    let acceptances = match Self::verify_accepted(&accepted, &staged) {
                        Ok(acceptances) => acceptances,
                        Err(error) => {
                            self.retain_noncanonical_acceptances(&accepted, &staged)?;
                            return Err(error)
                                .context("operator returned a malformed payment batch");
                        }
                    };
                    let indexed = acceptances.iter().enumerate().collect::<Vec<_>>();
                    self.store
                        .retain_indexed_payment_acceptances(&self.pending_payments, &indexed)
                        .context("retain returned operator receipt batch")?;
                    for (position, acceptance) in acceptances.into_iter().enumerate() {
                        self.pending_payments[position].acceptance = Some(acceptance);
                    }
                    self.resolve_pending(ctx, chain, operator, staged, Some(accepted), None)
                        .await?
                }
                operator_rpc::AcceptSendsResponse::Stale(stale) => {
                    ensure!(
                        stale.context.operator() == &self.operator,
                        "corrective context has an unexpected operator"
                    );

                    // The unsigned report releases the staged bytes only as far as receipts
                    // confirm it. Otherwise settlement of their epoch decides.
                    self.resolve_pending(ctx, chain, operator, staged, None, Some(stale))
                        .await?
                }
            };
            ensure!(
                matches!(
                    &resolution,
                    PendingOutcome::Resolved { .. } | PendingOutcome::Resigned { .. }
                ) || attempts < SUBMIT_ATTEMPTS,
                "the operator repeatedly rejected the unresolved payment"
            );
            attempts += 1;
            staged = match resolution {
                PendingOutcome::Live(staged) => {
                    ctx.sleep(POLL).await;
                    *staged
                }
                PendingOutcome::Resolved {
                    outcomes,
                    restage_suffix,
                } => {
                    let resolved = outcomes.len();
                    completed.extend(outcomes);
                    if !restage_suffix {
                        return Ok(completed);
                    }
                    requested.drain(..resolved);
                    attempts = 1;
                    self.restage_excluded(ctx, chain, operator, &requested)
                        .await?
                }
                PendingOutcome::Resigned {
                    outcomes,
                    staged: resigned,
                } => {
                    let resolved = outcomes.len();
                    completed.extend(outcomes);
                    requested.drain(..resolved);
                    attempts = 1;
                    *resigned
                }
            };
        }
    }

    async fn restage_excluded<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        requested: &[(Vec<Entry>, u64)],
    ) -> Result<StagedBatch> {
        ensure!(
            self.superseded.is_empty(),
            "the excluded payment waits for its earlier epoch to be decided"
        );
        match self.stage(ctx, chain, operator, requested).await {
            Ok(staged) => Ok(staged),
            Err(error)
                if !self.pending_payments.is_empty()
                    && self
                        .pending_payments
                        .iter()
                        .all(|payment| payment.replaceable) =>
            {
                let status = settlement_status(ctx, chain, self.deployment)
                    .await
                    .with_context(|| {
                        format!(
                            "settlement status unavailable while preserving excluded batch ({error:#})"
                        )
                    })?;
                if !status.hard_faulted {
                    return Err(error);
                }
                self.receipt_count = self
                    .store
                    .archive_replaceable_payments(&self.pending_payments, self.receipt_count)
                    .context("archive permanently excluded payment batch")?;
                self.pending_payments.clear();
                self.superseded.clear();
                self.cache = None;
                Err(error).context("payment batch was permanently excluded")
            }
            Err(error) => Err(error),
        }
    }

    /// Stages a fresh send: optimistically from local state under the cached context,
    /// or against one verified head read when no context is cached or the local floor
    /// cannot prove affordability.
    async fn stage<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        requested: &[(Vec<Entry>, u64)],
    ) -> Result<StagedBatch> {
        ensure!(
            self.pending_withdrawal.is_none(),
            "a withdrawal authorization is still active"
        );
        let total = requested.iter().try_fold(0_u64, |sum, (_, total)| {
            sum.checked_add(*total)
                .context("payment batch total overflow")
        })?;
        if let Some(cache) = self.cache.clone() {
            // The local view is a lower bound, so a shortfall is not proof of
            // unaffordability: funds from a deposit, or from an epoch the floor
            // predates, are invisible to it. Fall back to one head read, whose
            // live-balance precheck refuses a truly unaffordable send before staging
            // and whose verified opening re-anchors the floor.
            if self.spendable(&cache)? >= total {
                return self.stage_local(&cache, requested);
            }
        }
        self.stage_against_head(ctx, chain, operator, requested, total)
            .await
    }

    /// The wallet's lower bound on its spendable balance, from local SQL alone.
    ///
    /// The floor is the Merkle-verified opening cached with the signing context, whose
    /// balance covers every close before the floor epoch. On top of it the view adds
    /// only the wallet's own verified knowledge: held incoming credits from the floor
    /// epoch onward (a close commits its own epoch's payments, so the floor cannot
    /// contain them) minus the retained payment deltas from those epochs.
    /// Everything it leaves out moves the true balance up, never down: unintaken
    /// incoming credits and applied deposits only add, and a withdrawal invalidates the
    /// cache before its request can reach the operator. A precheck against this view
    /// therefore never stages a send an honest operator rejects as unaffordable.
    fn spendable(&self, cache: &ContextCache) -> Result<u64> {
        let opening = self
            .store
            .recovery_opening(&cache.root)?
            .context("cached context floor opening is missing")?;
        self.lower_bound(opening.balance.get(), cache.epoch)
    }

    /// The lower bound [`Self::spendable`] computes from one verified floor: the
    /// wallet's row in a certified root covering every close before `epoch`.
    fn lower_bound(&self, floor: u64, epoch: u64) -> Result<u64> {
        let funds = floor
            .checked_add(self.store.credits_since(epoch)?)
            .context("local balance view overflow")?;
        Ok(funds.saturating_sub(self.store.debits_since(epoch)?))
    }

    /// Signs the requested deltas against the wallet's durable prior vector state under
    /// `context`: the merged cumulative vector's root at the next batch sequence, the
    /// wallet's own successor debit endpoint, and `predecessor`.
    fn sign_payments(
        &self,
        context: &PaymentContext<Key, Digest>,
        predecessor: VectorRoot<Digest>,
        requested: &[(Vec<Entry>, u64)],
    ) -> Result<Vec<SendAuthorization<Key, Digest>>> {
        let prior = self.store.vector_state(context)?;
        let (mut seq, mut debit, mut prior_entries) = match prior {
            Some(state) => (state.seq, state.cumulative_debit, state.entries),
            None => (0, 0, Vec::new()),
        };
        let mut authorizations = Vec::with_capacity(requested.len());
        for (entries, total) in requested {
            seq = seq.checked_add(1).context("batch sequence overflow")?;
            debit = debit
                .checked_add(*total)
                .context("payment endpoint overflow")?;
            let merged = merge_entries(prior_entries, entries)?;
            let vector = OutVector::new(context.epoch(), self.account(), merged)
                .context("assemble signed out vector")?;
            let body = VectorSendBody::new(
                context,
                self.account(),
                seq,
                debit,
                vector
                    .root::<Sha256, Digest>()
                    .context("commit signed out vector")?,
            );
            prior_entries = vector.entries().to_vec();
            authorizations.push(SendAuthorization::sign(
                body,
                predecessor,
                self.wallet.signer(),
            ));
        }
        Ok(authorizations)
    }

    /// Signs and durably stages a send from local state alone: the cached context, the
    /// wallet's own authoritative endpoint and vector state, and the cached floor's
    /// retained opening as the staged recovery evidence.
    fn stage_local(
        &mut self,
        cache: &ContextCache,
        requested: &[(Vec<Entry>, u64)],
    ) -> Result<StagedBatch> {
        self.stage_under(cache.context.clone(), cache.root, requested)
    }

    /// Validates and canonically orders the requested batch entries with their checked total.
    fn payment_entries(&self, entries: &[(usize, u64)]) -> Result<(Vec<Entry>, u64)> {
        let mut requested = Vec::with_capacity(entries.len());
        for (receiver, amount) in entries {
            let receiver = self.receivers[receiver % self.receivers.len()].key.clone();
            ensure!(
                receiver != self.account(),
                "self-payments are omitted from this operator"
            );
            ensure!(*amount > 0, "payment amount must be positive");
            requested.push(Entry {
                recipient: receiver,
                amount: *amount,
            });
        }
        requested.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        ensure!(
            requested
                .windows(2)
                .all(|pair| pair[0].recipient < pair[1].recipient),
            "batch entries name unique receivers"
        );
        let total = entry_total(&requested)?;
        Ok((requested, total))
    }

    /// Resolves the staged authorization batch against receipts, a corrective report, its
    /// registration, and admitted activity. Admission fixes the close, so exclusion is permanent.
    /// Inclusion without a receipt requires finality before the wallet records a completed
    /// payment. Any supplied acceptance has already passed exact-message and receipt
    /// verification.
    ///
    /// # Stale replies
    ///
    /// An operator that has cut epoch `e` answers a send signed under `e` with `Stale`. The
    /// staged authorization is a valid payer signature over a cumulative endpoint in `e`, and the
    /// operator holds it. `Stale` is unsigned, so it does not bind the operator to leaving that
    /// endpoint out of `e`: a malicious operator can include it in `e`'s close and still answer
    /// `Stale`. A fresh authorization of the same payment under `e + 1` would be an independent
    /// debit, so re-signing on the reply alone would let such an operator settle both and make
    /// the payer pay twice.
    ///
    /// Every body therefore also signs its predecessor: the root of the payer's terminal vector
    /// in the preceding epoch, or the empty vector root when it had none there. `Stale` reports
    /// the payer's endpoint in `e`, frozen at the cut, and the root that bodies of the live epoch
    /// must bind. A report is usable when its vector is empty and the wallet holds no receipt in
    /// `e`, or when the wallet holds or fetches a verified receipt for its own body at the
    /// reported endpoint and that endpoint is at or above every receipt it holds. The wallet then
    /// includes the bodies at or below the endpoint with their receipts and re-signs the rest
    /// under `e + 1` right away, bound to the reported root. It keeps only the first usable report
    /// per epoch, and without one it waits for `e` to be admitted.
    ///
    /// Validators check `e + 1` only after `e` is admitted, and they read each payer's
    /// predecessor from the account rows of `e`'s admitted close. A body whose signed predecessor
    /// differs fails payer signature verification, and every certificate includes an honest
    /// signer, so no certified close for `e + 1` can carry it. A re-signed payment settles only if
    /// `e` ended exactly at the reported root, and that root excludes the original.
    ///
    /// An operator that reports one endpoint and carries another in `e` gains nothing. The
    /// re-signed bodies can no longer be carried. If the operator acknowledged any of them, a
    /// certified close for `e + 1` must omit them, and the acknowledgment convicts it with
    /// `HigherAckDebit` or `HigherAckEntry`. If it certifies no close for `e + 1` at all, that
    /// registration expires and faults the deployment. Once `e`'s admission shows the re-signed
    /// bodies dead, the wallet concludes the carried originals, keeps every receipt it holds for
    /// a dead body as evidence, and signs the remaining intents again. Its challenge watcher
    /// proves `HigherAckDebit` from those receipts while `e + 1`'s admitted close can be
    /// challenged, and prunes them once it cannot.
    ///
    /// The binding reaches back one epoch only. A body in `e + 2` pins the payer's terminal in
    /// `e + 1`, which says nothing about `e`. If a re-signed payment also misses `e + 1`, signing
    /// it again under `e + 2` could settle beside an original that `e` carries, whatever `e + 1`
    /// reports. So the wallet signs a payment again only after every earlier epoch in which it
    /// signed that payment, other than the immediately preceding one, is decided: admitted, or
    /// dead because its own preceding epoch was admitted at another root.
    ///
    /// No response is not exclusion. The operator may have accepted the send and lost the reply,
    /// so the wallet resubmits the exact bytes and keeps waiting for a receipt, a usable report,
    /// or `e`'s admission. Admission fixes `e`'s activity: an excluded endpoint concludes with no
    /// included prefix and restages under the successor, an included endpoint completes through
    /// its receipts or finality, and invalidation restages as well.
    async fn resolve_pending<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        staged: StagedBatch,
        accepted: Option<Vec<operator_rpc::AcceptedBatchResponse>>,
        report: Option<operator_rpc::StaleResponse>,
    ) -> Result<PendingOutcome> {
        // A receipted batch without superseded copies resolves through its receipts and its own
        // epoch, so it skips this read.
        if accepted.is_none() || !self.superseded.is_empty() {
            match self.decide_predecessor(ctx, chain, operator).await? {
                Predecessor::Open => {}
                Predecessor::Wait => return Ok(PendingOutcome::Live(Box::new(staged))),
                Predecessor::Settled(outcomes) => {
                    return Ok(PendingOutcome::Resolved {
                        restage_suffix: !self.pending_payments.is_empty(),
                        outcomes,
                    });
                }
            }
        }
        let context = &staged.context;
        let (range, descriptor_finalized) =
            match receipt_epoch(ctx, chain, self.deployment, context).await? {
                ReceiptEpoch::Invalidated => {
                    return self.conclude_staged_prefix(0, false);
                }
                ReceiptEpoch::Unresolved => return Ok(PendingOutcome::Live(Box::new(staged))),
                ReceiptEpoch::Live(None) => {
                    return match (accepted, report) {
                        (Some(accepted), _) => Ok(PendingOutcome::Resolved {
                            outcomes: self.record_payments(accepted)?,
                            restage_suffix: false,
                        }),
                        (None, Some(report)) => {
                            self.resign(ctx, chain, operator, staged, report).await
                        }
                        (None, None) => Ok(PendingOutcome::Live(Box::new(staged))),
                    };
                }
                ReceiptEpoch::Live(Some(admitted)) | ReceiptEpoch::Faulted(admitted) => {
                    (admitted.activity_range(), false)
                }
                ReceiptEpoch::Finalized(admitted) => (admitted.activity_range(), true),
                // The finalized close decides the batch from its retained rows until the epoch
                // after its successor finalizes. A wallet away for longer concludes only with
                // receipts, and without them the batch stays pending for good. That retention
                // is a deliberate bound, not a liveness guarantee.
                ReceiptEpoch::Retired => {
                    self.fetch_missing_acceptances(ctx, operator, &staged.sends)
                        .await?;
                    ensure!(
                        self.pending_payments
                            .iter()
                            .all(|payment| payment.acceptance.is_some()),
                        "finalized payment batch has no saved signed receipt coverage"
                    );
                    let outcomes = self.conclude_staged_prefix(staged.sends.len(), false)?;
                    self.cache = None;
                    return Ok(outcomes);
                }
            };
        let account = self.account();
        let lookup = self
            .holders
            .committed_account_at(ctx, chain, context.epoch(), &range, &account)
            .await?;
        let (_, activity) = lookup
            .resolve::<Sha256>(&range, &account)
            .context("verify admitted payer activity")?;
        let durable_base = self.store.vector_state(context)?;
        let included = match activity.filter(|activity| activity.has_outgoing()) {
            None => {
                ensure!(
                    durable_base.is_none(),
                    "committed activity omits the durable pre-batch vector"
                );
                0
            }
            Some(activity) => {
                if let Some((position, _)) =
                    staged.sends.iter().enumerate().find(|(_, send)| {
                        activity.matches_outgoing(context, send.authorization.body())
                    })
                {
                    position + 1
                } else {
                    let prior = durable_base
                        .context("committed activity names an unknown authorization")?;
                    let vector = OutVector::new(context.epoch(), account.clone(), prior.entries)?;
                    let body = VectorSendBody::new(
                        context,
                        account,
                        prior.seq,
                        prior.cumulative_debit,
                        vector.root::<Sha256, Digest>()?,
                    );
                    ensure!(
                        activity.matches_outgoing(context, &body),
                        "committed activity names an unknown authorization"
                    );
                    0
                }
            }
        };

        let highest_held = self
            .pending_payments
            .iter()
            .rposition(|payment| payment.acceptance.is_some())
            .map_or(0, |position| position + 1);
        ensure!(
            highest_held <= included || descriptor_finalized,
            "operator receipt conflicts with the admitted payer terminal"
        );

        // Activity is immutable, but evidence retrieval can cross finalization or a fault.
        // Only a fresh live verdict can authorize a newly acquired preconfirmation.
        let finalized = if descriptor_finalized {
            true
        } else {
            match receipt_epoch(ctx, chain, self.deployment, context).await? {
                ReceiptEpoch::Finalized(_) | ReceiptEpoch::Retired => true,
                ReceiptEpoch::Live(_)
                    if self.pending_payments[..included]
                        .iter()
                        .all(|payment| payment.acceptance.is_some()) =>
                {
                    false
                }
                ReceiptEpoch::Invalidated => return self.conclude_staged_prefix(0, false),
                _ => anyhow::bail!(
                    "the staged epoch has not finalized, so its commitment is not yet decidable"
                ),
            }
        };

        self.fetch_missing_acceptances(ctx, operator, &staged.sends[..included])
            .await?;
        let complete_receipts = self.pending_payments[..included]
            .iter()
            .all(|payment| payment.acceptance.is_some());
        if !complete_receipts && !finalized {
            return Ok(PendingOutcome::Live(Box::new(staged)));
        }
        let outcome = self.conclude_staged_prefix(included, finalized)?;
        if finalized {
            self.cache = None;
            if let Ok(status) = settlement_status(ctx, chain, self.deployment).await
                && let Ok(opening) = self
                    .holders
                    .validator_opening(ctx, chain, &self.account(), &status)
                    .await
            {
                self.retain_head(&status.state_root, &opening)?;
            }
        }
        Ok(outcome)
    }

    /// Decides the pending batch against its admitted preceding epoch.
    ///
    /// Every pending body binds one predecessor. A preceding close that ended at that root
    /// proves no superseded copy was carried, so the copies are archived. A close that ended at
    /// another root leaves no close able to carry any pending body: the superseded copies at or
    /// below its terminal settle their intents, and every other intent becomes replaceable. A
    /// receipt held for a pending body stays durable with it as evidence against the successor
    /// close.
    async fn decide_predecessor<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<Predecessor> {
        let Some(first) = self.pending_payments.first() else {
            return Ok(Predecessor::Open);
        };
        let predecessor = first.authorization.predecessor();
        let Some(previous) = first.authorization.body().epoch().checked_sub(1) else {
            return Ok(Predecessor::Open);
        };

        // An unadmitted predecessor decides nothing. The chain keeps an admission until the
        // epoch after the batch's own epoch finalizes, so only a wallet away for longer finds it
        // retired, and then it decides nothing either. Superseded copies stay undecided, which
        // blocks every re-sign of their intents. That retention is a deliberate bound, not a
        // liveness guarantee. Any other failed read is returned.
        let admitted = match chain.admitted(ctx, previous).await {
            Ok(admitted) => admitted,
            Err(error) => {
                let status = chain.recent_status(ctx).await?;
                ensure!(
                    status.deployment == self.deployment,
                    "settlement status has an unexpected deployment"
                );
                if !retired(&status, previous) {
                    return Err(error.context("read the admitted predecessor"));
                }
                None
            }
        };
        let Some(admitted) = admitted else {
            return Ok(Predecessor::Open);
        };
        let range = admitted.activity_range();
        let account = self.account();
        let lookup = self
            .holders
            .committed_account_at(ctx, chain, previous, &range, &account)
            .await?;
        let (_, activity) = lookup
            .resolve::<Sha256>(&range, &account)
            .context("verify admitted predecessor activity")?;
        let root = activity.as_ref().map_or_else(
            || commitment::empty_root::<Sha256>(VectorKind::OutEntry),
            AccountChange::send_root,
        );
        if root == predecessor {
            if !self.superseded.is_empty() {
                self.store
                    .drop_superseded(&self.pending_payments, &self.superseded)
                    .context("archive uncarried superseded copies")?;
                self.superseded.clear();
            }
            return Ok(Predecessor::Open);
        }

        // No close can carry a pending body. A receipt held for one proves a mismatch against
        // the successor close and stays durable with its body, so it never blocks the decision.
        let carried = match activity.filter(AccountChange::has_outgoing) {
            None => 0,
            Some(activity) => {
                match self.superseded.iter().position(|copy| {
                    activity
                        .matches_outgoing(&authorization_context(copy, &self.operator), copy.body())
                }) {
                    Some(position) => position + 1,
                    None => {
                        ensure!(
                            self.superseded
                                .iter()
                                .all(|copy| copy.body().seq() > activity.terminal_seq()),
                            "the admitted predecessor terminal names an unknown authorization"
                        );
                        0
                    }
                }
            }
        };

        // Carried copies conclude through their receipts, or through finality without them.
        let mut conclusions = Vec::with_capacity(carried);
        let mut outcomes = Vec::with_capacity(carried);
        for position in 0..carried {
            let copy = self.superseded[position].clone();
            let entries = self.pending_payments[position].entries.clone();
            let send = StagedSend {
                authorization: copy.clone(),
                entries,
            };
            let response = operator_rpc::accepted_batch(
                ctx,
                operator,
                operator_rpc::AcceptSendRequest {
                    authorization: send.authorization.clone(),
                    entries: send.entries.clone(),
                },
            )
            .await
            .ok()
            .flatten();
            let one = StagedBatch {
                context: authorization_context(&copy, &self.operator),
                sends: vec![send],
            };
            let verified = response.and_then(|response| {
                let mut verified =
                    Self::verify_accepted(std::slice::from_ref(&response), &one).ok()?;
                Some((verified.remove(0), response))
            });
            match verified {
                Some((verified, response)) => {
                    conclusions.push(PaymentConclusion::Accepted(Box::new(verified)));
                    outcomes.push(PaymentOutcome::Accepted(Box::new(response)));
                }
                None if admitted.finalized => {
                    conclusions.push(PaymentConclusion::Retired);
                    outcomes.push(PaymentOutcome::CommittedUnheld {
                        epoch: previous,
                        total: entry_total(&one.sends[0].entries)?,
                    });
                }
                None => return Ok(Predecessor::Wait),
            }
        }
        self.receipt_count = self
            .store
            .settle_superseded(
                &self.pending_payments,
                &self.superseded,
                &conclusions,
                self.receipt_count,
            )
            .context("settle carried superseded copies")?;
        self.pending_payments.drain(..carried);
        for payment in &mut self.pending_payments {
            payment.replaceable = true;
        }
        self.superseded.clear();
        self.cache = None;
        Ok(Predecessor::Settled(outcomes))
    }

    /// Re-signs the batch into the successor epoch against a usable corrective report.
    ///
    /// The bodies at or below the reported endpoint conclude with their receipts. The rest are
    /// signed again under the successor's verified context, bound to the reported root, and
    /// their originals stay durable as undecided superseded copies. An unusable report, or a
    /// head that names another epoch than the successor, leaves the exact bytes staged. An active
    /// withdrawal authorization refuses a re-sign and leaves them staged as well.
    async fn resign<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        staged: StagedBatch,
        report: operator_rpc::StaleResponse,
    ) -> Result<PendingOutcome> {
        let Some(included) = self.usable(ctx, operator, &staged, &report).await? else {
            return Ok(PendingOutcome::Live(Box::new(staged)));
        };
        if included == self.pending_payments.len() {
            return self.conclude_staged_prefix(included, false);
        }
        ensure!(
            self.pending_withdrawal.is_none(),
            "a withdrawal authorization is still active"
        );
        let requested = self.pending_payments[included..]
            .iter()
            .map(|payment| Ok((payment.entries.clone(), entry_total(&payment.entries)?)))
            .collect::<Result<Vec<_>>>()?;
        let total = requested.iter().try_fold(0_u64, |sum, (_, total)| {
            sum.checked_add(*total)
                .context("payment batch total overflow")
        })?;
        let successor = staged
            .context
            .epoch()
            .checked_add(1)
            .context("epoch overflow")?;
        let Ok((context, root)) = self.head_at(ctx, chain, operator, successor, total).await else {
            return Ok(PendingOutcome::Live(Box::new(staged)));
        };
        let authorizations = self.sign_payments(&context, report.predecessor, &requested)?;
        let replacement = authorizations
            .into_iter()
            .zip(requested)
            .map(|(authorization, (entries, _))| PendingPayment {
                authorization,
                entries,
                recovery_root: root,
                acceptance: None,
                replaceable: false,
            })
            .collect::<Vec<_>>();
        let receipts = self.pending_payments[..included]
            .iter()
            .map(|payment| {
                payment
                    .acceptance
                    .clone()
                    .context("reported prefix has no verified receipt")
            })
            .collect::<Result<Vec<_>>>()?;
        self.receipt_count = self
            .store
            .resign(
                &self.pending_payments,
                &receipts,
                &replacement,
                self.receipt_count,
            )
            .context("re-sign reported payment suffix")?;
        let outcomes = self.pending_payments[..included]
            .iter()
            .zip(&receipts)
            .map(|(payment, acceptance)| {
                Ok(PaymentOutcome::Accepted(Box::new(accepted_response(
                    payment, acceptance,
                )?)))
            })
            .collect::<Result<Vec<_>>>()?;
        self.superseded = self.pending_payments[included..]
            .iter()
            .map(|payment| payment.authorization.clone())
            .collect();
        self.pending_payments = replacement;
        Ok(PendingOutcome::Resigned {
            outcomes,
            staged: Box::new(self.staged_batch()?),
        })
    }

    /// Returns how many staged bodies lie at or below a usable report's endpoint.
    ///
    /// The report must describe the staged epoch while its successor is live, and every
    /// earlier copy of the staged intents must be decided. An empty endpoint is usable only
    /// while the wallet holds no receipt in the epoch. A nonempty one must be at or above every
    /// receipt the wallet holds and must name one of the wallet's own bodies, whose receipt the
    /// wallet holds or fetches together with every receipt below it.
    async fn usable<E: Env>(
        &mut self,
        ctx: &E,
        operator: SocketAddr,
        staged: &StagedBatch,
        report: &operator_rpc::StaleResponse,
    ) -> Result<Option<usize>> {
        let epoch = staged.context.epoch();
        if report.epoch != epoch
            || epoch.checked_add(1) != Some(report.context.epoch())
            || !self.superseded.is_empty()
        {
            return Ok(None);
        }

        // The endpoint must be a feasible cumulative vector whose root the successor requires.
        let Ok(vector) = OutVector::new(epoch, self.account(), report.entries.clone()) else {
            return Ok(None);
        };
        let root = vector
            .root::<Sha256, Digest>()
            .context("commit reported out vector")?;
        if root != report.predecessor
            || vector.totals().ok().map(|(debit, _)| debit) != Some(report.cumulative_debit)
            || (report.seq == 0) != report.entries.is_empty()
        {
            return Ok(None);
        }

        // Receipts the wallet holds in this epoch: its concluded endpoint and any staged
        // receipts.
        let base = self.store.vector_state(&staged.context)?;
        let concluded = base.as_ref().map_or(0, |state| state.seq);
        let held = self
            .pending_payments
            .iter()
            .filter(|payment| payment.acceptance.is_some())
            .map(|payment| payment.authorization.body().seq())
            .max()
            .unwrap_or(0)
            .max(concluded);
        if report.seq < held {
            return Ok(None);
        }
        if report.seq == 0 || report.seq == concluded {
            let expected = base.map(|state| state.entries).unwrap_or_default();
            return Ok((report.entries == expected).then_some(0));
        }
        let Some(position) = report
            .seq
            .checked_sub(concluded)
            .and_then(|offset| offset.checked_sub(1))
            .and_then(|position| usize::try_from(position).ok())
            .filter(|position| *position < staged.sends.len())
        else {
            return Ok(None);
        };
        let body = staged.sends[position].authorization.body();
        if body.send_root() != root || body.cumulative_debit() != report.cumulative_debit {
            return Ok(None);
        }
        self.fetch_missing_acceptances(ctx, operator, &staged.sends[..=position])
            .await?;
        Ok(self.pending_payments[..=position]
            .iter()
            .all(|payment| payment.acceptance.is_some())
            .then_some(position + 1))
    }

    async fn fetch_missing_acceptances<E: Env>(
        &mut self,
        ctx: &E,
        operator: SocketAddr,
        sends: &[StagedSend],
    ) -> Result<()> {
        for (position, send) in sends.iter().enumerate() {
            if self.pending_payments[position].acceptance.is_some() {
                continue;
            }
            let Some(response) = operator_rpc::accepted_batch(
                ctx,
                operator,
                operator_rpc::AcceptSendRequest {
                    authorization: send.authorization.clone(),
                    entries: send.entries.clone(),
                },
            )
            .await
            .ok()
            .flatten() else {
                continue;
            };
            let one = StagedBatch {
                context: authorization_context(&send.authorization, &self.operator),
                sends: vec![StagedSend {
                    authorization: send.authorization.clone(),
                    entries: send.entries.clone(),
                }],
            };
            let mut verified = Self::verify_accepted(std::slice::from_ref(&response), &one)?;
            let verified = verified.remove(0);
            self.store
                .retain_payment_acceptance(&self.pending_payments[position], &verified)
                .context("retain recovered operator receipts")?;
            self.pending_payments[position].acceptance = Some(verified);
        }
        Ok(())
    }

    fn conclude_staged_prefix(
        &mut self,
        included: usize,
        finalized: bool,
    ) -> Result<PendingOutcome> {
        ensure!(
            included <= self.pending_payments.len(),
            "included prefix exceeds the pending batch"
        );
        let conclusions = self.pending_payments[..included]
            .iter()
            .map(|payment| match &payment.acceptance {
                Some(acceptance) => PaymentConclusion::Accepted(Box::new(acceptance.clone())),
                None if finalized => PaymentConclusion::Retired,
                None => unreachable!("non-final included prefix requires receipt coverage"),
            })
            .collect::<Vec<_>>();
        self.receipt_count = self
            .store
            .conclude_payment_prefix(
                &self.pending_payments,
                &conclusions,
                self.receipt_count,
                true,
            )
            .context("conclude pending payment prefix")?;
        let outcomes = self.pending_payments[..included]
            .iter()
            .map(|payment| match &payment.acceptance {
                Some(acceptance) => Ok(PaymentOutcome::Accepted(Box::new(accepted_response(
                    payment, acceptance,
                )?))),
                None => Ok(PaymentOutcome::CommittedUnheld {
                    epoch: payment.authorization.body().epoch(),
                    total: entry_total(&payment.entries)?,
                }),
            })
            .collect::<Result<Vec<_>>>()?;
        self.pending_payments.drain(..included);
        if !self.superseded.is_empty() {
            self.superseded.drain(..included);
        }
        for payment in &mut self.pending_payments {
            payment.replaceable = true;
        }
        let restage_suffix = !self.pending_payments.is_empty();
        self.cache = None;
        Ok(PendingOutcome::Resolved {
            outcomes,
            restage_suffix,
        })
    }

    /// Verifies a payment context and its authenticated balance floor.
    ///
    /// The floor epoch lies between the first unfinalized epoch and the
    /// context's epoch. At the first unfinalized epoch the floor root is the
    /// chain's finalized state root. Above it, the floor root is the successor
    /// root of the admitted close just below the floor epoch, so a successor
    /// context never needs its own predecessor admitted.
    pub(super) async fn verify_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        head: &operator_rpc::PaymentHeadResponse,
        status: &StatusRecord,
    ) -> Result<()> {
        ensure!(
            head.context.deployment() == &self.deployment
                && head.context.payment().operator() == &self.operator
                && head.context.verify_anchor::<Sha256>(),
            "payment context is not bound to this deployment and operator"
        );
        self.check_withdrawal_floor(status)?;
        let first = floor_epoch(status)?;
        let floor = head.floor_epoch;
        ensure!(
            first <= floor && floor <= head.context.payment().epoch(),
            "payer floor epoch lies outside the unfinalized epochs up to its context"
        );
        if floor == first {
            ensure!(
                status.state_root == head.root,
                "payer opening is not the exact settlement head"
            );
        } else {
            ensure!(
                !status.hard_faulted,
                "settlement is permanently hard-faulted"
            );
            let admitted = chain
                .admitted(ctx, floor - 1)
                .await?
                .context("payer floor close has not been admitted")?;
            ensure!(
                admitted.roots.successor == head.root,
                "payer opening differs from its admitted floor close"
            );
        }
        self.retain_head(&head.root, &head.opening)?;
        self.cache_signing(head.context.payment(), &head.root, floor)
    }

    /// Retains a Current membership proof for custody recovery at its exact root.
    pub(super) fn retain_head(
        &mut self,
        root: &StateRoot<Digest>,
        opening: &StateOpening<Key, Digest>,
    ) -> Result<()> {
        check_opening(opening, root, &self.account())?;
        self.store
            .retain_recovery_opening(root, opening)
            .context("durably retain payer state opening")?;
        Ok(())
    }

    /// Re-anchors the optimistic signing state on a verified live head: `context`
    /// becomes the cached signing context and the opening retained at `root` its
    /// affordability floor.
    ///
    /// A withdrawal in flight suppresses the refresh, because it reduces the live
    /// balance before any served predecessor root can show it, and a floor cached in
    /// that window would overstate spendable balance.
    fn cache_signing(
        &mut self,
        context: &PaymentContext<Key, Digest>,
        root: &StateRoot<Digest>,
        epoch: u64,
    ) -> Result<()> {
        if self.pending_withdrawal.is_some() {
            return self.store.check_signing_context(context);
        }
        self.store
            .cache_context(context, root, epoch)
            .context("durably cache signing context")?;
        self.cache = Some(ContextCache {
            context: context.clone(),
            root: *root,
            epoch,
        });
        Ok(())
    }

    /// Reads the payer head, verifies affordability against the live balance, and
    /// durably stages a fresh send.
    ///
    /// This is the fallback off the optimistic hot path: it runs for a wallet with no
    /// cached context (a fresh wallet, or one invalidated by a withdrawal) and for a
    /// local floor that cannot prove affordability. The verified head refreshes the
    /// cached floor and the context used for the next authorization.
    ///
    /// The operator's head is the fast path. When it is unreachable or unusable, the
    /// signing context is the chain's certified registration and the affordability
    /// floor is the validators' opening at the finalized or admitted predecessor root.
    /// The operator only needs to accept the send.
    async fn stage_against_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        requested: &[(Vec<Entry>, u64)],
        total: u64,
    ) -> Result<StagedBatch> {
        let (context, root) = self.head(ctx, chain, operator, total).await?;
        self.stage_under(context, root, requested)
    }

    /// Reads a verified head that covers `total` and re-anchors the signing floor on it,
    /// returning its context and floor root.
    pub(crate) async fn head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        total: u64,
    ) -> Result<(PaymentContext<Key, Digest>, StateRoot<Digest>)> {
        let operator_error =
            match operator_head(ctx, operator, self.account(), &self.operator).await {
                Ok(head) => {
                    let status = staging_status(ctx, chain, self.deployment).await?;
                    match self.stage_head(ctx, chain, &head, &status, total).await {
                        Ok(()) => return Ok((head.context.payment().clone(), head.root)),
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };
        self.stage_chain_head(ctx, chain, total)
            .await
            .map_err(|error| unusable_head(operator_error, error))
    }

    /// Reads a verified head whose context names `epoch`.
    async fn head_at<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        epoch: u64,
        total: u64,
    ) -> Result<(PaymentContext<Key, Digest>, StateRoot<Digest>)> {
        let (context, root) = self.head(ctx, chain, operator, total).await?;
        ensure!(
            context.epoch() == epoch,
            "the verified head names epoch {} instead of {epoch}",
            context.epoch()
        );
        Ok((context, root))
    }

    /// Signs and durably stages a fresh send under `context`, with the opening
    /// retained at `root` as its recovery evidence.
    ///
    /// Every staged body binds the root of the wallet's terminal in the preceding epoch. The
    /// pending batch is empty or excluded here, so the wallet's concluded vector there is that
    /// terminal.
    fn stage_under(
        &mut self,
        context: PaymentContext<Key, Digest>,
        root: StateRoot<Digest>,
        requested: &[(Vec<Entry>, u64)],
    ) -> Result<StagedBatch> {
        let predecessor = self.store.predecessor(context.epoch())?;
        let authorizations = self.sign_payments(&context, predecessor, requested)?;
        let pending = authorizations
            .into_iter()
            .zip(requested)
            .map(|(authorization, (entries, _))| PendingPayment {
                authorization,
                entries: entries.clone(),
                recovery_root: root,
                acceptance: None,
                replaceable: false,
            })
            .collect::<Vec<_>>();
        let previous_debit = pending[0]
            .authorization
            .body()
            .cumulative_debit()
            .checked_sub(requested[0].1)
            .context("payment delta exceeds epoch debit")?;
        if self.pending_payments.is_empty() {
            self.store
                .stage_payments(&pending, previous_debit)
                .context("durably stage payment batch")?;
        } else {
            ensure!(
                self.pending_payments
                    .iter()
                    .all(|payment| payment.replaceable),
                "another payment batch remains ambiguous"
            );
            self.receipt_count = self
                .store
                .replace_payment_suffix(
                    &self.pending_payments,
                    &pending,
                    previous_debit,
                    self.receipt_count,
                )
                .context("replace excluded payment suffix")?;
        }
        self.pending_payments = pending;
        self.staged_batch()
    }

    fn staged_batch(&self) -> Result<StagedBatch> {
        let first = self
            .pending_payments
            .first()
            .context("pending payment batch is empty")?;
        ensure!(
            !first.replaceable
                && self
                    .pending_payments
                    .iter()
                    .all(|payment| !payment.replaceable),
            "excluded payment suffix has not been re-signed"
        );
        self.store
            .recovery_opening(&first.recovery_root)?
            .context("pending payment recovery opening is missing")?;
        Ok(StagedBatch {
            context: authorization_context(&first.authorization, &self.operator),
            sends: self
                .pending_payments
                .iter()
                .map(|payment| StagedSend {
                    authorization: payment.authorization.clone(),
                    entries: payment.entries.clone(),
                })
                .collect(),
        })
    }

    /// Admits the operator's head for staging: a live payer row whose live balance
    /// covers `total`, verified against the certified head and retained.
    async fn stage_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        head: &operator_rpc::PaymentHeadResponse,
        status: &StatusRecord,
        total: u64,
    ) -> Result<()> {
        // Mid-epoch credits only grow the payer balance and debits are serialized here, so
        // affordability at the head read holds at acceptance.
        ensure!(
            head.balance >= total,
            "payer has insufficient available balance"
        );
        self.verify_head(ctx, chain, head, status).await
    }

    /// Stages without the operator's head: the signing context is the chain's
    /// latest certified registration. The balance floor is the successor root of
    /// the context's admitted predecessor when it is admitted, otherwise the
    /// finalized head. A completed boundary replaces older balances before held
    /// credits can contribute to the successor's spending floor.
    async fn stage_chain_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        total: u64,
    ) -> Result<(PaymentContext<Key, Digest>, StateRoot<Digest>)> {
        let status = staging_status(ctx, chain, self.deployment).await?;
        self.check_withdrawal_floor(&status)?;
        let context = registered_context(ctx, chain, &self.operator).await?;
        let account = self.account();
        let first = floor_epoch(&status)?;
        ensure!(
            context.epoch() >= first,
            "the registered payment context is already finalized"
        );
        let predecessor = match context.epoch().checked_sub(1) {
            Some(previous) if previous >= first => chain.admitted(ctx, previous).await?,
            _ => None,
        };
        let (opening, root, epoch) = match predecessor {
            Some(admitted) => (
                self.holders
                    .successor_opening(ctx, chain, &account, &admitted)
                    .await?,
                admitted.roots.successor,
                context.epoch(),
            ),
            None => (
                self.holders
                    .validator_opening(ctx, chain, &account, &status)
                    .await?,
                status.state_root,
                first,
            ),
        };
        ensure!(
            self.lower_bound(opening.balance.get(), epoch)? >= total,
            "payer has insufficient available balance"
        );
        self.retain_head(&root, &opening)?;
        self.cache_signing(&context, &root, epoch)?;
        Ok((context, root))
    }

    /// Confirms an operator acceptance is the exact staged send with valid receipts:
    /// the acknowledged body and predecessor must be the staged message byte for byte,
    /// and the opened entries must credit the staged recipients positionally.
    fn verify_accepted(
        accepted: &[operator_rpc::AcceptedBatchResponse],
        staged: &StagedBatch,
    ) -> Result<Vec<VerifiedAcceptance>> {
        ensure!(
            accepted.len() == staged.sends.len(),
            "operator returned a partial payment batch"
        );
        let mut verifier = BatchVerifier::new(accepted.len());
        for (accepted, send) in accepted.iter().zip(&staged.sends) {
            let total = entry_total(&send.entries)?;
            ensure!(
                accepted.epoch == staged.context.epoch()
                    && accepted.sequence == send.authorization.body().seq()
                    && accepted.total == total
                    && accepted.acceptance.ack.body() == send.authorization.body()
                    && accepted.acceptance.ack.predecessor() == send.authorization.predecessor(),
                "operator returned another payment"
            );
            ensure!(
                accepted.acceptance.entries.len() == send.entries.len()
                    && accepted
                        .acceptance
                        .entries
                        .iter()
                        .zip(&send.entries)
                        .all(|(opened, delta)| opened.recipient == delta.recipient),
                "operator receipts do not credit the staged recipients"
            );
            ensure!(
                accepted.acceptance.ack.payer_signature() == send.authorization.payer_signature(),
                "operator acceptance changed the staged payer signature"
            );
            let body = accepted.acceptance.ack.body();
            verifier.add(
                VECTOR_ACK_SIGNATURE_NAMESPACE,
                &send.authorization.message(),
                staged.context.operator().as_zip215(),
                accepted.acceptance.ack.operator_signature(),
            );
            ensure!(
                accepted
                    .acceptance
                    .entries
                    .windows(2)
                    .all(|pair| pair[0].recipient < pair[1].recipient),
                "operator receipts are not strictly recipient-sorted"
            );
            for entry in &accepted.acceptance.entries {
                ensure!(
                    entry.cumulative > 0 && entry.count > 0 && entry.cumulative >= entry.count,
                    "operator receipt has an infeasible endpoint"
                );
                let opened = OutEntry {
                    recipient: entry.recipient.clone(),
                    cumulative: entry.cumulative,
                    count: entry.count,
                };
                entry
                    .opening
                    .verify::<Sha256>(
                        VectorKind::OutEntry,
                        &body.send_root(),
                        opened.encode().as_ref(),
                    )
                    .context("verify operator receipt opening")?;
            }
        }
        #[cfg(test)]
        let mut rng = commonware_utils::test_rng();
        #[cfg(not(test))]
        let mut rng = rand::rng();
        ensure!(
            verifier.verify(&mut rng, &Sequential),
            "operator receipt signature batch is invalid"
        );
        Ok(accepted
            .iter()
            .map(|response| VerifiedAcceptance::from_verified(response.acceptance.clone()))
            .collect())
    }

    /// Salvages every independently valid staged receipt from a malformed full response before
    /// returning its protocol error. This path is deliberately serial and rare: native batch
    /// verification remains the canonical response path, while isolation here prevents one bad
    /// or reordered member from destroying valid omission evidence for another member.
    fn retain_noncanonical_acceptances(
        &mut self,
        accepted: &[operator_rpc::AcceptedBatchResponse],
        staged: &StagedBatch,
    ) -> Result<()> {
        let mut seen = vec![false; staged.sends.len()];
        let mut verified = Vec::new();
        for response in accepted {
            let Some(position) = staged.sends.iter().position(|send| {
                response.epoch == staged.context.epoch()
                    && response.sequence == send.authorization.body().seq()
                    && entry_total(&send.entries).ok() == Some(response.total)
                    && response.acceptance.ack.body() == send.authorization.body()
                    && response.acceptance.ack.predecessor() == send.authorization.predecessor()
                    && response.acceptance.ack.payer_signature()
                        == send.authorization.payer_signature()
                    && response.acceptance.entries.len() == send.entries.len()
                    && response
                        .acceptance
                        .entries
                        .iter()
                        .zip(&send.entries)
                        .all(|(opened, delta)| opened.recipient == delta.recipient)
            }) else {
                continue;
            };
            if seen[position] || response.acceptance.verify(&staged.context).is_err() {
                continue;
            }
            verified.push((
                position,
                VerifiedAcceptance::from_verified(response.acceptance.clone()),
            ));
            seen[position] = true;
        }
        if verified.is_empty() {
            return Ok(());
        }
        verified.sort_unstable_by_key(|(position, _)| *position);
        let indexed = verified
            .iter()
            .map(|(position, acceptance)| (*position, acceptance))
            .collect::<Vec<_>>();
        self.store
            .retain_indexed_payment_acceptances(&self.pending_payments, &indexed)
            .context("retain valid receipts from malformed payment batch")?;
        for (position, acceptance) in verified {
            self.pending_payments[position].acceptance = Some(acceptance);
        }
        Ok(())
    }

    /// Durably commits a verified acceptance and advances the wallet-local debit endpoint.
    fn record_payments(
        &mut self,
        accepted: Vec<operator_rpc::AcceptedBatchResponse>,
    ) -> Result<Vec<PaymentOutcome>> {
        ensure!(
            accepted.len() == self.pending_payments.len(),
            "accepted payment count differs from pending batch"
        );
        let conclusions = self
            .pending_payments
            .iter()
            .map(|payment| {
                payment
                    .acceptance
                    .clone()
                    .map(|acceptance| PaymentConclusion::Accepted(Box::new(acceptance)))
                    .context("verified acceptance was not retained in memory")
            })
            .collect::<Result<Vec<_>>>()?;
        self.receipt_count = self
            .store
            .conclude_payment_prefix(
                &self.pending_payments,
                &conclusions,
                self.receipt_count,
                false,
            )
            .context("commit accepted receipt batch")?;
        self.pending_payments.clear();
        self.superseded.clear();
        Ok(accepted
            .into_iter()
            .map(|response| PaymentOutcome::Accepted(Box::new(response)))
            .collect())
    }

    /// Convicts admitted closes that omit this payer's acknowledged sends.
    ///
    /// A receipt for a body no close can carry stays evidence while its close can be
    /// challenged: a re-signed body whose predecessor the preceding admitted close contradicts,
    /// or a send its own admitted close excludes. That close's terminal debit for the payer is
    /// lower than the receipt's. For each payment context whose close is admitted and still
    /// challengeable, the highest receipt proves `HigherAckDebit` when it exceeds the committed
    /// terminal debit, so the wallet submits that challenge and reads the certified fault back.
    /// An unrelated fault does not stop this while the close survives it. Receipts of abandoned
    /// sends prove nothing once their close finalizes or can never be challenged, and are then
    /// pruned. Returns the epochs whose closes this pass convicted.
    pub(crate) async fn enforce<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<Vec<u64>> {
        let status = settlement_status(ctx, chain, self.deployment).await?;
        let mut convicted = Vec::new();
        for evidence in self.store.evidence(status.last_finalized)? {
            let body = evidence.acceptance.ack.body();
            let epoch = body.epoch();
            let context = PaymentContext::new(*body.anchor(), epoch, self.operator.clone());

            // A failed read retries on the next pass without shadowing other contexts.
            let prune = status.last_finalized.is_some_and(|last| epoch <= last)
                || match receipt_epoch(ctx, chain, self.deployment, &context).await {
                    // An unrelated fault leaves a surviving admitted close challengeable
                    // until its deadline.
                    Ok(ReceiptEpoch::Live(Some(admitted)) | ReceiptEpoch::Faulted(admitted)) => {
                        if self
                            .convict(ctx, chain, &admitted, &evidence.acceptance)
                            .await
                            .unwrap_or(false)
                        {
                            convicted.push(epoch);
                        }
                        false
                    }
                    Ok(
                        ReceiptEpoch::Finalized(_)
                        | ReceiptEpoch::Retired
                        | ReceiptEpoch::Invalidated,
                    ) => true,
                    Ok(ReceiptEpoch::Live(None) | ReceiptEpoch::Unresolved) | Err(_) => false,
                };
            if prune && evidence.abandoned {
                self.receipt_count = self
                    .store
                    .prune_evidence(&context, self.receipt_count)
                    .context("prune receipts that can no longer convict")?;
            }
        }
        Ok(convicted)
    }

    /// Submits `HigherAckDebit` against `admitted` when `acceptance` contradicts the payer's
    /// committed terminal, and reports whether the certified fault attributes that conviction
    /// to it.
    ///
    /// A fault keeps its first reason, so a conviction that follows an unrelated fault is
    /// visible only once terminal settlement records the challenged close as the start of the
    /// invalid suffix. Until then this reports false, and a later pass resubmits the challenge,
    /// which the chain rejects without effect once the close is challenged.
    ///
    /// The contradiction is the one adjudication proves: a higher acknowledged debit, another
    /// body at the terminal's sequence number, or an equal debit at a later sequence number.
    async fn convict<E: Env>(
        &self,
        ctx: &E,
        chain: &mut Client,
        admitted: &AdmittedRootsResponse,
        acceptance: &Acceptance,
    ) -> Result<bool> {
        let account = self.account();
        let body = acceptance.ack.body();
        let range = admitted.activity_range();
        let lookup = self
            .holders
            .committed_account_at(ctx, chain, body.epoch(), &range, &account)
            .await?;
        let (debit, terminal) = lookup
            .resolve::<Sha256>(&range, &account)
            .context("verify committed payer activity")?;
        let context = PaymentContext::new(*body.anchor(), body.epoch(), self.operator.clone());
        let contradicts = body.cumulative_debit() > debit
            || terminal.is_some_and(|terminal| {
                terminal.has_outgoing()
                    && !terminal.matches_outgoing(&context, body)
                    && (body.seq() == terminal.terminal_seq()
                        || (body.cumulative_debit() == debit
                            && body.seq() > terminal.terminal_seq()))
            });
        if !contradicts {
            return Ok(false);
        }
        let challenge = Challenge::HigherAckDebit {
            ack: Box::new(AckWitness::from_ack(&acceptance.ack)),
            payer: Box::new(lookup),
        };
        chain
            .deliver(
                ctx,
                &SettlementTx::Challenge(ChallengeRequest {
                    deployment: self.deployment,
                    batch_id: admitted.batch_id,
                    evidence: challenge.encode(),
                }),
            )
            .await?;
        for _ in 0..EFFECT_ATTEMPTS {
            match chain.fault(ctx).await? {
                Some(FaultRecord::Faulted(reason)) => {
                    return Ok(matches!(
                        reason,
                        HardFaultReasonResponse::ProvenChallenge {
                            batch_id,
                            kind: ChallengeKind::HigherAckDebit,
                        } if batch_id == admitted.batch_id
                    ));
                }
                Some(FaultRecord::Settling(settlement)) => {
                    return Ok(settlement.invalid_from == Some(admitted.batch_id));
                }
                None => {}
            }
            ctx.sleep(POLL).await;
        }
        Ok(false)
    }
}

async fn submit_staged<E: Env>(
    ctx: &E,
    operator: SocketAddr,
    staged: &StagedBatch,
) -> Result<operator_rpc::AcceptSendsResponse> {
    let sends = staged
        .sends
        .iter()
        .map(|send| operator_rpc::AcceptSendRequest {
            authorization: send.authorization.clone(),
            entries: send.entries.clone(),
        })
        .collect::<Vec<_>>();
    if sends.len() == 1 {
        return Ok(
            match operator_rpc::accept_send(ctx, operator, sends[0].clone()).await? {
                operator_rpc::AcceptSendResponse::Accepted(accepted) => {
                    operator_rpc::AcceptSendsResponse::Accepted(vec![accepted])
                }
                operator_rpc::AcceptSendResponse::Stale(stale) => {
                    operator_rpc::AcceptSendsResponse::Stale(stale)
                }
            },
        );
    }
    operator_rpc::accept_sends(ctx, operator, operator_rpc::AcceptSendsRequest { sends }).await
}

/// The certified status a fresh send may be staged against: `deployment`, the
/// one the wallet is bound to, not hard-faulted.
async fn staging_status<E: Env>(
    ctx: &E,
    chain: &mut Client,
    deployment: Digest,
) -> Result<StatusRecord> {
    let status = settlement_status(ctx, chain, deployment)
        .await
        .context("read settlement payment head")?;
    ensure!(
        !status.hard_faulted,
        "settlement is permanently hard-faulted"
    );
    Ok(status)
}

/// The operator's live head for `account`, checked to name `bound`, the
/// operator the wallet is bound to.
pub(super) async fn operator_head<E: Env>(
    ctx: &E,
    operator: SocketAddr,
    account: Key,
    bound: &Key,
) -> Result<operator_rpc::PaymentHeadResponse> {
    let head =
        operator_rpc::payment_head(ctx, operator, operator_rpc::PaymentHeadRequest { account })
            .await
            .context("read payer state")?;
    ensure!(
        head.context.payment().operator() == bound,
        "payment context has an unexpected operator"
    );
    Ok(head)
}

/// The latest registered payment context from the chain alone: the epoch
/// and the anchor settlement certified for it, under `bound`, the operator the
/// wallet is bound to. A send signed under it needs no operator head, and the
/// context cannot be false because the anchor is the chain's own registration
/// record.
///
/// A successor can register while its predecessor still accepts payments. A send under the
/// successor waits for the operator's handoff, retaining its exact authorization while pending.
/// An admitted close is fixed, so its epoch cannot accept a new send.
async fn registered_context<E: Env>(
    ctx: &E,
    chain: &mut Client,
    bound: &Key,
) -> Result<PaymentContext<Key, Digest>> {
    let registration = chain
        .registration(ctx)
        .await
        .context("read the latest registration")?
        .context("no epoch is registered, so there is no payment context to sign under")?;
    ensure!(
        registration.admitted.is_none(),
        "the registered close is admitted, so there is no live payment context to sign under"
    );
    Ok(PaymentContext::new(
        registration.anchor,
        registration.epoch,
        bound.clone(),
    ))
}

/// Rebuilds the payment context a signed authorization binds, under the bound
/// deployment's operator.
fn authorization_context(
    authorization: &SendAuthorization<Key, Digest>,
    operator: &Key,
) -> PaymentContext<Key, Digest> {
    PaymentContext::new(
        *authorization.body().anchor(),
        authorization.body().epoch(),
        operator.clone(),
    )
}

fn accepted_response(
    payment: &PendingPayment,
    acceptance: &VerifiedAcceptance,
) -> Result<operator_rpc::AcceptedBatchResponse> {
    Ok(operator_rpc::AcceptedBatchResponse {
        epoch: payment.authorization.body().epoch(),
        sequence: payment.authorization.body().seq(),
        total: entry_total(&payment.entries)?,
        acceptance: acceptance.acceptance().clone(),
    })
}

/// The checked total of strictly recipient-sorted positive delta entries.
fn entry_total(entries: &[Entry]) -> Result<u64> {
    entries.iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(entry.amount)
            .context("payment total overflow")
    })
}

/// Merges positive deltas into a strictly recipient-sorted cumulative vector.
pub(super) fn merge_entries(
    mut merged: Vec<OutEntry<Key>>,
    deltas: &[Entry],
) -> Result<Vec<OutEntry<Key>>> {
    for delta in deltas {
        match merged.binary_search_by(|edge| edge.recipient.cmp(&delta.recipient)) {
            Ok(position) => {
                merged[position].cumulative = merged[position]
                    .cumulative
                    .checked_add(delta.amount)
                    .context("edge cumulative overflow")?;
                merged[position].count = merged[position]
                    .count
                    .checked_add(1)
                    .context("edge count overflow")?;
            }
            Err(position) => merged.insert(
                position,
                OutEntry {
                    recipient: delta.recipient.clone(),
                    cumulative: delta.amount,
                    count: 1,
                },
            ),
        }
    }
    Ok(merged)
}

/// The first epoch whose payments are absent from the finalized balance floor.
fn floor_epoch(status: &StatusRecord) -> Result<u64> {
    status
        .last_finalized
        .map_or(Some(0), |last| last.checked_add(1))
        .context("epoch overflow")
}
