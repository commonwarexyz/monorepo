//! Durable, context-scoped payment authorization and authenticated outcome resolution.
//!
//! Ordinary payments sign from local accepted epoch state and a verified balance floor.
//! A submitted intent keeps its exact bytes until receipts or settlement resolve it.
//! Operator corrections never authorize the same ambiguous intent in another context.

use super::{
    Agent,
    evidence::{check_opening, unusable_head},
    store::{ContextCache, PaymentConclusion, PendingPayment, VerifiedAcceptance},
    wallet::{ReceiptEpoch, receipt_epoch, settlement_status},
};
use crate::{
    chain::{
        client::{Chain, Client, Env, POLL, SUBMIT_ATTEMPTS},
        state::StatusRecord,
    },
    operator::rpc as operator_rpc,
    protocol::{Entry, Key, MAX_BATCH_SEND_ENTRIES, MAX_SENDS_PER_BATCH},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    commitment::VectorKind,
    payment::{PaymentContext, SendAuthorization, VECTOR_ACK_SIGNATURE_NAMESPACE, VectorSendBody},
    qmdb::{StateOpening, StateRoot},
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
        self.observe_withdrawal_expiry(ctx, chain).await?;
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
                    return match self
                        .resolve_pending(ctx, chain, operator, staged, None)
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
                    self.resolve_pending(ctx, chain, operator, staged, Some(accepted))
                        .await?
                }
                operator_rpc::AcceptSendsResponse::Stale { context, .. } => {
                    ensure!(
                        context.operator() == &self.operator,
                        "corrective context has an unexpected operator"
                    );
                    self.resolve_pending(ctx, chain, operator, staged, None)
                        .await?
                }
            };
            ensure!(
                matches!(&resolution, PendingOutcome::Resolved { .. })
                    || attempts < SUBMIT_ATTEMPTS,
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
    /// `context`: the merged cumulative vector's root at the next batch sequence and the
    /// wallet's own successor debit endpoint.
    fn sign_payments(
        &self,
        context: &PaymentContext<Key, Digest>,
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
            authorizations.push(SendAuthorization::sign(body, self.wallet.signer()));
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

    /// Resolves the staged authorization batch against its registration and admitted activity.
    /// Admission fixes the close, so exclusion is permanent. Inclusion without a receipt
    /// requires finality before the wallet records a completed payment. Any supplied acceptance
    /// has already passed exact-body and receipt verification.
    async fn resolve_pending<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        staged: StagedBatch,
        accepted: Option<Vec<operator_rpc::AcceptedBatchResponse>>,
    ) -> Result<PendingOutcome> {
        let context = &staged.context;
        let (range, descriptor_finalized) =
            match receipt_epoch(ctx, chain, self.deployment, context).await? {
                ReceiptEpoch::Invalidated => {
                    return self.conclude_staged_prefix(0, false);
                }
                ReceiptEpoch::Unresolved => return Ok(PendingOutcome::Live(Box::new(staged))),
                ReceiptEpoch::Live(None) => {
                    return match accepted {
                        Some(accepted) => Ok(PendingOutcome::Resolved {
                            outcomes: self.record_payments(accepted)?,
                            restage_suffix: false,
                        }),
                        None => Ok(PendingOutcome::Live(Box::new(staged))),
                    };
                }
                ReceiptEpoch::Live(Some(admitted)) | ReceiptEpoch::Faulted(admitted) => {
                    (admitted.activity_range(), false)
                }
                ReceiptEpoch::Finalized(admitted) => (admitted.activity_range(), true),
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

    /// Verifies a payment context and its finalized or admitted predecessor balance floor.
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
        let finalized_epoch = floor_epoch(status)?;
        let epoch = head.context.payment().epoch();
        let epoch = if epoch > finalized_epoch {
            ensure!(
                !status.hard_faulted,
                "settlement is permanently hard-faulted"
            );
            let predecessor = chain
                .admitted(ctx, epoch - 1)
                .await?
                .context("payer predecessor close has not been admitted")?;
            ensure!(
                predecessor.roots.successor == head.root,
                "payer opening differs from its admitted predecessor"
            );
            epoch
        } else {
            ensure!(
                status.state_root == head.root,
                "payer opening is not the exact settlement head"
            );
            finalized_epoch
        };
        self.retain_head(&head.root, &head.opening)?;
        self.cache_signing(head.context.payment(), &head.root, epoch)
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
        let operator_error =
            match operator_head(ctx, operator, self.account(), &self.operator).await {
                Ok(head) => {
                    let status = staging_status(ctx, chain, self.deployment).await?;
                    match self.stage_head(ctx, chain, &head, &status, total).await {
                        Ok(()) => {
                            return self.stage_under(
                                head.context.payment().clone(),
                                head.root,
                                requested,
                            );
                        }
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };
        let (context, root) = self
            .stage_chain_head(ctx, chain, total)
            .await
            .map_err(|error| unusable_head(operator_error, error))?;
        self.stage_under(context, root, requested)
    }

    /// Signs and durably stages a fresh send under `context`, with the opening
    /// retained at `root` as its recovery evidence.
    fn stage_under(
        &mut self,
        context: PaymentContext<Key, Digest>,
        root: StateRoot<Digest>,
        requested: &[(Vec<Entry>, u64)],
    ) -> Result<StagedBatch> {
        let authorizations = self.sign_payments(&context, requested)?;
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
    /// certified registration and the balance floor comes from its admitted predecessor
    /// for a successor epoch, otherwise the finalized head. A completed boundary replaces older
    /// balances before held credits can contribute to the successor's spending floor.
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
        let finalized_epoch = floor_epoch(&status)?;
        let predecessor = if context.epoch() > finalized_epoch {
            Some(
                chain
                    .admitted(ctx, context.epoch() - 1)
                    .await?
                    .context("payer predecessor close has not been admitted")?,
            )
        } else {
            None
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
                finalized_epoch,
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
    /// the acknowledged body must be the staged body byte for byte, and the opened
    /// entries must credit the staged recipients positionally.
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
                    && accepted.acceptance.ack.body() == send.authorization.body(),
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
                &body.encode(),
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
        Ok(accepted
            .into_iter()
            .map(|response| PaymentOutcome::Accepted(Box::new(response)))
            .collect())
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
                operator_rpc::AcceptSendResponse::Stale {
                    context,
                    cumulative_debit,
                    seq,
                    entries,
                } => operator_rpc::AcceptSendsResponse::Stale {
                    context,
                    cumulative_debit,
                    seq,
                    entries,
                },
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

/// The live payment context from the chain alone: the registered epoch and the
/// anchor settlement certified for it, under `bound`, the operator the wallet
/// is bound to. A send signed under it needs no operator head, and the context
/// cannot be false because the anchor is the chain's own registration record.
///
/// The registration singleton keeps naming an epoch after its close is
/// admitted, until the successor registers or finalization retires it. An
/// admitted close is fixed, so that epoch is dead for a new send: only an
/// unadmitted registration is a live context.
async fn registered_context<E: Env>(
    ctx: &E,
    chain: &mut Client,
    bound: &Key,
) -> Result<PaymentContext<Key, Digest>> {
    let registration = chain
        .registration(ctx)
        .await
        .context("read the registered close")?
        .context("no close is registered, so there is no payment context to sign under")?;
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
