//! Durable, context-scoped payment authorization and authenticated outcome resolution.
//!
//! Ordinary payments sign from local accepted epoch state and a verified balance floor.
//! A submitted intent keeps its exact bytes until receipts or settlement resolve it.
//! Operator corrections never authorize the same ambiguous intent in another context.

use super::{
    Agent,
    evidence::{check_opening, unusable_head},
    store::{ContextCache, PendingPayment},
    wallet::{ReceiptEpoch, receipt_epoch, settlement_status},
};
use crate::{
    chain::{
        client::{Chain, Client, Env, POLL, SUBMIT_ATTEMPTS},
        state::StatusRecord,
    },
    operator::rpc as operator_rpc,
    protocol::{Entry, Key},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
    qmdb::{StateOpening, StateRoot},
    vector::{OutEntry, OutVector},
};
use commonware_cryptography::{Sha256, sha256::Digest};
use std::net::SocketAddr;

/// One send resolved and ready for the shared accept, verify, and commit tail.
struct StagedSend {
    context: PaymentContext<Key, Digest>,
    authorization: SendAuthorization<Key, Digest>,
    entries: Vec<Entry>,
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

/// How verified receipts and settlement resolve one staged send.
enum PendingOutcome {
    /// No admitted outcome resolves the intent, so resubmit the exact bytes.
    Live(Box<StagedSend>),
    /// A verified receipt or finalized inclusion concluded the send.
    Resolved(PaymentOutcome),
    /// The send provably never committed and was abandoned, so a fresh one must be staged.
    Abandoned,
}

impl Agent {
    /// Pays a canonical batch, retaining one exact outstanding authorization until resolved.
    pub(crate) async fn pay<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        entries: &[(usize, u64)],
    ) -> Result<PaymentOutcome> {
        let (requested, total) = self.payment_entries(entries)?;
        self.pay_requested(ctx, chain, operator, requested, total)
            .await
    }

    /// Resumes the durably staged pending send, when one exists.
    ///
    /// The exact staged bytes resubmit and adjudicate through the standard
    /// pipeline, so an interrupted run's in-flight payment concludes before
    /// any new intent is staged.
    pub(crate) async fn resume_pending_payment<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<Option<PaymentOutcome>> {
        let Some(pending) = &self.pending_payment else {
            return Ok(None);
        };
        let requested = pending.entries.clone();
        let total = entry_total(&requested)?;
        self.pay_requested(ctx, chain, operator, requested, total)
            .await
            .map(Some)
    }

    async fn pay_requested<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        requested: Vec<Entry>,
        total: u64,
    ) -> Result<PaymentOutcome> {
        let mut staged = match self.pending_payment.clone() {
            Some(pending) => {
                // Exact retries use the durable bytes. A verified receipt or authenticated
                // settlement outcome resolves the intent before another one can be signed.
                ensure!(
                    pending.entries == requested,
                    "another payment retry is pending"
                );
                self.store
                    .recovery_opening(&pending.recovery_root)?
                    .context("pending payment recovery opening is missing")?;
                StagedSend {
                    context: authorization_context(&pending.authorization, &self.operator),
                    authorization: pending.authorization,
                    entries: pending.entries,
                }
            }
            None => self.stage(ctx, chain, operator, &requested, total).await?,
        };

        let mut attempts = 1;
        loop {
            let response = match operator_rpc::accept_send(
                ctx,
                operator,
                operator_rpc::AcceptSendRequest {
                    authorization: staged.authorization.clone(),
                    entries: staged.entries.clone(),
                },
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    return match self
                        .resolve_pending(ctx, chain, operator, staged, None)
                        .await
                    {
                        Ok(PendingOutcome::Resolved(outcome)) => Ok(outcome),
                        Ok(PendingOutcome::Live(_) | PendingOutcome::Abandoned) => {
                            Err(error).context("submit payment")
                        }
                        Err(unresolved) => Err(unresolved).context(format!(
                            "payment submission failed ({error:#}); outcome unresolved"
                        )),
                    };
                }
            };
            let resolution = match response {
                operator_rpc::AcceptSendResponse::Accepted(accepted) => {
                    Self::verify_accepted(&accepted, &staged, total)?;
                    let resolution = self
                        .resolve_pending(ctx, chain, operator, staged, Some(accepted))
                        .await?;
                    ensure!(
                        !matches!(resolution, PendingOutcome::Abandoned),
                        "accepted payment was permanently excluded by settlement"
                    );
                    resolution
                }
                operator_rpc::AcceptSendResponse::Stale { context, .. } => {
                    ensure!(
                        context.operator() == &self.operator,
                        "corrective context has an unexpected operator"
                    );
                    self.resolve_pending(ctx, chain, operator, staged, None)
                        .await?
                }
            };
            ensure!(
                matches!(&resolution, PendingOutcome::Resolved(_)) || attempts < SUBMIT_ATTEMPTS,
                "the operator repeatedly rejected the unresolved payment"
            );
            attempts += 1;
            staged = match resolution {
                PendingOutcome::Live(staged) => {
                    ctx.sleep(POLL).await;
                    *staged
                }
                PendingOutcome::Abandoned => {
                    self.stage(ctx, chain, operator, &requested, total).await?
                }
                PendingOutcome::Resolved(outcome) => return Ok(outcome),
            };
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
        requested: &[Entry],
        total: u64,
    ) -> Result<StagedSend> {
        if let Some(cache) = self.cache.clone() {
            // The local view is a lower bound, so a shortfall is not proof of
            // unaffordability: funds from a deposit, or from an epoch the floor
            // predates, are invisible to it. Fall back to one head read, whose
            // live-balance precheck refuses a truly unaffordable send before staging
            // and whose verified opening re-anchors the floor.
            if self.spendable(&cache)? >= total {
                return self.stage_local(&cache, requested, total);
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
    fn sign_batch(
        &self,
        context: &PaymentContext<Key, Digest>,
        requested: &[Entry],
        total: u64,
    ) -> Result<SendAuthorization<Key, Digest>> {
        let prior = self.store.vector_state(context)?;
        let (seq, debit, prior_entries) = match prior {
            Some(state) => (
                state
                    .seq
                    .checked_add(1)
                    .context("batch sequence overflow")?,
                state.cumulative_debit,
                state.entries,
            ),
            None => (1, 0, Vec::new()),
        };
        let merged = merge_entries(prior_entries, requested)?;
        let vector = OutVector::new(context.epoch(), self.account(), merged)
            .context("assemble signed out vector")?;
        let body = VectorSendBody::new(
            context,
            self.account(),
            seq,
            debit
                .checked_add(total)
                .context("payment endpoint overflow")?,
            vector
                .root::<Sha256, Digest>()
                .context("commit signed out vector")?,
        );
        Ok(SendAuthorization::sign(body, self.wallet.signer()))
    }

    /// Signs and durably stages a send from local state alone: the cached context, the
    /// wallet's own authoritative endpoint and vector state, and the cached floor's
    /// retained opening as the staged recovery evidence.
    fn stage_local(
        &mut self,
        cache: &ContextCache,
        requested: &[Entry],
        total: u64,
    ) -> Result<StagedSend> {
        self.stage_under(cache.context.clone(), cache.root, requested, total)
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

    /// Resolves the staged authorization against its registration and admitted activity.
    /// Admission fixes the close, so exclusion is permanent. Inclusion without a receipt
    /// requires finality before the wallet records a completed payment. Any supplied acceptance
    /// has already passed exact-body and receipt verification.
    async fn resolve_pending<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        staged: StagedSend,
        accepted: Option<operator_rpc::AcceptedBatchResponse>,
    ) -> Result<PendingOutcome> {
        let context = &staged.context;
        let admitted = match receipt_epoch(ctx, chain, self.deployment, context).await? {
            ReceiptEpoch::Invalidated => return self.abandon_staged(&staged),
            ReceiptEpoch::Unresolved => return Ok(PendingOutcome::Live(Box::new(staged))),
            ReceiptEpoch::Live(None) => {
                return match accepted {
                    Some(accepted) => Ok(PendingOutcome::Resolved(PaymentOutcome::Accepted(
                        Box::new(self.record_payment(accepted, &staged, false)?),
                    ))),
                    None => Ok(PendingOutcome::Live(Box::new(staged))),
                };
            }
            ReceiptEpoch::Live(Some(admitted))
            | ReceiptEpoch::Finalized(admitted)
            | ReceiptEpoch::Faulted(admitted) => admitted,
        };
        let account = self.account();
        let lookup = self
            .holders
            .committed_account(ctx, chain, &admitted, &account)
            .await?;
        let (_, activity) = lookup
            .resolve::<Sha256>(&admitted.roots.change, &account)
            .context("verify admitted payer activity")?;
        let Some(activity) = activity.filter(|activity| activity.has_outgoing()) else {
            return self.abandon_staged(&staged);
        };
        if !activity.matches_outgoing(context, staged.authorization.body()) {
            let prior = self
                .store
                .vector_state(context)?
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
            return self.abandon_staged(&staged);
        }

        // Activity is immutable, but evidence retrieval can cross finalization or a fault.
        // Only a fresh live verdict can authorize a newly acquired preconfirmation.
        let finalized = if admitted.finalized {
            true
        } else {
            match receipt_epoch(ctx, chain, self.deployment, context).await? {
                ReceiptEpoch::Finalized(_) => true,
                ReceiptEpoch::Live(_) if accepted.is_some() => false,
                ReceiptEpoch::Invalidated => return self.abandon_staged(&staged),
                _ => anyhow::bail!(
                    "the staged epoch has not finalized, so its commitment is not yet decidable"
                ),
            }
        };

        let total = entry_total(&staged.entries)?;
        let previous_debit = staged
            .authorization
            .body()
            .cumulative_debit()
            .checked_sub(total)
            .context("staged payment total exceeds its epoch debit")?;
        let fetched = match accepted {
            Some(accepted) => Some(accepted),
            None => operator_rpc::accepted_batch(
                ctx,
                operator,
                operator_rpc::AcceptSendRequest {
                    authorization: staged.authorization.clone(),
                    entries: staged.entries.clone(),
                },
            )
            .await
            .ok()
            .flatten()
            .filter(|accepted| Self::verify_accepted(accepted, &staged, total).is_ok()),
        };
        let outcome = match fetched {
            Some(accepted) => PaymentOutcome::Accepted(Box::new(
                self.record_payment(accepted, &staged, finalized)?,
            )),
            None => {
                self.store
                    .finalize_payment_unheld(&staged.authorization, &staged.entries, previous_debit)
                    .context("record finalized payment without receipts")?;
                self.pending_payment = None;
                PaymentOutcome::CommittedUnheld {
                    epoch: context.epoch(),
                    total,
                }
            }
        };
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
        Ok(PendingOutcome::Resolved(outcome))
    }

    /// Clears an intent only after its caller authenticates exclusion or permanent invalidation.
    fn abandon_staged(&mut self, staged: &StagedSend) -> Result<PendingOutcome> {
        self.store
            .abandon_payment(&staged.authorization)
            .context("record excluded payment")?;
        self.pending_payment = None;
        self.cache = None;
        Ok(PendingOutcome::Abandoned)
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
        if self.pending_withdrawal.is_some() || self.pending_withdrawal_claim.is_some() {
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
        requested: &[Entry],
        total: u64,
    ) -> Result<StagedSend> {
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
                                total,
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
        self.stage_under(context, root, requested, total)
    }

    /// Signs and durably stages a fresh send under `context`, with the opening
    /// retained at `root` as its recovery evidence.
    fn stage_under(
        &mut self,
        context: PaymentContext<Key, Digest>,
        root: StateRoot<Digest>,
        requested: &[Entry],
        total: u64,
    ) -> Result<StagedSend> {
        let authorization = self.sign_batch(&context, requested, total)?;
        self.store
            .stage_payment(
                &authorization,
                requested,
                &root,
                authorization
                    .body()
                    .cumulative_debit()
                    .checked_sub(total)
                    .context("payment delta exceeds epoch debit")?,
            )
            .context("durably stage payment")?;
        self.pending_payment = Some(PendingPayment {
            authorization: authorization.clone(),
            entries: requested.to_vec(),
            recovery_root: root,
        });
        Ok(StagedSend {
            context,
            authorization,
            entries: requested.to_vec(),
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
        accepted: &operator_rpc::AcceptedBatchResponse,
        staged: &StagedSend,
        total: u64,
    ) -> Result<()> {
        ensure!(
            accepted.epoch == staged.context.epoch()
                && accepted.sequence == staged.authorization.body().seq()
                && accepted.total == total
                && accepted.acceptance.ack.body() == staged.authorization.body(),
            "operator returned another payment"
        );
        ensure!(
            accepted.acceptance.entries.len() == staged.entries.len()
                && accepted
                    .acceptance
                    .entries
                    .iter()
                    .zip(&staged.entries)
                    .all(|(opened, delta)| opened.recipient == delta.recipient),
            "operator receipts do not credit the staged recipients"
        );
        accepted
            .acceptance
            .verify(&staged.context)
            .context("verify operator receipts")
    }

    /// Durably commits a verified acceptance and advances the wallet-local debit endpoint.
    fn record_payment(
        &mut self,
        accepted: operator_rpc::AcceptedBatchResponse,
        staged: &StagedSend,
        finalized: bool,
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        let receipt_count = self
            .store
            .commit_payment(
                &accepted.acceptance,
                &staged.authorization,
                &staged.entries,
                staged
                    .authorization
                    .body()
                    .cumulative_debit()
                    .checked_sub(entry_total(&staged.entries)?)
                    .context("payment delta exceeds epoch debit")?,
                self.receipt_count,
                finalized,
            )
            .context("commit accepted receipts")?;
        self.pending_payment = None;
        self.receipt_count = receipt_count;
        Ok(accepted)
    }
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
