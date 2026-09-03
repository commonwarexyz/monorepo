//! The optimistic payment flow: local staging, submission, corrective retry, settlement
//! resolution, and receipt commitment.
//!
//! Ordinary payments touch nothing but local SQL before the wire: the wallet's durable
//! cumulative debit is the authoritative signing endpoint, the durable per-context vector
//! state supplies the batch sequence and cumulative entries the signed root commits, the
//! cached operator-served context is the claimed `(epoch, anchor)` binding, and the cached
//! verified floor lower-bounds affordability. When the operator has moved to a new context
//! or endpoint view, the wallet is taught by the typed corrective rejection its send earns,
//! adopts the corrected context and endpoint, and re-signs the same intent. Head reads
//! survive only as the fallback for a wallet with no cache or a floor that cannot prove
//! affordability.
//!
//! Signing under a cached, possibly stale context is safe because a send authorizes a
//! cumulative debit endpoint. Two sends at one endpoint under different contexts can
//! never both debit: if the old context's close commits the endpoint, the successor
//! send has a zero delta against that committed debit and is infeasible, and if it does
//! not, the old send is dead the moment its context is unregistrable. At most one of an
//! optimistic send and its corrective retry ever commits, even against a Byzantine
//! operator that claims rejection while secretly keeping the signed bytes.

use super::{
    Agent,
    evidence::{check_opening, unusable_head},
    store::{ContextCache, PendingPayment},
    wallet::settlement_status,
};
use crate::{
    chain::{
        client::{Chain, Client, Env},
        state::StatusRecord,
    },
    operator::rpc as operator_rpc,
    protocol::{Entry, Key},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::StateOpening,
    commitment::VectorRoot,
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
    state::AccountState,
    vector::{OutEntry, OutVector},
};
use commonware_cryptography::{Sha256, sha256::Digest};
use std::{net::SocketAddr, time::Duration};

/// Corrective context adoptions tolerated within one payment.
///
/// Two legitimate moves can stack inside one submission: an epoch roll
/// (rotation to the successor context), and the chain's registration-time
/// deadline assignment, which re-anchors the successor context at the
/// absolute deadlines execution derived from the registration's inclusion
/// height. Each corrective carries the operator's full endpoint view, so one
/// adoption also synchronizes the batch sequence and vector state. Beyond
/// that, a corrective loop is an operator fault and the payment fails.
const MAX_CORRECTIONS: usize = 2;

/// Certified anchor polls before an acceptance is reported unconfirmed. The
/// operator registers on the chain before it releases a receipt, so absence
/// here is read lag.
const CONFIRM_ATTEMPTS: usize = 50;

/// Pause between certified anchor polls.
const CONFIRM_POLL: Duration = Duration::from_millis(200);

/// One send resolved and ready for the shared accept, verify, and commit tail.
struct StagedSend {
    context: PaymentContext<Key, Digest>,
    authorization: SendAuthorization<Key, Digest>,
    entries: Vec<Entry>,
    predecessor_state_root: VectorRoot<Digest>,
}

/// One concluded payment.
#[derive(Debug)]
pub(crate) enum PaymentOutcome {
    /// The operator accepted the send and its verified receipts are held.
    Accepted(Box<operator_rpc::AcceptedBatchResponse>),
    /// The send committed in a finalized close, proven by the wallet's endpoint in a
    /// verified finalized root, but its receipts could not be fetched. The protocol's
    /// pipelined-exposure carve-out lets the next send proceed without them.
    CommittedUnheld {
        /// Epoch the send committed in.
        epoch: u64,
        /// Batch total the send debited.
        total: u64,
    },
}

/// How the wallet resolved an already-staged pending send before submission.
enum PendingOutcome {
    /// The staged context is still live, so resubmit the exact bytes.
    Live(Box<StagedSend>),
    /// The send's commitment was concluded from a finalized settlement root.
    Resolved(PaymentOutcome),
    /// The send provably never committed and was abandoned, so a fresh one must be staged.
    Abandoned,
}

impl Agent {
    /// Pays every `(receiver index, amount)` entry with one batched send, signing from
    /// local state alone whenever a context is cached.
    ///
    /// A send this operator deterministically rejects must never be staged, because a
    /// retry resubmits the exact staged bytes. The local affordability precheck holds
    /// that rule on the optimistic path: the cached floor view is a lower bound on
    /// spendable balance, so a send it admits is affordable at an honest operator, and
    /// a shortfall falls back to one verified head read whose live-balance precheck
    /// refuses before staging. A stale context or endpoint view is not a staging hazard
    /// at all: the operator answers it with a typed corrective rejection carrying its
    /// live context and the payer's accepted endpoint, and the wallet re-signs the same
    /// intent at its own endpoint, boundedly per rejection reason.
    ///
    /// A corrective rejection claiming an endpoint other than the wallet's own is never
    /// adopted. It is the lost-acceptance signal, so the wallet routes through the
    /// settlement-anchored resolution instead: while the staged context is still live it
    /// resubmits unchanged, and once the staged epoch has finalized the wallet concludes
    /// commitment by reading its own endpoint out of a Merkle-verified opening of the
    /// finalized root, fetching receipts through the optional `accepted_batch` recovery.
    /// A committed send finishes locally, and a send the finalized endpoint provably
    /// excludes is abandoned and re-staged, so the wallet can never drop or double count
    /// a real transfer.
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
                // Resubmit the exact staged bytes without any read: the operator's
                // typed reply adjudicates whether they are replayed, accepted, or
                // rejected with a corrective context.
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
                    predecessor_state_root: pending.recovery_root,
                }
            }
            None => self.stage(ctx, chain, operator, &requested, total).await?,
        };

        // Submission is bounded per rejection reason, never a loop: bounded
        // corrective re-signs for moved contexts, and one settlement-anchored
        // recovery for a corrective claiming an endpoint this wallet does not
        // recognize.
        let mut corrections = 0;
        let mut recovered = false;
        loop {
            // The ledger tracks the slot's lifecycle: the send is durably marked
            // submitted before the wire attempt, so its row never claims less than what
            // may have reached the operator.
            self.store
                .mark_payment_submitted(&staged.authorization)
                .context("mark payment submitted")?;
            let response = operator_rpc::accept_send(
                ctx,
                operator,
                operator_rpc::AcceptSendRequest {
                    authorization: staged.authorization.clone(),
                    entries: staged.entries.clone(),
                },
            )
            .await
            .context("submit payment")?;
            let (context, cumulative_debit, seq, entries) = match response {
                operator_rpc::AcceptSendResponse::Accepted(accepted) => {
                    Self::verify_accepted(&accepted, &staged, total)?;
                    let accepted = self
                        .confirm_and_record(ctx, chain, &staged, accepted)
                        .await?;
                    return Ok(PaymentOutcome::Accepted(Box::new(accepted)));
                }
                operator_rpc::AcceptSendResponse::Stale {
                    context,
                    cumulative_debit,
                    seq,
                    entries,
                } => (context, cumulative_debit, seq, entries),
            };
            ensure!(
                context.operator() == &self.operator,
                "corrective context has an unexpected operator"
            );
            if cumulative_debit == self.cumulative_debit {
                ensure!(
                    corrections < MAX_CORRECTIONS,
                    "the operator moved its context {} times within one payment",
                    corrections + 1
                );
                corrections += 1;
                staged = self.correct(context, seq, entries, &staged)?;
            } else {
                // The operator claims this payer stands at an endpoint the wallet does
                // not recognize. That claim is never adopted: it is the lost-acceptance
                // signal, and only settlement's finalized endpoint may decide it.
                ensure!(
                    !recovered,
                    "the operator repeated an unrecognized endpoint after resolution"
                );
                recovered = true;
                staged = match self.resolve_pending(ctx, chain, operator, staged).await? {
                    PendingOutcome::Live(staged) => *staged,
                    PendingOutcome::Resolved(outcome) => return Ok(outcome),
                    PendingOutcome::Abandoned => {
                        self.stage(ctx, chain, operator, &requested, total).await?
                    }
                };
            }
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
    /// contain them) minus every debit the wallet signed past the floor endpoint.
    /// Everything it leaves out moves the true balance up, never down: unintaken
    /// incoming credits and applied deposits only add, and a withdrawal invalidates the
    /// cache before its request can reach the operator. A precheck against this view
    /// therefore never stages a send an honest operator rejects as unaffordable.
    fn spendable(&self, cache: &ContextCache) -> Result<u64> {
        let opening = self
            .store
            .recovery_opening(&cache.root)?
            .context("cached context floor opening is missing")?;
        self.lower_bound(&opening.leaf.state, cache.epoch)
    }

    /// The lower bound [`Self::spendable`] computes from one verified floor: the
    /// wallet's row in a certified root covering every close before `epoch`.
    fn lower_bound(&self, floor: &AccountState, epoch: u64) -> Result<u64> {
        let debited = self
            .cumulative_debit
            .checked_sub(floor.cumulative_debit)
            .context("the wallet endpoint is behind its verified floor: stale wallet database")?;
        let funds = floor
            .balance
            .checked_add(self.store.credits_since(epoch)?)
            .context("local balance view overflow")?;

        // Debits can legitimately exceed the tracked funds when a deposit financed
        // them, so the lower bound saturates at zero and the fallback re-anchors it.
        Ok(funds.saturating_sub(debited))
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
        let (seq, prior_entries) = match prior {
            Some(state) => {
                ensure!(
                    state.cumulative_debit == self.cumulative_debit,
                    "the durable vector state is not at the wallet endpoint"
                );
                (state.seq, state.entries)
            }
            None => (0, Vec::new()),
        };
        let merged = merge_entries(prior_entries, requested)?;
        let vector = OutVector::new(context.epoch(), self.account(), merged)
            .context("assemble signed out vector")?;
        let body = VectorSendBody::new(
            context,
            self.account(),
            seq.checked_add(1).context("batch sequence overflow")?,
            self.cumulative_debit
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

    /// Adopts a corrective context and endpoint view, and re-signs the exact staged
    /// intent at the wallet's own endpoint.
    ///
    /// Endpoint exclusivity makes the adoption safe even against a Byzantine operator
    /// that claims rejection while keeping the replaced bytes: both sends authorize the
    /// same cumulative debit interval, so if the old context's close commits the
    /// replaced send, the corrected one has a zero delta against that committed
    /// endpoint and is infeasible, and if it does not, the replaced send is dead the
    /// moment its context is unregistrable. At most one of the two ever commits, and
    /// either way the ledger's endpoint arithmetic stays exact. The adopted batch
    /// sequence and vector entries are equally harmless: a false claim only produces a
    /// send whose root the operator rejects again.
    fn correct(
        &mut self,
        context: PaymentContext<Key, Digest>,
        seq: u64,
        entries: Vec<OutEntry<Key>>,
        staged: &StagedSend,
    ) -> Result<StagedSend> {
        self.store
            .adopt_vector(&context, seq, self.cumulative_debit, &entries)
            .context("durably adopt corrective endpoint")?;
        let total = staged
            .authorization
            .body()
            .cumulative_debit()
            .checked_sub(self.cumulative_debit)
            .context("staged payment total is checked")?;
        let authorization = self.sign_batch(&context, &staged.entries, total)?;
        ensure!(
            authorization.body() != staged.authorization.body(),
            "corrective rejection repeated the rejected endpoint"
        );
        self.store
            .restage_payment(
                &staged.authorization,
                &authorization,
                &staged.entries,
                self.cumulative_debit,
            )
            .context("durably restage corrected payment")?;
        if let Some(pending) = self.pending_payment.as_mut() {
            pending.authorization = authorization.clone();
        }

        // The corrected context is operator-claimed data adopted only for signing: the
        // certified anchor gate still decides whether anything gets recorded.
        // Without a cached row there is no floor to pair it with, so the next fresh
        // payment re-reads the head instead.
        if self.cache.is_some() {
            self.store
                .adopt_context(&context)
                .context("durably adopt corrective context")?;
            if let Some(cache) = self.cache.as_mut() {
                cache.context = context.clone();
            }
        }
        Ok(StagedSend {
            context,
            authorization,
            entries: staged.entries.clone(),
            predecessor_state_root: staged.predecessor_state_root,
        })
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

    /// Resolves a staged pending send from settlement-anchored evidence, after a
    /// corrective rejection claimed an endpoint the wallet does not recognize.
    ///
    /// A live staged context is resubmitted unchanged (a lost-response retry). A cut context
    /// resolves by settlement-anchored arithmetic: once the staged epoch has certifiably
    /// finalized, the wallet's endpoint in a Merkle-verified opening of the finalized head
    /// decides commitment, and until then resolution errs and retries. The opening comes
    /// from the operator's head when it verifies and from the slice holders otherwise, so
    /// an operator that refuses or forges it can neither decide nor stall the resolution.
    async fn resolve_pending<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        staged: StagedSend,
    ) -> Result<PendingOutcome> {
        // Re-read the head to learn whether the staged epoch is still the live context:
        // the operator's head says so, or, without one, the chain's registration. The
        // registration singleton keeps naming an epoch after its close is admitted,
        // until finalization retires it, and an admitted close is fixed, so the exact
        // bytes can never be accepted again: only an unadmitted registration is live.
        let served = operator_head(ctx, operator, self.account(), &self.operator).await;
        let context = &staged.context;
        let live = match &served {
            Ok(head) => {
                head.context.epoch() == context.epoch() && head.context.anchor() == context.anchor()
            }
            Err(_) => chain
                .registration(ctx)
                .await
                .context("read the registered close")?
                .is_some_and(|registration| {
                    registration.epoch == context.epoch()
                        && registration.anchor == *context.anchor()
                        && registration.admitted.is_none()
                }),
        };
        if live {
            // The staged context is still live: resubmit the exact bytes unchanged.
            self.store
                .recovery_opening(&staged.predecessor_state_root)?
                .context("pending payment recovery opening is missing")?;
            return Ok(PendingOutcome::Live(Box::new(staged)));
        }

        // The staged epoch was cut, so the exact bytes can never be accepted again. The
        // endpoint chain is linear and single-slot, so commitment is decided from
        // settlement alone: epochs finalize in order, and once the staged epoch has
        // certifiably finalized, the wallet's own row in a verified opening of the
        // finalized head carries the staged successor endpoint exactly when the send
        // committed and the prior endpoint exactly when it never did.
        let status = chain
            .status(ctx)
            .await
            .context("read settlement finalization head")?;
        ensure!(
            status.deployment == self.deployment,
            "settlement status has an unexpected deployment"
        );
        ensure!(
            status
                .last_finalized
                .is_some_and(|finalized| finalized >= context.epoch()),
            "the staged epoch has not finalized, so its commitment is not yet decidable"
        );

        let endpoint = match served.and_then(|head| {
            self.verify_head(&head, &status)?;
            Ok(head.opening.leaf.state.cumulative_debit)
        }) {
            Ok(endpoint) => endpoint,
            Err(operator_error) => {
                let account = self.account();
                let opening = self
                    .holders
                    .validator_opening(ctx, chain, &account, &status)
                    .await
                    .map_err(|error| unusable_head(operator_error, error))?;
                self.retain_head(&status.state_root, &opening)?;

                // Only an operator head could have re-anchored the signing state on
                // its live context, and the cached context is at best the cut one
                // this send was staged under. Invalidate it, so the fresh stage reads
                // a live context instead of signing under a dead epoch.
                self.store
                    .clear_context()
                    .context("invalidate cached signing context")?;
                self.cache = None;
                opening.leaf.state.cumulative_debit
            }
        };
        let staged_endpoint = staged.authorization.body().cumulative_debit();
        let outcome = if endpoint == staged_endpoint {
            // The send committed. The operator is only an optional source of receipts,
            // never a verdict: an unanswered or unverifiable fetch still commits, with the
            // batch's receipts durably recorded as unheld.
            let total = staged_endpoint
                .checked_sub(self.cumulative_debit)
                .context("staged payment total is checked")?;
            let fetched = operator_rpc::accepted_batch(
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
            .filter(|accepted| Self::verify_accepted(accepted, &staged, total).is_ok());
            match fetched {
                Some(accepted) => PendingOutcome::Resolved(PaymentOutcome::Accepted(Box::new(
                    self.record_payment(accepted, &staged)?,
                ))),
                None => {
                    self.store
                        .finalize_payment_unheld(
                            &staged.authorization,
                            &staged.entries,
                            self.cumulative_debit,
                        )
                        .context("record finalized payment without receipts")?;
                    self.cumulative_debit = staged_endpoint;
                    self.pending_payment = None;
                    PendingOutcome::Resolved(PaymentOutcome::CommittedUnheld {
                        epoch: context.epoch(),
                        total,
                    })
                }
            }
        } else if endpoint == self.cumulative_debit {
            // Settlement's proof of non-commitment: no finalizable close ever included the
            // send, so abandoning cannot drop or double count a real transfer. The ledger
            // keeps the abandoned row and the slot frees for a fresh send.
            self.store
                .abandon_payment(&staged.authorization)
                .context("abandon stale staged payment")?;
            self.pending_payment = None;
            PendingOutcome::Abandoned
        } else {
            // A third value is reachable: an earlier acknowledged send advanced the
            // committed endpoint before its epoch finalized, and a Byzantine operator then
            // finalized a close omitting it, leaving the finalized endpoint below the
            // committed one. That omission is provable fraud with the held receipts, or
            // this wallet database is stale. Neither commit nor abandon: keep the slot.
            anyhow::bail!(
                "finalized endpoint {endpoint} matches neither the committed endpoint {} nor \
                 the staged successor {staged_endpoint}: the operator omitted an acknowledged \
                 send from the finalized close or this wallet database is stale",
                self.cumulative_debit
            )
        };

        Ok(outcome)
    }

    /// Verifies the served opening is this wallet's own row in settlement's exact head
    /// root, durably retains it for frozen-root recovery, opportunistically records
    /// accepted payments that finalized root covers, and re-anchors the optimistic
    /// signing state.
    ///
    /// This is the safety core of every operator head read: the opening travels through
    /// the operator but cannot be forged, because it must Merkle-verify against the
    /// certified state root. Retention lives in [`Self::retain_head`], the one
    /// chokepoint shared with validator-served openings, so every resolution that read
    /// the head leaves recovery evidence behind if the deployment later hard-faults
    /// frozen at this root.
    pub(super) fn verify_head(
        &mut self,
        head: &operator_rpc::PaymentHeadResponse,
        status: &StatusRecord,
    ) -> Result<()> {
        ensure!(
            status.state_root == head.root,
            "payer opening is not the exact settlement head"
        );
        check_opening(&head.opening, &head.root, &self.account())?;
        if self.retain_head(&head.root, &head.opening)? {
            self.cache_signing(&head.context, &head.root)?;
        }
        Ok(())
    }

    /// Durably retains a verified opening for frozen-root recovery and records the
    /// finalized payments its endpoint covers, returning whether the row is live.
    ///
    /// A row without live custody carries nothing a hard-fault claim could release, so
    /// only live openings are retained. The store refuses dead rows for the same reason.
    pub(super) fn retain_head(
        &mut self,
        root: &VectorRoot<Digest>,
        opening: &StateOpening<Key, Digest>,
    ) -> Result<bool> {
        let live = opening.leaf.state.active && opening.leaf.state.balance > 0;
        if live {
            self.store
                .retain_recovery_opening(root, opening)
                .context("durably retain payer state opening")?;
        }
        self.store
            .observe_finalized(opening.leaf.state.cumulative_debit)
            .context("record finalized payments")?;
        Ok(live)
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
        root: &VectorRoot<Digest>,
    ) -> Result<()> {
        if self.pending_withdrawal.is_some() || self.pending_withdrawal_claim.is_some() {
            return Ok(());
        }
        self.store
            .cache_context(context, root)
            .context("durably cache signing context")?;
        self.cache = Some(ContextCache {
            context: context.clone(),
            root: *root,
            epoch: context.epoch(),
        });
        Ok(())
    }

    /// Reads the payer head, verifies affordability against the live balance, and
    /// durably stages a fresh send.
    ///
    /// This is the fallback off the optimistic hot path: it runs for a wallet with no
    /// cached context (a fresh wallet, or one invalidated by a withdrawal) and for a
    /// local floor that cannot prove affordability. The verified head it reads re-caches
    /// the signing state, so it is structural at most once per wallet lifetime in steady
    /// operation: every later context move is learned from the corrective rejection.
    ///
    /// The operator's head is the fast path. When it is unreachable or unusable, the
    /// signing context is the chain's certified registration and the affordability
    /// floor is the slice holders' opening at the certified head, so the operator is
    /// left with nothing to do but accept the send.
    async fn stage_against_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        requested: &[Entry],
        total: u64,
    ) -> Result<StagedSend> {
        let operator_error = match operator_head(ctx, operator, self.account(), &self.operator)
            .await
        {
            Ok(head) => {
                let status = staging_status(ctx, chain, self.deployment).await?;
                match self.stage_head(&head, &status, total) {
                    Ok(()) => return self.stage_under(head.context, head.root, requested, total),
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
        root: VectorRoot<Digest>,
        requested: &[Entry],
        total: u64,
    ) -> Result<StagedSend> {
        let authorization = self.sign_batch(&context, requested, total)?;
        self.store
            .stage_payment(&authorization, requested, &root, self.cumulative_debit)
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
            predecessor_state_root: root,
        })
    }

    /// Admits the operator's head for staging: a live payer row whose live balance
    /// covers `total`, verified against the certified head and retained.
    fn stage_head(
        &mut self,
        head: &operator_rpc::PaymentHeadResponse,
        status: &StatusRecord,
        total: u64,
    ) -> Result<()> {
        ensure!(
            head.opening.leaf.state.active && head.opening.leaf.state.balance > 0,
            "payer opening is not live"
        );

        // Mid-epoch credits only grow the payer balance and debits are serialized here, so
        // affordability at the head read holds at acceptance.
        ensure!(
            head.state.balance >= total,
            "payer has insufficient available balance"
        );
        self.verify_head(head, status)
    }

    /// Stages without the operator's head: the signing context is the chain's
    /// certified registration and the affordability floor is the slice holders'
    /// opening at the certified head, verified, retained, and cached like an operator
    /// head. Returns the context to sign under and the root the opening is retained at.
    async fn stage_chain_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        total: u64,
    ) -> Result<(PaymentContext<Key, Digest>, VectorRoot<Digest>)> {
        let status = staging_status(ctx, chain, self.deployment).await?;
        let context = registered_context(ctx, chain, &self.operator).await?;
        let account = self.account();
        let opening = self
            .holders
            .validator_opening(ctx, chain, &account, &status)
            .await?;
        ensure!(
            opening.leaf.state.active && opening.leaf.state.balance > 0,
            "payer opening is not live"
        );

        // The floor covers every close through the finalized head, so the lower bound
        // adds only the credits held from the next epoch on.
        let floor_epoch = status
            .last_finalized
            .map_or(Some(0), |last| last.checked_add(1))
            .context("epoch overflow")?;
        ensure!(
            self.lower_bound(&opening.leaf.state, floor_epoch)? >= total,
            "payer has insufficient available balance"
        );
        self.retain_head(&status.state_root, &opening)?;
        self.cache_signing(&context, &status.state_root)?;
        Ok((context, status.state_root))
    }

    /// Confirms the send's context is a settlement registration through a certified
    /// anchor read, and only then durably commits its verified receipts.
    ///
    /// The anchor commits the entire epoch context (deployment, boundary, liability,
    /// and the chain-assigned absolute deadlines) and anchor records persist for the
    /// life of the deployment, so a certified anchor equal to the send's context proves
    /// settlement registered exactly this payment context. The operator registers on
    /// the chain before it releases a receipt, so an absent anchor is read lag and is
    /// polled through briefly rather than failing the payment.
    ///
    /// Every live-path acceptance commits through here, so the registration gate is
    /// structural. The only other endpoint-advancing paths are in [`Self::resolve_pending`],
    /// where a Merkle-verified finalized root itself is the proof of registration.
    async fn confirm_and_record<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        staged: &StagedSend,
        accepted: operator_rpc::AcceptedBatchResponse,
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        let context = &staged.context;
        for attempt in 0..CONFIRM_ATTEMPTS {
            match chain.anchor(ctx, context.epoch()).await {
                Ok(Some(anchor)) => {
                    ensure!(
                        anchor == *context.anchor(),
                        "confirm payment registration: another anchor is registered for the epoch"
                    );
                    return self.record_payment(accepted, staged);
                }
                Ok(None) if attempt + 1 < CONFIRM_ATTEMPTS => {}
                Ok(None) => anyhow::bail!(
                    "confirm payment registration: the payment context is not registered"
                ),
                Err(error) if attempt + 1 == CONFIRM_ATTEMPTS => {
                    return Err(error.context("confirm payment registration"));
                }
                Err(_) => {}
            }
            ctx.sleep(CONFIRM_POLL).await;
        }
        unreachable!("the confirmation loop returns on its final attempt")
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
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        let receipt_count = self
            .store
            .commit_payment(
                &accepted.acceptance,
                &staged.authorization,
                &staged.entries,
                self.cumulative_debit,
                self.receipt_count,
            )
            .context("commit accepted receipts")?;
        self.cumulative_debit = staged.authorization.body().cumulative_debit();
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
        head.context.operator() == bound,
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
fn merge_entries(mut merged: Vec<OutEntry<Key>>, deltas: &[Entry]) -> Result<Vec<OutEntry<Key>>> {
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
