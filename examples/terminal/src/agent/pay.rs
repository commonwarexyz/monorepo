//! The payment flow: staging, submission, retry resolution, and receipt commitment.

use super::{Agent, store::PendingPayment};
use crate::{
    operator::rpc as operator_rpc,
    protocol::{Key, deployment, operator_key},
    settlement::rpc as settlement_rpc,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    commitment::{VectorKind, VectorRoot},
    payment::{Entry, PaymentContext, SignedSend},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::Network;
use std::net::SocketAddr;

/// One send resolved and ready for the shared accept, verify, and commit tail.
struct StagedSend {
    context: PaymentContext<Key, Digest>,
    send: SignedSend<Key, Digest>,
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
    /// Pays every `(receiver index, amount)` entry with one batched send.
    ///
    /// A send this operator deterministically rejects must never be staged: a retry resubmits the
    /// exact staged bytes. Those bytes bind one `(anchor, epoch)`, so once that epoch is cut they
    /// can never be accepted again. A retry therefore re-reads the head first: while the staged
    /// context is still live it resubmits unchanged (a lost-response retry), and once the
    /// operator has moved past it the wallet concludes commitment from settlement alone, by
    /// reading its own endpoint out of a Merkle-verified opening of a finalized root. A
    /// committed send finishes locally, and a send the finalized endpoint provably excludes is
    /// abandoned and re-staged against the live context, so the wallet can never drop or double
    /// count a real transfer.
    pub(crate) async fn pay<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        entries: &[(usize, u64)],
    ) -> Result<PaymentOutcome> {
        let (requested, total) = self.payment_entries(entries)?;
        let staged = match self
            .pending_payment
            .as_ref()
            .map(|pending| (pending.send.clone(), pending.recovery_root))
        {
            Some((pending_send, recovery_root)) => {
                match self
                    .resolve_pending(
                        network,
                        settlement,
                        operator,
                        &pending_send,
                        recovery_root,
                        &requested,
                    )
                    .await?
                {
                    PendingOutcome::Live(staged) => *staged,
                    PendingOutcome::Resolved(outcome) => return Ok(outcome),
                    PendingOutcome::Abandoned => {
                        self.stage_against_head(network, settlement, operator, &requested, total)
                            .await?
                    }
                }
            }
            None => {
                self.stage_against_head(network, settlement, operator, &requested, total)
                    .await?
            }
        };
        let accepted = self
            .submit_and_commit(network, settlement, operator, staged)
            .await?;
        Ok(PaymentOutcome::Accepted(Box::new(accepted)))
    }

    /// Validates and canonically orders the requested batch entries with their checked total.
    fn payment_entries(&self, entries: &[(usize, u64)]) -> Result<(Vec<Entry<Key>>, u64)> {
        let mut requested = Vec::with_capacity(entries.len());
        let mut total = 0_u64;
        for (receiver, amount) in entries {
            let receiver = self.receivers[receiver % self.receivers.len()].key.clone();
            ensure!(
                receiver != self.account(),
                "self-payments are omitted from this operator"
            );
            total = total
                .checked_add(*amount)
                .context("payment total overflow")?;
            requested.push(Entry::new(receiver, *amount).context("stage payment entry")?);
        }
        requested.sort_unstable_by(|left, right| left.recipient().cmp(right.recipient()));
        Ok((requested, total))
    }

    /// Resolves a staged pending send before it is submitted.
    ///
    /// A live staged context is resubmitted unchanged (a lost-response retry). A cut context
    /// resolves by settlement-anchored arithmetic: once the staged epoch has finalized, the
    /// wallet's endpoint in a Merkle-verified opening of the finalized head decides
    /// commitment, and until then resolution errs and retries. The opening still travels
    /// through the operator's head, so the independence is about trust, not availability:
    /// the operator can refuse to serve it but cannot forge it, and sustained refusal ends
    /// in settlement's liveness deadlines and the hard-fault recovery path.
    async fn resolve_pending<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        pending_send: &SignedSend<Key, Digest>,
        recovery_root: VectorRoot<Digest>,
        requested: &[Entry<Key>],
    ) -> Result<PendingOutcome> {
        ensure!(
            pending_send.body().entries() == requested,
            "another payment retry is pending"
        );

        // Re-read the head to learn whether the staged epoch is still the operator's live context.
        let head = operator_rpc::payment_head(
            network,
            operator,
            operator_rpc::PaymentHeadRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        ensure!(
            head.context.operator() == &operator_key(),
            "payment context has an unexpected operator"
        );
        let context = PaymentContext::new(
            *pending_send.body().anchor(),
            pending_send.body().epoch(),
            operator_key(),
        );
        if head.context.epoch() == context.epoch() && head.context.anchor() == context.anchor() {
            // The staged context is still live: resubmit the exact bytes unchanged.
            self.store
                .recovery_opening(&recovery_root)?
                .context("pending payment recovery opening is missing")?;
            return Ok(PendingOutcome::Live(Box::new(StagedSend {
                context,
                send: pending_send.clone(),
                predecessor_state_root: recovery_root,
            })));
        }

        // The staged epoch was cut, so the exact bytes can never be accepted again. The
        // endpoint chain is linear and single-slot, so commitment is decided from
        // settlement alone: epochs finalize in order, and once the staged epoch has
        // finalized, the wallet's own row in a verified opening of the finalized head
        // carries the staged successor endpoint exactly when the send committed and the
        // prior endpoint exactly when it never did.
        let settlement_status = settlement_rpc::status(network, settlement)
            .await
            .context("read settlement finalization head")?;
        ensure!(
            settlement_status.deployment == deployment(),
            "settlement status has an unexpected deployment"
        );
        ensure!(
            settlement_status
                .last_finalized
                .is_some_and(|finalized| finalized >= context.epoch()),
            "the staged epoch has not finalized, so its commitment is not yet decidable"
        );

        self.verify_head(&head, &settlement_status)?;
        let endpoint = head.opening.leaf.state.cumulative_debit;
        let staged_endpoint = pending_send.body().cumulative_debit();
        let outcome = if endpoint == staged_endpoint {
            // The send committed. The operator is only an optional source of receipts,
            // never a verdict: an unanswered or unverifiable fetch still commits, with the
            // batch's receipts durably recorded as unheld.
            let fetched = operator_rpc::accepted_batch(
                network,
                operator,
                operator_rpc::AcceptSendRequest {
                    send: pending_send.clone(),
                },
            )
            .await
            .ok()
            .flatten()
            .filter(|accepted| Self::verify_accepted(accepted, pending_send, &context).is_ok());
            match fetched {
                Some(accepted) => PendingOutcome::Resolved(PaymentOutcome::Accepted(Box::new(
                    self.record_payment(accepted, pending_send)?,
                ))),
                None => {
                    let total = pending_send
                        .body()
                        .total()
                        .context("staged payment total is checked")?;
                    self.store
                        .finalize_payment_unheld(pending_send, self.cumulative_debit)
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
                .abandon_payment(pending_send)
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
    /// root, durably retains it for frozen-root recovery, then opportunistically records
    /// accepted payments that finalized root covers.
    ///
    /// This is the safety core of every head read: the opening travels through the
    /// operator but cannot be forged, because it must Merkle-verify against settlement's
    /// own root. Retention lives here, the one chokepoint, so every resolution that read
    /// the head leaves recovery evidence behind if the deployment later hard-faults
    /// frozen at this root.
    pub(super) fn verify_head(
        &mut self,
        head: &operator_rpc::PaymentHeadResponse,
        settlement_status: &settlement_rpc::StatusResponse,
    ) -> Result<()> {
        ensure!(
            settlement_status.state_root == head.root,
            "payer opening is not the exact settlement head"
        );
        ensure!(
            head.opening.leaf.account == self.account(),
            "payer opening belongs to another account"
        );
        head.opening
            .proof
            .verify::<Sha256>(
                VectorKind::State,
                &head.root,
                head.opening.leaf.encode().as_ref(),
            )
            .context("verify payer state opening")?;

        // A row without live custody carries nothing a hard-fault claim could release, so
        // only live openings are retained. The store refuses dead rows for the same reason.
        if head.opening.leaf.state.active && head.opening.leaf.state.balance > 0 {
            self.store
                .retain_recovery_opening(&head.root, &head.opening)
                .context("durably retain payer state opening")?;
        }
        self.store
            .observe_finalized(head.opening.leaf.state.cumulative_debit)
            .context("record finalized payments")?;
        Ok(())
    }

    /// Reads the payer head, verifies affordability, and durably stages a fresh send.
    async fn stage_against_head<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        requested: &[Entry<Key>],
        total: u64,
    ) -> Result<StagedSend> {
        let head = operator_rpc::payment_head(
            network,
            operator,
            operator_rpc::PaymentHeadRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        ensure!(
            head.context.operator() == &operator_key(),
            "payment context has an unexpected operator"
        );
        let settlement_status = settlement_rpc::status(network, settlement)
            .await
            .context("read settlement payment head")?;
        ensure!(
            settlement_status.deployment == deployment(),
            "settlement status has an unexpected deployment"
        );
        ensure!(
            !settlement_status.hard_faulted,
            "settlement is permanently hard-faulted"
        );
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
        self.verify_head(&head, &settlement_status)?;
        let send = SignedSend::sign_next_batch(
            &head.context,
            self.wallet.signer(),
            requested.to_vec(),
            self.cumulative_debit,
        )
        .context("sign payment")?;
        self.store
            .stage_payment(&send, &head.root, self.cumulative_debit)
            .context("durably stage payment")?;
        self.pending_payment = Some(PendingPayment {
            send: send.clone(),
            recovery_root: head.root,
        });
        Ok(StagedSend {
            context: head.context,
            send,
            predecessor_state_root: head.root,
        })
    }

    /// Submits the staged send, confirms its live registration, and commits its receipts.
    async fn submit_and_commit<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        staged: StagedSend,
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        let StagedSend {
            context,
            send,
            predecessor_state_root,
        } = staged;

        // The ledger tracks the slot's lifecycle: the send is durably marked submitted
        // before the wire attempt, so its row never claims less than what may have
        // reached the operator.
        self.store
            .mark_payment_submitted(&send)
            .context("mark payment submitted")?;
        let accepted = operator_rpc::accept_send(
            network,
            operator,
            operator_rpc::AcceptSendRequest { send: send.clone() },
        )
        .await
        .context("submit payment")?;
        Self::verify_accepted(&accepted, &send, &context)?;
        self.confirm_and_record(
            network,
            settlement,
            &context,
            predecessor_state_root,
            accepted,
            &send,
        )
        .await
    }

    /// Confirms the send's context is settlement's live registration and only then durably
    /// commits its verified receipts.
    ///
    /// Every live-path acceptance commits through here, so the registration gate is
    /// structural. The only other endpoint-advancing paths are in [`Self::resolve_pending`],
    /// where a Merkle-verified finalized root itself is the proof of registration.
    async fn confirm_and_record<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        context: &PaymentContext<Key, Digest>,
        predecessor_state_root: VectorRoot<Digest>,
        accepted: operator_rpc::AcceptedBatchResponse,
        send: &SignedSend<Key, Digest>,
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        settlement_rpc::confirm_registration(
            network,
            settlement,
            settlement_rpc::RegistrationQuery {
                epoch: context.epoch(),
                anchor: *context.anchor(),
                state_root: predecessor_state_root,
            },
        )
        .await
        .context("confirm payment registration")?;
        self.record_payment(accepted, send)
    }

    /// Confirms an operator acceptance is the exact staged send with valid receipts.
    fn verify_accepted(
        accepted: &operator_rpc::AcceptedBatchResponse,
        send: &SignedSend<Key, Digest>,
        context: &PaymentContext<Key, Digest>,
    ) -> Result<()> {
        let total = send
            .body()
            .total()
            .context("staged payment total is checked")?;
        ensure!(
            accepted.epoch == context.epoch()
                && accepted.total == total
                && accepted.acceptance.send == *send,
            "operator returned another payment"
        );
        accepted
            .acceptance
            .verify(context)
            .context("verify operator receipts")
    }

    /// Durably commits a verified acceptance and advances the wallet-local debit endpoint.
    fn record_payment(
        &mut self,
        accepted: operator_rpc::AcceptedBatchResponse,
        send: &SignedSend<Key, Digest>,
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        let receipt_count = self
            .store
            .commit_payment(
                &accepted.acceptance,
                self.cumulative_debit,
                self.receipt_count,
            )
            .context("commit accepted receipts")?;
        self.cumulative_debit = send.body().cumulative_debit();
        self.pending_payment = None;
        self.receipt_count = receipt_count;
        Ok(accepted)
    }
}
