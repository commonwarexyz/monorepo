//! The receive lane: verified incoming intake and anchored reconciliation.

use super::{
    Agent,
    store::IncomingRecord,
    wallet::{ReceiptEpoch, invalidated_epoch, receipt_epoch},
};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{AdmittedRootsResponse, FaultRecord, HardFaultReasonResponse, StatusRecord},
        tx::{ChallengeRequest, SettlementTx},
    },
    operator::rpc as operator_rpc,
    protocol::{Key, Receipt},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::{AckWitness, Challenge, ChallengeKind, EntryWitness, HigherEntryLookup},
    payment::PaymentContext,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use std::net::SocketAddr;

/// What one reconciliation pass decided across the epochs it examined.
///
/// The heartbeat surfaces these as enforcement events, so the conviction arc is visible in the
/// running wallet, not only in tests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReconcileSummary {
    /// Epochs whose held credits the committed close covered, marked reconciled.
    pub(crate) reconciled: Vec<u64>,
    /// Epochs whose omitted credit was convicted with a proven `HigherAckEntry` challenge.
    pub(crate) convicted: Vec<u64>,
    /// Epochs whose admitted close was invalidated before finalization.
    pub(crate) protected: Vec<u64>,
    /// Epochs whose held credit can no longer be enforced: a finalized close understated it
    /// past the window, or its close never admitted before settlement faulted.
    pub(crate) unenforceable: Vec<u64>,
    /// Epochs that finalized while the operator still withholds the committed-side evidence
    /// needed to verify or convict, reported once per stretch of withholding. The epoch keeps
    /// retrying and self-heals if the evidence is later served.
    pub(crate) withheld: Vec<u64>,
}

impl ReconcileSummary {
    #[cfg(test)]
    pub(crate) const fn is_empty(&self) -> bool {
        self.reconciled.is_empty()
            && self.convicted.is_empty()
            && self.protected.is_empty()
            && self.unenforceable.is_empty()
            && self.withheld.is_empty()
    }
}

/// The verdict for one held receipt against the anchored committed close.
enum EntryVerdict {
    /// The committed terminal entry covered the held receipt.
    Covered,
    /// Served evidence was unavailable, unanchored, or unprovable before publication.
    Refused,
    /// Challenge delivery began but its certified outcome is unknown.
    Unconfirmed,
    /// The omission was convicted with a proven challenge.
    Convicted,
    /// A finalized close understated the held receipt past the challenge window.
    Uncovered,
}

impl Agent {
    /// Acquires incoming receipts as live conditional preconfirmations or verified finalized credits.
    ///
    /// Signatures, entry membership, recipient, and the registered anchor authenticate each
    /// receipt. First-time historical credit also requires finalized coverage of both its
    /// cumulative amount and count. Previously held evidence remains available for reconciliation.
    /// Each credited row commits with its cursor before another remote read. Skipped rows
    /// share the next cursor write, including when later evidence is unavailable. Unresolved
    /// evidence retries its row while preceding credits remain durable. Per-edge deltas make
    /// retries idempotent.
    pub(crate) async fn intake_incoming<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<()> {
        let page = operator_rpc::incoming_payments(
            ctx,
            operator,
            operator_rpc::IncomingPaymentsRequest {
                account: self.account(),
                cursor: self.incoming.cursor,
            },
        )
        .await
        .context("fetch incoming payments")?;
        if page.pairs.is_empty() {
            return Ok(());
        }

        let mut sequence = self.incoming.cursor;
        for incoming in &page.pairs {
            ensure!(
                incoming.sequence > sequence,
                "incoming page sequences are not strictly increasing after the requested cursor"
            );
            sequence = incoming.sequence;
        }
        ensure!(
            page.next_cursor == sequence,
            "incoming page cursor does not match its last sequence"
        );

        let mut cursor = self.incoming.cursor;
        let mut result = Ok(());
        for incoming in page.pairs {
            let record = match self
                .incoming_record(ctx, chain, operator, incoming.receipt)
                .await
            {
                Ok(record) => record,
                Err(error) => {
                    result = Err(error);
                    break;
                }
            };
            cursor = incoming.sequence;
            if let Some(record) = record {
                self.incoming = self
                    .store
                    .record_incoming(&[record], cursor)
                    .context("persist verified incoming receipt")?;
                self.last_reconciled_epoch = self.store.last_reconciled_epoch()?;
            }
        }
        if cursor > self.incoming.cursor {
            self.incoming = self
                .store
                .record_incoming(&[], cursor)
                .context("persist processed incoming cursor")?;
        }
        result
    }

    /// Verifies one receipt's credit before its cursor can advance.
    async fn incoming_record<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        receipt: Receipt,
    ) -> Result<Option<IncomingRecord>> {
        let account = self.account();
        let body = receipt.ack.body();
        let epoch = body.epoch();
        let context = PaymentContext::new(*body.anchor(), epoch, self.operator.clone());
        if receipt.verify::<Sha256>(&context).is_err() || receipt.recipient != account {
            return Ok(None);
        }
        let payer = body.payer().clone();
        let prior = self.store.held_edge(&payer, epoch)?.unwrap_or((0, 0));
        if receipt.cumulative <= prior.0 || receipt.count <= prior.1 {
            return Ok(None);
        }
        match receipt_epoch(ctx, chain, self.deployment, &context).await? {
            ReceiptEpoch::Live(_) => {}
            ReceiptEpoch::Finalized(admitted) => {
                let lookup = self
                    .incoming_lookup(ctx, chain, operator, epoch, &admitted, &payer)
                    .await?;
                let (cumulative, count) =
                    lookup.resolve::<Sha256>(&admitted.roots.change, &payer, &account)?;
                if cumulative < receipt.cumulative || count < receipt.count {
                    return Ok(None);
                }
            }
            ReceiptEpoch::Invalidated => return Ok(None),
            ReceiptEpoch::Unresolved | ReceiptEpoch::Faulted(_) => {
                anyhow::bail!("incoming receipt settlement is not yet decidable");
            }
        }
        Ok(Some(IncomingRecord {
            id: Sha256::hash(&[body.encode().as_ref()]),
            payer,
            epoch,
            cumulative: receipt.cumulative,
            count: receipt.count,
            amount: receipt.cumulative - prior.0,
            receipt,
        }))
    }

    /// Reconciles held incoming credits against the committed close, convicting understatement.
    ///
    /// This is a background assurance loop that never gates payments or claims. For every epoch
    /// holding credits, per payer edge, the committed close's public terminal entry must be at
    /// or above the wallet's highest held cumulative credit and payment count. The trust story
    /// is anchored: the chain certifies the batch identity and change root of the close it
    /// admitted for the epoch (read with the recency bound, so the admitted-or-absent verdict
    /// holds at a certified tip no older than the recency threshold), and committed-side
    /// evidence is trusted only when it verifies under that anchor. The evidence comes from
    /// validators, which retain the complete close. The operator is a fallback when every
    /// validator declines. Missing, unanchored, or unprovable evidence leaves that epoch
    /// unresolved without blocking other epochs. After finalization the challenge window
    /// is closed, so withheld evidence raises an alarm and remains retryable at every age.
    ///
    /// The challenge window sits between admission and finalization. On the first held receipt
    /// that exceeds the anchored committed entry while that window is open, the wallet convicts
    /// the close with one [`Challenge::HigherAckEntry`] transaction whose proven outcome is
    /// read back certified, records protection durably, and stops, because one proven
    /// challenge invalidates the whole close. A certified invalidation boundary also establishes
    /// protection without attributing the challenge. When the anchored entry covers every held receipt
    /// and the epoch has finalized, the wallet marks the epoch reconciled. The two enforcement
    /// dead ends, a finalized close that understated a held receipt past the window and a
    /// registered epoch whose close never admitted before settlement faulted, are recorded
    /// loudly rather than skipped.
    pub(crate) async fn reconcile<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<ReconcileSummary> {
        let mut summary = ReconcileSummary::default();
        let epochs = self
            .store
            .unreconciled_incoming_epochs()
            .context("read unreconciled incoming epochs")?;
        if epochs.is_empty() {
            return Ok(summary);
        }
        let status = chain
            .status(ctx)
            .await
            .context("read settlement reconciliation head")?;
        ensure!(
            status.deployment == self.deployment,
            "settlement status has an unexpected deployment"
        );
        let operator_key = self.operator.clone();
        for epoch in epochs {
            // Isolate each epoch: a soft per-epoch failure retries next heartbeat and must not
            // shadow the higher epochs, but a store fault poisons the wallet and is fatal.
            if let Err(error) = self
                .reconcile_epoch(
                    ctx,
                    chain,
                    operator,
                    epoch,
                    &status,
                    &operator_key,
                    &mut summary,
                )
                .await
            {
                self.store
                    .ensure_usable()
                    .context("reconciliation aborted by a store fault")?;
                let _ = error;
            }
        }
        Ok(summary)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one reconcile step, one call site"
    )]
    async fn reconcile_epoch<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        epoch: u64,
        status: &StatusRecord,
        operator_key: &Key,
        summary: &mut ReconcileSummary,
    ) -> Result<()> {
        let held = self
            .store
            .held_receipts(epoch, operator_key)
            .context("read held receipts")?;
        if held.is_empty() {
            return Ok(());
        }
        let account = self.account();

        // The anchor is the chain's own admission record for this epoch, recency-bounded.
        // An unreachable or lagging chain is a soft retry. Intake only stored
        // chain-registered receipts, so registration itself needs no re-check here.
        let fault = if status.hard_faulted {
            chain.fault(ctx).await?
        } else {
            None
        };
        let Ok(admitted) = chain.admitted(ctx, epoch).await else {
            return Ok(());
        };
        let Some(admitted) = admitted else {
            // No close admitted yet. If settlement faulted, this epoch's close never will, so
            // its held credit is enforcement-dead: record it loudly rather than retry forever.
            if status.hard_faulted {
                self.store
                    .record_unenforceable(epoch)
                    .context("record unenforceable epoch")?;
                summary.unenforceable.push(epoch);
            }
            return Ok(());
        };

        if !admitted.finalized
            && let Some(fault) = fault
            && invalidated_epoch(ctx, chain, epoch, status, &fault).await?
        {
            self.store.record_protected(epoch)?;
            self.withheld.remove(&epoch);
            summary.protected.push(epoch);
            return Ok(());
        }

        let mut uncovered = false;
        let mut refused = false;
        for entry in &held {
            match self
                .assess_entry(ctx, chain, operator, epoch, &admitted, &account, entry)
                .await
            {
                // One proven challenge invalidates the whole close, so record it immediately and
                // stop: continuing would resubmit distinct evidence under the same batch and trip
                // the chain's evidence-replay guard, aborting before the conviction is recorded.
                EntryVerdict::Convicted => {
                    self.store
                        .record_protected(epoch)
                        .context("record protected outcome")?;
                    self.withheld.remove(&epoch);
                    summary.convicted.push(epoch);
                    return Ok(());
                }
                // An attempted challenge may already have taken effect. Wait for its certified
                // outcome before submitting distinct evidence under the same batch.
                EntryVerdict::Unconfirmed => return Ok(()),
                // Unavailable evidence for one payer does not shadow independent payer edges.
                EntryVerdict::Refused => refused = true,
                EntryVerdict::Uncovered => uncovered = true,
                EntryVerdict::Covered => {}
            }
        }

        if uncovered {
            self.store
                .record_unenforceable(epoch)
                .context("record unenforceable epoch")?;
            self.withheld.remove(&epoch);
            summary.unenforceable.push(epoch);
        } else if refused {
            // Finalized close evidence remains accountable at every age. An unavailable
            // edge stays unresolved and alarms once until evidence is served.
            if admitted.finalized && self.withheld.insert(epoch) {
                summary.withheld.push(epoch);
            }
        } else if admitted.finalized {
            self.store
                .mark_reconciled(epoch)
                .context("record reconciled epoch")?;
            self.withheld.remove(&epoch);
            summary.reconciled.push(epoch);
            self.last_reconciled_epoch = Some(
                self.last_reconciled_epoch
                    .map_or(epoch, |last| last.max(epoch)),
            );
        }
        Ok(())
    }

    /// Fetches committed entry evidence from validators, with an authenticated operator fallback.
    async fn incoming_lookup<E: Env>(
        &mut self,
        ctx: &E,
        chain: &Client,
        operator: SocketAddr,
        epoch: u64,
        admitted: &AdmittedRootsResponse,
        payer: &Key,
    ) -> Result<HigherEntryLookup<Key, Digest>> {
        let account = self.account();
        if let Ok(lookup) = self
            .holders
            .committed_entry(ctx, chain, admitted, payer, &account)
            .await
        {
            return Ok(lookup);
        }
        let evidence = operator_rpc::committed_entry(
            ctx,
            operator,
            operator_rpc::CommittedEntryRequest {
                epoch,
                payer: payer.clone(),
                recipient: account,
            },
        )
        .await?;
        ensure!(
            evidence.batch_id == admitted.batch_id && evidence.change_root == admitted.roots.change,
            "committed entry differs from the certified close"
        );
        Ok(evidence.lookup)
    }

    /// Assesses one held receipt and publishes its challenge when undercoverage is provable.
    ///
    /// Served evidence that is unavailable, unanchored, or unprovable before a challenge is
    /// attempted is retryable independently. Once delivery begins, an unconfirmed outcome
    /// stops this epoch so the caller never submits distinct evidence under the same batch.
    #[allow(clippy::too_many_arguments, reason = "one assessment, one call site")]
    async fn assess_entry<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        epoch: u64,
        admitted: &AdmittedRootsResponse,
        account: &Key,
        held: &super::store::HeldEntry,
    ) -> EntryVerdict {
        let Ok(lookup) = self
            .incoming_lookup(ctx, chain, operator, epoch, admitted, &held.payer)
            .await
        else {
            return EntryVerdict::Refused;
        };

        // Resolving served evidence is a cryptographic check on an untrusted party, so a
        // failure is a retryable refusal rather than a fatal error.
        let Ok((cumulative, count)) =
            lookup.resolve::<Sha256>(&admitted.roots.change, &held.payer, account)
        else {
            return EntryVerdict::Refused;
        };
        if cumulative >= held.cumulative && count >= held.count {
            return EntryVerdict::Covered;
        }
        if admitted.finalized {
            return EntryVerdict::Uncovered;
        }

        // The lookup proves the HigherAckEntry condition. The immutable first fault
        // permits exact attribution; an earlier fault leaves this attempt unresolved
        // until a certified invalidation boundary is available.
        let challenge = Challenge::HigherAckEntry {
            entry: Box::new(EntryWitness {
                ack: AckWitness::from_ack(&held.receipt.ack),
                recipient: account.clone(),
                cumulative: held.cumulative,
                count: held.count,
                opening: held.receipt.opening.clone(),
            }),
            sender: Box::new(lookup),
        };
        let tx = SettlementTx::Challenge(ChallengeRequest {
            deployment: self.deployment,
            batch_id: admitted.batch_id,
            evidence: challenge.encode(),
        });
        if chain.deliver(ctx, &tx).await.is_err() {
            return EntryVerdict::Unconfirmed;
        }
        for _ in 0..EFFECT_ATTEMPTS {
            let Ok(fault) = chain.fault(ctx).await else {
                return EntryVerdict::Unconfirmed;
            };
            if let Some(fault) = fault {
                let reason = match fault {
                    FaultRecord::Faulted(reason) => reason,
                    FaultRecord::Settling(settlement) => settlement.reason,
                };
                return if matches!(
                    reason,
                    HardFaultReasonResponse::ProvenChallenge { batch_id, kind }
                        if batch_id == admitted.batch_id && kind == ChallengeKind::HigherAckEntry
                ) {
                    EntryVerdict::Convicted
                } else {
                    EntryVerdict::Unconfirmed
                };
            }
            ctx.sleep(POLL).await;
        }
        EntryVerdict::Unconfirmed
    }
}
