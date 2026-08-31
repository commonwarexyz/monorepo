//! The receive lane: verified incoming intake and anchored reconciliation.

use super::{Agent, store::IncomingRecord};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{AdmittedRootsResponse, FaultRecord, HardFaultReasonResponse},
        tx::{ChallengeRequest, SettlementTx},
    },
    operator::rpc as operator_rpc,
    protocol::{Key, Payment},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::{Challenge, ChallengeKind},
    payment::{PaymentContext, PaymentWitness},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Sha256, sha256::Digest};
use std::net::SocketAddr;

/// What one reconciliation pass decided across the epochs it examined.
///
/// The heartbeat surfaces these as enforcement events, so the conviction arc is visible in the
/// running wallet, not only in tests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReconcileSummary {
    /// Epochs whose held credits the committed close covered, marked reconciled.
    pub(crate) reconciled: Vec<u64>,
    /// Epochs whose omitted credit was convicted with a proven `HigherShardTip` challenge.
    pub(crate) convicted: Vec<u64>,
    /// Epochs whose held credit can no longer be enforced: a finalized close understated it
    /// past the window, or its close never admitted and settlement faulted.
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
            && self.unenforceable.is_empty()
            && self.withheld.is_empty()
    }
}

/// The verdict for one held receipt against the anchored committed close.
enum ShardVerdict {
    /// The committed tip covered the held receipt.
    Covered,
    /// Operator-served evidence was unavailable, unanchored, or unprovable: retry the epoch.
    Refused,
    /// The omission was convicted with a proven challenge.
    Convicted,
    /// A finalized close understated the held receipt past the challenge window.
    Uncovered,
}

impl Agent {
    /// Pulls, verifies, settlement-anchors, and durably persists the pairs newly crediting this
    /// wallet.
    ///
    /// This is the receiver's intake, folded into the balance heartbeat. A receiver may rely on
    /// a payment exactly when its verified pair is durably held: a balance read from the
    /// operator's head is an observation, not reliance-grade. Every fetched pair is fully
    /// verified, sends grouped by transaction id and each distinct send verified once, then the
    /// operator receipt, its exact linkage, and its recipient. It is then anchored: the pair's
    /// `(epoch, anchor)` must be the anchor the chain certifiably registered for that epoch,
    /// read with the recency bound so a proven absence holds at a certified tip no older than
    /// the recency threshold. A receipt over an operator-chosen anchor with no settlement
    /// obligation has no
    /// close to adjudicate against and can never be enforced, so it is not reliance-grade.
    /// Unverifiable and unanchored pairs are ignored and never stored, yet the durable cursor
    /// still advances past them so a poisoned entry cannot wedge intake. The pairs and the
    /// advanced cursor commit together, so reliance never outruns durability, and a lost
    /// response refetches the exact page and reinserts it idempotently.
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

        let account = self.account();
        let operator_key = self.operator.clone();
        let mut verified_sends = std::collections::BTreeSet::<Digest>::new();
        let mut anchors = std::collections::BTreeMap::<u64, Option<Digest>>::new();
        let mut records = Vec::with_capacity(page.pairs.len());
        for incoming in page.pairs {
            let (send, receipt) = incoming.payment.into_parts();
            let context = PaymentContext::new(
                *send.body().anchor(),
                send.body().epoch(),
                operator_key.clone(),
            );
            let tx_id = send.tx_id::<Sha256>();
            let tx_digest = *tx_id.digest();

            // Verify each distinct send once, then the receipt, its linkage, and its recipient.
            if !verified_sends.contains(&tx_digest) {
                if send.verify(&context).is_err() {
                    continue;
                }
                verified_sends.insert(tx_digest);
            }
            if receipt.verify(&context).is_err()
                || !receipt.links(send.body(), &tx_id)
                || receipt.body().recipient() != &account
            {
                continue;
            }

            // Anchor the context to the chain's certified registration. A read failure
            // aborts the whole intake so the cursor never advances past an unconfirmed pair.
            // A proven absence or mismatch skips the pair like an invalid one.
            let epoch = send.body().epoch();
            let anchor = *send.body().anchor();
            let registered_anchor = match anchors.get(&epoch) {
                Some(cached) => *cached,
                None => {
                    let fetched = chain
                        .anchor(ctx, epoch)
                        .await
                        .context("read settlement registration anchor")?;
                    anchors.insert(epoch, fetched);
                    fetched
                }
            };
            if registered_anchor != Some(anchor) {
                continue;
            }
            let body = receipt.body();
            records.push(IncomingRecord {
                tx_id: tx_digest,
                payer: send.body().payer().clone(),
                epoch,
                anchor,
                shard: body.shard(),
                cumulative_shard_credit: body.cumulative_shard_credit(),
                receipt_index: body.index(),
                amount: body.amount(),
                cursor: incoming.cursor,
                pair: Payment::from_parts_unchecked(send, receipt),
            });
        }
        self.incoming = self
            .store
            .record_incoming(&records, page.next_cursor)
            .context("persist verified incoming pairs")?;
        Ok(())
    }

    /// Reconciles held incoming credits against the committed close, convicting understatement.
    ///
    /// This is a background assurance loop that never gates payments or claims. For every epoch
    /// holding credits, per receive shard, the committed close's public credit tip must be at or
    /// above the wallet's highest held cumulative credit and receipt index. The trust story is
    /// anchored: the chain certifies the batch identity and change root of the close it admitted
    /// for the epoch (read with the recency bound, so the admitted-or-absent verdict holds at a
    /// certified tip no older than the recency threshold), and operator-served committed-side
    /// evidence is trusted
    /// only when it matches that anchor exactly. Operator refusal, an unanchored or unprovable
    /// lookup, and a per-epoch fault are all the documented availability dependence: that epoch
    /// stays unreconciled and retries without shadowing the others. The operator can never buy
    /// coverage with a fabricated root, but conviction and the understatement alarm both need
    /// the operator-served lookup, and an admitted close has no settlement-clock backstop for
    /// serving it. An epoch that finalizes while that evidence is still withheld is therefore
    /// surfaced as withheld and kept retrying, the availability dependence the protocol places
    /// on its embedding.
    ///
    /// The challenge window sits between admission and finalization. On the first held receipt
    /// that exceeds the anchored committed tip while that window is open, the wallet convicts
    /// the close with one [`Challenge::HigherShardTip`] transaction whose proven outcome is
    /// read back certified, records the conviction durably, and stops, because one proven
    /// challenge invalidates the whole close. When the anchored tip covers every held receipt
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
                    status.hard_faulted,
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
        hard_faulted: bool,
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
        // chain-registered pairs, so registration itself needs no re-check here.
        let Ok(admitted) = chain.admitted(ctx, epoch).await else {
            return Ok(());
        };
        let Some(admitted) = admitted else {
            // No close admitted yet. If settlement faulted, this epoch's close never will, so
            // its held credit is enforcement-dead: record it loudly rather than retry forever.
            if hard_faulted {
                self.store
                    .record_unenforceable(epoch)
                    .context("record unenforceable epoch")?;
                summary.unenforceable.push(epoch);
            }
            return Ok(());
        };

        let mut uncovered = false;
        for receipt in &held {
            match self
                .assess_shard_tip(ctx, chain, operator, epoch, &admitted, &account, receipt)
                .await
            {
                // One proven challenge invalidates the whole close, so record it immediately and
                // stop: continuing would resubmit distinct evidence under the same batch and trip
                // the chain's evidence-replay guard, aborting before the conviction is recorded.
                ShardVerdict::Convicted => {
                    self.store
                        .record_challenge(epoch)
                        .context("record challenge outcome")?;
                    self.withheld.remove(&epoch);
                    summary.convicted.push(epoch);
                    return Ok(());
                }
                // Operator-served evidence was unavailable, unanchored, or unprovable: retry the
                // whole epoch next heartbeat. Once the close has finalized, withheld evidence is
                // an alarm, not a wait: conviction is no longer possible and coverage can no
                // longer be verified, so surface the dead end (once per stretch of withholding)
                // while still retrying in case the evidence is eventually served.
                ShardVerdict::Refused => {
                    if admitted.finalized && self.withheld.insert(epoch) {
                        summary.withheld.push(epoch);
                    }
                    return Ok(());
                }
                ShardVerdict::Uncovered => uncovered = true,
                ShardVerdict::Covered => {}
            }
        }

        if uncovered {
            self.store
                .record_unenforceable(epoch)
                .context("record unenforceable epoch")?;
            self.withheld.remove(&epoch);
            summary.unenforceable.push(epoch);
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

    /// Assesses one held receipt against the anchored committed close without mutating state.
    ///
    /// Every operator-served-evidence failure, an unavailable, unanchored, or unprovable lookup
    /// and a non-proven verdict, is demoted to a soft refusal so it retries rather than aborting.
    #[allow(clippy::too_many_arguments, reason = "one assessment, one call site")]
    async fn assess_shard_tip<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        epoch: u64,
        admitted: &AdmittedRootsResponse,
        account: &Key,
        receipt: &super::store::HeldReceipt,
    ) -> ShardVerdict {
        let Ok(tip) = operator_rpc::committed_shard_tip(
            ctx,
            operator,
            operator_rpc::CommittedShardTipRequest {
                account: account.clone(),
                shard: receipt.shard,
                epoch,
            },
        )
        .await
        else {
            return ShardVerdict::Refused;
        };

        // Served evidence must be the anchored close before any coverage verdict: a fabricated
        // batch or root could otherwise fake coverage through the window, or point a challenge at
        // another close and burn the window on a worthless verdict.
        if tip.batch_id != admitted.batch_id || tip.change_root != admitted.change {
            return ShardVerdict::Refused;
        }

        // Resolving operator-served evidence is a cryptographic check on an untrusted party, so
        // a failure is refusal, not a fatal error that would shadow the higher epochs.
        let Ok(committed) = tip
            .lookup
            .resolve::<Sha256>(&admitted.change, account, receipt.shard)
        else {
            return ShardVerdict::Refused;
        };
        let (credit, index) = committed.map_or((0, 0), |tip| (tip.cumulative_credit, tip.index));
        if credit >= receipt.cumulative_shard_credit && index >= receipt.receipt_index {
            return ShardVerdict::Covered;
        }
        if admitted.finalized {
            return ShardVerdict::Uncovered;
        }
        if !(receipt.cumulative_shard_credit > credit || receipt.receipt_index > index) {
            return ShardVerdict::Refused;
        }

        // The local adjudication above dry-ran the exact HigherShardTip
        // condition, so an honest wallet never submits a no-contradiction
        // challenge. Submit and complete on the transaction's effect: the
        // certified fault record naming the proven challenge over exactly
        // this batch. Rejections are effect-free, so a challenge that never
        // earns the fault record is a soft refusal that retries.
        let challenge = Challenge::HigherShardTip {
            payment: Box::new(PaymentWitness::from_payment(&receipt.pair)),
            recipient: Box::new(tip.lookup),
        };
        let tx = SettlementTx::Challenge(ChallengeRequest {
            batch_id: admitted.batch_id,
            evidence: challenge.encode(),
        });
        if chain.deliver(ctx, &tx).await.is_err() {
            return ShardVerdict::Refused;
        }
        for _ in 0..EFFECT_ATTEMPTS {
            let Ok(fault) = chain.fault(ctx).await else {
                return ShardVerdict::Refused;
            };
            if let Some(fault) = fault {
                let reason = match fault {
                    FaultRecord::Faulted(reason) => reason,
                    FaultRecord::Settling(settlement) => settlement.reason,
                };
                return if matches!(
                    reason,
                    HardFaultReasonResponse::ProvenChallenge { batch_id, kind }
                        if batch_id == admitted.batch_id && kind == ChallengeKind::HigherShardTip
                ) {
                    ShardVerdict::Convicted
                } else {
                    ShardVerdict::Refused
                };
            }
            ctx.sleep(POLL).await;
        }
        ShardVerdict::Refused
    }
}
