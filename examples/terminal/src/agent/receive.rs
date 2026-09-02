//! The receive lane: verified incoming intake and anchored reconciliation.

use super::{Agent, store::IncomingRecord};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{AdmittedRootsResponse, FaultRecord, HardFaultReasonResponse, StatusRecord},
        tx::{ChallengeRequest, SettlementTx},
    },
    operator::{Operator, rpc as operator_rpc},
    protocol::Key,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::{AckWitness, Challenge, ChallengeKind, EntryWitness},
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
    /// Epochs whose held credit can no longer be enforced: a finalized close understated it
    /// past the window, or its close never admitted and settlement faulted.
    pub(crate) unenforceable: Vec<u64>,
    /// Epochs that finalized while the operator still withholds the committed-side evidence
    /// needed to verify or convict, reported once per stretch of withholding. The epoch keeps
    /// retrying and self-heals if the evidence is later served.
    pub(crate) withheld: Vec<u64>,
    /// Epochs whose committed-side evidence aged out of the operator's retention window before
    /// their held credits reconciled, decided as unavailable: the honest operator no longer
    /// reconstructs the close, so a refusal there is not withholding.
    pub(crate) unavailable: Vec<u64>,
}

impl ReconcileSummary {
    #[cfg(test)]
    pub(crate) const fn is_empty(&self) -> bool {
        self.reconciled.is_empty()
            && self.convicted.is_empty()
            && self.unenforceable.is_empty()
            && self.withheld.is_empty()
            && self.unavailable.is_empty()
    }
}

/// The verdict for one held receipt against the anchored committed close.
enum EntryVerdict {
    /// The committed terminal entry covered the held receipt.
    Covered,
    /// Served evidence was unavailable, unanchored, or unprovable: retry the epoch.
    Refused,
    /// The omission was convicted with a proven challenge.
    Convicted,
    /// A finalized close understated the held receipt past the challenge window.
    Uncovered,
}

impl Agent {
    /// Pulls, verifies, settlement-anchors, and durably persists the receipts newly crediting
    /// this wallet.
    ///
    /// This is the receiver's intake, folded into the balance heartbeat. A receiver may rely on
    /// a payment exactly when its verified receipt is durably held: a balance read from the
    /// operator's head is an observation, not reliance-grade. Every fetched receipt is fully
    /// verified: both signatures over the acknowledged endpoint, the entry's membership under
    /// the acknowledged root, and its recipient. It is then anchored: the receipt's
    /// `(epoch, anchor)` must be the anchor the chain certifiably registered for that epoch,
    /// read with the recency bound so a proven absence holds at a certified tip no older than
    /// the recency threshold. A receipt over an operator-chosen anchor with no settlement
    /// obligation has no close to adjudicate against and can never be enforced, so it is not
    /// reliance-grade. A receipt's cumulative is per-edge cumulative, so intake credits the
    /// DELTA versus the previously held entry for that (payer, epoch) edge, and a
    /// non-advancing or duplicate receipt is skipped idempotently. Unverifiable and unanchored
    /// receipts are ignored and never stored, yet the durable cursor still advances past them
    /// so a poisoned entry cannot wedge intake. The receipts and the advanced cursor commit
    /// together, so reliance never outruns durability, and a lost response refetches the exact
    /// page and reinserts it idempotently.
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
        let mut anchors = std::collections::BTreeMap::<u64, Option<Digest>>::new();
        let mut held = std::collections::BTreeMap::<(Key, u64), (u64, u64)>::new();
        let mut records = Vec::with_capacity(page.pairs.len());
        for incoming in page.pairs {
            let receipt = incoming.receipt;
            let body = receipt.ack.body();
            let context = PaymentContext::new(*body.anchor(), body.epoch(), operator_key.clone());

            // Verify both signatures, the entry opening, and the credited recipient.
            if receipt.verify::<Sha256>(&context).is_err() || receipt.recipient != account {
                continue;
            }

            // Anchor the context to the chain's certified registration. A read failure
            // aborts the whole intake so the cursor never advances past an unconfirmed
            // receipt. A proven absence or mismatch skips the receipt like an invalid one.
            let epoch = body.epoch();
            let anchor = *body.anchor();
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

            // The per-edge delta versus the previously held entry keeps the ledger's
            // amount-sum semantics: skip a receipt that does not strictly advance the
            // edge on both dimensions.
            let payer = body.payer().clone();
            let edge = (payer.clone(), epoch);
            let prior = match held.get(&edge) {
                Some(prior) => *prior,
                None => {
                    let stored = self
                        .store
                        .held_edge(&payer, epoch)
                        .context("read held edge endpoint")?
                        .unwrap_or((0, 0));
                    held.insert(edge.clone(), stored);
                    stored
                }
            };
            if receipt.cumulative <= prior.0 || receipt.count <= prior.1 {
                continue;
            }
            let amount = receipt
                .cumulative
                .checked_sub(prior.0)
                .context("held edge delta is checked")?;
            held.insert(edge, (receipt.cumulative, receipt.count));
            records.push(IncomingRecord {
                id: Sha256::hash(&[body.encode().as_ref()]),
                payer,
                epoch,
                anchor,
                seq: body.seq(),
                cumulative: receipt.cumulative,
                count: receipt.count,
                amount,
                cursor: incoming.sequence,
                receipt,
            });
        }
        self.incoming = self
            .store
            .record_incoming(&records, page.next_cursor)
            .context("persist verified incoming receipts")?;
        Ok(())
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
    /// the payer's slice holders, the validators retaining the admitted close's sealed
    /// dealing through its challenge window, so the accused operator is never the source
    /// of the lookup that convicts it. The operator's reconstruction is the fallback only
    /// when every holder declines, which is the case once the window closed and the
    /// dealing was released. A refusal from both, an unanchored or unprovable lookup, and a
    /// per-epoch fault are all the documented availability dependence: that epoch stays
    /// unreconciled and retries without shadowing the others. Nobody can buy coverage with
    /// a fabricated root, but coverage of a finalized close can no longer be convicted, only
    /// verified, so an epoch that finalizes while its evidence is still withheld is surfaced
    /// as withheld and kept retrying. That dependence is bounded by the operator's retention
    /// contract: the honest operator reconstructs a finalized close until
    /// [`Operator::RETAINED_EPOCHS`] further epochs finalize, so a refusal for an older
    /// epoch that the validators also cannot serve is unavailability, and the epoch is
    /// decided as such instead of alarmed or retried.
    ///
    /// The challenge window sits between admission and finalization. On the first held receipt
    /// that exceeds the anchored committed entry while that window is open, the wallet convicts
    /// the close with one [`Challenge::HigherAckEntry`] transaction whose proven outcome is
    /// read back certified, records the conviction durably, and stops, because one proven
    /// challenge invalidates the whole close. When the anchored entry covers every held receipt
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

        let mut uncovered = false;
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
                        .record_challenge(epoch)
                        .context("record challenge outcome")?;
                    self.withheld.remove(&epoch);
                    summary.convicted.push(epoch);
                    return Ok(());
                }
                // Served evidence was unavailable, unanchored, or unprovable: retry the whole
                // epoch next heartbeat. Once the close has finalized, withheld evidence is
                // an alarm, not a wait: conviction is no longer possible and coverage can no
                // longer be verified, so surface the dead end (once per stretch of withholding)
                // while still retrying in case the evidence is eventually served. Past the
                // operator's retention window the honest operator no longer reconstructs the
                // close, so the refusal is unavailability rather than withholding, and the
                // epoch is decided loudly instead of retried.
                EntryVerdict::Refused => {
                    if !admitted.finalized {
                        return Ok(());
                    }
                    if retained(epoch, status.last_finalized) {
                        if self.withheld.insert(epoch) {
                            summary.withheld.push(epoch);
                        }
                    } else {
                        self.store
                            .record_unavailable(epoch)
                            .context("record unavailable epoch")?;
                        self.withheld.remove(&epoch);
                        summary.unavailable.push(epoch);
                    }
                    return Ok(());
                }
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
    /// Every served-evidence failure, an unavailable, unanchored, or unprovable lookup and a
    /// non-proven verdict, is demoted to a soft refusal so it retries rather than aborting.
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
        // The committed entry comes from the payer's slice holders, verified against the
        // anchored change root. The operator is the accused party, so its reconstruction is
        // the fallback only when every holder declines.
        let lookup = match self
            .holders
            .committed_entry(ctx, chain, admitted, &held.payer, account)
            .await
        {
            Ok(lookup) => lookup,
            Err(_) => {
                let Ok(evidence) = operator_rpc::committed_entry(
                    ctx,
                    operator,
                    operator_rpc::CommittedEntryRequest {
                        epoch,
                        payer: held.payer.clone(),
                        recipient: account.clone(),
                    },
                )
                .await
                else {
                    return EntryVerdict::Refused;
                };

                // Served evidence must be the anchored close before any coverage verdict: a
                // fabricated batch or root could otherwise fake coverage through the window,
                // or point a challenge at another close and burn the window on a worthless
                // verdict.
                if evidence.batch_id != admitted.batch_id || evidence.change_root != admitted.change
                {
                    return EntryVerdict::Refused;
                }
                evidence.lookup
            }
        };

        // Resolving served evidence is a cryptographic check on an untrusted party, so a
        // failure is refusal, not a fatal error that would shadow the higher epochs.
        let Ok((cumulative, count)) =
            lookup.resolve::<Sha256>(&admitted.change, &held.payer, account)
        else {
            return EntryVerdict::Refused;
        };
        if cumulative >= held.cumulative && count >= held.count {
            return EntryVerdict::Covered;
        }
        if admitted.finalized {
            return EntryVerdict::Uncovered;
        }

        // The coverage check above dry-ran the exact HigherAckEntry condition,
        // so an honest wallet never submits a no-contradiction challenge.
        // Submit and complete on the transaction's effect: the certified fault
        // record naming the proven challenge over exactly this batch.
        // Rejections are effect-free, so a challenge that never earns the
        // fault record is a soft refusal that retries.
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
            batch_id: admitted.batch_id,
            evidence: challenge.encode(),
        });
        if chain.deliver(ctx, &tx).await.is_err() {
            return EntryVerdict::Refused;
        }
        for _ in 0..EFFECT_ATTEMPTS {
            let Ok(fault) = chain.fault(ctx).await else {
                return EntryVerdict::Refused;
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
                    EntryVerdict::Refused
                };
            }
            ctx.sleep(POLL).await;
        }
        EntryVerdict::Refused
    }
}

/// Whether the honest operator still reconstructs `epoch`'s committed close when
/// `last_finalized` is the certified finalization head: the retention contract behind the
/// withholding alarm. A status read lagging the admitted record can only understate the head,
/// which errs toward alarming withholding and retrying.
fn retained(epoch: u64, last_finalized: Option<u64>) -> bool {
    last_finalized.is_none_or(|last| {
        epoch
            .checked_add(Operator::RETAINED_EPOCHS)
            .is_none_or(|horizon| last < horizon)
    })
}
