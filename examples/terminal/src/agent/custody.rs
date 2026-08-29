//! Custody flows: deposits, withdrawal authorization and escalation, and recovery.

use super::{Agent, store::PendingWithdrawalClaim};
use crate::{
    operator::rpc as operator_rpc,
    protocol::{DepositEvent, Key, deployment, identities},
    settlement::rpc as settlement_rpc,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalAction},
    commitment::VectorRoot,
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::Network;
#[cfg(not(test))]
use rand::RngExt as _;
use std::net::SocketAddr;

const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_AGENT_DEPOSIT";

#[derive(Debug)]
pub(crate) enum DepositOutcome {
    Applied {
        epoch: u64,
        event: DepositEvent,
    },
    Recorded {
        event: DepositEvent,
        error: anyhow::Error,
    },
}

#[derive(Debug)]
pub(crate) enum WithdrawalOutcome {
    Applied {
        epoch: u64,
        request: SignedWithdrawal<Key, Digest>,
    },
    Signed {
        request: SignedWithdrawal<Key, Digest>,
        error: anyhow::Error,
    },
}

pub(super) const fn withdrawal_deadline(now: u64) -> u64 {
    now.saturating_add(50)
}

#[cfg(test)]
pub(super) const fn initial_deposit_nonce() -> u64 {
    0
}

#[cfg(not(test))]
pub(super) fn initial_deposit_nonce() -> u64 {
    rand::rng().random()
}

impl Agent {
    pub(crate) async fn recover_hard_fault<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::ClaimHardFaultResponse> {
        let hard_fault = settlement_rpc::begin_hard_fault_settlement(network, settlement)
            .await
            .context("begin hard-fault settlement")?;

        // Recovery at a frozen root requires an opening retained at or refreshed to that
        // root. Openings refresh on every head read or balance poll, so this fails only for a
        // wallet passive across the final finalization, which then depends on the
        // operator's survival to serve one.
        let opening = self
            .store
            .recovery_opening(&hard_fault.frozen_state_root)?
            .context(
                "no payer opening is retained for the frozen state root: the wallet was \
                 passive across the final finalization and needs the operator to serve one",
            )?;
        let expected_custody = opening.leaf.state.balance;
        let release = settlement_rpc::claim_hard_fault(
            network,
            settlement,
            settlement_rpc::ClaimHardFaultRequest { opening },
        )
        .await
        .context("claim hard-fault payer state")?;
        ensure!(
            release.account == self.account(),
            "settlement released another account"
        );
        ensure!(
            release.released_custody == expected_custody,
            "settlement released the wrong payer custody"
        );
        let withdrawal = release
            .withdrawal
            .as_ref()
            .map_or(0, |output| output.amount());
        ensure!(
            withdrawal.checked_add(release.residual) == Some(release.released_custody),
            "settlement release does not decompose into withdrawal and residual"
        );
        Ok(release)
    }

    pub(crate) async fn recover_pending_deposit<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::ClaimPendingDepositResponse> {
        let account = self.account();
        let refund = settlement_rpc::claim_pending_deposit(
            network,
            settlement,
            settlement_rpc::ClaimPendingDepositRequest {
                account: account.clone(),
            },
        )
        .await
        .context("claim pending settlement deposit")?;
        ensure!(
            refund.account == account,
            "settlement refunded another account"
        );
        ensure!(
            refund.amount > 0,
            "settlement returned a zero deposit refund"
        );
        Ok(refund)
    }

    pub(crate) async fn deposit<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        amount: u64,
    ) -> Result<DepositOutcome> {
        ensure!(amount > 0, "deposit amount must be positive");
        let next_deposit_nonce = self
            .deposit_nonce
            .checked_add(1)
            .context("deposit nonce overflow")?;
        let event = match &self.pending_deposit {
            Some(event) => {
                ensure!(event.amount == amount, "another deposit retry is pending");
                event.clone()
            }
            None => {
                let account = self.account();

                // Settlement takes custody only for configured identities, so any other
                // account would deterministically wedge as staged forever.
                ensure!(
                    identities().iter().any(|identity| identity.key == account),
                    "deposits are limited to configured terminal agents"
                );
                let event = DepositEvent {
                    id: Sha256::hash(&[
                        DEPOSIT_ID_NAMESPACE,
                        account.as_ref(),
                        &self.deposit_nonce.to_be_bytes(),
                        &amount.to_be_bytes(),
                    ]),
                    account,
                    amount,
                };

                // The id above derives from a volatile nonce and custody moves at the
                // settlement call below. Stage the event durably first so a crash in that
                // window cannot orphan the recorded deposit: a restarted wallet retries the
                // exact id, which settlement and the operator both deduplicate.
                self.store
                    .stage_deposit(&event)
                    .context("durably stage deposit")?;
                self.pending_deposit = Some(event.clone());
                event
            }
        };
        if let Err(error) = settlement_rpc::deposit(
            network,
            settlement,
            settlement_rpc::DepositRequest {
                id: event.id,
                account: event.account.clone(),
                amount: event.amount,
            },
        )
        .await
        {
            // A rejected call may still have recorded custody (its response can be lost),
            // so only settlement's own statement that the id was never recorded proves no
            // custody moved. Only then is the staged event discarded so a permanent
            // rejection cannot wedge the deposit flow. Any other answer keeps the exact
            // staged retry.
            if let Ok(settlement_rpc::DepositConfirmation::Unknown) =
                settlement_rpc::confirm_deposit(network, settlement, event.clone()).await
            {
                self.store
                    .discard_deposit(&event)
                    .context("discard unrecorded deposit")?;
                self.pending_deposit = None;
            }
            return Err(error.context("record settlement deposit"));
        }
        let applied = match operator_rpc::apply_deposit(
            network,
            operator,
            operator_rpc::ApplyDepositRequest {
                id: event.id,
                account: event.account.clone(),
                amount: event.amount,
            },
        )
        .await
        {
            Ok(applied) => applied,
            Err(error) => {
                return Ok(DepositOutcome::Recorded {
                    event,
                    error: error.context("credit operator deposit"),
                });
            }
        };
        if applied.id != event.id
            || applied.account != event.account
            || applied.amount != event.amount
        {
            return Ok(DepositOutcome::Recorded {
                event,
                error: anyhow::anyhow!("operator acknowledged another deposit"),
            });
        }
        self.store
            .complete_deposit(&event)
            .context("complete staged deposit")?;
        self.pending_deposit = None;
        self.deposit_nonce = next_deposit_nonce;
        Ok(DepositOutcome::Applied {
            epoch: applied.epoch,
            event,
        })
    }

    pub(crate) async fn withdraw<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        action: WithdrawalAction,
    ) -> Result<WithdrawalOutcome> {
        // One withdrawal claim intent exists per wallet, and a recorded release pins its
        // evidence until the operator acknowledgement completes it. A new withdrawal must
        // wait: silently skipping the open would drop the new reserve's intent instead.
        ensure!(
            self.pending_withdrawal_claim.is_none(),
            "the pending withdrawal claim must complete before a new withdrawal"
        );
        let request = match &self.pending_withdrawal {
            Some(pending) => {
                ensure!(
                    pending.body().action() == &action,
                    "another withdrawal retry is pending"
                );
                pending.clone()
            }
            None => {
                let settlement_status = settlement_rpc::status(network, settlement)
                    .await
                    .context("read settlement withdrawal head")?;
                ensure!(
                    settlement_status.deployment == deployment(),
                    "settlement status has an unexpected deployment"
                );
                ensure!(
                    !settlement_status.hard_faulted,
                    "settlement is permanently hard-faulted"
                );

                // Retain a head opening before signing. It is not sent anywhere: if the
                // deployment later hard-faults while frozen at this root, recovery needs it.
                if self
                    .store
                    .recovery_opening(&settlement_status.state_root)
                    .context("read retained withdrawal opening")?
                    .is_none()
                {
                    let opening = operator_rpc::withdrawal_opening(
                        network,
                        operator,
                        operator_rpc::WithdrawalOpeningRequest {
                            account: self.account(),
                        },
                    )
                    .await
                    .context("read withdrawal opening")?;
                    ensure!(
                        settlement_status.state_root == opening.root,
                        "operator opening is not the settlement head"
                    );
                    self.store
                        .retain_recovery_opening(&opening.root, &opening.opening)
                        .context("durably retain withdrawal opening")?;
                }
                let deadline = withdrawal_deadline(settlement_status.now);
                let request = SignedWithdrawal::sign(
                    settlement_status.deployment,
                    settlement_status.state_root.digest,
                    Bytes::copy_from_slice(self.wallet.name.as_bytes()),
                    action,
                    deadline,
                    self.wallet.signer(),
                );
                self.pending_withdrawal = Some(request.clone());
                request
            }
        };
        let digest = operator_rpc::withdrawal_digest(&request);
        let applied = match operator_rpc::apply_withdrawal(
            network,
            operator,
            operator_rpc::ApplyWithdrawalRequest {
                request: request.clone(),
            },
        )
        .await
        {
            Ok(applied) => applied,
            Err(error) => {
                return Ok(WithdrawalOutcome::Signed {
                    request,
                    error: error.context("apply operator withdrawal"),
                });
            }
        };
        if applied.digest != digest {
            return Ok(WithdrawalOutcome::Signed {
                request,
                error: anyhow::anyhow!("operator acknowledged another withdrawal"),
            });
        }

        // The acknowledged epoch is display only and never trusted: the claim intent
        // carries no epoch, and the claim binds to its finalized batch only when fetched
        // evidence verifies locally against that batch's own claim roots.
        self.store
            .open_withdrawal_claim()
            .context("open withdrawal claim")?;
        self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
            evidence: None,
            result: None,
        });
        self.pending_withdrawal = None;
        Ok(WithdrawalOutcome::Applied {
            epoch: applied.epoch,
            request,
        })
    }

    /// Escalates a signed withdrawal the operator would not carry directly to settlement.
    ///
    /// This is the censorship-fallback exit. When [`Self::withdraw`] returns
    /// [`WithdrawalOutcome::Signed`] because the operator is unreachable, the wallet queues the
    /// exact retained request and its head opening at settlement, where its deadline becomes an
    /// on-chain obligation that expires into hard-fault recovery. Settlement deduplicates the
    /// account's queued request, so a lost response replays it unchanged, and the retained
    /// opening remains the durable evidence hard-fault recovery later releases against.
    ///
    /// A `Signed` outcome does not prove the operator skipped the request: it may have applied
    /// it and lost only the response, in which case the next registered close must carry the
    /// queued request verbatim and finalizes an operator-carried claim. The wallet therefore
    /// opens the claim slot exactly like the applied path, so that claim stays recoverable. The
    /// two payout paths are exclusive: a carried request finalizes a claimable reserve and no
    /// fault occurs, while an expired obligation faults the deployment and hard-fault recovery
    /// pays out, leaving the idle claim intent permanently unavailable and harmless.
    pub(crate) async fn escalate_withdrawal<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<SignedWithdrawal<Key, Digest>> {
        let request = self
            .pending_withdrawal
            .clone()
            .context("no signed withdrawal awaits escalation")?;
        let root = VectorRoot {
            digest: *request.body().state_root(),
        };
        let opening = self
            .store
            .recovery_opening(&root)?
            .context("no retained head opening for the signed withdrawal")?;
        settlement_rpc::queue_withdrawal(
            network,
            settlement,
            settlement_rpc::QueueWithdrawalRequest {
                request: request.clone(),
                openings: vec![opening],
            },
        )
        .await
        .context("queue signed withdrawal at settlement")?;

        // The request is now a settlement obligation. Open the claim slot in case the operator
        // already applied the request and only the response was lost: a close that carries it
        // finalizes an operator-carried claim this slot recovers, while a true non-carriage
        // expires into hard-fault recovery against the retained opening.
        self.store
            .open_withdrawal_claim()
            .context("open withdrawal claim")?;
        self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
            evidence: None,
            result: None,
        });
        self.pending_withdrawal = None;
        Ok(request)
    }
}
