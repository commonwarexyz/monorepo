//! One-wallet client workflows for the clearing terminal.

use crate::{
    agent_store::{
        AgentState, AgentStore, PendingClaim, PendingPayment, PendingPayoutClaim,
        PendingWithdrawalClaim,
    },
    operator_rpc,
    protocol::{
        AccountIdentity, DepositEvent, Key, Wallet, deployment, external_identity, external_wallet,
        identities, operator_key, wallets,
    },
    settlement_rpc,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalAction},
    commitment::{VectorKind, VectorRoot},
    payment::{Entry, PaymentContext, SignedSend},
    transition::BatchId,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::Network;
#[cfg(not(test))]
use rand::RngExt as _;
use std::{net::SocketAddr, path::Path};

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

/// An agent owns one payer key and retains the receipts returned by the operator.
///
/// Durable state follows one discipline. It holds only what this wallet alone can
/// produce: its signed sends, its signed withdrawal requests, and its deposit identities.
/// The exceptions are proofs that must survive counterparty death, namely the frozen-root
/// recovery openings and cached claim evidence. Everything the counterparty can reproduce
/// is an overwritable cache and never gates progress.
///
/// Frozen-root recovery requires an opening retained at or refreshed to the last
/// finalized root, which advances with every finalization by anyone. Openings refresh on
/// every quote or balance poll, so only a wallet passive across the final finalization
/// holds none, and it then depends on the operator's survival to serve one.
pub(crate) struct Agent {
    wallet: Wallet,
    store: AgentStore,
    recipients: Vec<AccountIdentity>,
    deposit_nonce: u64,
    pending_payment: Option<PendingPayment>,
    pending_deposit: Option<DepositEvent>,
    pending_withdrawal: Option<SignedWithdrawal<Key, Digest>>,
    pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pending_payout_claim: Option<PendingPayoutClaim>,
    pending_close_epoch: Option<u64>,
    cumulative_debit: u64,
    receipt_count: u64,
}

const fn withdrawal_deadline(now: u64) -> u64 {
    now.saturating_add(50)
}

#[cfg(test)]
const fn initial_deposit_nonce() -> u64 {
    0
}

#[cfg(not(test))]
fn initial_deposit_nonce() -> u64 {
    rand::rng().random()
}

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

/// One claim kind's wiring for the shared claim driver.
trait ClaimChannel {
    type Evidence: Clone + PartialEq;
    type Release: Clone + PartialEq;

    /// Claim noun used by the driver's errors and contexts.
    const NOUN: &'static str;

    fn pending(agent: &Agent) -> &Option<PendingClaim<Self::Evidence, Self::Release>>;
    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingClaim<Self::Evidence, Self::Release>>;

    /// Returns the finalized batch the evidence names.
    fn batch(evidence: &Self::Evidence) -> BatchId<Digest>;

    /// Binds operator-supplied evidence to this wallet by full local verification against
    /// the claim roots of the finalized batch the evidence names, before it may be cached.
    fn bind(
        agent: &Agent,
        evidence: &Self::Evidence,
        roots: &settlement_rpc::ClaimRootsResponse,
    ) -> Result<()>;

    /// Confirms a settlement release pays what the bound evidence certifies.
    fn verify_release(
        agent: &Agent,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()>;

    async fn fetch<E: Network>(
        agent: &Agent,
        network: &E,
        operator: SocketAddr,
    ) -> Result<Self::Evidence>;

    async fn submit<E: Network>(
        network: &E,
        settlement: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<settlement_rpc::ClaimResponse<Self::Release>>;

    async fn acknowledge<E: Network>(
        network: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()>;

    fn cache(store: &mut AgentStore, evidence: &Self::Evidence) -> Result<()>;
    fn drop_evidence(store: &mut AgentStore, evidence: &Self::Evidence) -> Result<()>;
    fn record(
        store: &mut AgentStore,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()>;
    fn complete(
        store: &mut AgentStore,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()>;
}

struct WithdrawalChannel;

impl ClaimChannel for WithdrawalChannel {
    type Evidence = operator_rpc::WithdrawalEvidenceResponse;
    type Release = settlement_rpc::WithdrawalResponse;

    const NOUN: &'static str = "withdrawal";

    fn pending(agent: &Agent) -> &Option<PendingWithdrawalClaim> {
        &agent.pending_withdrawal_claim
    }

    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingWithdrawalClaim> {
        &mut agent.pending_withdrawal_claim
    }

    fn batch(evidence: &Self::Evidence) -> BatchId<Digest> {
        evidence.batch_id
    }

    /// Binding is full local verification: the claim must open against the finalized
    /// batch's own withdrawal-outputs root, belong to this wallet's account, and pay the
    /// destination this wallet signs into every withdrawal. The output amount is
    /// deliberately unchecked: the batch may have finalized the withdrawal degraded to a
    /// zero release, and it is still the one batch that settles this claim.
    fn bind(
        agent: &Agent,
        evidence: &Self::Evidence,
        roots: &settlement_rpc::ClaimRootsResponse,
    ) -> Result<()> {
        let output = evidence
            .claim
            .verify::<Sha256>(&roots.withdrawal_outputs)
            .context("verify withdrawal claim against its finalized batch")?;
        ensure!(
            evidence.account == agent.account(),
            "operator returned withdrawal evidence for another account"
        );
        ensure!(
            output.destination().as_ref() == agent.wallet.name.as_bytes(),
            "operator returned withdrawal evidence for another destination"
        );
        Ok(())
    }

    fn verify_release(_: &Agent, evidence: &Self::Evidence, release: &Self::Release) -> Result<()> {
        ensure!(
            release.destination == *evidence.claim.output().destination()
                && release.amount == evidence.claim.output().amount(),
            "settlement returned another withdrawal output"
        );
        Ok(())
    }

    async fn fetch<E: Network>(
        agent: &Agent,
        network: &E,
        operator: SocketAddr,
    ) -> Result<Self::Evidence> {
        operator_rpc::withdrawal_evidence(
            network,
            operator,
            operator_rpc::WithdrawalEvidenceRequest {
                account: agent.account(),
            },
        )
        .await
    }

    async fn submit<E: Network>(
        network: &E,
        settlement: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<settlement_rpc::ClaimResponse<Self::Release>> {
        settlement_rpc::claim_withdrawal(
            network,
            settlement,
            settlement_rpc::WithdrawalClaimRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    async fn acknowledge<E: Network>(
        network: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()> {
        operator_rpc::acknowledge_withdrawal(
            network,
            operator,
            operator_rpc::AcknowledgeWithdrawalRequest {
                batch_id: evidence.batch_id,
                account: evidence.account.clone(),
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    fn cache(store: &mut AgentStore, evidence: &Self::Evidence) -> Result<()> {
        store.cache_withdrawal_claim(evidence)
    }

    fn drop_evidence(store: &mut AgentStore, evidence: &Self::Evidence) -> Result<()> {
        store.drop_withdrawal_claim_evidence(evidence)
    }

    fn record(
        store: &mut AgentStore,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        store.record_withdrawal_result(evidence, release)
    }

    fn complete(
        store: &mut AgentStore,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        store.complete_withdrawal_claim(evidence, release)
    }
}

struct PayoutChannel;

impl ClaimChannel for PayoutChannel {
    type Evidence = operator_rpc::ExternalPayoutEvidenceResponse;
    type Release = settlement_rpc::ExternalPayoutResponse;

    const NOUN: &'static str = "external payout";

    fn pending(agent: &Agent) -> &Option<PendingPayoutClaim> {
        &agent.pending_payout_claim
    }

    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingPayoutClaim> {
        &mut agent.pending_payout_claim
    }

    fn batch(evidence: &Self::Evidence) -> BatchId<Digest> {
        evidence.batch_id
    }

    /// Binding is full local verification: the claim must open against the finalized
    /// batch's own change root and certify this wallet as the recipient settlement pays.
    fn bind(
        agent: &Agent,
        evidence: &Self::Evidence,
        roots: &settlement_rpc::ClaimRootsResponse,
    ) -> Result<()> {
        let payout = evidence
            .claim
            .verify::<Sha256>(&roots.change)
            .context("verify external payout claim against its finalized batch")?;
        ensure!(
            payout.recipient == agent.account(),
            "operator returned external-payout evidence for another account"
        );
        Ok(())
    }

    fn verify_release(agent: &Agent, _: &Self::Evidence, release: &Self::Release) -> Result<()> {
        ensure!(
            release.recipient == agent.account(),
            "settlement returned another external payout"
        );
        Ok(())
    }

    async fn fetch<E: Network>(
        agent: &Agent,
        network: &E,
        operator: SocketAddr,
    ) -> Result<Self::Evidence> {
        operator_rpc::external_payout_evidence(
            network,
            operator,
            operator_rpc::ExternalPayoutEvidenceRequest {
                account: agent.account(),
            },
        )
        .await
    }

    async fn submit<E: Network>(
        network: &E,
        settlement: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<settlement_rpc::ClaimResponse<Self::Release>> {
        settlement_rpc::claim_external_payout(
            network,
            settlement,
            settlement_rpc::ExternalPayoutClaimRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    async fn acknowledge<E: Network>(
        network: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()> {
        operator_rpc::acknowledge_external_payout(
            network,
            operator,
            operator_rpc::AcknowledgeExternalPayoutRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    fn cache(store: &mut AgentStore, evidence: &Self::Evidence) -> Result<()> {
        store.cache_payout_claim(evidence)
    }

    fn drop_evidence(store: &mut AgentStore, evidence: &Self::Evidence) -> Result<()> {
        store.drop_payout_claim_evidence(evidence)
    }

    fn record(
        store: &mut AgentStore,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        store.record_payout_result(evidence, release)
    }

    fn complete(
        store: &mut AgentStore,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        store.complete_payout_claim(evidence, release)
    }
}

impl Agent {
    pub(crate) fn new(identity: usize) -> Result<Self> {
        let (wallet, recipients) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = AgentStore::in_memory(&account, &deployment(), &operator_key())?;
        Ok(Self::from_state(
            wallet,
            recipients,
            store,
            state,
            initial_deposit_nonce(),
        ))
    }

    pub(crate) fn open(path: &Path, identity: usize) -> Result<Self> {
        let (wallet, recipients) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = AgentStore::open(path, &account, &deployment(), &operator_key())?;
        Ok(Self::from_state(
            wallet,
            recipients,
            store,
            state,
            initial_deposit_nonce(),
        ))
    }

    fn identity(identity: usize) -> Result<(Wallet, Vec<AccountIdentity>)> {
        let mut wallets = wallets();
        ensure!(identity <= wallets.len(), "agent identity is out of range");
        let wallet = if identity == wallets.len() {
            external_wallet()
        } else {
            wallets.remove(identity)
        };
        let mut recipients = identities();
        recipients.push(external_identity());
        Ok((wallet, recipients))
    }

    fn from_state(
        wallet: Wallet,
        recipients: Vec<AccountIdentity>,
        store: AgentStore,
        state: AgentState,
        deposit_nonce: u64,
    ) -> Self {
        Self {
            wallet,
            store,
            recipients,
            deposit_nonce,
            pending_payment: state.pending_payment,
            pending_deposit: state.pending_deposit,
            pending_withdrawal: None,
            pending_withdrawal_claim: state.pending_withdrawal_claim,
            pending_payout_claim: state.pending_payout_claim,
            pending_close_epoch: None,
            cumulative_debit: state.cumulative_debit,
            receipt_count: state.receipt_count,
        }
    }

    pub(crate) const fn name(&self) -> &'static str {
        self.wallet.name
    }

    pub(crate) fn account(&self) -> Key {
        self.wallet.public_key()
    }

    pub(crate) const fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Returns the first selectable recipient that is not this wallet.
    pub(crate) fn default_recipient(&self) -> usize {
        let account = self.account();
        self.recipients
            .iter()
            .position(|identity| identity.key != account)
            .expect("the recipient roster is larger than one wallet")
    }

    pub(crate) fn recipient_name(&self, index: usize) -> &'static str {
        self.recipients[index % self.recipients.len()].name
    }

    pub(crate) const fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    pub(crate) async fn operator_status<E: Network>(
        &self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<operator_rpc::StatusResponse> {
        operator_rpc::status(network, operator).await
    }

    pub(crate) async fn settlement_status<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::StatusResponse> {
        settlement_rpc::status(network, settlement).await
    }

    /// Reads the live balance quote and verifies it against settlement's exact head.
    ///
    /// Polling doubles as the passive wallet's retention heartbeat: the verified head
    /// opening is retained through [`Self::verify_quoted_head`], so a wallet that only
    /// watches its balance still refreshes its frozen-root recovery evidence.
    pub(crate) async fn balance<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<u64> {
        let quote = operator_rpc::payment_quote(
            network,
            operator,
            operator_rpc::PaymentQuoteRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        let settlement_status = settlement_rpc::status(network, settlement)
            .await
            .context("read settlement balance head")?;
        ensure!(
            settlement_status.deployment == deployment(),
            "settlement status has an unexpected deployment"
        );
        self.verify_quoted_head(&quote, &settlement_status)?;
        Ok(quote.state.balance)
    }

    /// Pays every `(recipient index, amount)` entry with one batched send.
    ///
    /// A send this operator deterministically rejects must never be staged: a retry resubmits the
    /// exact staged bytes. Those bytes bind one `(anchor, epoch)`, so once that epoch is cut they
    /// can never be accepted again. A retry therefore re-quotes first: while the staged context is
    /// still live it resubmits unchanged (a lost-response retry), and once the operator has moved
    /// past it the wallet concludes commitment from settlement alone, by reading its own
    /// endpoint out of a Merkle-verified opening of a finalized root. A committed send finishes
    /// locally, and a send the finalized endpoint provably excludes is abandoned and re-staged
    /// against the live context, so the wallet can never drop or double count a real transfer.
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
                        self.quote_and_stage(network, settlement, operator, &requested, total)
                            .await?
                    }
                }
            }
            None => {
                self.quote_and_stage(network, settlement, operator, &requested, total)
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
        for (recipient, amount) in entries {
            let recipient = self.recipients[recipient % self.recipients.len()]
                .key
                .clone();
            ensure!(
                recipient != self.account(),
                "self-payments are omitted from this operator"
            );
            total = total
                .checked_add(*amount)
                .context("payment total overflow")?;
            requested.push(Entry::new(recipient, *amount).context("stage payment entry")?);
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
    /// through the operator's quote, so the independence is about trust, not availability:
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

        // Re-quote to learn whether the staged epoch is still the operator's live context.
        let quote = operator_rpc::payment_quote(
            network,
            operator,
            operator_rpc::PaymentQuoteRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        ensure!(
            quote.context.operator() == &operator_key(),
            "payment context has an unexpected operator"
        );
        let context = PaymentContext::new(
            *pending_send.body().anchor(),
            pending_send.body().epoch(),
            operator_key(),
        );
        if quote.context.epoch() == context.epoch() && quote.context.anchor() == context.anchor() {
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

        self.verify_quoted_head(&quote, &settlement_status)?;
        let endpoint = quote.opening.leaf.state.cumulative_debit;
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

    /// Verifies the quoted opening is this wallet's own row in settlement's exact head
    /// root, durably retains it for frozen-root recovery, then opportunistically records
    /// accepted payments that finalized root covers.
    ///
    /// This is the safety core of every head read: the opening travels through the
    /// operator but cannot be forged, because it must Merkle-verify against settlement's
    /// own root. Retention lives here, the one chokepoint, so every resolution that read
    /// the head leaves recovery evidence behind if the deployment later hard-faults
    /// frozen at this root.
    fn verify_quoted_head(
        &mut self,
        quote: &operator_rpc::PaymentQuoteResponse,
        settlement_status: &settlement_rpc::StatusResponse,
    ) -> Result<()> {
        ensure!(
            settlement_status.state_root == quote.root,
            "payer opening is not the exact settlement head"
        );
        ensure!(
            quote.opening.leaf.account == self.account(),
            "payer opening belongs to another account"
        );
        quote
            .opening
            .proof
            .verify::<Sha256>(
                VectorKind::State,
                &quote.root,
                quote.opening.leaf.encode().as_ref(),
            )
            .context("verify payer state opening")?;

        // A row without live custody carries nothing a hard-fault claim could release, so
        // only live openings are retained. The store refuses dead rows for the same reason.
        if quote.opening.leaf.state.active && quote.opening.leaf.state.balance > 0 {
            self.store
                .retain_recovery_opening(&quote.root, &quote.opening)
                .context("durably retain payer state opening")?;
        }
        self.store
            .observe_finalized(quote.opening.leaf.state.cumulative_debit)
            .context("record finalized payments")?;
        Ok(())
    }

    /// Quotes the payer head, verifies affordability, and durably stages a fresh send.
    async fn quote_and_stage<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        requested: &[Entry<Key>],
        total: u64,
    ) -> Result<StagedSend> {
        let quote = operator_rpc::payment_quote(
            network,
            operator,
            operator_rpc::PaymentQuoteRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        ensure!(
            quote.context.operator() == &operator_key(),
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
            quote.opening.leaf.state.active && quote.opening.leaf.state.balance > 0,
            "payer opening is not live"
        );

        // Mid-epoch credits only grow the payer balance and debits are serialized here, so
        // affordability at the quote holds at acceptance.
        ensure!(
            quote.state.balance >= total,
            "payer has insufficient available balance"
        );
        self.verify_quoted_head(&quote, &settlement_status)?;
        let send = SignedSend::sign_next_batch(
            &quote.context,
            self.wallet.signer(),
            requested.to_vec(),
            self.cumulative_debit,
        )
        .context("sign payment")?;
        self.store
            .stage_payment(&send, &quote.root, self.cumulative_debit)
            .context("durably stage payment")?;
        self.pending_payment = Some(PendingPayment {
            send: send.clone(),
            recovery_root: quote.root,
        });
        Ok(StagedSend {
            context: quote.context,
            send,
            predecessor_state_root: quote.root,
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

    pub(crate) async fn recover_hard_fault<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::ClaimHardFaultResponse> {
        let hard_fault = settlement_rpc::begin_hard_fault_settlement(network, settlement)
            .await
            .context("begin hard-fault settlement")?;

        // Recovery at a frozen root requires an opening retained at or refreshed to that
        // root. Openings refresh on every quote or balance poll, so this fails only for a
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

    /// Resolves this wallet's open claim of `C`'s kind through the shared claim driver.
    ///
    /// A held copy always gets its submission before any replacement, and the cache exists
    /// to protect a finalized reserve against the operator vanishing after finalization.
    /// Only self-verified evidence ever enters it: each attempt without a held copy
    /// fetches fresh evidence, looks up the claim roots of the finalized batch that
    /// evidence names, and verifies the claim locally against those roots before caching.
    /// Every cached copy is therefore releasable, so poisoning and epoch lies are
    /// structurally impossible.
    async fn drive_claim<C: ClaimChannel, E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<C::Release> {
        let pending = C::pending(self)
            .clone()
            .with_context(|| format!("no {} claim is pending", C::NOUN))?;
        let recorded = pending.result.clone();
        let evidence = match pending.evidence.clone() {
            Some(evidence) => evidence,
            None => {
                let fresh = C::fetch(self, network, operator)
                    .await
                    .with_context(|| format!("fetch {} evidence", C::NOUN))?;

                // An unknown batch is an availability signal, never a verdict: the batch
                // may simply not have finalized yet, so nothing is cached and the exact
                // claim retries later.
                let roots = settlement_rpc::claim_roots(network, settlement, C::batch(&fresh))
                    .await
                    .with_context(|| format!("look up the {} claim batch", C::NOUN))?
                    .with_context(|| {
                        format!(
                            "the {} batch has not finalized, so its evidence is not yet cacheable",
                            C::NOUN
                        )
                    })?;
                C::bind(self, &fresh, &roots)?;
                C::cache(&mut self.store, &fresh)
                    .with_context(|| format!("cache {} evidence", C::NOUN))?;
                *C::pending_mut(self) = Some(PendingClaim {
                    evidence: Some(fresh.clone()),
                    result: None,
                });
                fresh
            }
        };
        let release = match C::submit(network, settlement, &evidence)
            .await
            .with_context(|| format!("claim settlement {}", C::NOUN))?
        {
            settlement_rpc::ClaimResponse::Released(release) => release,
            settlement_rpc::ClaimResponse::Unavailable => {
                // The batch may not be claimable at this instant. Nothing is dropped: the
                // exact claim retries later.
                anyhow::bail!("{} batch is not claimable yet", C::NOUN)
            }
            settlement_rpc::ClaimResponse::Invalid => {
                // Adjudicated against an immutable finalized batch, so this exact copy can
                // never succeed. Local verification at bind makes this arm unreachable for
                // cached copies, but it stays as the honest fallback: drop only the cache
                // and keep the intent open. Evidence with a recorded release is never
                // dropped: settlement already paid it and only the operator
                // acknowledgement is outstanding.
                ensure!(
                    recorded.is_none(),
                    "settlement rejected a {} claim it already released",
                    C::NOUN
                );
                C::drop_evidence(&mut self.store, &evidence)
                    .with_context(|| format!("drop rejected {} evidence", C::NOUN))?;
                *C::pending_mut(self) = Some(PendingClaim {
                    evidence: None,
                    result: None,
                });
                anyhow::bail!("settlement rejected the cached {} evidence", C::NOUN)
            }
        };
        C::verify_release(self, &evidence, &release)?;
        if let Some(expected) = &recorded {
            ensure!(
                &release == expected,
                "settlement replayed another {} release",
                C::NOUN
            );
        } else {
            C::record(&mut self.store, &evidence, &release)
                .with_context(|| format!("persist {} release", C::NOUN))?;
            *C::pending_mut(self) = Some(PendingClaim {
                evidence: Some(evidence.clone()),
                result: Some(release.clone()),
            });
        }
        C::acknowledge(network, operator, &evidence)
            .await
            .with_context(|| format!("acknowledge claimed {}", C::NOUN))?;
        C::complete(&mut self.store, &evidence, &release)
            .with_context(|| format!("complete {} claim", C::NOUN))?;
        *C::pending_mut(self) = None;
        Ok(release)
    }

    pub(crate) async fn claim_withdrawal<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::WithdrawalResponse> {
        self.drive_claim::<WithdrawalChannel, E>(network, settlement, operator)
            .await
    }

    /// Claims this wallet's external payout.
    ///
    /// The recipient needs no out-of-band provenance: fetched evidence names its batch
    /// and is verified locally against that batch's own claim roots.
    pub(crate) async fn claim_external_payout<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::ExternalPayoutResponse> {
        if self.pending_payout_claim.is_none() {
            self.store
                .open_payout_claim()
                .context("open external payout claim")?;
            self.pending_payout_claim = Some(PendingPayoutClaim {
                evidence: None,
                result: None,
            });
        }
        self.drive_claim::<PayoutChannel, E>(network, settlement, operator)
            .await
    }

    pub(crate) async fn start_close<E: Network>(
        &mut self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<operator_rpc::StartCloseResponse> {
        let expected_epoch = match self.pending_close_epoch {
            Some(epoch) => epoch,
            None => {
                let epoch = operator_rpc::status(network, operator).await?.epoch;
                self.pending_close_epoch = Some(epoch);
                epoch
            }
        };
        let started = operator_rpc::start_close(network, operator, expected_epoch).await?;
        ensure!(
            started.epoch == expected_epoch,
            "operator started another close epoch"
        );
        self.pending_close_epoch = None;
        Ok(started)
    }

    pub(crate) async fn poll_close<E: Network>(
        &self,
        network: &E,
        operator: SocketAddr,
        epoch: u64,
    ) -> Result<operator_rpc::PollCloseResponse> {
        operator_rpc::poll_close(network, operator, epoch).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        operator::Operator,
        protocol::{Acceptance, AccountCache},
        rpc,
        settlement::Settlement,
    };
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        payment::{Payment, SignedReceipt},
        state::{AccountState, StateLeaf},
        transition::BatchId,
    };
    use commonware_codec::{DecodeExt as _, Encode};
    use commonware_runtime::{
        Listener as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use std::{
        fs,
        num::{NonZeroU64, NonZeroUsize},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDatabase {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TempDatabase {
        fn new() -> Self {
            let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "commonware-terminal-agent-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("agent.sqlite");
            Self { directory, path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    async fn respond_rpc<L: commonware_runtime::Listener>(
        listener: &mut L,
        handle: impl FnOnce(rpc::Request) -> rpc::Response,
    ) {
        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
        let request = rpc::recv_request(&mut stream).await.unwrap();
        let response = handle(request);
        rpc::send_response(&mut sink, &response).await.unwrap();
    }

    async fn respond<L: commonware_runtime::Listener>(
        listener: &mut L,
        handle: impl FnOnce(operator_rpc::OperatorRequest) -> rpc::Response,
    ) {
        respond_rpc(listener, |request| {
            handle(operator_rpc::decode_request(request).unwrap())
        })
        .await;
    }

    async fn respond_registration<L: commonware_runtime::Listener>(
        listener: &mut L,
        context: &PaymentContext<Key, Digest>,
    ) {
        respond_rpc(listener, |request| {
            assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
            assert_eq!(
                settlement_rpc::RegistrationQuery::decode(request.body).unwrap(),
                settlement_rpc::RegistrationQuery {
                    epoch: context.epoch(),
                    anchor: *context.anchor(),
                    state_root: settlement_status_response().state_root,
                }
            );
            rpc::Response::Success { body: Bytes::new() }
        })
        .await;
    }

    fn accepted(outcome: PaymentOutcome) -> operator_rpc::AcceptedBatchResponse {
        match outcome {
            PaymentOutcome::Accepted(payment) => *payment,
            PaymentOutcome::CommittedUnheld { epoch, total } => {
                panic!("epoch {epoch} payment for {total} committed without receipts")
            }
        }
    }

    /// Opens a withdrawal-claim intent directly, standing in for a completed withdrawal.
    fn open_withdrawal_intent(agent: &mut Agent) {
        agent.store.open_withdrawal_claim().unwrap();
        agent.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
            evidence: None,
            result: None,
        });
    }

    async fn respond_claim_roots<L: commonware_runtime::Listener>(
        listener: &mut L,
        batch: BatchId<Digest>,
        roots: Option<settlement_rpc::ClaimRootsResponse>,
    ) {
        respond_rpc(listener, move |request| {
            assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_ROOTS);
            assert_eq!(
                settlement_rpc::ClaimRootsRequest::decode(request.body).unwrap(),
                settlement_rpc::ClaimRootsRequest { batch_id: batch }
            );
            rpc::Response::Success {
                body: roots.encode(),
            }
        })
        .await;
    }

    fn claim_roots_response(
        roots: &commonware_clearing::bajillion::transition::RootBundle<Digest>,
    ) -> settlement_rpc::ClaimRootsResponse {
        settlement_rpc::ClaimRootsResponse {
            withdrawal_outputs: roots.withdrawal_outputs,
            change: roots.change,
        }
    }

    fn quote_response_with_debit(
        context: PaymentContext<Key, Digest>,
        state: AccountState,
        leaf_debit: u64,
    ) -> operator_rpc::PaymentQuoteResponse {
        let account = wallets()[0].public_key();
        let opening = AccountCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance: 100,
                active: true,
                cumulative_debit: leaf_debit,
                ..AccountState::default()
            },
        }])
        .unwrap();
        operator_rpc::PaymentQuoteResponse {
            context,
            state,
            root: opening.root(),
            opening: opening.opening(&account).unwrap(),
        }
    }

    fn payment_quote_response(
        context: PaymentContext<Key, Digest>,
        state: AccountState,
    ) -> operator_rpc::PaymentQuoteResponse {
        quote_response_with_debit(context, state, 0)
    }

    fn settlement_status_response() -> settlement_rpc::StatusResponse {
        let quote = payment_quote_response(
            PaymentContext::new(Sha256::hash(&[b"status-root"]), 0, operator_key()),
            AccountState::default(),
        );
        settlement_rpc::StatusResponse {
            now: 0,
            deployment: deployment(),
            state_root: quote.root,
            last_finalized: None,
            custody_balance: 400,
            claimable_balance: 0,
            hard_faulted: false,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum PaymentQuoteGateCase {
        WrongDeployment,
        HardFaulted,
        MismatchedStateRoot,
        WrongAccount,
        InactivePayer,
        ZeroBalance,
        InvalidProof,
    }

    impl PaymentQuoteGateCase {
        const ALL: [Self; 7] = [
            Self::WrongDeployment,
            Self::HardFaulted,
            Self::MismatchedStateRoot,
            Self::WrongAccount,
            Self::InactivePayer,
            Self::ZeroBalance,
            Self::InvalidProof,
        ];

        const fn actor(self) -> &'static str {
            match self {
                Self::WrongDeployment => "wrong_deployment",
                Self::HardFaulted => "hard_faulted",
                Self::MismatchedStateRoot => "mismatched_state_root",
                Self::WrongAccount => "wrong_account",
                Self::InactivePayer => "inactive_payer",
                Self::ZeroBalance => "zero_balance",
                Self::InvalidProof => "invalid_proof",
            }
        }

        const fn expected_error(self) -> &'static str {
            match self {
                Self::WrongDeployment => "settlement status has an unexpected deployment",
                Self::HardFaulted => "settlement is permanently hard-faulted",
                Self::MismatchedStateRoot => "payer opening is not the exact settlement head",
                Self::WrongAccount => "payer opening belongs to another account",
                Self::InactivePayer | Self::ZeroBalance => "payer opening is not live",
                Self::InvalidProof => "verify payer state opening",
            }
        }

        fn corrupt(
            self,
            quote: &mut operator_rpc::PaymentQuoteResponse,
            status: &mut settlement_rpc::StatusResponse,
        ) {
            match self {
                Self::WrongDeployment => {
                    status.deployment = Sha256::hash(&[b"wrong-settlement-deployment"]);
                }
                Self::HardFaulted => status.hard_faulted = true,
                Self::MismatchedStateRoot => {
                    status.state_root.digest = Sha256::hash(&[b"different-state-root"]);
                }
                Self::WrongAccount => {
                    let account = wallets()[2].public_key();
                    let opening = AccountCache::new::<Sha256>(vec![StateLeaf {
                        account: account.clone(),
                        state: quote.opening.leaf.state,
                    }])
                    .unwrap();
                    quote.root = opening.root();
                    quote.opening = opening.opening(&account).unwrap();
                    status.state_root = quote.root;
                }
                Self::InactivePayer => quote.opening.leaf.state.active = false,
                Self::ZeroBalance => quote.opening.leaf.state.balance = 0,
                Self::InvalidProof => {
                    quote.opening.proof.proof.leaf_count = 2;
                    quote
                        .opening
                        .proof
                        .proof
                        .siblings
                        .push(Sha256::hash(&[b"invalid-payer-opening"]));
                }
            }
        }
    }

    #[test]
    fn payment_debit_is_local_and_advances_only_after_a_verified_receipt() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let impostor = Wallet::from_seed("impostor", 1_001);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"agent-payment-counter"]),
                7,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                cumulative_debit: 10_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                let mut first_payment = None;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("payment retry unexpectedly requested another quote");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let linked =
                        Payment::new::<Sha256>(&payment_context, request.send.clone(), receipt)
                            .unwrap();
                    let (send, receipt) = linked.into_parts();
                    first_payment = Some(Acceptance {
                        send,
                        receipts: vec![receipt],
                    });
                    let forged = SignedReceipt::sign_body_by_authority(
                        first_payment.as_ref().unwrap().receipts[0].body().clone(),
                        impostor.signer(),
                    );
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: Acceptance {
                                send: request.send,
                                receipts: vec![forged],
                            },
                        }
                        .encode(),
                    }
                })
                .await;
                let first_payment = first_payment.unwrap();

                // The retry re-quotes to confirm the staged context is still live before it
                // resubmits the exact bytes.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 93,
                                cumulative_debit: 10_007,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("live retry unexpectedly skipped its resubmission");
                    };
                    assert_eq!(request.send, first_payment.send);
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: first_payment.clone(),
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;

                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 93,
                                cumulative_debit: 20_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the second signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        7,
                        1,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    let payment = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 1,
                            total: 3,
                            acceptance: payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
            });

            let mut agent = Agent::new(0).unwrap();
            let rejected = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{rejected:#}").contains("verify operator receipt"));
            assert_eq!(agent.receipt_count(), 0);

            let payment = accepted(
                agent
                    .pay(&context, operator_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(agent.receipt_count(), 1);

            let payment = accepted(
                agent
                    .pay(&context, operator_address, operator_address, &[(1, 3)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 3);
            assert_eq!(agent.receipt_count(), 2);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn stale_uncommitted_payment_is_abandoned_on_the_finalized_endpoint_proof() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let cut = PaymentContext::new(
                Sha256::hash(&[b"stale-cut-epoch-0"]),
                0,
                operator.public_key(),
            );
            let live = PaymentContext::new(
                Sha256::hash(&[b"stale-cut-epoch-1"]),
                1,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let cut_context = cut.clone();
            let live_context = live.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            cut_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                // The first accept response is lost, so the send stays staged and uncommitted.
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(request).unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }

                // The retry re-quotes and learns the staged epoch was cut. The quote's
                // verified opening still carries the prior endpoint, and the staged epoch
                // has finalized, so the wallet abandons on settlement's proof alone.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            live_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    let mut status = settlement_status_response();
                    status.last_finalized = Some(0);
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;

                // The wallet re-stages against the live epoch and this send commits.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            live_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("re-stage did not resubmit a fresh send");
                    };
                    assert_eq!(request.send.body().epoch(), live_context.epoch());
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &live_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&live_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: live_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: Acceptance {
                                send,
                                receipts: vec![receipt],
                            },
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &live_context).await;
            });

            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            let pending = agent.pending_payment.as_ref().unwrap();
            assert_eq!(pending.send.body().epoch(), cut.epoch());
            assert_eq!(agent.cumulative_debit, 0);

            let payment = accepted(
                agent
                    .pay(&context, operator_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.epoch, live.epoch());
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 1);
            assert!(agent.pending_payment.is_none());
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn committed_payment_resolves_from_the_finalized_endpoint_without_a_verdict() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let committed = PaymentContext::new(
                Sha256::hash(&[b"committed-across-cut-0"]),
                0,
                operator.public_key(),
            );
            let successor_context = PaymentContext::new(
                Sha256::hash(&[b"committed-across-cut-1"]),
                1,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let committed_context = committed.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            committed_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                // The operator commits the batch, but its response is lost before the wallet
                // records it.
                let recorded;
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(request) =
                        operator_rpc::decode_request(request).unwrap()
                    else {
                        panic!("expected the initially staged send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &committed_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&committed_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    recorded = operator_rpc::AcceptedBatchResponse {
                        epoch: committed_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: Acceptance {
                            send,
                            receipts: vec![receipt],
                        },
                    };
                }

                // The retry re-quotes and learns the committed epoch was cut. The verified
                // opening of the finalized head carries the staged successor endpoint, so
                // the wallet concludes commitment itself and only fetches the receipts.
                let quote = quote_response_with_debit(
                    successor_context.clone(),
                    AccountState {
                        balance: 93,
                        ..AccountState::default()
                    },
                    7,
                );
                let mut status = settlement_status_response();
                status.state_root = quote.root;
                status.last_finalized = Some(0);
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptedBatch(request) = request else {
                        panic!("the receipts fetch did not name the exact staged bytes");
                    };
                    assert_eq!(request.send, recorded.acceptance.send);
                    rpc::Response::Success {
                        body: Some(recorded).encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            assert_eq!(
                agent.pending_payment.as_ref().unwrap().send.body().epoch(),
                0
            );

            let payment = accepted(
                agent
                    .pay(&context, operator_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.epoch, committed.epoch());
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 1);
            assert!(agent.pending_payment.is_none());
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn unfinalized_staged_epoch_keeps_resolution_undecidable() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let cut = PaymentContext::new(
                Sha256::hash(&[b"unavailable-probe-0"]),
                0,
                operator.public_key(),
            );
            let live_context = PaymentContext::new(
                Sha256::hash(&[b"unavailable-probe-1"]),
                1,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let cut_context = cut.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            cut_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                // The first accept response is lost, so the send stays staged and uncommitted.
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(request).unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }
                // The retry re-quotes and learns the staged epoch was cut, but nothing has
                // finalized yet, so commitment is not decidable and everything is kept.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            live_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            let staged = agent.pending_payment.as_ref().unwrap().send.clone();
            assert_eq!(staged.body().epoch(), cut.epoch());

            // An undecidable resolution must retry, never abandon: the exact staged send
            // stays pending and the debit endpoint does not advance.
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("not yet decidable"));
            assert_eq!(
                agent.pending_payment.as_ref().unwrap().send.encode(),
                staged.encode()
            );
            assert_eq!(agent.cumulative_debit, 0);
            assert_eq!(agent.receipt_count(), 0);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn finalized_endpoint_commits_without_receipts_when_the_fetch_fails() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let cut = PaymentContext::new(
                Sha256::hash(&[b"unheld-receipts-0"]),
                0,
                operator.public_key(),
            );
            let live = PaymentContext::new(
                Sha256::hash(&[b"unheld-receipts-1"]),
                1,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let cut_context = cut.clone();
            let live_context = live.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            cut_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                // The accept response is lost and the operator later serves no batch for
                // the send: only settlement's finalized endpoint proves the commitment.
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(request).unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }
                let quote = quote_response_with_debit(
                    live_context.clone(),
                    AccountState {
                        balance: 93,
                        ..AccountState::default()
                    },
                    7,
                );
                let mut status = settlement_status_response();
                status.state_root = quote.root;
                status.last_finalized = Some(0);
                let resolution_status = status;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: resolution_status.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::AcceptedBatch(_)
                    ));
                    rpc::Response::Success {
                        body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                    }
                })
                .await;

                // The carve-out lets the next send proceed against the live epoch even
                // though the finalized batch's receipts are unheld.
                let quote = quote_response_with_debit(
                    live_context.clone(),
                    AccountState {
                        balance: 93,
                        cumulative_debit: 7,
                        ..AccountState::default()
                    },
                    7,
                );
                let mut status = settlement_status_response();
                status.state_root = quote.root;
                status.last_finalized = Some(0);
                let fresh_status = status;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: fresh_status.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the successor send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &live_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&live_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: live_context.epoch(),
                            sequence: 0,
                            total: 3,
                            acceptance: Acceptance {
                                send,
                                receipts: vec![receipt],
                            },
                        }
                        .encode(),
                    }
                })
                .await;
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
                    rpc::Response::Success { body: Bytes::new() }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));

            let outcome = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
            ));
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 0);
            assert!(agent.pending_payment.is_none());
            drop(agent);

            // The unheld commit is durable: the endpoint survives restart without any
            // retained receipts, and the next send debits its exact successor.
            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 0);
            assert!(recovered.pending_payment.is_none());
            let payment = accepted(
                recovered
                    .pay(&context, operator_address, operator_address, &[(1, 3)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 3);
            assert_eq!(recovered.cumulative_debit, 10);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn forged_resolution_opening_fails_verification_and_retries() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let cut = PaymentContext::new(
                Sha256::hash(&[b"forged-resolution-0"]),
                0,
                operator.public_key(),
            );
            let live = PaymentContext::new(
                Sha256::hash(&[b"forged-resolution-1"]),
                1,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let cut_context = cut.clone();
            let live_context = live.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            cut_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(request).unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }

                // A lying operator serves a corrupted opening under settlement's true head
                // root. It cannot forge the Merkle proof, so resolution rejects it and the
                // wallet retries with everything intact.
                let mut quote = payment_quote_response(
                    live_context.clone(),
                    AccountState {
                        balance: 100,
                        ..AccountState::default()
                    },
                );
                quote.opening.proof.proof.leaf_count = 2;
                quote
                    .opening
                    .proof
                    .proof
                    .siblings
                    .push(Sha256::hash(&[b"forged-resolution-opening"]));
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    let mut status = settlement_status_response();
                    status.last_finalized = Some(0);
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            let staged = agent.pending_payment.as_ref().unwrap().send.clone();

            // The forged opening cannot cause a wrong abandon or a wrong commit.
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("verify payer state opening"));
            assert_eq!(
                agent.pending_payment.as_ref().unwrap().send.encode(),
                staged.encode()
            );
            assert_eq!(agent.cumulative_debit, 0);
            assert_eq!(agent.receipt_count(), 0);
            operator_server.await.unwrap();
            let _ = live;
        });
    }

    #[test]
    fn finalized_endpoint_below_the_committed_endpoint_is_reported_not_healed() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let live =
                PaymentContext::new(Sha256::hash(&[b"omitted-send-0"]), 0, operator.public_key());
            let successor =
                PaymentContext::new(Sha256::hash(&[b"omitted-send-1"]), 1, operator.public_key());
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let live_context = live.clone();
            let successor_context = successor.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                // The first payment commits normally and advances the durable endpoint on
                // the operator acknowledgment, before anything finalizes.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            live_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the first signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &live_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&live_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: live_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: Acceptance {
                                send,
                                receipts: vec![receipt],
                            },
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &live_context).await;

                // A second send is staged and its accept response is lost.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            live_context.clone(),
                            AccountState {
                                balance: 93,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(request).unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }

                // A Byzantine operator finalizes a close omitting BOTH sends: the verified
                // finalized endpoint sits below the committed one on every retry.
                for _ in 0..2 {
                    respond(&mut listener, |request| {
                        assert!(matches!(
                            request,
                            operator_rpc::OperatorRequest::PaymentQuote(_)
                        ));
                        rpc::Response::Success {
                            body: payment_quote_response(
                                successor_context.clone(),
                                AccountState {
                                    balance: 93,
                                    ..AccountState::default()
                                },
                            )
                            .encode(),
                        }
                    })
                    .await;
                    respond(&mut listener, |request| {
                        assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                        let mut status = settlement_status_response();
                        status.last_finalized = Some(0);
                        rpc::Response::Success {
                            body: status.encode(),
                        }
                    })
                    .await;
                }
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            accepted(
                agent
                    .pay(&context, operator_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(agent.cumulative_debit, 7);
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            let staged = agent.pending_payment.as_ref().unwrap().send.clone();

            // The mismatch names the fraud instead of panicking or healing, and it
            // survives restart with the slot intact.
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("omitted an acknowledged send"));
            assert_eq!(agent.cumulative_debit, 7);
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 7);
            let error = recovered
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("omitted an acknowledged send"));
            assert_eq!(
                recovered.pending_payment.as_ref().unwrap().send.encode(),
                staged.encode()
            );
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 1);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn deterministically_rejected_sends_are_never_staged() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let payment_context =
                PaymentContext::new(Sha256::hash(&[b"never-staged"]), 7, operator.public_key());
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
            });

            // A self entry is rejected before any request or durable staging.
            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(0, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("self-payments"));
            assert!(agent.pending_payment.is_none());

            // An unaffordable batch total is rejected after the quote, before staging, so the
            // wallet can immediately stage an acceptable send instead.
            let error = agent
                .pay(
                    &context,
                    operator_address,
                    operator_address,
                    &[(1, 60), (2, 41)],
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("insufficient available balance"));
            assert!(agent.pending_payment.is_none());
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn withdrawal_deadline_caps_at_the_clock_horizon() {
        assert_eq!(withdrawal_deadline(7), 57);
        assert_eq!(withdrawal_deadline(u64::MAX - 20), u64::MAX);
    }

    #[test]
    fn pending_deposit_recovery_validates_the_settlement_refund() {
        deterministic::Runner::default().start(|context| async move {
            let agent = Agent::new(0).unwrap();
            let account = agent.account();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let expected_account = account.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT);
                    let claim =
                        settlement_rpc::ClaimPendingDepositRequest::decode(request.body).unwrap();
                    assert_eq!(claim.account, expected_account);
                    rpc::Response::Success {
                        body: settlement_rpc::ClaimPendingDepositResponse {
                            account: wallets()[1].public_key(),
                            amount: 7,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT);
                    let claim =
                        settlement_rpc::ClaimPendingDepositRequest::decode(request.body).unwrap();
                    assert_eq!(claim.account, expected_account);
                    rpc::Response::Success {
                        body: settlement_rpc::ClaimPendingDepositResponse {
                            account: expected_account,
                            amount: 0,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let error = agent
                .recover_pending_deposit(&context, settlement_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("refunded another account"));
            let error = agent
                .recover_pending_deposit(&context, settlement_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("zero deposit refund"));
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn deposit_response_loss_preserves_exact_retry_until_acknowledged() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                        settlement_rpc::handle(&mut settlement, request)
                    })
                    .await;
                }
                settlement.status().unwrap().custody_balance
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let first = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(first.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                let first_body = first.body.clone();
                let first = operator_rpc::decode_request(first).unwrap();
                assert!(matches!(
                    operator_rpc::handle_decoded(&mut operator, first),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                    assert_eq!(request.body, first_body);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let first = agent
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Recorded { event, error } = first else {
                panic!("lost operator response unexpectedly applied deposit");
            };
            assert!(format!("{error:#}").contains("credit operator deposit"));
            assert_eq!(agent.pending_deposit.as_ref(), Some(&event));
            assert_eq!(agent.deposit_nonce, 0);

            let retry = agent
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Applied {
                epoch,
                event: applied,
            } = retry
            else {
                panic!("exact deposit retry was not acknowledged");
            };
            assert_eq!(epoch, 0);
            assert_eq!(applied, event);
            assert!(agent.pending_deposit.is_none());
            assert_eq!(agent.deposit_nonce, 1);
            assert_eq!(settlement_server.await.unwrap(), 407);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn deposit_nonce_overflow_precedes_custody() {
        deterministic::Runner::default().start(|context| async move {
            let mut agent = Agent::new(0).unwrap();
            agent.deposit_nonce = u64::MAX;
            let error = agent
                .deposit(
                    &context,
                    SocketAddr::from(([127, 0, 0, 1], 1)),
                    SocketAddr::from(([127, 0, 0, 1], 2)),
                    7,
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("deposit nonce overflow"));
            assert!(agent.pending_deposit.is_none());
        });
    }

    #[test]
    fn conflicting_deposit_acks_preserve_pending_custody() {
        deterministic::Runner::default().start(|context| async move {
            for case in 0..4 {
                let mut settlement_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 10 + case * 2)))
                    .await
                    .unwrap();
                let settlement_address = settlement_listener.local_addr().unwrap();
                let settlement_server = context.child("settlement").spawn(move |_| async move {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                        rpc::Response::Success { body: Bytes::new() }
                    })
                    .await;
                });

                let mut operator_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 11 + case * 2)))
                    .await
                    .unwrap();
                let operator_address = operator_listener.local_addr().unwrap();
                let operator_server = context.child("operator").spawn(move |_| async move {
                    respond_rpc(&mut operator_listener, |request| {
                        assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                        let operator_rpc::OperatorRequest::ApplyDeposit(request) =
                            operator_rpc::decode_request(request).unwrap()
                        else {
                            panic!("expected a deposit request");
                        };
                        if case == 3 {
                            return rpc::Response::Success {
                                body: Bytes::from_static(&[0]),
                            };
                        }
                        let mut ack = operator_rpc::DepositAck {
                            epoch: 0,
                            id: request.id,
                            account: request.account,
                            amount: request.amount,
                        };
                        match case {
                            0 => ack.id = Sha256::hash(&[b"another-deposit-id"]),
                            1 => ack.account = wallets()[1].public_key(),
                            2 => ack.amount += 1,
                            _ => unreachable!(),
                        }
                        rpc::Response::Success { body: ack.encode() }
                    })
                    .await;
                });

                let mut agent = Agent::new(0).unwrap();
                let outcome = agent
                    .deposit(&context, settlement_address, operator_address, 7)
                    .await
                    .unwrap();
                let DepositOutcome::Recorded { event, .. } = outcome else {
                    panic!("conflicting operator response cleared pending custody");
                };
                assert_eq!(agent.pending_deposit.as_ref(), Some(&event));
                assert_eq!(agent.deposit_nonce, 0);
                settlement_server.await.unwrap();
                operator_server.await.unwrap();
            }
        });
    }

    #[test]
    fn withdrawal_response_loss_and_wrong_ack_preserve_one_exact_request() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_OPENING);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;

                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let first = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(first.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                let first_body = first.body.clone();
                let first = operator_rpc::decode_request(first).unwrap();
                assert!(matches!(
                    operator_rpc::handle_decoded(&mut operator, first),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                    assert_eq!(request.body, first_body);
                    let request = operator_rpc::decode_request(request).unwrap();
                    assert!(matches!(
                        operator_rpc::handle_decoded(&mut operator, request),
                        rpc::Response::Success { .. }
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::WithdrawalAck {
                            epoch: 0,
                            digest: Sha256::hash(&[b"another-withdrawal"]),
                        }
                        .encode(),
                    }
                })
                .await;

                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                    assert_eq!(request.body, first_body);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            });

            let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
            let mut agent = Agent::new(0).unwrap();
            let first = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Signed { request, error } = first else {
                panic!("lost operator response unexpectedly applied withdrawal");
            };
            assert!(format!("{error:#}").contains("apply operator withdrawal"));
            assert!(agent.pending_withdrawal.is_some());

            let wrong_ack = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Signed {
                request: retained,
                error,
            } = wrong_ack
            else {
                panic!("wrong operator acknowledgement cleared withdrawal");
            };
            assert_eq!(retained, request);
            assert!(format!("{error:#}").contains("another withdrawal"));
            assert!(agent.pending_withdrawal.is_some());

            let retry = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Applied {
                epoch,
                request: applied,
            } = retry
            else {
                panic!("exact withdrawal retry was not acknowledged");
            };
            assert_eq!(epoch, 0);
            assert_eq!(applied, request);
            assert!(agent.pending_withdrawal.is_none());
            settlement_server.await.unwrap();
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn withdrawal_uses_only_the_exact_retained_head_when_the_operator_is_unreachable() {
        deterministic::Runner::default().start(|context| async move {
            let account = wallets()[0].public_key();
            let current = AccountCache::new::<Sha256>(vec![StateLeaf {
                account: account.clone(),
                state: AccountState {
                    balance: 100,
                    active: true,
                    ..AccountState::default()
                },
            }])
            .unwrap();
            let stale = AccountCache::new::<Sha256>(vec![StateLeaf {
                account: account.clone(),
                state: AccountState {
                    balance: 99,
                    active: true,
                    ..AccountState::default()
                },
            }])
            .unwrap();
            let current_root = current.root();
            let current_opening = current.opening(&account).unwrap();
            let stale_root = stale.root();
            let stale_opening = stale.opening(&account).unwrap();
            assert_ne!(current_root, stale_root);

            let mut agent = Agent::new(0).unwrap();
            agent
                .store
                .retain_recovery_opening(&current_root, &current_opening)
                .unwrap();
            agent
                .store
                .retain_recovery_opening(&stale_root, &stale_opening)
                .unwrap();

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    let mut status = settlement_status_response();
                    status.state_root = current_root;
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
            });

            let outcome = agent
                .withdraw(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 2)),
                    WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                )
                .await
                .unwrap();
            let WithdrawalOutcome::Signed { request, error } = outcome else {
                panic!("unreachable operator unexpectedly applied withdrawal");
            };
            assert_eq!(
                request.body().action(),
                &WithdrawalAction::Amount(NonZeroU64::new(7).unwrap())
            );
            assert_eq!(request.body().state_root(), &current_root.digest);
            assert!(format!("{error:#}").contains("apply operator withdrawal"));
            assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
            settlement_server.await.unwrap();

            let mut wrong_only = Agent::new(0).unwrap();
            wrong_only
                .store
                .retain_recovery_opening(&stale_root, &stale_opening)
                .unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server =
                context
                    .child("wrong_only_settlement")
                    .spawn(move |_| async move {
                        respond_rpc(&mut settlement_listener, |request| {
                            assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                            let mut status = settlement_status_response();
                            status.state_root = current_root;
                            rpc::Response::Success {
                                body: status.encode(),
                            }
                        })
                        .await;
                    });

            let error = wrong_only
                .withdraw(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 4)),
                    WithdrawalAction::Close,
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("read withdrawal opening"));
            assert!(wrong_only.pending_withdrawal.is_none());
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn forged_quote_operator_is_rejected_before_staging() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let impostor = Wallet::from_seed("impostor", 1_001);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"forged-quote-operator"]),
                7,
                impostor.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context,
                            AccountState {
                                balance: 100,
                                cumulative_debit: 50_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("unexpected operator"));
            drop(agent);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 0);
            assert!(recovered.pending_payment.is_none());
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn adversarial_payment_quotes_are_rejected_before_send_or_persistence() {
        deterministic::Runner::default().start(|context| async move {
            for (case_index, case) in PaymentQuoteGateCase::ALL.into_iter().enumerate() {
                let database = TempDatabase::new();
                let payment_context = PaymentContext::new(
                    Sha256::hash(&[b"adversarial-payment-quote"]),
                    7,
                    operator_key(),
                );
                let mut quote = payment_quote_response(
                    payment_context,
                    AccountState {
                        balance: 100,
                        ..AccountState::default()
                    },
                );
                let mut status = settlement_status_response();
                status.state_root = quote.root;
                case.corrupt(&mut quote, &mut status);
                let rejected_root = quote.root;
                let base_port = u16::try_from(case_index).unwrap() * 2;

                let mut operator_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 1)))
                    .await
                    .unwrap();
                let operator_address = operator_listener.local_addr().unwrap();
                let mut settlement_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 2)))
                    .await
                    .unwrap();
                let settlement_address = settlement_listener.local_addr().unwrap();
                let server = context.child(case.actor()).spawn(move |_| async move {
                    respond(&mut operator_listener, |request| {
                        let operator_rpc::OperatorRequest::PaymentQuote(request) = request else {
                            panic!("expected one payment quote request");
                        };
                        assert_eq!(request.account, wallets()[0].public_key());
                        rpc::Response::Success {
                            body: quote.encode(),
                        }
                    })
                    .await;
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                        assert_eq!(request.body, settlement_rpc::StatusRequest.encode());
                        rpc::Response::Success {
                            body: status.encode(),
                        }
                    })
                    .await;
                });

                let mut agent = Agent::open(database.path(), 0).unwrap();
                let error = agent
                    .pay(&context, settlement_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap_err();
                let error = format!("{error:#}");
                assert!(
                    error.contains(case.expected_error()),
                    "{case:?} returned an unexpected error: {error}"
                );
                drop(agent);
                server.await.unwrap();

                let recovered = Agent::open(database.path(), 0).unwrap();
                assert_eq!(recovered.cumulative_debit, 0, "{case:?}");
                assert!(recovered.pending_payment.is_none(), "{case:?}");
                assert_eq!(recovered.receipt_count(), 0, "{case:?}");
                assert!(
                    recovered
                        .store
                        .recovery_opening(&rejected_root)
                        .unwrap()
                        .is_none(),
                    "{case:?} retained an unauthenticated payer opening"
                );
            }
        });
    }

    #[test]
    fn unregistered_valid_payment_context_does_not_commit() {
        deterministic::Runner::default().start(|context| async move {
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                let mut first_send = None;
                for expected in [
                    operator_rpc::METHOD_PAYMENT_QUOTE,
                    operator_rpc::METHOD_ACCEPT_SEND,
                    operator_rpc::METHOD_PAYMENT_QUOTE,
                    operator_rpc::METHOD_ACCEPT_SEND,
                ] {
                    respond_rpc(&mut operator_listener, |request| {
                        assert_eq!(request.method, expected);
                        let request = operator_rpc::decode_request(request).unwrap();
                        if let operator_rpc::OperatorRequest::AcceptSend(request) = &request {
                            if let Some(first) = &first_send {
                                assert_eq!(&request.send, first);
                            } else {
                                first_send = Some(request.send.clone());
                            }
                        }
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                }
            });

            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for expected in [
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_CONFIRM_REGISTRATION,
                ] {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, expected);
                        settlement_rpc::handle(&mut settlement, request)
                    })
                    .await;
                }
                settlement
                    .register_epoch(
                        0,
                        400,
                        DepositBatch::<Key>::empty().root::<Sha256>().unwrap(),
                        DepositBatch::<Key>::empty().root::<Sha256>().unwrap(),
                        WithdrawalBatch::empty(),
                        &[],
                    )
                    .unwrap();
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, settlement_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains("confirm payment registration"));
            assert!(error.contains("payment registration is no longer live"));
            assert_eq!(agent.cumulative_debit, 0);
            assert_eq!(agent.receipt_count(), 0);
            let pending = agent.pending_payment.as_ref().unwrap();
            assert!(
                agent
                    .store
                    .recovery_opening(&pending.recovery_root)
                    .unwrap()
                    .is_some()
            );

            let payment = accepted(
                agent
                    .pay(&context, settlement_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 1);
            assert!(agent.pending_payment.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn response_loss_restart_retries_byte_identical_pending_send() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"response-loss-restart"]),
                7,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                cumulative_debit: 50_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                let accepted;
                let first_send;
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(request) =
                        operator_rpc::decode_request(request).unwrap()
                    else {
                        panic!("expected the initially staged send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    first_send = request.send;
                    let recipient = first_send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &first_send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, first_send.clone(), receipt)
                            .unwrap()
                            .into_parts();
                    accepted = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                }

                // The restarted retry re-quotes to confirm the staged context is still live.
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 93,
                                cumulative_debit: 50_007,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("restart retry unexpectedly skipped its resubmission");
                    };
                    assert_eq!(request.send.encode(), first_send.encode());
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: accepted,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            assert!(agent.pending_payment.is_some());
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_payment.is_some());
            let payment = accepted(
                recovered
                    .pay(&context, operator_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 1);
            assert!(recovered.pending_payment.is_none());
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_payment.is_none());
            assert_eq!(recovered.receipt_count(), 1);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn successful_receipt_commit_survives_restart_and_advances_next_debit() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"successful-payment-restart"]),
                7,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                cumulative_debit: 10_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the first signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    let payment = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 93,
                                cumulative_debit: 20_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the second signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        7,
                        1,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    let payment = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 1,
                            total: 3,
                            acceptance: payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap();
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 1);
            recovered
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap();
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 10);
            assert_eq!(recovered.receipt_count(), 2);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn withdrawal_claim_ack_loss_recovers_after_agent_restart() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator
                .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                .unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let account = wallets()[0].public_key();
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.withdrawal_evidence(&account).unwrap();
            let evidence = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            };
            let release = settlement_rpc::WithdrawalResponse {
                amount: evidence.claim.output().amount(),
                destination: evidence.claim.output().destination().clone(),
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_evidence = evidence.clone();
            let settlement_release = release.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_claim_roots(
                    &mut settlement_listener,
                    settlement_evidence.batch_id,
                    Some(roots),
                )
                .await;
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                        let request =
                            settlement_rpc::WithdrawalClaimRequest::decode(request.body).unwrap();
                        assert_eq!(request.batch_id, settlement_evidence.batch_id);
                        assert_eq!(request.claim, settlement_evidence.claim);
                        rpc::Response::Success {
                            body: settlement_rpc::WithdrawalClaimResponse::Released(
                                settlement_release.clone(),
                            )
                            .encode(),
                        }
                    })
                    .await;
                }
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = evidence.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::WithdrawalEvidence(request) = request else {
                        panic!("expected withdrawal evidence request");
                    };
                    assert_eq!(request.account, operator_evidence.account);
                    rpc::Response::Success {
                        body: operator_rpc::WithdrawalEvidenceResponse {
                            batch_id: operator_evidence.batch_id,
                            account: operator_evidence.account.clone(),
                            claim: operator_evidence.claim.clone(),
                        }
                        .encode(),
                    }
                })
                .await;

                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let request =
                    operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                        .unwrap();
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected withdrawal acknowledgement");
                };
                assert_eq!(request.as_ref(), &operator_evidence);
                assert!(matches!(
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request
                    else {
                        panic!("restart requested withdrawal evidence again");
                    };
                    assert_eq!(request.as_ref(), &operator_evidence);
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            open_withdrawal_intent(&mut agent);
            let lost = agent
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("acknowledge claimed withdrawal"));
            drop(agent);

            // The released-but-unacknowledged claim survives the restart with its exact
            // evidence pinned, and the retry goes straight to settlement without a fetch.
            let mut recovered = Agent::open(database.path(), 0).unwrap();
            let held = recovered.pending_withdrawal_claim.clone().unwrap();
            assert_eq!(held.evidence.as_ref(), Some(&evidence));
            assert_eq!(held.result.as_ref(), Some(&release));
            assert_eq!(
                recovered
                    .claim_withdrawal(&context, settlement_address, operator_address)
                    .await
                    .unwrap(),
                release
            );
            assert!(recovered.pending_withdrawal_claim.is_none());
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_withdrawal_claim.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn external_payout_ack_loss_recovers_after_agent_restart() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator.pay(0, operator.wallet_count(), 100).unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let identity = wallets().len();
            let account = external_identity().key;
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.external_payout_evidence(&account).unwrap();
            let evidence = operator_rpc::ExternalPayoutEvidenceResponse {
                batch_id: evidence.batch_id,
                claim: evidence.claim,
            };
            let payout = settlement_rpc::ExternalPayoutResponse {
                recipient: account.clone(),
                amount: 100,
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_evidence = evidence.clone();
            let settlement_payout = payout.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_claim_roots(
                    &mut settlement_listener,
                    settlement_evidence.batch_id,
                    Some(roots),
                )
                .await;
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_EXTERNAL_PAYOUT);
                        let request =
                            settlement_rpc::ExternalPayoutClaimRequest::decode(request.body)
                                .unwrap();
                        assert_eq!(request.batch_id, settlement_evidence.batch_id);
                        assert_eq!(request.claim, settlement_evidence.claim);
                        rpc::Response::Success {
                            body: settlement_rpc::ExternalPayoutClaimResponse::Released(
                                settlement_payout.clone(),
                            )
                            .encode(),
                        }
                    })
                    .await;
                }
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = evidence.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::ExternalPayoutEvidence(request) = request
                    else {
                        panic!("expected external-payout evidence request");
                    };
                    assert_eq!(request.account, account);
                    rpc::Response::Success {
                        body: operator_rpc::ExternalPayoutEvidenceResponse {
                            batch_id: operator_evidence.batch_id,
                            claim: operator_evidence.claim.clone(),
                        }
                        .encode(),
                    }
                })
                .await;

                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let request =
                    operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                        .unwrap();
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("expected external-payout acknowledgement");
                };
                assert_eq!(request.as_ref(), &operator_evidence);
                assert!(matches!(
                    operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                    else {
                        panic!("restart requested external-payout evidence again");
                    };
                    assert_eq!(request.as_ref(), &operator_evidence);
                    operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), identity).unwrap();
            let lost = agent
                .claim_external_payout(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("acknowledge claimed external payout"));
            drop(agent);

            let mut recovered = Agent::open(database.path(), identity).unwrap();
            assert!(recovered.pending_payout_claim.is_some());
            assert_eq!(
                recovered
                    .claim_external_payout(&context, settlement_address, operator_address)
                    .await
                    .unwrap(),
                payout
            );
            assert!(recovered.pending_payout_claim.is_none());
            drop(recovered);

            let recovered = Agent::open(database.path(), identity).unwrap();
            assert!(recovered.pending_payout_claim.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn foreign_withdrawal_evidence_is_never_cached() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator
                .withdraw(1, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                .unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            // Bob's certified claim pays destination "Bob". A hostile operator relabels the
            // evidence with Alice's account and serves it to Alice.
            let victim = wallets()[0].public_key();
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator
                .withdrawal_evidence(&wallets()[1].public_key())
                .unwrap();
            let forged = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: victim,
                claim: evidence.claim,
            };

            let batch = forged.batch_id;
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_claim_roots(&mut settlement_listener, batch, Some(roots)).await;
            });
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: forged.encode(),
                    }
                })
                .await;
            });

            // The genuine claim verifies against the batch's own root and the forged
            // account label passes its check, so only the destination binding stands
            // between Alice and caching Bob's claim as her own.
            let mut agent = Agent::open(database.path(), 0).unwrap();
            open_withdrawal_intent(&mut agent);
            let error = agent
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("another destination"));
            assert!(
                agent
                    .pending_withdrawal_claim
                    .as_ref()
                    .is_some_and(|held| held.evidence.is_none())
            );
            drop(agent);

            // Nothing was cached, so a restarted wallet fetches fresh evidence.
            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(
                recovered
                    .pending_withdrawal_claim
                    .as_ref()
                    .is_some_and(|held| held.evidence.is_none())
            );
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn staged_deposit_survives_restart_and_retries_the_same_id() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                        settlement_rpc::handle(&mut settlement, request)
                    })
                    .await;
                }
                settlement.status().unwrap().custody_balance
            });

            // Settlement records custody, then the wallet dies before the operator credit.
            // The unreachable operator stands in for that crash window.
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let first = agent
                .deposit(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 9)),
                    7,
                )
                .await
                .unwrap();
            let DepositOutcome::Recorded { event, .. } = first else {
                panic!("unreachable operator unexpectedly applied deposit");
            };
            drop(agent);

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            });

            // The restarted wallet restores the exact staged event, so the retry replays
            // the recorded id even though its volatile nonce differs.
            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.pending_deposit.as_ref(), Some(&event));
            recovered.deposit_nonce = 41;
            let retry = recovered
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Applied { event: applied, .. } = retry else {
                panic!("restored deposit retry was not acknowledged");
            };
            assert_eq!(applied, event);
            assert!(recovered.pending_deposit.is_none());
            assert_eq!(recovered.deposit_nonce, 42);
            drop(recovered);

            let reopened = Agent::open(database.path(), 0).unwrap();
            assert!(reopened.pending_deposit.is_none());
            assert_eq!(settlement_server.await.unwrap(), 407);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn unrecorded_deposit_rejection_discards_the_staged_event() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                // The first rejection cannot be classified: the confirmation connection
                // dies, so the staged event must survive for an exact retry.
                let mut first_deposit = Bytes::new();
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                    first_deposit = request.body;
                    rpc::error_response("deposit capacity".to_string())
                })
                .await;
                {
                    let (_, _sink, mut stream) = settlement_listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_DEPOSIT);
                }

                // The retry replays the exact staged event, and this time settlement
                // states the id was never recorded, so no custody moved.
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                    assert_eq!(request.body, first_deposit);
                    rpc::error_response("deposit capacity".to_string())
                })
                .await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_DEPOSIT);
                    rpc::Response::Success {
                        body: settlement_rpc::DepositConfirmation::Unknown.encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .deposit(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 9)),
                    7,
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("record settlement deposit"));
            assert!(agent.pending_deposit.is_some());

            let error = agent
                .deposit(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 9)),
                    7,
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("record settlement deposit"));
            assert!(agent.pending_deposit.is_none());
            drop(agent);

            // The discard is durable, so the flow is not wedged on the rejected event.
            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_deposit.is_none());
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn unfinalized_batch_evidence_is_not_cached_and_completes_after_finalization() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator
                .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                .unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let account = wallets()[0].public_key();
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.withdrawal_evidence(&account).unwrap();
            let honest = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            };

            // Well formed and destination bound, but naming a batch settlement does not
            // know: an unknown batch is not finalized, so nothing may enter the cache and
            // the claim retries later.
            let poisoned = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: BatchId::new(Sha256::hash(&[b"mislabeled-withdrawal-batch"])),
                account: honest.account.clone(),
                claim: honest.claim.clone(),
            };
            let release = settlement_rpc::WithdrawalResponse {
                amount: honest.claim.output().amount(),
                destination: honest.claim.output().destination().clone(),
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let honest_batch = honest.batch_id;
            let honest_claim = honest.claim.clone();
            let poisoned_batch = poisoned.batch_id;
            let settlement_release = release.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_claim_roots(&mut settlement_listener, poisoned_batch, None).await;
                respond_claim_roots(&mut settlement_listener, honest_batch, Some(roots)).await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    let request =
                        settlement_rpc::WithdrawalClaimRequest::decode(request.body).unwrap();
                    assert_eq!(request.batch_id, honest_batch);
                    assert_eq!(request.claim, honest_claim);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(settlement_release)
                            .encode(),
                    }
                })
                .await;
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = honest.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: poisoned.encode(),
                    }
                })
                .await;
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: operator_evidence.encode(),
                    }
                })
                .await;
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request
                    else {
                        panic!("expected withdrawal acknowledgement");
                    };
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            open_withdrawal_intent(&mut agent);
            let error = agent
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("has not finalized"));
            assert!(
                agent
                    .pending_withdrawal_claim
                    .as_ref()
                    .is_some_and(|held| held.evidence.is_none())
            );
            drop(agent);

            // Nothing entered the cache, and the next fetch verifies against the
            // finalized batch and completes the claim.
            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(
                recovered
                    .claim_withdrawal(&context, settlement_address, operator_address)
                    .await
                    .unwrap(),
                release
            );
            assert!(recovered.pending_withdrawal_claim.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn cached_evidence_claims_after_the_operator_vanishes() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator
                .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                .unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let account = wallets()[0].public_key();
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.withdrawal_evidence(&account).unwrap();
            let honest = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            };
            let release = settlement_rpc::WithdrawalResponse {
                amount: honest.claim.output().amount(),
                destination: honest.claim.output().destination().clone(),
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let honest_batch = honest.batch_id;
            let settlement_release = release.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_claim_roots(&mut settlement_listener, honest_batch, Some(roots)).await;

                // The first submission's response is lost after the evidence was cached.
                {
                    let (_, _sink, mut stream) = settlement_listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                }
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(settlement_release)
                            .encode(),
                    }
                })
                .await;
            });

            // The operator serves the evidence once, cached at its first verified fetch,
            // and then vanishes for good.
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = honest.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: operator_evidence.encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            open_withdrawal_intent(&mut agent);
            let error = agent
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("claim settlement withdrawal"));
            operator_server.await.unwrap();

            // The reserve still releases from the cached copy with the operator gone, and
            // the recorded result survives with only the acknowledgement outstanding.
            let error = agent
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("acknowledge claimed withdrawal"));
            let held = agent.pending_withdrawal_claim.clone().unwrap();
            assert_eq!(held.evidence.as_ref(), Some(&honest));
            assert_eq!(held.result.as_ref(), Some(&release));
            drop(agent);

            let recovered = Agent::open(database.path(), 0).unwrap();
            let held = recovered.pending_withdrawal_claim.unwrap();
            assert_eq!(held.evidence, Some(honest));
            assert_eq!(held.result, Some(release));
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn unfinalized_batch_payout_evidence_is_not_cached_and_completes_after_finalization() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator.pay(0, operator.wallet_count(), 100).unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let identity = wallets().len();
            let account = external_identity().key;
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.external_payout_evidence(&account).unwrap();
            let honest = operator_rpc::ExternalPayoutEvidenceResponse {
                batch_id: evidence.batch_id,
                claim: evidence.claim,
            };

            // Recipient bound, but naming a batch settlement does not know: an unknown
            // batch is not finalized, so nothing may enter the cache.
            let poisoned = operator_rpc::ExternalPayoutEvidenceResponse {
                batch_id: BatchId::new(Sha256::hash(&[b"mislabeled-payout-batch"])),
                claim: honest.claim.clone(),
            };
            let payout = settlement_rpc::ExternalPayoutResponse {
                recipient: account.clone(),
                amount: 100,
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let honest_batch = honest.batch_id;
            let poisoned_batch = poisoned.batch_id;
            let settlement_payout = payout.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_claim_roots(&mut settlement_listener, poisoned_batch, None).await;
                respond_claim_roots(&mut settlement_listener, honest_batch, Some(roots)).await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_EXTERNAL_PAYOUT);
                    let request =
                        settlement_rpc::ExternalPayoutClaimRequest::decode(request.body).unwrap();
                    assert_eq!(request.batch_id, honest_batch);
                    rpc::Response::Success {
                        body: settlement_rpc::ExternalPayoutClaimResponse::Released(
                            settlement_payout,
                        )
                        .encode(),
                    }
                })
                .await;
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = honest.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: poisoned.encode(),
                    }
                })
                .await;
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: operator_evidence.encode(),
                    }
                })
                .await;
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                    else {
                        panic!("expected external-payout acknowledgement");
                    };
                    operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), identity).unwrap();
            let error = agent
                .claim_external_payout(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("has not finalized"));
            assert!(
                agent
                    .pending_payout_claim
                    .as_ref()
                    .is_some_and(|held| held.evidence.is_none())
            );
            drop(agent);

            // Nothing entered the cache, and the next fetch verifies against the
            // finalized batch and completes the claim.
            let mut recovered = Agent::open(database.path(), identity).unwrap();
            assert_eq!(
                recovered
                    .claim_external_payout(&context, settlement_address, operator_address)
                    .await
                    .unwrap(),
                payout
            );
            assert!(recovered.pending_payout_claim.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn released_evidence_is_immutable_until_acknowledged() {
        deterministic::Runner::default().start(|_context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator
                .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                .unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let account = wallets()[0].public_key();
            let evidence = operator.withdrawal_evidence(&account).unwrap();
            let honest = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            };
            let release = settlement_rpc::WithdrawalResponse {
                amount: honest.claim.output().amount(),
                destination: honest.claim.output().destination().clone(),
            };

            let mut agent = Agent::open(database.path(), 0).unwrap();
            agent.store.open_withdrawal_claim().unwrap();
            agent.store.cache_withdrawal_claim(&honest).unwrap();
            agent
                .store
                .record_withdrawal_result(&honest, &release)
                .unwrap();

            // A recorded release pins its evidence until the acknowledgement completes,
            // so an overwrite attempt fails instead of replacing it.
            let replacement = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: BatchId::new(Sha256::hash(&[b"replacement-batch"])),
                account: honest.account.clone(),
                claim: honest.claim.clone(),
            };
            let error = agent
                .store
                .cache_withdrawal_claim(&replacement)
                .unwrap_err();
            assert!(format!("{error:#}").contains("immutable"));
            drop(agent);

            let recovered = Agent::open(database.path(), 0).unwrap();
            let held = recovered.pending_withdrawal_claim.unwrap();
            assert_eq!(held.evidence, Some(honest));
            assert_eq!(held.result, Some(release));
        });
    }

    #[test]
    fn endpoint_resolved_payment_recovers_after_hard_fault_frozen_at_its_head() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let cut = PaymentContext::new(
                Sha256::hash(&[b"endpoint-resolution-recovery-0"]),
                0,
                operator.public_key(),
            );
            let live = PaymentContext::new(
                Sha256::hash(&[b"endpoint-resolution-recovery-1"]),
                1,
                operator.public_key(),
            );
            let account = wallets()[0].public_key();

            // The finalized head H whose verified opening resolves the send as committed.
            let quote = quote_response_with_debit(
                live.clone(),
                AccountState {
                    balance: 93,
                    ..AccountState::default()
                },
                7,
            );
            let frozen_root = quote.root;
            let frozen_opening = quote.opening.clone();
            let mut status = settlement_status_response();
            status.state_root = frozen_root;
            status.last_finalized = Some(0);

            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let cut_context = cut.clone();
            let claim_account = account.clone();
            let server = context.child("server").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            cut_context.clone(),
                            AccountState {
                                balance: 100,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                // The accept response is lost, so only the endpoint rule can resolve.
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(request).unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::AcceptedBatch(_)
                    ));
                    rpc::Response::Success {
                        body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                    }
                })
                .await;

                // The operator vanished and the deployment hard-faulted frozen at H.
                respond_rpc(&mut listener, |request| {
                    assert_eq!(
                        request.method,
                        settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT
                    );
                    rpc::Response::Success {
                        body: settlement_rpc::BeginHardFaultSettlementResponse {
                            reason: settlement_rpc::HardFaultReasonResponse::ExpiredRegistration {
                                anchor: *live.anchor(),
                                epoch: 1,
                                expired_at: 22,
                            },
                            admission_fence_epoch: 1,
                            invalid_from: None,
                            frozen_state_root: frozen_root,
                            state_liability: 100,
                            unfinalized_deposit_total: 0,
                            custody_balance: 100,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_HARD_FAULT);
                    let claim =
                        settlement_rpc::ClaimHardFaultRequest::decode(request.body).unwrap();
                    assert_eq!(claim.opening, frozen_opening);
                    rpc::Response::Success {
                        body: settlement_rpc::ClaimHardFaultResponse {
                            account: claim_account,
                            withdrawal: None,
                            residual: 100,
                            released_custody: 100,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, address, address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));

            // The endpoint rule resolves the send as committed at H, and the verified
            // opening is retained without any staging path running.
            let outcome = agent
                .pay(&context, address, address, &[(1, 7)])
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
            ));
            drop(agent);

            // Recovery finds the opening retained at resolution, with no other head read.
            let recovered = Agent::open(database.path(), 0).unwrap();
            let release = recovered
                .recover_hard_fault(&context, address)
                .await
                .unwrap();
            assert_eq!(release.account, account);
            assert_eq!(release.released_custody, 100);
            server.await.unwrap();
        });
    }

    #[test]
    fn false_epoch_withdrawal_ack_cannot_strand_the_claim() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let account = wallets()[0].public_key();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server_account = account.clone();
            let server = context.child("server").spawn(move |_| async move {
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_OPENING);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;

                // A Byzantine operator acknowledges the exact request but lies about the
                // epoch. The digest binds the request, the epoch binds nothing.
                respond_rpc(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::ApplyWithdrawal(request) =
                        operator_rpc::decode_request(request).unwrap()
                    else {
                        panic!("expected the signed withdrawal");
                    };
                    let digest = operator_rpc::withdrawal_digest(&request.request);
                    operator.apply_withdrawal(request.request).unwrap();
                    rpc::Response::Success {
                        body: operator_rpc::WithdrawalAck { epoch: 999, digest }.encode(),
                    }
                })
                .await;

                // The true reserve finalizes in the real epoch-0 batch.
                operator.start_close(0).unwrap();
                operator.wait_for_closes().unwrap();
                let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
                let evidence = operator.withdrawal_evidence(&server_account).unwrap();
                let evidence = operator_rpc::WithdrawalEvidenceResponse {
                    batch_id: evidence.batch_id,
                    account: evidence.account,
                    claim: evidence.claim,
                };
                let release = settlement_rpc::WithdrawalResponse {
                    amount: evidence.claim.output().amount(),
                    destination: evidence.claim.output().destination().clone(),
                };

                let served = evidence.clone();
                respond(&mut listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                    ));
                    rpc::Response::Success {
                        body: served.encode(),
                    }
                })
                .await;
                respond_claim_roots(&mut listener, evidence.batch_id, Some(roots)).await;
                let settlement_release = release.clone();
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(settlement_release)
                            .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request
                    else {
                        panic!("expected withdrawal acknowledgement");
                    };
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
                })
                .await;
                release
            });

            let mut agent = Agent::new(0).unwrap();
            let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
            let outcome = agent
                .withdraw(&context, address, address, action)
                .await
                .unwrap();

            // The lie lands only in the display value. The durable intent carries no
            // epoch, so nothing pins the claim to the false batch.
            let WithdrawalOutcome::Applied { epoch, .. } = outcome else {
                panic!("acknowledged withdrawal was not applied");
            };
            assert_eq!(epoch, 999);

            let release = agent
                .claim_withdrawal(&context, address, address)
                .await
                .unwrap();
            assert_eq!(release, server.await.unwrap());
            assert_eq!(release.amount, 7);
            assert!(agent.pending_withdrawal_claim.is_none());
        });
    }

    #[test]
    fn withdrawal_is_refused_while_a_prior_claim_is_unfinished() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let account = wallets()[0].public_key();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server_account = account.clone();
            let server = context.child("server").spawn(move |_| async move {
                // The first withdrawal is applied and its epoch closes.
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
                for method in [
                    operator_rpc::METHOD_WITHDRAWAL_OPENING,
                    operator_rpc::METHOD_APPLY_WITHDRAWAL,
                ] {
                    respond_rpc(&mut listener, |request| {
                        assert_eq!(request.method, method);
                        let request = operator_rpc::decode_request(request).unwrap();
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                }
                operator.start_close(0).unwrap();
                operator.wait_for_closes().unwrap();
                let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
                let evidence = operator.withdrawal_evidence(&server_account).unwrap();
                let batch = evidence.batch_id;
                let first_release = settlement_rpc::WithdrawalResponse {
                    amount: evidence.claim.output().amount(),
                    destination: evidence.claim.output().destination().clone(),
                };

                // The first claim reaches recorded-but-unacknowledged: settlement
                // releases, and the acknowledgement response is lost.
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_EVIDENCE);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
                respond_claim_roots(&mut listener, batch, Some(roots)).await;
                let release = first_release.clone();
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(release).encode(),
                    }
                })
                .await;
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, operator_rpc::METHOD_ACKNOWLEDGE_WITHDRAWAL);
                }

                // The claim retry replays the release and completes the acknowledgement.
                let release = first_release.clone();
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(release).encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request
                    else {
                        panic!("expected the first withdrawal acknowledgement");
                    };
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
                })
                .await;

                // The second withdrawal now proceeds against the advanced head.
                let head = operator.withdrawal_opening(&server_account).unwrap();
                let mut status = settlement_status_response();
                status.state_root = head.root;
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
                for method in [
                    operator_rpc::METHOD_WITHDRAWAL_OPENING,
                    operator_rpc::METHOD_APPLY_WITHDRAWAL,
                ] {
                    respond_rpc(&mut listener, |request| {
                        assert_eq!(request.method, method);
                        let request = operator_rpc::decode_request(request).unwrap();
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                }
                operator.start_close(1).unwrap();
                operator.wait_for_closes().unwrap();
                let roots = claim_roots_response(&operator.settlement_roots(1).unwrap());
                let evidence = operator.withdrawal_evidence(&server_account).unwrap();
                let batch = evidence.batch_id;
                let second_release = settlement_rpc::WithdrawalResponse {
                    amount: evidence.claim.output().amount(),
                    destination: evidence.claim.output().destination().clone(),
                };
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_EVIDENCE);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
                respond_claim_roots(&mut listener, batch, Some(roots)).await;
                let release = second_release.clone();
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(release).encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request
                    else {
                        panic!("expected the second withdrawal acknowledgement");
                    };
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
                })
                .await;
                (first_release, second_release)
            });

            let mut agent = Agent::new(0).unwrap();
            let first = agent
                .withdraw(
                    &context,
                    address,
                    address,
                    WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                )
                .await
                .unwrap();
            assert!(matches!(first, WithdrawalOutcome::Applied { .. }));
            let lost = agent
                .claim_withdrawal(&context, address, address)
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("acknowledge claimed withdrawal"));

            // A second withdrawal is refused cleanly while the recorded claim is
            // unfinished, and the pinned claim state survives untouched.
            let refused = agent
                .withdraw(
                    &context,
                    address,
                    address,
                    WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
                )
                .await
                .unwrap_err();
            assert!(format!("{refused:#}").contains("pending withdrawal claim must complete"));
            let held = agent.pending_withdrawal_claim.clone().unwrap();
            assert!(held.evidence.is_some());
            assert!(held.result.is_some());

            // Completing the first claim unblocks the second withdrawal, and both
            // reserves release.
            let first_release = agent
                .claim_withdrawal(&context, address, address)
                .await
                .unwrap();
            assert!(agent.pending_withdrawal_claim.is_none());
            let second = agent
                .withdraw(
                    &context,
                    address,
                    address,
                    WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
                )
                .await
                .unwrap();
            assert!(matches!(second, WithdrawalOutcome::Applied { .. }));
            let second_release = agent
                .claim_withdrawal(&context, address, address)
                .await
                .unwrap();
            assert!(agent.pending_withdrawal_claim.is_none());
            assert_eq!((first_release, second_release), server.await.unwrap());
        });
    }

    #[test]
    fn balance_poll_retains_the_head_for_hard_fault_recovery() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"balance-poll-retention"]),
                0,
                operator.public_key(),
            );
            let account = wallets()[0].public_key();
            let quote = payment_quote_response(
                payment_context,
                AccountState {
                    balance: 100,
                    ..AccountState::default()
                },
            );
            let frozen_root = quote.root;
            let frozen_opening = quote.opening.clone();
            let mut status = settlement_status_response();
            status.state_root = frozen_root;

            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let claim_account = account.clone();
            let server = context.child("server").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;

                // The operator vanished and the deployment hard-faulted frozen at the
                // polled head.
                respond_rpc(&mut listener, |request| {
                    assert_eq!(
                        request.method,
                        settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT
                    );
                    rpc::Response::Success {
                        body: settlement_rpc::BeginHardFaultSettlementResponse {
                            reason: settlement_rpc::HardFaultReasonResponse::ExpiredRegistration {
                                anchor: Sha256::hash(&[b"balance-poll-anchor"]),
                                epoch: 0,
                                expired_at: 10,
                            },
                            admission_fence_epoch: 0,
                            invalid_from: None,
                            frozen_state_root: frozen_root,
                            state_liability: 100,
                            unfinalized_deposit_total: 0,
                            custody_balance: 100,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_HARD_FAULT);
                    let claim =
                        settlement_rpc::ClaimHardFaultRequest::decode(request.body).unwrap();
                    assert_eq!(claim.opening, frozen_opening);
                    rpc::Response::Success {
                        body: settlement_rpc::ClaimHardFaultResponse {
                            account: claim_account,
                            withdrawal: None,
                            residual: 100,
                            released_custody: 100,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            // Balance polling alone verifies and retains the current head opening.
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert_eq!(
                agent.balance(&context, address, address).await.unwrap(),
                100
            );
            drop(agent);

            let recovered = Agent::open(database.path(), 0).unwrap();
            let release = recovered
                .recover_hard_fault(&context, address)
                .await
                .unwrap();
            assert_eq!(release.account, account);
            assert_eq!(release.released_custody, 100);
            server.await.unwrap();
        });
    }
}
