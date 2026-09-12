//! SQLite ownership boundary for one agent wallet.
//!
//! Exact pending authorizations, concluded payment deltas, and verified receipts survive
//! reopening. Accepted vectors belong to their immutable epoch context, independently of
//! cached balance floors and account presence.
//!
//! The receiver's held incoming receipts follow the same discipline. Each is a self-verified
//! entry receipt crediting this wallet, durably retained so a receiver can enforce its
//! preconfirmation. They are irreplaceable once the operator is gone, so like the recovery
//! openings they are counterparty-death-surviving evidence, never an overwritable cache.

use crate::{
    chain::state as chain_state,
    operator::rpc as operator_rpc,
    protocol::{
        Acceptance, Ack, DepositEvent, Entry, Key, MAX_ACCEPTANCE_BYTES, MAX_ENTRIES, Receipt,
    },
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
    qmdb::{StateOpening, StateRoot},
    transition::BatchId,
    vector::{OutEntry, OutVector},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, FixedSize, RangeCfg};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use std::path::Path;

const SCHEMA_VERSION: i64 = 16;
const MAX_PENDING_CLAIM_BYTES: usize = 16 * 1024;
const MIN_STATE_OPENING_BYTES: usize = Key::SIZE + u64::SIZE;
const MAX_STATE_OPENING_BYTES: usize = 16 * 1024;
const MAX_STATE_PROOF_DIGESTS: usize = 256;
const DEPOSIT_EVENT_BYTES: usize = Digest::SIZE + Key::SIZE + u64::SIZE;
const AUTHORIZATION_BYTES: usize = SendAuthorization::<Key, Digest>::SIZE;
/// Bounds one encoded delta-entry list: a bounded length prefix plus [`MAX_ENTRIES`] fixed
/// entries.
const MAX_DELTA_BYTES: usize = 5 + MAX_ENTRIES * (Key::SIZE + u64::SIZE);
/// Bounds one encoded held [`Receipt`]: the fixed acknowledgment and entry fields plus a
/// full-depth membership opening.
const MAX_RECEIPT_BYTES: usize =
    Ack::SIZE + Key::SIZE + u64::SIZE * 2 + u32::SIZE * 2 + 1 + Digest::SIZE * u32::BITS as usize;

#[derive(Clone)]
pub(crate) struct PendingPayment {
    pub(crate) authorization: SendAuthorization<Key, Digest>,
    pub(crate) entries: Vec<Entry>,
    pub(crate) recovery_root: StateRoot<Digest>,
}

/// An operator-claimed signing context paired with an independently authenticated floor.
/// `epoch` is the first epoch the retained finalized balance does not include.
#[derive(Clone)]
pub(crate) struct ContextCache {
    pub(crate) context: PaymentContext<Key, Digest>,
    pub(crate) root: StateRoot<Digest>,
    pub(crate) epoch: u64,
}

/// One open claim intent: the claim kind and this wallet's identity, an overwritable
/// cache of self-verified evidence, and a recorded settlement release that pins the exact
/// evidence it paid until the operator acknowledgement completes the claim.
///
/// The intent deliberately carries no epoch: no counterparty-supplied provenance is
/// verifiable at open time, so the claim binds to its finalized batch only when fetched
/// evidence verifies locally against that batch's own claim roots.
#[derive(Clone)]
pub(crate) struct PendingClaim<E, R> {
    pub(crate) evidence: Option<E>,
    pub(crate) result: Option<R>,
}

pub(crate) type PendingWithdrawalClaim =
    PendingClaim<operator_rpc::WithdrawalEvidenceResponse, chain_state::WithdrawalResponse>;
pub(crate) type PendingPayoutClaim =
    PendingClaim<operator_rpc::ExternalPayoutEvidenceResponse, chain_state::ExternalPayoutResponse>;

pub(crate) struct State {
    /// The durable optimistic signing state, absent for a fresh wallet or after an
    /// invalidation.
    pub(crate) cache: Option<ContextCache>,
    pub(crate) pending_payment: Option<PendingPayment>,
    pub(crate) pending_deposit: Option<DepositEvent>,
    pub(crate) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pub(crate) pending_payout_claim: Option<PendingPayoutClaim>,
    pub(crate) receipt_count: u64,
    /// Receiver intake state: the durable fetch cursor and the verified-credit ledger summary.
    pub(crate) incoming: IncomingSummary,
    /// Highest epoch whose held credits were reconciled against the committed close.
    pub(crate) last_reconciled_epoch: Option<u64>,
}

/// The receiver's verified incoming ledger summary: total credited value, count of held
/// pairs, and the durable fetch cursor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IncomingSummary {
    pub(crate) total: u64,
    pub(crate) count: u64,
    pub(crate) cursor: u64,
}

/// One verified incoming receipt ready to persist: the payer-signed body digest keying it,
/// the credited edge endpoint, the delta amount versus the previously held entry, its
/// acceptance cursor, and the canonical [`Receipt`] bytes.
pub(crate) struct IncomingRecord {
    pub(crate) id: Digest,
    pub(crate) payer: Key,
    pub(crate) epoch: u64,
    pub(crate) anchor: Digest,
    pub(crate) seq: u64,
    pub(crate) cumulative: u64,
    pub(crate) count: u64,
    pub(crate) amount: u64,
    pub(crate) cursor: u64,
    pub(crate) receipt: Receipt,
}

/// The wallet's highest held receipt on one payer edge of one epoch.
pub(crate) struct HeldEntry {
    pub(crate) payer: Key,
    pub(crate) cumulative: u64,
    pub(crate) count: u64,
    pub(crate) receipt: Receipt,
}

/// One held credit answering a receiver's service-accounting query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IncomingCredit {
    pub(crate) epoch: u64,
    pub(crate) amount: u64,
}

/// The wallet's durable prior vector state for one signing context: the accepted batch
/// sequence, the epoch cumulative debit at that sequence, and the cumulative
/// per-recipient entries.
pub(crate) struct VectorState {
    pub(crate) seq: u64,
    pub(crate) cumulative_debit: u64,
    pub(crate) entries: Vec<OutEntry<Key>>,
}

/// The durable outcome of reconciling one epoch's held credits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub(crate) enum ReconcileOutcome {
    /// The committed close's terminal entries covered every held receipt.
    Reconciled = 1,
    /// A held entry exceeded the committed terminal entry and a proven challenge was submitted.
    Challenged = 2,
    /// An enforcement dead end: a finalized close understated a held receipt past the
    /// challenge window, or a registered epoch's close never admitted and settlement faulted.
    Unenforceable = 3,
}

#[derive(Clone, Copy)]
#[repr(i64)]
enum ClaimKind {
    Withdrawal = 1,
    ExternalPayout = 2,
}

/// Durable payment lifecycle. The outstanding slot holds `Staged` or `Submitted`, and the
/// ledger records every concluded payment as `Accepted` (operator receipts held),
/// `Finalized` (exact outgoing body authenticated in finalized activity), or `Abandoned`.
#[derive(Clone, Copy)]
#[repr(i64)]
enum PaymentState {
    Staged = 1,
    Submitted = 2,
    Accepted = 3,
    Finalized = 4,
    Abandoned = 5,
}

/// Payment conclusions whose deltas contribute to the wallet's balance lower bound.
const SETTLED_STATES: [i64; 2] = [
    PaymentState::Accepted as i64,
    PaymentState::Finalized as i64,
];

struct Binding {
    account: Key,
    deployment: Digest,
    operator: Key,
}

pub(crate) struct Store {
    connection: Connection,
    account: Key,
    operator: Key,
    poisoned: bool,
}

impl Store {
    pub(crate) fn open(
        path: &Path,
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, State)> {
        let connection = Connection::open(path)
            .with_context(|| format!("open SQLite agent at {}", path.display()))?;
        Self::from_connection(connection, false, account, deployment, operator)
    }

    pub(crate) fn in_memory(
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, State)> {
        Self::from_connection(
            Connection::open_in_memory().context("open in-memory SQLite agent")?,
            true,
            account,
            deployment,
            operator,
        )
    }

    fn from_connection(
        mut connection: Connection,
        in_memory: bool,
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, State)> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 5000;",
        )?;

        configure_durability(&connection, in_memory)?;
        let schema = schema_presence(&connection)?;
        match schema {
            SchemaPresence::Empty => {
                initialize_schema(&mut connection, account, deployment, operator)?;
            }
            SchemaPresence::Complete => {}
        }

        let binding = read_binding(&connection)?;
        ensure!(
            binding.account == *account,
            "agent database belongs to another account"
        );
        ensure!(
            binding.deployment == *deployment,
            "agent database belongs to another deployment"
        );
        ensure!(
            binding.operator == *operator,
            "agent database belongs to another operator"
        );
        let state = read_state(&connection, account, operator)?;

        Ok((
            Self {
                connection,
                account: account.clone(),
                operator: operator.clone(),
                poisoned: false,
            },
            state,
        ))
    }

    pub(crate) fn retain_recovery_opening(
        &mut self,
        root: &StateRoot<Digest>,
        opening: &StateOpening<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_recovery_opening(root, opening, &self.account)?;
        let encoded_root = root.encode();
        let encoded_opening = opening.encode();
        ensure!(
            encoded_root.len() == StateRoot::<Digest>::SIZE,
            "state root encoding has an unexpected length"
        );
        ensure!(
            encoded_opening.len() <= MAX_STATE_OPENING_BYTES,
            "state opening encoding exceeds its bound"
        );

        let result = retain_recovery_opening_transaction(
            &mut self.connection,
            &self.account,
            root,
            encoded_root.as_ref(),
            opening,
            encoded_opening.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn recovery_opening(
        &self,
        root: &StateRoot<Digest>,
    ) -> Result<Option<StateOpening<Key, Digest>>> {
        self.ensure_usable()?;
        read_recovery_opening(&self.connection, root, &self.account)
    }

    /// Durably caches the wallet's optimistic signing state from one verified head read:
    /// the operator-served payment context to sign under, and the retained opening at
    /// `root` as the affordability floor that context was served against.
    pub(crate) fn cache_context(
        &mut self,
        context: &PaymentContext<Key, Digest>,
        root: &StateRoot<Digest>,
        floor_epoch: u64,
    ) -> Result<()> {
        self.ensure_usable()?;
        ensure!(
            context.operator() == &self.operator,
            "cached payment context has an unexpected operator"
        );
        let epoch = sql_u64(floor_epoch, "cached floor epoch")?;
        let encoded_context = context.encode();
        let encoded_root = root.encode();
        let result = cache_context_transaction(
            &mut self.connection,
            &self.account,
            root,
            encoded_context.as_ref(),
            encoded_root.as_ref(),
            epoch,
        );
        self.finish_mutation(result)
    }

    /// Invalidates the cached signing state.
    ///
    /// A withdrawal reduces the live balance ahead of any predecessor root a floor could
    /// be read from, so the wallet clears the cache before its request can reach the
    /// operator and re-caches only from a verified head read once no withdrawal is in
    /// flight.
    pub(crate) fn clear_context(&mut self) -> Result<()> {
        self.ensure_usable()?;
        let result = clear_context_transaction(&mut self.connection);
        self.finish_mutation(result)
    }

    /// Sums the held incoming credits accepted at or after `epoch`.
    ///
    /// These are exactly the verified credits a floor served under `epoch` cannot
    /// include yet: a close commits its own epoch's accepted payments, so the
    /// predecessor state a context is served against covers only earlier epochs.
    pub(crate) fn credits_since(&self, epoch: u64) -> Result<u64> {
        self.ensure_usable()?;
        let total = self.connection.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM agent_incoming WHERE epoch >= ?1",
            [sql_u64(epoch, "credit floor epoch")?],
            |row| row.get::<_, i64>(0),
        )?;
        from_sql_u64(total, "held credit total")
    }

    /// Opens the withdrawal-claim intent. Opening is idempotent.
    pub(crate) fn open_withdrawal_claim(&mut self) -> Result<()> {
        self.ensure_usable()?;
        let result = open_claim_transaction(&mut self.connection, ClaimKind::Withdrawal);
        self.finish_mutation(result)
    }

    /// Opens the external-payout-claim intent. Opening is idempotent.
    pub(crate) fn open_payout_claim(&mut self) -> Result<()> {
        self.ensure_usable()?;
        let result = open_claim_transaction(&mut self.connection, ClaimKind::ExternalPayout);
        self.finish_mutation(result)
    }

    /// Overwrites the open withdrawal-claim intent's evidence cache.
    ///
    /// Evidence is counterparty-reproducible, so any self-verified copy may replace the
    /// cache. The one exception is evidence with a recorded settlement release, which
    /// stays immutable until the operator acknowledgement completes the claim. Evidence
    /// naming an already-completed (batch, position) is refused outright: its release is
    /// spent, so caching it could close a new intent against an old obligation.
    pub(crate) fn cache_withdrawal_claim(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_evidence(evidence, &self.account)?;
        let batch = evidence.batch_id.encode();
        let position = i64::from(evidence.claim.position());
        let encoded = evidence.encode();
        ensure_claim_bound(encoded.as_ref(), "withdrawal evidence")?;
        let result = cache_claim_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            batch.as_ref(),
            position,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Whether a withdrawal claim against this exact (batch, position) already completed.
    pub(crate) fn withdrawal_claim_completed(
        &self,
        batch_id: BatchId<Digest>,
        position: u32,
    ) -> Result<bool> {
        self.ensure_usable()?;
        claim_completed(
            &self.connection,
            ClaimKind::Withdrawal,
            batch_id.encode().as_ref(),
            i64::from(position),
        )
    }

    pub(crate) fn record_withdrawal_result(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
        result: &chain_state::WithdrawalResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_evidence(evidence, &self.account)?;
        validate_withdrawal_result(evidence, result)?;
        let evidence = evidence.encode();
        let result = result.encode();
        ensure_claim_bound(evidence.as_ref(), "withdrawal evidence")?;
        ensure_claim_bound(result.as_ref(), "withdrawal result")?;
        let result = record_claim_result_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            evidence.as_ref(),
            result.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn complete_withdrawal_claim(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
        result: &chain_state::WithdrawalResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_evidence(evidence, &self.account)?;
        validate_withdrawal_result(evidence, result)?;
        let batch = evidence.batch_id.encode();
        let position = i64::from(evidence.claim.position());
        let evidence = evidence.encode();
        let result = result.encode();
        ensure_claim_bound(evidence.as_ref(), "withdrawal evidence")?;
        ensure_claim_bound(result.as_ref(), "withdrawal result")?;
        let result = complete_claim_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            batch.as_ref(),
            position,
            evidence.as_ref(),
            result.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Overwrites the open external-payout-claim intent's evidence cache, under the same
    /// immutability and completed-claim rules as [`Self::cache_withdrawal_claim`].
    pub(crate) fn cache_payout_claim(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_payout_evidence(evidence, &self.account)?;
        let batch = evidence.batch_id.encode();
        let position = i64::from(evidence.claim.position());
        let encoded = evidence.encode();
        ensure_claim_bound(encoded.as_ref(), "external-payout evidence")?;
        let result = cache_claim_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            batch.as_ref(),
            position,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Whether an external-payout claim against this exact (batch, position) already
    /// completed.
    pub(crate) fn payout_claim_completed(
        &self,
        batch_id: BatchId<Digest>,
        position: u32,
    ) -> Result<bool> {
        self.ensure_usable()?;
        claim_completed(
            &self.connection,
            ClaimKind::ExternalPayout,
            batch_id.encode().as_ref(),
            i64::from(position),
        )
    }

    pub(crate) fn record_payout_result(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
        payout: &chain_state::ExternalPayoutResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_payout_evidence(evidence, &self.account)?;
        validate_payout_result(payout, &self.account)?;
        let evidence = evidence.encode();
        let payout = payout.encode();
        ensure_claim_bound(evidence.as_ref(), "external-payout evidence")?;
        ensure_claim_bound(payout.as_ref(), "external payout")?;
        let result = record_claim_result_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            evidence.as_ref(),
            payout.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn complete_payout_claim(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
        payout: &chain_state::ExternalPayoutResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_payout_evidence(evidence, &self.account)?;
        validate_payout_result(payout, &self.account)?;
        let batch = evidence.batch_id.encode();
        let position = i64::from(evidence.claim.position());
        let evidence = evidence.encode();
        let payout = payout.encode();
        ensure_claim_bound(evidence.as_ref(), "external-payout evidence")?;
        ensure_claim_bound(payout.as_ref(), "external payout")?;
        let result = complete_claim_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            batch.as_ref(),
            position,
            evidence.as_ref(),
            payout.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn ensure_usable(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "agent database is unusable after a failed mutation"
        );
        Ok(())
    }

    const fn finish_mutation<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Reads the wallet's durable prior vector state for `context`.
    ///
    /// Returns `None` when this exact `(epoch, anchor)` has no accepted vector.
    /// The local sender allocates sequence one after that empty epoch state.
    pub(crate) fn vector_state(
        &self,
        context: &PaymentContext<Key, Digest>,
    ) -> Result<Option<VectorState>> {
        self.ensure_usable()?;
        read_vector_state(&self.connection, context.epoch(), context.anchor())
    }

    pub(crate) fn stage_payment(
        &mut self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
        recovery_root: &StateRoot<Digest>,
        previous_debit: u64,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_authorization(
            authorization,
            entries,
            &self.account,
            &self.operator,
            previous_debit,
        )?;
        self.merged_vector(authorization.body(), entries, previous_debit)?;
        sql_u64(
            authorization.body().cumulative_debit(),
            "pending cumulative debit",
        )?;
        let encoded = authorization.encode();
        let encoded_entries = encode_entries(entries)?;
        let encoded_root = recovery_root.encode();
        let result = stage_payment_transaction(
            &mut self.connection,
            &self.account,
            recovery_root,
            previous_debit,
            encoded_root.as_ref(),
            encoded.as_ref(),
            encoded_entries.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Marks the outstanding send submitted before its bytes go on the wire, so the ledger
    /// never claims less than what may have reached the operator.
    pub(crate) fn mark_payment_submitted(
        &mut self,
        authorization: &SendAuthorization<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        let encoded = authorization.encode();
        let result = mark_payment_submitted_transaction(&mut self.connection, encoded.as_ref());
        self.finish_mutation(result)
    }

    /// Records a staged send proven never to have committed and frees the outstanding slot.
    ///
    /// The caller must authenticate exact-epoch activity exclusion or an immutable
    /// conflicting registration that permanently invalidates the authorization. The
    /// abandoned row preserves the wallet's history, and the retained recovery opening is
    /// deliberately left in place. It is keyed by full root, can be shared with an already
    /// committed sibling payment read at the same finalized head, and stays load-bearing
    /// for frozen-root recovery.
    pub(crate) fn abandon_payment(
        &mut self,
        authorization: &SendAuthorization<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        let body = authorization.body();
        let endpoint = sql_u64(body.cumulative_debit(), "abandoned cumulative debit")?;
        let id = body_id(body);
        let encoded = authorization.encode();
        let result = abandon_payment_transaction(
            &mut self.connection,
            id.as_ref(),
            endpoint,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Durably commits a send proven finalized whose operator receipts are not held, and
    /// advances the endpoint and the vector state.
    ///
    /// The caller must authenticate the exact signed body in finalized epoch activity.
    /// Finalized activity settles the debit even when its receipts cannot be fetched.
    pub(crate) fn finalize_payment_unheld(
        &mut self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
        previous_debit: u64,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_authorization(
            authorization,
            entries,
            &self.account,
            &self.operator,
            previous_debit,
        )?;
        let body = authorization.body();
        let merged = self.merged_vector(body, entries, previous_debit)?;
        let endpoint = sql_u64(body.cumulative_debit(), "finalized cumulative debit")?;
        let id = body_id(body);
        let encoded = authorization.encode();
        let vector = VectorWrite {
            epoch: body.epoch(),
            anchor: *body.anchor(),
            seq: body.seq(),
            cumulative_debit: body.cumulative_debit(),
            entries: merged,
        };
        let result = finalize_payment_unheld_transaction(
            &mut self.connection,
            previous_debit,
            id.as_ref(),
            endpoint,
            encoded.as_ref(),
            &vector,
        );
        self.finish_mutation(result)
    }

    /// Merges the staged deltas into the durable prior vector state and requires the
    /// result to commit exactly the signed root, returning the merged entries.
    fn merged_vector(
        &self,
        body: &VectorSendBody<Key, Digest>,
        entries: &[Entry],
        previous_debit: u64,
    ) -> Result<Vec<OutEntry<Key>>> {
        let prior = read_vector_state(&self.connection, body.epoch(), body.anchor())?;
        let (prior_seq, mut merged) = match prior {
            Some(state) => {
                ensure!(
                    state.cumulative_debit == previous_debit,
                    "the durable vector state is not at the committing endpoint"
                );
                (Some(state.seq), state.entries)
            }
            None => {
                ensure!(previous_debit == 0, "new context has nonzero prior debit");
                (None, Vec::new())
            }
        };
        ensure!(
            prior_seq.map_or(Some(1), |seq| seq.checked_add(1)) == Some(body.seq()),
            "the committed batch does not extend the durable vector sequence"
        );
        for entry in entries {
            match merged.binary_search_by(|edge| edge.recipient.cmp(&entry.recipient)) {
                Ok(position) => {
                    merged[position].cumulative = merged[position]
                        .cumulative
                        .checked_add(entry.amount)
                        .context("edge cumulative overflow")?;
                    merged[position].count = merged[position]
                        .count
                        .checked_add(1)
                        .context("edge count overflow")?;
                }
                Err(position) => merged.insert(
                    position,
                    OutEntry {
                        recipient: entry.recipient.clone(),
                        cumulative: entry.amount,
                        count: 1,
                    },
                ),
            }
        }
        let vector = OutVector::new(body.epoch(), self.account.clone(), merged)
            .context("assemble committed out vector")?;
        ensure!(
            vector
                .root::<Sha256, Digest>()
                .context("commit merged out vector")?
                == body.send_root(),
            "the committed batch does not extend the durable vector state"
        );
        Ok(vector.entries().to_vec())
    }

    /// Sums retained payment deltas not covered by the authenticated floor epoch.
    pub(crate) fn debits_since(&self, epoch: u64) -> Result<u64> {
        self.ensure_usable()?;
        let mut statement = self
            .connection
            .prepare("SELECT total FROM agent_payments WHERE state IN (?1, ?2) AND epoch >= ?3")?;
        let mut rows = statement.query(params![
            SETTLED_STATES[0],
            SETTLED_STATES[1],
            sql_u64(epoch, "floor epoch")?
        ])?;
        let mut total = 0_u64;
        while let Some(row) = rows.next()? {
            total = total
                .checked_add(from_sql_u64(row.get(0)?, "payment total")?)
                .context("payment history total overflow")?;
        }
        Ok(total)
    }

    /// Durably commits one accepted send's receipts and advances the endpoint and the
    /// vector state.
    pub(crate) fn commit_payment(
        &mut self,
        acceptance: &Acceptance,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
        previous_debit: u64,
        receipt_count: u64,
        finalized: bool,
    ) -> Result<u64> {
        self.ensure_usable()?;
        validate_acceptance(acceptance, &self.account, &self.operator)?;
        ensure!(
            acceptance.ack.body() == authorization.body(),
            "acceptance does not acknowledge the staged endpoint"
        );
        let body = acceptance.ack.body();

        // The acceptance verification above already authenticated this exact endpoint, so
        // the remaining checks bind it to the staged intent: the endpoint must be the
        // exact successor of the caller's previous debit by the delta total, and the
        // opened entries must credit the staged recipients positionally.
        let total = entry_total(entries)?;
        ensure!(
            previous_debit.checked_add(total) == Some(body.cumulative_debit()),
            "accepted debit is not the exact successor"
        );
        ensure!(
            acceptance.entries.len() == entries.len()
                && acceptance
                    .entries
                    .iter()
                    .zip(entries)
                    .all(|(opened, delta)| opened.recipient == delta.recipient),
            "acceptance entries do not credit the staged recipients"
        );
        let merged = self.merged_vector(body, entries, previous_debit)?;
        let endpoint = sql_u64(body.cumulative_debit(), "accepted cumulative debit")?;
        let receipts =
            u64::try_from(acceptance.entries.len()).context("agent receipt count overflow")?;
        let next_receipt_count = receipt_count
            .checked_add(receipts)
            .context("agent receipt count overflow")?;
        sql_u64(next_receipt_count, "agent receipt count")?;
        let id = body_id(body);
        let encoded_authorization = authorization.encode();
        let encoded = acceptance.encode();
        ensure!(
            encoded.len() <= MAX_ACCEPTANCE_BYTES,
            "acceptance encoding exceeds its bound"
        );
        let vector = VectorWrite {
            epoch: body.epoch(),
            anchor: *body.anchor(),
            seq: body.seq(),
            cumulative_debit: body.cumulative_debit(),
            entries: merged,
        };
        let result = commit_payment_transaction(
            &mut self.connection,
            previous_debit,
            id.as_ref(),
            endpoint,
            receipts,
            encoded_authorization.as_ref(),
            encoded.as_ref(),
            &vector,
            finalized,
        );
        self.finish_mutation(result).map(|()| next_receipt_count)
    }

    /// Durably stages one deposit event before custody moves at settlement.
    ///
    /// The event's identifier derives from a volatile nonce and only that exact identifier
    /// can be retried against recorded custody. Staging first means a crash between the
    /// settlement record and the operator credit cannot orphan the deposit: a restarted
    /// wallet retries the same event, which both custody surfaces deduplicate.
    pub(crate) fn stage_deposit(&mut self, event: &DepositEvent) -> Result<()> {
        self.ensure_usable()?;
        validate_deposit(event, &self.account)?;
        let encoded = event.encode();
        ensure!(
            encoded.len() == DEPOSIT_EVENT_BYTES,
            "deposit event encoding has an unexpected length"
        );
        let result = stage_deposit_transaction(&mut self.connection, encoded.as_ref());
        self.finish_mutation(result)
    }

    /// Removes the staged deposit after the operator acknowledged the exact event.
    pub(crate) fn complete_deposit(&mut self, event: &DepositEvent) -> Result<()> {
        self.ensure_usable()?;
        let encoded = event.encode();
        let result = remove_deposit_transaction(
            &mut self.connection,
            encoded.as_ref(),
            "pending deposit completion",
        );
        self.finish_mutation(result)
    }

    /// Discards the staged deposit after settlement confirmed the exact id was never
    /// recorded.
    ///
    /// The caller must hold that confirmation: it proves no custody moved, so abandoning
    /// the event cannot orphan a recorded deposit and a fresh event may be staged.
    pub(crate) fn discard_deposit(&mut self, event: &DepositEvent) -> Result<()> {
        self.ensure_usable()?;
        let encoded = event.encode();
        let result = remove_deposit_transaction(
            &mut self.connection,
            encoded.as_ref(),
            "pending deposit discard",
        );
        self.finish_mutation(result)
    }

    /// Durably records one verified intake page: the accepted receipts and the advanced
    /// cursor.
    ///
    /// The receipts and the cursor commit together, so a receiver that observes the cursor
    /// advance is guaranteed to hold every credit up to it. Insertion is idempotent per
    /// payer-signed body digest, so a crash before this commit leaves the cursor unchanged
    /// and the exact page refetches and reinserts without duplication. Only self-verified
    /// receipts reach here: an invalid receipt is never stored, yet the cursor still
    /// advances past it.
    pub(crate) fn record_incoming(
        &mut self,
        records: &[IncomingRecord],
        next_cursor: u64,
    ) -> Result<IncomingSummary> {
        self.ensure_usable()?;
        for record in records {
            let body = record.receipt.ack.body();
            ensure!(
                record.id == body_id(body)
                    && &record.payer == body.payer()
                    && record.epoch == body.epoch()
                    && record.anchor == *body.anchor()
                    && record.seq == body.seq()
                    && record.cumulative == record.receipt.cumulative
                    && record.count == record.receipt.count,
                "incoming record does not project its receipt"
            );
            ensure!(record.amount > 0, "incoming record credits no value");
            let encoded = record.receipt.encode();
            ensure!(
                !encoded.is_empty() && encoded.len() <= MAX_RECEIPT_BYTES,
                "incoming receipt encoding exceeds its bound"
            );
            sql_u64(record.cursor, "incoming cursor")?;
        }
        let result = record_incoming_transaction(&mut self.connection, records, next_cursor);
        self.finish_mutation(result)?;
        read_incoming_summary(&self.connection)
    }

    /// Answers the receiver's service-accounting question: has `payer` paid this account under
    /// the batch identified by `id`, and for how much? The id is the digest of the
    /// payer-signed acknowledgment body, so it is the natural invoice reference.
    pub(crate) fn paid(&self, payer: &Key, id: &Digest) -> Result<Option<IncomingCredit>> {
        self.ensure_usable()?;
        self.connection
            .query_row(
                "SELECT epoch, amount FROM agent_incoming
                 WHERE payer = ?1 AND id = ?2",
                params![payer.as_ref(), id.as_ref()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .map(|(epoch, amount)| {
                Ok(IncomingCredit {
                    epoch: from_sql_u64(epoch, "incoming epoch")?,
                    amount: from_sql_u64(amount, "incoming amount")?,
                })
            })
            .transpose()
    }

    /// Returns the highest held (cumulative, count) endpoint on one payer edge of one
    /// epoch, so intake can compute the per-edge delta of a newly served receipt.
    pub(crate) fn held_edge(&self, payer: &Key, epoch: u64) -> Result<Option<(u64, u64)>> {
        self.ensure_usable()?;
        let mut statement = self.connection.prepare(
            "SELECT cumulative, count FROM agent_incoming WHERE payer = ?1 AND epoch = ?2",
        )?;
        let mut held: Option<(u64, u64)> = None;
        for row in statement.query_map(
            params![payer.as_ref(), sql_u64(epoch, "held epoch")?],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )? {
            let (cumulative, count) = row?;
            let endpoint = (
                from_sql_u64(cumulative, "held cumulative")?,
                from_sql_u64(count, "held count")?,
            );
            if held.is_none_or(|best| endpoint > best) {
                held = Some(endpoint);
            }
        }
        Ok(held)
    }

    /// Returns the epochs holding incoming credits that reconciliation has not yet decided.
    pub(crate) fn unreconciled_incoming_epochs(&self) -> Result<Vec<u64>> {
        self.ensure_usable()?;
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT epoch FROM agent_incoming
             WHERE epoch NOT IN (SELECT epoch FROM agent_reconciled)
             ORDER BY epoch",
        )?;
        let epochs = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .map(|value| from_sql_u64(value.map_err(anyhow::Error::from)?, "unreconciled epoch"))
            .collect::<Result<Vec<_>>>()?;
        Ok(epochs)
    }

    /// Returns the wallet's highest held receipt on each payer edge of one epoch.
    pub(crate) fn held_receipts(&self, epoch: u64, operator: &Key) -> Result<Vec<HeldEntry>> {
        self.ensure_usable()?;
        let mut statement = self.connection.prepare(
            "SELECT payer, cumulative, count, length(receipt), receipt
             FROM agent_incoming WHERE epoch = ?1 ORDER BY payer",
        )?;
        let rows = statement
            .query_map([sql_u64(epoch, "epoch")?], |row| {
                let payer = row.get::<_, Vec<u8>>(0)?;
                let cumulative =
                    from_sql_u64(row.get(1)?, "held cumulative").map_err(to_sqlite_error)?;
                let count = from_sql_u64(row.get(2)?, "held count").map_err(to_sqlite_error)?;
                let encoded = read_bounded_blob(row, 3, 4, MAX_RECEIPT_BYTES, "held receipt")?;
                Ok((payer, cumulative, count, encoded))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        // Fold to the terminal receipt per edge: the highest (cumulative, count) endpoint.
        let mut held = Vec::<HeldEntry>::new();
        for (payer, cumulative, count, encoded) in rows {
            let payer = Key::decode(payer.as_slice()).context("decode held payer")?;
            let receipt =
                Receipt::decode(encoded.as_slice()).context("decode held incoming receipt")?;
            match held.last_mut() {
                Some(last) if last.payer == payer => {
                    if (cumulative, count) > (last.cumulative, last.count) {
                        *last = HeldEntry {
                            payer,
                            cumulative,
                            count,
                            receipt,
                        };
                    }
                }
                _ => held.push(HeldEntry {
                    payer,
                    cumulative,
                    count,
                    receipt,
                }),
            }
        }

        // Re-verify each terminal receipt against its own context before it can back a
        // challenge.
        for entry in &held {
            let context = context_for_body(entry.receipt.ack.body(), operator);
            entry
                .receipt
                .verify::<Sha256>(&context)
                .context("verify held incoming receipt")?;
            ensure!(
                entry.receipt.recipient == self.account
                    && entry.receipt.cumulative == entry.cumulative
                    && entry.receipt.count == entry.count
                    && entry.receipt.ack.body().payer() == &entry.payer,
                "held incoming receipt does not credit this account's edge"
            );
        }
        Ok(held)
    }

    /// Durably records that an epoch's held credits reconciled cleanly with the committed close.
    pub(crate) fn mark_reconciled(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::Reconciled)
    }

    /// Durably records that a proven challenge was submitted for an understated epoch.
    pub(crate) fn record_challenge(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::Challenged)
    }

    /// Durably records an epoch whose held credit can no longer be enforced: a finalized close
    /// understated it past the window, or its close never admitted and settlement faulted.
    pub(crate) fn record_unenforceable(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::Unenforceable)
    }

    fn record_outcome(&mut self, epoch: u64, outcome: ReconcileOutcome) -> Result<()> {
        self.ensure_usable()?;
        let result = record_reconcile_transaction(
            &mut self.connection,
            sql_u64(epoch, "reconciled epoch")?,
            outcome as i64,
        );
        self.finish_mutation(result)
    }
}

/// Verifies one acceptance owned by `account`: the dual-signed endpoint and every opened
/// entry under its committed root.
fn validate_acceptance(acceptance: &Acceptance, account: &Key, operator: &Key) -> Result<()> {
    ensure!(
        acceptance.ack.body().payer() == account,
        "accepted payment belongs to another payer"
    );
    acceptance.verify(&context_for_body(acceptance.ack.body(), operator))
}

enum SchemaPresence {
    Empty,
    Complete,
}

fn schema_presence(connection: &Connection) -> Result<SchemaPresence> {
    let has_meta = table_exists(connection, "agent_meta")?;
    let has_openings = table_exists(connection, "agent_state_openings")?;
    let has_context = table_exists(connection, "agent_context")?;
    let has_vector = table_exists(connection, "agent_vector")?;
    let has_vector_entries = table_exists(connection, "agent_vector_entries")?;
    let has_pending = table_exists(connection, "agent_pending_payment")?;
    let has_pending_deposit = table_exists(connection, "agent_pending_deposit")?;
    let has_pending_claims = table_exists(connection, "agent_pending_claims")?;
    let has_completed_claims = table_exists(connection, "agent_completed_claims")?;
    let has_payments = table_exists(connection, "agent_payments")?;
    let has_incoming_cursor = table_exists(connection, "agent_incoming_cursor")?;
    let has_incoming = table_exists(connection, "agent_incoming")?;
    let has_reconciled = table_exists(connection, "agent_reconciled")?;
    let has_unexpected: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE (type = 'table'
                    AND name NOT LIKE 'sqlite_%'
                    AND name NOT IN (
                        'agent_meta', 'agent_state_openings', 'agent_context',
                        'agent_vector', 'agent_vector_entries',
                        'agent_pending_payment', 'agent_pending_deposit',
                        'agent_pending_claims', 'agent_completed_claims', 'agent_payments',
                        'agent_incoming_cursor', 'agent_incoming', 'agent_reconciled'
                    ))
                OR type IN ('trigger', 'view')
                OR (type = 'index'
                    AND name NOT LIKE 'sqlite_autoindex_%'
                    AND name NOT IN (
                        'agent_payments_settled',
                        'agent_incoming_payer_id', 'agent_incoming_epoch_payer'
                    ))
             LIMIT 1
         )",
        [],
        |row| row.get(0),
    )?;

    if !has_meta
        && !has_openings
        && !has_context
        && !has_vector
        && !has_vector_entries
        && !has_pending
        && !has_pending_deposit
        && !has_pending_claims
        && !has_completed_claims
        && !has_payments
        && !has_incoming_cursor
        && !has_incoming
        && !has_reconciled
        && !has_unexpected
    {
        return Ok(SchemaPresence::Empty);
    }
    ensure!(
        has_meta
            && has_openings
            && has_context
            && has_vector
            && has_vector_entries
            && has_pending
            && has_pending_deposit
            && has_pending_claims
            && has_completed_claims
            && has_payments
            && has_incoming_cursor
            && has_incoming
            && has_reconciled
            && !has_unexpected,
        "incompatible agent database schema"
    );
    Ok(SchemaPresence::Complete)
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1 LIMIT 1
         )",
        [table],
        |row| row.get(0),
    )?)
}

fn configure_durability(connection: &Connection, in_memory: bool) -> Result<()> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .context("enable SQLite agent WAL")?;
    ensure!(
        (in_memory && journal_mode.eq_ignore_ascii_case("memory"))
            || journal_mode.eq_ignore_ascii_case("wal"),
        "SQLite agent database did not enter WAL mode"
    );
    connection
        .execute_batch("PRAGMA synchronous = FULL;")
        .context("configure SQLite agent durability")?;
    let locking_mode: String = connection
        .query_row("PRAGMA locking_mode = EXCLUSIVE", [], |row| row.get(0))
        .context("reserve SQLite agent ownership")?;
    ensure!(
        locking_mode.eq_ignore_ascii_case("exclusive"),
        "SQLite agent database did not enter exclusive locking mode"
    );
    connection
        .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .context("acquire SQLite agent ownership")?;
    Ok(())
}

fn initialize_schema(
    connection: &mut Connection,
    account: &Key,
    deployment: &Digest,
    operator: &Key,
) -> Result<()> {
    let schema = format!(
        "CREATE TABLE agent_meta (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL,
             account BLOB NOT NULL CHECK (length(account) = {key_size}),
             deployment BLOB NOT NULL CHECK (length(deployment) = {digest_size}),
             operator BLOB NOT NULL CHECK (length(operator) = {key_size})
         );

         CREATE TABLE agent_state_openings (
             root BLOB NOT NULL PRIMARY KEY CHECK (length(root) = {root_size}),
             opening BLOB NOT NULL CHECK (
                 length(opening) BETWEEN {min_opening_size} AND {max_opening_size}
             )
         );

         CREATE TABLE agent_context (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             context BLOB NOT NULL CHECK (length(context) = {context_size}),
             root BLOB NOT NULL CHECK (length(root) = {root_size}),
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE,
             FOREIGN KEY (root) REFERENCES agent_state_openings(root)
         );

         CREATE TABLE agent_vector (
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             anchor BLOB NOT NULL CHECK (length(anchor) = {digest_size}),
             seq INTEGER NOT NULL CHECK (seq >= 0),
             cumulative_debit INTEGER NOT NULL CHECK (cumulative_debit > 0),
             PRIMARY KEY (epoch, anchor)
         );

         CREATE TABLE agent_vector_entries (
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             anchor BLOB NOT NULL CHECK (length(anchor) = {digest_size}),
             recipient BLOB NOT NULL CHECK (length(recipient) = {key_size}),
             cumulative INTEGER NOT NULL CHECK (cumulative > 0),
             count INTEGER NOT NULL CHECK (count > 0 AND count <= cumulative),
             PRIMARY KEY (epoch, anchor, recipient),
             FOREIGN KEY (epoch, anchor) REFERENCES agent_vector(epoch, anchor)
         );

         CREATE TABLE agent_pending_payment (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             recovery_root BLOB NOT NULL CHECK (length(recovery_root) = {root_size}),
             authorization BLOB NOT NULL CHECK (length(authorization) = {authorization_size}),
             entries BLOB NOT NULL CHECK (
                 length(entries) BETWEEN 1 AND {max_delta_size}
             ),
             state INTEGER NOT NULL CHECK (state IN (1, 2)),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE,
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );

         CREATE TABLE agent_pending_deposit (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             event BLOB NOT NULL CHECK (length(event) = {deposit_event_size}),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE
         );

         CREATE TABLE agent_pending_claims (
             kind INTEGER PRIMARY KEY CHECK (kind IN (1, 2)),
             evidence BLOB CHECK (
                 evidence IS NULL OR length(evidence) BETWEEN 1 AND {max_claim_size}
             ),
             result BLOB CHECK (
                 result IS NULL OR (
                     evidence IS NOT NULL
                     AND length(result) BETWEEN 1 AND {max_claim_size}
                 )
             )
         );

         CREATE TABLE agent_completed_claims (
             kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
             batch BLOB NOT NULL CHECK (length(batch) = {batch_id_size}),
             position INTEGER NOT NULL CHECK (position >= 0),
             PRIMARY KEY (kind, batch, position)
         );

         CREATE TABLE agent_payments (
             id BLOB PRIMARY KEY CHECK (length(id) = {digest_size}),
             cumulative_debit INTEGER NOT NULL CHECK (cumulative_debit > 0),
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             anchor BLOB NOT NULL CHECK (length(anchor) = {digest_size}),
             total INTEGER NOT NULL CHECK (total > 0),
             recovery_root BLOB NOT NULL CHECK (length(recovery_root) = {root_size}),
             authorization BLOB NOT NULL CHECK (length(authorization) = {authorization_size}),
             entries BLOB NOT NULL CHECK (
                 length(entries) BETWEEN 1 AND {max_delta_size}
             ),
             state INTEGER NOT NULL CHECK (state IN (3, 4, 5)),
             receipts INTEGER CHECK (receipts IS NULL OR receipts > 0),
             acceptance BLOB CHECK (
                 acceptance IS NULL OR length(acceptance) BETWEEN 1 AND {max_acceptance_size}
             ),
             CHECK ((receipts IS NULL) = (acceptance IS NULL)),
             CHECK (state != 3 OR acceptance IS NOT NULL),
             CHECK (state != 5 OR acceptance IS NULL),
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );

         CREATE INDEX agent_payments_settled
             ON agent_payments (state, epoch);

         CREATE TABLE agent_incoming_cursor (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             cursor INTEGER NOT NULL CHECK (cursor >= 0)
         );

         CREATE TABLE agent_incoming (
             id BLOB PRIMARY KEY CHECK (length(id) = {digest_size}),
             payer BLOB NOT NULL CHECK (length(payer) = {key_size}),
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             anchor BLOB NOT NULL CHECK (length(anchor) = {digest_size}),
             seq INTEGER NOT NULL CHECK (seq >= 0),
             cumulative INTEGER NOT NULL CHECK (cumulative > 0),
             count INTEGER NOT NULL CHECK (count > 0 AND count <= cumulative),
             amount INTEGER NOT NULL CHECK (amount > 0),
             cursor INTEGER NOT NULL CHECK (cursor > 0),
             receipt BLOB NOT NULL CHECK (length(receipt) BETWEEN 1 AND {max_receipt_size})
         );
         CREATE INDEX agent_incoming_payer_id ON agent_incoming (payer, id);
         CREATE INDEX agent_incoming_epoch_payer ON agent_incoming (epoch, payer);

         CREATE TABLE agent_reconciled (
             epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
             status INTEGER NOT NULL CHECK (status IN (1, 2, 3))
         );",
        key_size = Key::SIZE,
        digest_size = Digest::SIZE,
        root_size = StateRoot::<Digest>::SIZE,
        context_size = PaymentContext::<Key, Digest>::SIZE,
        authorization_size = AUTHORIZATION_BYTES,
        max_delta_size = MAX_DELTA_BYTES,
        max_acceptance_size = MAX_ACCEPTANCE_BYTES,
        min_opening_size = MIN_STATE_OPENING_BYTES,
        max_opening_size = MAX_STATE_OPENING_BYTES,
        max_claim_size = MAX_PENDING_CLAIM_BYTES,
        batch_id_size = BatchId::<Digest>::SIZE,
        max_receipt_size = MAX_RECEIPT_BYTES,
        deposit_event_size = DEPOSIT_EVENT_BYTES,
    );
    let encoded_account = account.encode();
    let encoded_deployment = deployment.encode();
    let encoded_operator = operator.encode();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin SQLite agent initialization")?;
    transaction
        .execute_batch(&schema)
        .context("create SQLite agent schema")?;
    transaction.execute(
        "INSERT INTO agent_meta (
             singleton, schema_version, account, deployment, operator
         ) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            SCHEMA_VERSION,
            encoded_account.as_ref(),
            encoded_deployment.as_ref(),
            encoded_operator.as_ref(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO agent_incoming_cursor (singleton, cursor) VALUES (1, 0)",
        [],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("agent initialization", source))?;
    Ok(())
}

fn read_binding(connection: &Connection) -> Result<Binding> {
    let mut statement = connection.prepare(
        "SELECT singleton, schema_version,
                length(account), account,
                length(deployment), deployment,
                length(operator), operator
         FROM agent_meta
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.context("agent database metadata is missing")?;
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database metadata singleton is not canonical"
    );
    let schema_version: i64 = row.get(1)?;
    let encoded_account = read_fixed_blob(row, 2, 3, Key::SIZE, "agent account")?;
    let encoded_deployment = read_fixed_blob(row, 4, 5, Digest::SIZE, "agent deployment")?;
    let encoded_operator = read_fixed_blob(row, 6, 7, Key::SIZE, "agent operator")?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has extra metadata rows"
    );
    ensure!(
        schema_version == SCHEMA_VERSION,
        "unsupported agent database schema version {schema_version}"
    );

    Ok(Binding {
        account: Key::decode(encoded_account.as_slice()).context("decode agent account")?,
        deployment: Digest::decode(encoded_deployment.as_slice())
            .context("decode agent deployment")?,
        operator: Key::decode(encoded_operator.as_slice()).context("decode agent operator")?,
    })
}

fn read_state(connection: &Connection, account: &Key, operator: &Key) -> Result<State> {
    let receipt_count = read_receipt_state(connection, account, operator)?;
    let cache = read_context_cache(connection, account, operator)?;
    let pending_payment = read_pending_payment(connection, account)?;
    let pending_deposit = read_pending_deposit(connection, account)?;
    let (pending_withdrawal_claim, pending_payout_claim) =
        read_pending_claims(connection, account)?;
    if let Some(pending) = &pending_payment {
        validate_authorization(
            &pending.authorization,
            &pending.entries,
            account,
            operator,
            context_debit(connection, pending.authorization.body())?,
        )?;
        sql_u64(
            pending.authorization.body().cumulative_debit(),
            "pending cumulative debit",
        )?;
    }

    let incoming = read_incoming_summary(connection)?;
    let last_reconciled_epoch = read_last_reconciled(connection)?;

    Ok(State {
        cache,
        pending_payment,
        pending_deposit,
        pending_withdrawal_claim,
        pending_payout_claim,
        receipt_count,
        incoming,
        last_reconciled_epoch,
    })
}

fn read_incoming_summary(connection: &Connection) -> Result<IncomingSummary> {
    let cursor = from_sql_u64(
        connection.query_row(
            "SELECT cursor FROM agent_incoming_cursor WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?,
        "incoming cursor",
    )?;
    let (total, count) = connection.query_row(
        "SELECT COALESCE(SUM(amount), 0), COUNT(*) FROM agent_incoming",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok(IncomingSummary {
        total: from_sql_u64(total, "incoming total")?,
        count: from_sql_u64(count, "incoming count")?,
        cursor,
    })
}

fn read_last_reconciled(connection: &Connection) -> Result<Option<u64>> {
    connection
        .query_row(
            "SELECT MAX(epoch) FROM agent_reconciled WHERE status = ?1",
            [ReconcileOutcome::Reconciled as i64],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .map(|epoch| from_sql_u64(epoch, "reconciled epoch"))
        .transpose()
}

fn read_receipt_state(connection: &Connection, account: &Key, operator: &Key) -> Result<u64> {
    let receipt_count = from_sql_u64(
        connection.query_row(
            "SELECT COALESCE(SUM(receipts), 0) FROM agent_payments WHERE state IN (?1, ?2)",
            SETTLED_STATES,
            |row| row.get(0),
        )?,
        "agent receipt count",
    )?;

    // Validate the most recently recorded receipt independently of its epoch debit value.
    let stored = connection
        .query_row(
            "SELECT cumulative_debit, receipts,
                    length(recovery_root), recovery_root,
                    length(authorization), authorization,
                    length(acceptance), acceptance
             FROM agent_payments
             WHERE state IN (?1, ?2)
             ORDER BY rowid DESC
             LIMIT 1",
            SETTLED_STATES,
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    read_fixed_blob(row, 2, 3, StateRoot::<Digest>::SIZE, "recovery root")?,
                    read_fixed_blob(row, 4, 5, AUTHORIZATION_BYTES, "retained authorization")?,
                    read_optional_bounded_blob(
                        row,
                        6,
                        7,
                        MAX_ACCEPTANCE_BYTES,
                        "retained acceptance",
                    )?,
                ))
            },
        )
        .optional()?;
    let Some((stored_endpoint, stored_receipts, encoded_root, encoded_authorization, encoded)) =
        stored
    else {
        ensure!(receipt_count == 0, "agent receipt count is inconsistent");
        return Ok(0);
    };
    let stored_endpoint = from_sql_u64(stored_endpoint, "retained cumulative debit")?;
    let recovery_root =
        StateRoot::decode(encoded_root.as_slice()).context("decode receipt recovery root")?;
    read_recovery_opening(connection, &recovery_root, account)?
        .context("receipt recovery opening is missing")?;
    let authorization = SendAuthorization::decode(encoded_authorization.as_slice())
        .context("decode retained authorization")?;
    ensure!(
        authorization.body().payer() == account,
        "retained authorization belongs to another payer"
    );
    authorization
        .verify(&context_for_body(authorization.body(), operator))
        .map_err(|error| anyhow::anyhow!("verify retained authorization: {error}"))?;
    ensure!(
        authorization.body().cumulative_debit() == stored_endpoint,
        "retained authorization has another debit endpoint"
    );
    match (encoded, stored_receipts) {
        (Some(encoded), Some(stored_receipts)) => {
            let stored_receipts = from_sql_u64(stored_receipts, "retained receipt count")?;
            let acceptance =
                Acceptance::decode(encoded.as_slice()).context("decode retained acceptance")?;
            validate_acceptance(&acceptance, account, operator)
                .context("verify retained acceptance")?;
            ensure!(
                acceptance.ack.body() == authorization.body(),
                "retained acceptance does not acknowledge its ledger authorization"
            );
            ensure!(
                u64::try_from(acceptance.entries.len()).ok() == Some(stored_receipts),
                "retained acceptance receipt count is inconsistent"
            );
        }
        (None, None) => {}
        _ => anyhow::bail!("retained receipt count and acceptance disagree"),
    }
    Ok(receipt_count)
}

fn read_context_cache(
    connection: &Connection,
    account: &Key,
    operator: &Key,
) -> Result<Option<ContextCache>> {
    let mut statement = connection.prepare(
        "SELECT singleton, length(context), context, length(root), root, epoch
         FROM agent_context
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database context singleton is not canonical"
    );
    let encoded_context = read_fixed_blob(
        row,
        1,
        2,
        PaymentContext::<Key, Digest>::SIZE,
        "cached payment context",
    )?;
    let encoded_root = read_fixed_blob(row, 3, 4, StateRoot::<Digest>::SIZE, "cached floor root")?;
    let epoch = from_sql_u64(row.get(5)?, "cached context epoch")?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has extra context rows"
    );
    let context = PaymentContext::decode(encoded_context.as_slice())
        .context("decode cached payment context")?;
    ensure!(
        context.operator() == operator,
        "cached payment context has an unexpected operator"
    );
    let root = StateRoot::decode(encoded_root.as_slice()).context("decode cached floor root")?;
    read_recovery_opening(connection, &root, account)?
        .context("cached context floor opening is missing")?;
    Ok(Some(ContextCache {
        context,
        root,
        epoch,
    }))
}

fn read_pending_payment(connection: &Connection, account: &Key) -> Result<Option<PendingPayment>> {
    let mut statement = connection.prepare(
        "SELECT singleton,
                length(recovery_root), recovery_root,
                length(authorization), authorization,
                length(entries), entries,
                state
         FROM agent_pending_payment
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database pending payment singleton is not canonical"
    );
    let encoded_root = read_fixed_blob(
        row,
        1,
        2,
        StateRoot::<Digest>::SIZE,
        "pending recovery root",
    )?;
    let encoded_authorization =
        read_fixed_blob(row, 3, 4, AUTHORIZATION_BYTES, "pending authorization")?;
    let encoded_entries = read_bounded_blob(row, 5, 6, MAX_DELTA_BYTES, "pending entries")?;
    let state = row.get::<_, i64>(7)?;
    ensure!(
        state == PaymentState::Staged as i64 || state == PaymentState::Submitted as i64,
        "pending payment state is not canonical"
    );
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending payments"
    );
    let recovery_root =
        StateRoot::decode(encoded_root.as_slice()).context("decode pending recovery root")?;
    read_recovery_opening(connection, &recovery_root, account)?
        .context("pending recovery opening is missing")?;
    Ok(Some(PendingPayment {
        authorization: SendAuthorization::decode(encoded_authorization.as_slice())
            .context("decode pending authorization")?,
        entries: decode_entries(encoded_entries.as_slice())?,
        recovery_root,
    }))
}

fn read_pending_deposit(connection: &Connection, account: &Key) -> Result<Option<DepositEvent>> {
    let mut statement = connection.prepare(
        "SELECT singleton, length(event), event
         FROM agent_pending_deposit
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database pending deposit singleton is not canonical"
    );
    let encoded = read_fixed_blob(row, 1, 2, DEPOSIT_EVENT_BYTES, "pending deposit event")?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending deposits"
    );
    let event = DepositEvent::decode(encoded.as_slice()).context("decode pending deposit event")?;
    validate_deposit(&event, account)?;
    Ok(Some(event))
}

fn read_pending_claims(
    connection: &Connection,
    account: &Key,
) -> Result<(Option<PendingWithdrawalClaim>, Option<PendingPayoutClaim>)> {
    let mut statement = connection.prepare(
        "SELECT kind, length(evidence), evidence, length(result), result
         FROM agent_pending_claims
         ORDER BY kind
         LIMIT 3",
    )?;
    let mut rows = statement.query([])?;
    let mut withdrawal = None;
    let mut payout = None;
    while let Some(row) = rows.next()? {
        let kind = row.get::<_, i64>(0)?;
        let evidence = read_optional_bounded_blob(
            row,
            1,
            2,
            MAX_PENDING_CLAIM_BYTES,
            "pending claim evidence",
        )?;
        let result =
            read_optional_bounded_blob(row, 3, 4, MAX_PENDING_CLAIM_BYTES, "pending claim result")?;
        ensure!(
            result.is_none() || evidence.is_some(),
            "recorded claim result has no pinned evidence"
        );
        match kind {
            value if value == ClaimKind::Withdrawal as i64 => {
                ensure!(
                    withdrawal.is_none(),
                    "multiple withdrawal claims are pending"
                );
                let evidence = evidence
                    .map(|encoded| {
                        operator_rpc::WithdrawalEvidenceResponse::decode(encoded.as_slice())
                            .context("decode pending withdrawal evidence")
                    })
                    .transpose()?;
                let result = result
                    .map(|encoded| {
                        chain_state::WithdrawalResponse::decode(encoded.as_slice())
                            .context("decode pending withdrawal result")
                    })
                    .transpose()?;
                if let Some(evidence) = &evidence {
                    validate_withdrawal_evidence(evidence, account)?;
                    if let Some(result) = &result {
                        validate_withdrawal_result(evidence, result)?;
                    }
                }
                withdrawal = Some(PendingWithdrawalClaim { evidence, result });
            }
            value if value == ClaimKind::ExternalPayout as i64 => {
                ensure!(payout.is_none(), "multiple external payouts are pending");
                let evidence = evidence
                    .map(|encoded| {
                        operator_rpc::ExternalPayoutEvidenceResponse::decode(encoded.as_slice())
                            .context("decode pending external-payout evidence")
                    })
                    .transpose()?;
                let result = result
                    .map(|encoded| {
                        chain_state::ExternalPayoutResponse::decode(encoded.as_slice())
                            .context("decode pending external payout")
                    })
                    .transpose()?;
                if let Some(evidence) = &evidence {
                    validate_payout_evidence(evidence, account)?;
                }
                if let Some(result) = &result {
                    validate_payout_result(result, account)?;
                }
                payout = Some(PendingPayoutClaim { evidence, result });
            }
            _ => anyhow::bail!("pending claim kind is not canonical"),
        }
    }
    Ok((withdrawal, payout))
}

fn validate_recovery_opening(
    root: &StateRoot<Digest>,
    opening: &StateOpening<Key, Digest>,
    account: &Key,
) -> Result<()> {
    ensure!(
        opening.account == *account,
        "state opening belongs to another account"
    );
    opening
        .verify::<Sha256>(root)
        .context("verify payer state opening")?;
    Ok(())
}

fn validate_deposit(event: &DepositEvent, account: &Key) -> Result<()> {
    ensure!(
        &event.account == account,
        "pending deposit belongs to another account"
    );
    ensure!(event.amount > 0, "pending deposit has no value");
    Ok(())
}

fn validate_withdrawal_evidence(
    evidence: &operator_rpc::WithdrawalEvidenceResponse,
    account: &Key,
) -> Result<()> {
    ensure!(
        &evidence.account == account,
        "pending withdrawal evidence belongs to another account"
    );
    Ok(())
}

fn validate_withdrawal_result(
    evidence: &operator_rpc::WithdrawalEvidenceResponse,
    result: &chain_state::WithdrawalResponse,
) -> Result<()> {
    ensure!(
        result.destination == *evidence.claim.output().destination()
            && result.amount == evidence.claim.output().amount(),
        "pending withdrawal result differs from its evidence"
    );
    Ok(())
}

fn validate_payout_evidence(
    evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    account: &Key,
) -> Result<()> {
    ensure!(
        evidence.claim.recipient() == account,
        "pending external-payout evidence belongs to another account"
    );
    Ok(())
}

fn validate_payout_result(
    result: &chain_state::ExternalPayoutResponse,
    account: &Key,
) -> Result<()> {
    ensure!(
        &result.receiver == account,
        "pending external payout belongs to another account"
    );
    Ok(())
}

fn ensure_claim_bound(encoded: &[u8], field: &str) -> Result<()> {
    ensure!(
        !encoded.is_empty() && encoded.len() <= MAX_PENDING_CLAIM_BYTES,
        "{field} exceeds its persistence bound"
    );
    Ok(())
}

fn read_recovery_opening(
    connection: &Connection,
    root: &StateRoot<Digest>,
    account: &Key,
) -> Result<Option<StateOpening<Key, Digest>>> {
    let encoded_root = root.encode();
    let encoded = connection
        .query_row(
            "SELECT length(opening), opening
             FROM agent_state_openings WHERE root = ?1",
            [encoded_root.as_ref()],
            |row| read_bounded_blob(row, 0, 1, MAX_STATE_OPENING_BYTES, "state opening"),
        )
        .optional()?;
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let opening = StateOpening::decode_cfg(Bytes::from(encoded), &MAX_STATE_PROOF_DIGESTS)
        .context("decode state opening")?;
    validate_recovery_opening(root, &opening, account)?;
    Ok(Some(opening))
}

/// Verifies one staged authorization owned by `account`: the payer signature, the canonical
/// delta entries, and the exact-successor endpoint over `previous_debit`. Returns the checked
/// delta total.
fn validate_authorization(
    authorization: &SendAuthorization<Key, Digest>,
    entries: &[Entry],
    account: &Key,
    operator: &Key,
    previous_debit: u64,
) -> Result<u64> {
    let body = authorization.body();
    ensure!(
        body.payer() == account,
        "pending payment belongs to another payer"
    );
    authorization
        .verify(&context_for_body(body, operator))
        .context("verify pending payer authorization")?;
    let total = entry_total(entries)?;
    ensure!(
        previous_debit.checked_add(total) == Some(body.cumulative_debit()),
        "pending debit is not the exact successor"
    );
    Ok(total)
}

/// Validates the canonical delta-entry shape and returns the checked total.
fn entry_total(entries: &[Entry]) -> Result<u64> {
    ensure!(!entries.is_empty(), "batched send credits no entries");
    ensure!(
        entries.len() <= MAX_ENTRIES,
        "batched send exceeds the entry bound"
    );
    ensure!(
        entries
            .windows(2)
            .all(|pair| pair[0].recipient < pair[1].recipient),
        "batch entries are not strictly recipient-sorted"
    );
    let mut total = 0_u64;
    for entry in entries {
        ensure!(entry.amount > 0, "batch entry amount must be positive");
        total = total
            .checked_add(entry.amount)
            .context("batch total overflow")?;
    }
    Ok(total)
}

fn context_for_body(
    body: &VectorSendBody<Key, Digest>,
    operator: &Key,
) -> PaymentContext<Key, Digest> {
    PaymentContext::new(*body.anchor(), body.epoch(), operator.clone())
}

/// The payer-signed body digest keying ledger and incoming rows.
fn body_id(body: &VectorSendBody<Key, Digest>) -> Digest {
    Sha256::hash(&[body.encode().as_ref()])
}

fn encode_entries(entries: &[Entry]) -> Result<Vec<u8>> {
    let encoded = entries.to_vec().encode().to_vec();
    ensure!(
        !encoded.is_empty() && encoded.len() <= MAX_DELTA_BYTES,
        "delta entries encoding exceeds its bound"
    );
    Ok(encoded)
}

fn decode_entries(encoded: &[u8]) -> Result<Vec<Entry>> {
    Vec::<Entry>::decode_cfg(encoded, &(RangeCfg::new(1..=MAX_ENTRIES), ()))
        .context("decode delta entries")
}

/// The vector state written durably alongside an endpoint-advancing conclusion.
struct VectorWrite {
    epoch: u64,
    anchor: Digest,
    seq: u64,
    cumulative_debit: u64,
    entries: Vec<OutEntry<Key>>,
}

/// Reads accepted epoch state independently of balance presence or cached floors.
fn read_vector_state(
    connection: &Connection,
    epoch: u64,
    anchor: &Digest,
) -> Result<Option<VectorState>> {
    let epoch = sql_u64(epoch, "vector epoch")?;
    let header = connection
        .query_row(
            "SELECT seq, cumulative_debit FROM agent_vector WHERE epoch = ?1 AND anchor = ?2",
            params![epoch, anchor.as_ref()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((seq, debit)) = header else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT length(recipient), recipient, cumulative, count FROM agent_vector_entries
         WHERE epoch = ?1 AND anchor = ?2 ORDER BY recipient",
    )?;
    let entries = statement
        .query_map(params![epoch, anchor.as_ref()], |row| {
            Ok((
                read_fixed_blob(row, 0, 1, Key::SIZE, "vector recipient")?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|(recipient, cumulative, count)| {
            Ok(OutEntry {
                recipient: Key::decode(recipient.as_slice()).context("decode vector recipient")?,
                cumulative: from_sql_u64(cumulative, "vector cumulative")?,
                count: from_sql_u64(count, "vector count")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let debit = from_sql_u64(debit, "epoch debit")?;
    ensure!(
        entries
            .iter()
            .try_fold(0_u64, |sum, entry| sum.checked_add(entry.cumulative))
            == Some(debit),
        "stored epoch debit does not equal its vector total"
    );
    Ok(Some(VectorState {
        seq: from_sql_u64(seq, "vector sequence")?,
        cumulative_debit: debit,
        entries,
    }))
}

fn context_debit(connection: &Connection, body: &VectorSendBody<Key, Digest>) -> Result<u64> {
    let debit = connection
        .query_row(
            "SELECT cumulative_debit FROM agent_vector WHERE epoch = ?1 AND anchor = ?2",
            params![
                sql_u64(body.epoch(), "vector epoch")?,
                body.anchor().as_ref()
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    debit.map_or(Ok(0), |debit| from_sql_u64(debit, "epoch debit"))
}

/// Replaces the durable vector state inside `transaction`.
fn replace_vector_rows(
    transaction: &rusqlite::Transaction<'_>,
    epoch: u64,
    anchor: &Digest,
    seq: u64,
    cumulative_debit: u64,
    entries: &[OutEntry<Key>],
) -> Result<()> {
    transaction.execute(
        "INSERT INTO agent_vector (epoch, anchor, seq, cumulative_debit)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(epoch, anchor) DO UPDATE SET
             seq = excluded.seq,
             cumulative_debit = excluded.cumulative_debit",
        params![
            sql_u64(epoch, "vector epoch")?,
            anchor.as_ref(),
            sql_u64(seq, "vector sequence")?,
            sql_u64(cumulative_debit, "vector cumulative debit")?,
        ],
    )?;
    transaction.execute(
        "DELETE FROM agent_vector_entries WHERE epoch = ?1 AND anchor = ?2",
        params![sql_u64(epoch, "vector epoch")?, anchor.as_ref()],
    )?;
    let mut insert = transaction.prepare_cached(
        "INSERT INTO agent_vector_entries (recipient, cumulative, count, epoch, anchor) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for entry in entries {
        insert.execute(params![
            entry.recipient.as_ref(),
            sql_u64(entry.cumulative, "vector cumulative")?,
            sql_u64(entry.count, "vector count")?,
            sql_u64(epoch, "vector epoch")?,
            anchor.as_ref(),
        ])?;
    }
    Ok(())
}

fn retain_recovery_opening_transaction(
    connection: &mut Connection,
    account: &Key,
    root: &StateRoot<Digest>,
    encoded_root: &[u8],
    opening: &StateOpening<Key, Digest>,
    encoded_opening: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin recovery opening retention")?;
    transaction.execute(
        "INSERT INTO agent_state_openings (root, opening) VALUES (?1, ?2)
         ON CONFLICT(root) DO NOTHING",
        params![encoded_root, encoded_opening],
    )?;
    let retained = read_recovery_opening(&transaction, root, account)?
        .context("retained recovery opening is missing")?;
    ensure!(
        retained.account == opening.account && retained.balance == opening.balance,
        "state root is bound to another account balance"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("recovery opening retention", source))?;
    Ok(())
}

fn cache_context_transaction(
    connection: &mut Connection,
    account: &Key,
    root: &StateRoot<Digest>,
    encoded_context: &[u8],
    encoded_root: &[u8],
    epoch: i64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin signing context cache")?;
    read_recovery_opening(&transaction, root, account)?
        .context("signing context floor opening is missing")?;
    transaction.execute(
        "INSERT INTO agent_context (singleton, context, root, epoch) VALUES (1, ?1, ?2, ?3)
         ON CONFLICT(singleton) DO UPDATE SET
             context = excluded.context,
             root = excluded.root,
             epoch = excluded.epoch",
        params![encoded_context, encoded_root, epoch],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("signing context cache", source))?;
    Ok(())
}

fn clear_context_transaction(connection: &mut Connection) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin signing context invalidation")?;
    transaction.execute("DELETE FROM agent_context WHERE singleton = 1", [])?;

    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("signing context invalidation", source))?;
    Ok(())
}

fn stage_payment_transaction(
    connection: &mut Connection,
    account: &Key,
    recovery_root: &StateRoot<Digest>,
    previous_debit: u64,
    encoded_root: &[u8],
    encoded_authorization: &[u8],
    encoded_entries: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending payment stage")?;
    ensure!(
        context_debit(
            &transaction,
            SendAuthorization::<Key, Digest>::decode(encoded_authorization)?.body()
        )? == previous_debit,
        "agent debit changed before payment staging"
    );
    read_recovery_opening(&transaction, recovery_root, account)?
        .context("payment recovery opening is missing")?;
    let pending_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_pending_payment LIMIT 1)",
        [],
        |row| row.get(0),
    )?;
    ensure!(!pending_exists, "another payment is already staged");
    transaction.execute(
        "INSERT INTO agent_pending_payment (
             singleton, recovery_root, authorization, entries, state
         ) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            encoded_root,
            encoded_authorization,
            encoded_entries,
            PaymentState::Staged as i64,
        ],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending payment stage", source))?;
    Ok(())
}

fn mark_payment_submitted_transaction(
    connection: &mut Connection,
    encoded_authorization: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin payment submission mark")?;
    let marked = transaction.execute(
        "UPDATE agent_pending_payment SET state = ?1 WHERE singleton = 1 AND authorization = ?2",
        params![PaymentState::Submitted as i64, encoded_authorization],
    )?;
    ensure!(marked == 1, "no staged payment matched the submission mark");
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("payment submission mark", source))?;
    Ok(())
}

/// Moves the outstanding slot's exact authorization into the ledger, clears the slot, and
/// replaces the durable vector state when the conclusion advances the endpoint.
///
/// A committing conclusion checks the prior debit under the authorization's exact context
/// inside the transaction that consumes the outstanding slot.
#[allow(
    clippy::too_many_arguments,
    reason = "one durable conclusion, three call sites"
)]
fn conclude_payment_transaction(
    connection: &mut Connection,
    operation: &'static str,
    previous_debit: Option<u64>,
    id: &[u8],
    endpoint: i64,
    state: PaymentState,
    receipts: Option<i64>,
    encoded_authorization: &[u8],
    encoded_acceptance: Option<&[u8]>,
    vector: Option<&VectorWrite>,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .with_context(|| format!("begin {operation}"))?;
    let authorization = SendAuthorization::<Key, Digest>::decode(encoded_authorization)?;
    let body = authorization.body();
    if let Some(previous_debit) = previous_debit {
        ensure!(
            context_debit(&transaction, body)? == previous_debit,
            "agent debit changed before {operation}"
        );
    }
    let encoded_entries: Vec<u8> = transaction.query_row(
        "SELECT entries FROM agent_pending_payment WHERE singleton = 1 AND authorization = ?1",
        [encoded_authorization],
        |row| row.get(0),
    )?;
    let total = entry_total(&decode_entries(&encoded_entries)?)?;
    ensure!(
        transaction.execute(
            "INSERT INTO agent_payments (
                 id, cumulative_debit, recovery_root, authorization, entries,
                 state, receipts, acceptance, epoch, anchor, total
             )
             SELECT ?1, ?2, recovery_root, authorization, entries, ?3, ?4, ?5, ?7, ?8, ?9
             FROM agent_pending_payment WHERE singleton = 1 AND authorization = ?6",
            params![
                id,
                endpoint,
                state as i64,
                receipts,
                encoded_acceptance,
                encoded_authorization,
                sql_u64(body.epoch(), "payment epoch")?,
                body.anchor().as_ref(),
                sql_u64(total, "payment total")?,
            ],
        )? == 1,
        "pending payment changed before {operation}"
    );
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_payment WHERE singleton = 1 AND authorization = ?1",
            [encoded_authorization],
        )? == 1,
        "pending payment changed before {operation}"
    );
    if let Some(vector) = vector {
        replace_vector_rows(
            &transaction,
            vector.epoch,
            &vector.anchor,
            vector.seq,
            vector.cumulative_debit,
            &vector.entries,
        )?;
    }
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new(operation, source))?;
    Ok(())
}

fn abandon_payment_transaction(
    connection: &mut Connection,
    id: &[u8],
    endpoint: i64,
    encoded_authorization: &[u8],
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "payment abandonment",
        None,
        id,
        endpoint,
        PaymentState::Abandoned,
        None,
        encoded_authorization,
        None,
        None,
    )
}

fn finalize_payment_unheld_transaction(
    connection: &mut Connection,
    previous_debit: u64,
    id: &[u8],
    endpoint: i64,
    encoded_authorization: &[u8],
    vector: &VectorWrite,
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "finalized payment commit",
        Some(previous_debit),
        id,
        endpoint,
        PaymentState::Finalized,
        None,
        encoded_authorization,
        None,
        Some(vector),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one durable commit, one call site"
)]
fn commit_payment_transaction(
    connection: &mut Connection,
    previous_debit: u64,
    id: &[u8],
    endpoint: i64,
    receipts: u64,
    encoded_authorization: &[u8],
    encoded_acceptance: &[u8],
    vector: &VectorWrite,
    finalized: bool,
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "accepted payment",
        Some(previous_debit),
        id,
        endpoint,
        if finalized {
            PaymentState::Finalized
        } else {
            PaymentState::Accepted
        },
        Some(sql_u64(receipts, "retained receipt count")?),
        encoded_authorization,
        Some(encoded_acceptance),
        Some(vector),
    )
}

fn stage_deposit_transaction(connection: &mut Connection, encoded_event: &[u8]) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending deposit stage")?;
    transaction.execute(
        "INSERT INTO agent_pending_deposit (singleton, event) VALUES (1, ?1)
         ON CONFLICT(singleton) DO NOTHING",
        [encoded_event],
    )?;
    let stored = transaction
        .query_row(
            "SELECT event FROM agent_pending_deposit WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .context("staged deposit event is missing")?;
    ensure!(stored == encoded_event, "another deposit is already staged");
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending deposit stage", source))?;
    Ok(())
}

fn remove_deposit_transaction(
    connection: &mut Connection,
    encoded_event: &[u8],
    operation: &'static str,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .with_context(|| format!("begin {operation}"))?;
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_deposit WHERE singleton = 1 AND event = ?1",
            [encoded_event],
        )? == 1,
        "{operation} does not match durable staging"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new(operation, source))?;
    Ok(())
}

fn record_incoming_transaction(
    connection: &mut Connection,
    records: &[IncomingRecord],
    next_cursor: u64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin incoming intake record")?;
    let current = from_sql_u64(
        transaction.query_row(
            "SELECT cursor FROM agent_incoming_cursor WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?,
        "incoming cursor",
    )?;
    {
        let mut insert = transaction.prepare_cached(
            "INSERT INTO agent_incoming (
                 id, payer, epoch, anchor, seq, cumulative, count, amount, cursor, receipt
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO NOTHING",
        )?;
        for record in records {
            let encoded = record.receipt.encode();
            insert.execute(params![
                record.id.as_ref(),
                record.payer.as_ref(),
                sql_u64(record.epoch, "incoming epoch")?,
                record.anchor.as_ref(),
                sql_u64(record.seq, "incoming sequence")?,
                sql_u64(record.cumulative, "incoming cumulative")?,
                sql_u64(record.count, "incoming count")?,
                sql_u64(record.amount, "incoming amount")?,
                sql_u64(record.cursor, "incoming cursor")?,
                encoded.as_ref(),
            ])?;
        }
    }

    // The cursor never rewinds, so an out-of-order or duplicate page cannot lose ground.
    let advanced = current.max(next_cursor);
    transaction.execute(
        "UPDATE agent_incoming_cursor SET cursor = ?1 WHERE singleton = 1",
        [sql_u64(advanced, "incoming cursor")?],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("incoming intake record", source))?;
    Ok(())
}

fn record_reconcile_transaction(
    connection: &mut Connection,
    epoch: i64,
    status: i64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin reconcile outcome record")?;

    // The first recorded outcome for an epoch is durable: reconcile never reopens a decided
    // epoch, so an idempotent re-run leaves it unchanged.
    transaction.execute(
        "INSERT INTO agent_reconciled (epoch, status) VALUES (?1, ?2)
         ON CONFLICT(epoch) DO NOTHING",
        params![epoch, status],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("reconcile outcome record", source))?;
    Ok(())
}

fn open_claim_transaction(connection: &mut Connection, kind: ClaimKind) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin claim intent open")?;
    transaction.execute(
        "INSERT INTO agent_pending_claims (kind, evidence, result)
         VALUES (?1, NULL, NULL)
         ON CONFLICT(kind) DO NOTHING",
        [kind as i64],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("claim intent open", source))?;
    Ok(())
}

fn cache_claim_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    batch: &[u8],
    position: i64,
    evidence: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin claim evidence cache")?;
    ensure!(
        !claim_completed(&transaction, kind, batch, position)?,
        "claim evidence names an already-completed (batch, position)"
    );
    let result_recorded: Option<bool> = transaction
        .query_row(
            "SELECT result IS NOT NULL FROM agent_pending_claims WHERE kind = ?1",
            [kind as i64],
            |row| row.get(0),
        )
        .optional()?;
    let result_recorded = result_recorded.context("no claim intent is open")?;
    ensure!(
        !result_recorded,
        "claim evidence with a recorded result is immutable"
    );
    transaction.execute(
        "UPDATE agent_pending_claims SET evidence = ?1 WHERE kind = ?2",
        params![evidence, kind as i64],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("claim evidence cache", source))?;
    Ok(())
}

fn record_claim_result_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    evidence: &[u8],
    result: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending claim result")?;
    let (stored_evidence, stored_result) = transaction
        .query_row(
            "SELECT evidence, result FROM agent_pending_claims WHERE kind = ?1",
            [kind as i64],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            },
        )
        .context("pending claim evidence is missing")?;
    ensure!(
        stored_evidence.as_deref() == Some(evidence),
        "another claim of this kind is pending"
    );
    if let Some(stored_result) = stored_result {
        ensure!(stored_result == result, "pending claim has another result");
    } else {
        ensure!(
            transaction.execute(
                "UPDATE agent_pending_claims SET result = ?1
                 WHERE kind = ?2 AND evidence = ?3 AND result IS NULL",
                params![result, kind as i64, evidence],
            )? == 1,
            "pending claim changed before its result was recorded"
        );
    }
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending claim result", source))?;
    Ok(())
}

/// Completes the claim: the intent deletion and the durable record of the
/// consumed (kind, batch, position) commit in one transaction, so evidence
/// against a spent release can never rebind to a later intent of this kind.
fn complete_claim_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    batch: &[u8],
    position: i64,
    evidence: &[u8],
    result: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending claim completion")?;
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_claims
             WHERE kind = ?1 AND evidence = ?2 AND result = ?3",
            params![kind as i64, evidence, result],
        )? == 1,
        "pending claim completion does not match durable evidence"
    );

    // The cache guard refuses completed evidence before it can pin an intent,
    // so the deleted intent's key is never already recorded: a conflicting
    // insert aborts the completion loudly instead of masking that breach.
    transaction.execute(
        "INSERT INTO agent_completed_claims (kind, batch, position) VALUES (?1, ?2, ?3)",
        params![kind as i64, batch, position],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending claim completion", source))?;
    Ok(())
}

fn claim_completed(
    connection: &Connection,
    kind: ClaimKind,
    batch: &[u8],
    position: i64,
) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM agent_completed_claims
             WHERE kind = ?1 AND batch = ?2 AND position = ?3
         )",
        params![kind as i64, batch, position],
        |row| row.get(0),
    )?)
}

fn read_fixed_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    expected: usize,
    field: &str,
) -> rusqlite::Result<Vec<u8>> {
    let length = usize::try_from(row.get::<_, i64>(length_column)?)
        .map_err(|_| to_sqlite_error(anyhow::anyhow!("invalid {field} length")))?;
    if length != expected {
        return Err(to_sqlite_error(anyhow::anyhow!(
            "invalid {field} length {length}, expected {expected}"
        )));
    }
    row.get(value_column)
}

fn read_bounded_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    maximum: usize,
    field: &str,
) -> rusqlite::Result<Vec<u8>> {
    let length = usize::try_from(row.get::<_, i64>(length_column)?)
        .map_err(|_| to_sqlite_error(anyhow::anyhow!("invalid {field} length")))?;
    if length == 0 || length > maximum {
        return Err(to_sqlite_error(anyhow::anyhow!(
            "invalid {field} length {length}, maximum {maximum}"
        )));
    }
    row.get(value_column)
}

fn read_optional_bounded_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    maximum: usize,
    field: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let length = row.get::<_, Option<i64>>(length_column)?;
    let value = row.get::<_, Option<Vec<u8>>>(value_column)?;
    match (length, value) {
        (None, None) => Ok(None),
        (Some(length), Some(value)) => {
            let length = usize::try_from(length)
                .map_err(|_| to_sqlite_error(anyhow::anyhow!("invalid {field} length")))?;
            if length == 0 || length > maximum || value.len() != length {
                return Err(to_sqlite_error(anyhow::anyhow!(
                    "invalid {field} length {length}, maximum {maximum}"
                )));
            }
            Ok(Some(value))
        }
        _ => Err(to_sqlite_error(anyhow::anyhow!(
            "{field} length and value disagree"
        ))),
    }
}

fn sql_u64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds SQLite INTEGER range"))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{field} is negative"))
}

fn to_sqlite_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, error.into())
}

#[cfg(test)]
mod tests {
    use super::{super::fixtures::StateFixture, *};
    use crate::protocol::{Wallet, deployment, identities, operator_key, wallets};
    use std::{
        fs,
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
                "commonware-terminal-agent-store-{}-{id}",
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

    fn open_error(path: &Path, account: &Key, deployment: &Digest, operator: &Key) -> String {
        match Store::open(path, account, deployment, operator) {
            Ok(_) => panic!("incompatible agent database was accepted"),
            Err(error) => format!("{error:#}"),
        }
    }

    fn open_store(path: &Path, account: &Key) -> (Store, State) {
        Store::open(path, account, &deployment(), &operator_key()).unwrap()
    }

    fn recovery_evidence(
        account: &Key,
        balance: u64,
    ) -> (StateRoot<Digest>, StateOpening<Key, Digest>) {
        let cache = StateFixture::new(vec![(account.clone(), balance)]);
        (cache.root(), cache.opening(account).unwrap())
    }

    /// Signs the first epoch-local batch from an empty outgoing vector.
    fn sign_delta(
        context: &PaymentContext<Key, Digest>,
        wallet: &Wallet,
        amount: u64,
    ) -> (SendAuthorization<Key, Digest>, Vec<Entry>) {
        let recipient = identities().remove(1).key;
        let entries = vec![Entry {
            recipient: recipient.clone(),
            amount,
        }];
        let vector = OutVector::new(
            context.epoch(),
            wallet.public_key(),
            vec![OutEntry {
                recipient,
                cumulative: amount,
                count: 1,
            }],
        )
        .unwrap();
        let body = VectorSendBody::new(
            context,
            wallet.public_key(),
            1,
            amount,
            vector.root::<Sha256, Digest>().unwrap(),
        );
        (SendAuthorization::sign(body, wallet.signer()), entries)
    }

    fn signed_send(wallet: &Wallet, anchor: &[u8]) -> (SendAuthorization<Key, Digest>, Vec<Entry>) {
        let context = PaymentContext::new(Sha256::hash(&[anchor]), 1, operator_key());
        sign_delta(&context, wallet, 1)
    }

    #[test]
    fn context_floor_round_trips_independently_of_signing_epoch() {
        let database = TempDatabase::new();
        let account = identities().remove(0).key;
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, state) = open_store(database.path(), &account);
        assert!(state.cache.is_none());
        let context = PaymentContext::new(Sha256::hash(&[b"cache-context"]), 3, operator_key());
        let error = store.cache_context(&context, &root, 0).unwrap_err();
        assert!(format!("{error:#}").contains("floor opening is missing"));
        drop(store);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.cache_context(&context, &root, 0).unwrap();
        drop(store);
        let (mut store, state) = open_store(database.path(), &account);
        let cache = state.cache.unwrap();
        assert_eq!(cache.context, context);
        assert_eq!(cache.root, root);
        assert_eq!(cache.epoch, 0);
        store.clear_context().unwrap();
        drop(store);
        let (_, state) = open_store(database.path(), &account);
        assert!(state.cache.is_none());
    }

    #[test]
    fn submitted_intent_cannot_be_replaced_by_another_epoch() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        let (original, entries) = signed_send(&wallet, b"original");
        store.stage_payment(&original, &entries, &root, 0).unwrap();
        store.mark_payment_submitted(&original).unwrap();
        let next = PaymentContext::new(Sha256::hash(&[b"next"]), 2, operator_key());
        let (replacement, _) = sign_delta(&next, &wallet, 1);
        assert!(
            store
                .stage_payment(&replacement, &entries, &root, 0)
                .is_err()
        );
        drop(store);
        let (_, state) = open_store(database.path(), &account);
        let retained = state.pending_payment.unwrap();
        assert_eq!(retained.authorization.encode(), original.encode());
        assert_eq!(retained.entries, entries);
        assert_eq!(retained.recovery_root, root);
    }

    #[test]
    fn accepted_epoch_state_survives_floor_invalidation_and_reopen() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let context = PaymentContext::new(Sha256::hash(&[b"durable-epoch"]), 1, operator_key());
        let (authorization, entries) = sign_delta(&context, &wallet, 7);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store
            .stage_payment(&authorization, &entries, &root, 0)
            .unwrap();
        store
            .finalize_payment_unheld(&authorization, &entries, 0)
            .unwrap();
        store.clear_context().unwrap();
        drop(store);
        let (store, state) = open_store(database.path(), &account);
        assert!(state.cache.is_none());
        let retained = store.vector_state(&context).unwrap().unwrap();
        assert_eq!(retained.cumulative_debit, 7);
        assert_eq!(retained.seq, authorization.body().seq());
        assert_eq!(retained.entries[0].cumulative, 7);
    }

    #[test]
    fn lower_epoch_debit_preserves_both_contexts_and_exact_retry() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let first = PaymentContext::new(Sha256::hash(&[b"first-epoch"]), 1, operator_key());
        let second = PaymentContext::new(Sha256::hash(&[b"second-epoch"]), 2, operator_key());
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        let (authorization, entries) = sign_delta(&first, &wallet, 7);
        store
            .stage_payment(&authorization, &entries, &root, 0)
            .unwrap();
        store
            .finalize_payment_unheld(&authorization, &entries, 0)
            .unwrap();
        let (next, entries) = sign_delta(&second, &wallet, 3);
        store.stage_payment(&next, &entries, &root, 0).unwrap();
        store.mark_payment_submitted(&next).unwrap();
        drop(store);
        let (mut store, state) = open_store(database.path(), &account);
        assert_eq!(state.pending_payment.unwrap().authorization, next);
        store.finalize_payment_unheld(&next, &entries, 0).unwrap();
        drop(store);
        let (store, _) = open_store(database.path(), &account);
        assert_eq!(
            store
                .vector_state(&first)
                .unwrap()
                .unwrap()
                .cumulative_debit,
            7
        );
        assert_eq!(
            store
                .vector_state(&second)
                .unwrap()
                .unwrap()
                .cumulative_debit,
            3
        );
        assert_eq!(store.debits_since(1).unwrap(), 10);
        assert_eq!(store.debits_since(2).unwrap(), 3);
        assert_eq!(store.debits_since(3).unwrap(), 0);
    }

    #[test]
    fn credits_since_sums_only_the_floor_epoch_onward() {
        let database = TempDatabase::new();
        let account = identities().remove(0).key;
        let (store, _) = open_store(database.path(), &account);
        let payer = identities().remove(1).key;
        for (epoch, amount, tag) in [(0_i64, 5_i64, 0_u8), (1, 7, 1), (3, 11, 2)] {
            store
                .connection
                .execute(
                    "INSERT INTO agent_incoming (
                         id, payer, epoch, anchor, seq, cumulative, count, amount, cursor, receipt
                     ) VALUES (?1, ?2, ?3, ?4, 1, ?5, 1, ?5, ?6, x'01')",
                    params![
                        Sha256::hash(&[b"credit-id", &[tag]]).as_ref(),
                        payer.as_ref(),
                        epoch,
                        Sha256::hash(&[b"credit-anchor"]).as_ref(),
                        amount,
                        epoch + 1,
                    ],
                )
                .unwrap();
        }

        assert_eq!(store.credits_since(0).unwrap(), 23);
        assert_eq!(store.credits_since(1).unwrap(), 18);
        assert_eq!(store.credits_since(2).unwrap(), 11);
        assert_eq!(store.credits_since(4).unwrap(), 0);
    }

    #[test]
    fn recovery_opening_retention_is_exact_and_idempotent() {
        let database = TempDatabase::new();
        let account = identities().remove(0).key;
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);

        store.retain_recovery_opening(&root, &opening).unwrap();
        store.retain_recovery_opening(&root, &opening).unwrap();

        assert_eq!(store.recovery_opening(&root).unwrap(), Some(opening));
        let retained_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM agent_state_openings", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained_count, 1);
    }

    #[test]
    fn recovery_opening_history_is_keyed_by_full_root() {
        let database = TempDatabase::new();
        let account = identities().remove(0).key;
        let (first_root, first_opening) = recovery_evidence(&account, 100);
        let (second_root, second_opening) = recovery_evidence(&account, 200);
        assert_ne!(first_root, second_root);
        let (mut store, _) = open_store(database.path(), &account);
        store
            .retain_recovery_opening(&first_root, &first_opening)
            .unwrap();
        store
            .retain_recovery_opening(&second_root, &second_opening)
            .unwrap();
        drop(store);

        let (store, _) = open_store(database.path(), &account);
        assert_eq!(
            store.recovery_opening(&first_root).unwrap(),
            Some(first_opening)
        );
        assert_eq!(
            store.recovery_opening(&second_root).unwrap(),
            Some(second_opening)
        );
    }

    #[test]
    fn stage_payment_requires_retained_recovery_opening() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (send, entries) = signed_send(&wallet, b"missing-recovery-opening");
        let (root, _) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);

        let error = store.stage_payment(&send, &entries, &root, 0).unwrap_err();
        assert!(format!("{error:#}").contains("payment recovery opening is missing"));
        assert!(store.poisoned);
        drop(store);

        let (store, state) = open_store(database.path(), &account);
        assert!(state.pending_payment.is_none());
        let pending_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM agent_pending_payment", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending_count, 0);
    }

    #[test]
    fn pending_payment_reopens_with_its_original_recovery_root() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (send, entries) = signed_send(&wallet, b"pending-original-recovery-root");
        let (original_root, original_opening) = recovery_evidence(&account, 100);
        let (later_root, later_opening) = recovery_evidence(&account, 200);
        assert_ne!(original_root, later_root);
        let (mut store, _) = open_store(database.path(), &account);
        store
            .retain_recovery_opening(&original_root, &original_opening)
            .unwrap();
        store
            .retain_recovery_opening(&later_root, &later_opening)
            .unwrap();
        store
            .stage_payment(&send, &entries, &original_root, 0)
            .unwrap();
        drop(store);

        let (store, state) = open_store(database.path(), &account);
        let pending = state.pending_payment.unwrap();
        assert_eq!(pending.authorization, send);
        assert_eq!(pending.entries, entries);
        assert_eq!(pending.recovery_root, original_root);
        assert_eq!(
            store.recovery_opening(&pending.recovery_root).unwrap(),
            Some(original_opening)
        );
    }

    #[test]
    fn oversized_recovery_opening_is_rejected_boundedly_on_reopen() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (send, entries) = signed_send(&wallet, b"oversized-recovery-opening");
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payment(&send, &entries, &root, 0).unwrap();
        drop(store);

        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection
            .execute(
                "UPDATE agent_state_openings SET opening = zeroblob(?1) WHERE root = ?2",
                params![
                    i64::try_from(MAX_STATE_OPENING_BYTES + 1).unwrap(),
                    root.encode().as_ref()
                ],
            )
            .unwrap();
        drop(connection);

        let error = open_error(database.path(), &account, &deployment(), &operator_key());
        assert!(error.contains("invalid state opening length"));
        assert!(error.contains(&format!("maximum {MAX_STATE_OPENING_BYTES}")));
    }

    #[test]
    fn stored_recovery_opening_for_another_account_is_rejected() {
        let database = TempDatabase::new();
        let identities = identities();
        let account = identities[0].key.clone();
        let foreign_account = identities[1].key.clone();
        let (foreign_root, foreign_opening) = recovery_evidence(&foreign_account, 100);
        let (store, _) = open_store(database.path(), &account);
        drop(store);

        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute(
                "INSERT INTO agent_state_openings (root, opening) VALUES (?1, ?2)",
                params![
                    foreign_root.encode().as_ref(),
                    foreign_opening.encode().as_ref()
                ],
            )
            .unwrap();
        drop(connection);

        let (store, _) = open_store(database.path(), &account);
        let error = store.recovery_opening(&foreign_root).unwrap_err();
        assert!(format!("{error:#}").contains("state opening belongs to another account"));
    }

    #[test]
    fn database_binding_rejects_another_identity() {
        let database = TempDatabase::new();
        let identities = identities();
        let (store, _) = Store::open(
            database.path(),
            &identities[0].key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);

        let error = open_error(
            database.path(),
            &identities[1].key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("another account"));
    }

    #[test]
    fn malformed_or_incompatible_database_is_rejected() {
        let incompatible = TempDatabase::new();
        let connection = Connection::open(incompatible.path()).unwrap();
        connection
            .execute("CREATE TABLE unrelated (value BLOB)", [])
            .unwrap();
        drop(connection);
        let identity = identities().remove(0);
        let error = open_error(
            incompatible.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("incompatible agent database schema"));

        let malformed = TempDatabase::new();
        let (store, _) = Store::open(
            malformed.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);
        let connection = Connection::open(malformed.path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_meta SET account = zeroblob(1048576) WHERE singleton = 1;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(
            malformed.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("invalid agent account length"));
    }

    #[test]
    fn database_rejects_unexpected_trigger() {
        let database = TempDatabase::new();
        let identity = identities().remove(0);
        let (store, _) = Store::open(
            database.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER discard_pending
                 AFTER INSERT ON agent_pending_payment
                 BEGIN
                     DELETE FROM agent_pending_payment;
                 END;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(
            database.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("incompatible agent database schema"));
    }

    #[test]
    fn database_rejects_noncanonical_singletons() {
        let identity = identities().remove(0);

        let metadata = TempDatabase::new();
        let (store, _) = Store::open(
            metadata.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);
        let connection = Connection::open(metadata.path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_meta SET singleton = 2 WHERE singleton = 1;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(
            metadata.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("metadata singleton"));

        let pending = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (mut store, _) =
            Store::open(pending.path(), &account, &deployment(), &operator_key()).unwrap();
        let context = PaymentContext::new(
            Sha256::hash(&[b"noncanonical-pending-singleton"]),
            1,
            operator_key(),
        );
        let (send, entries) = sign_delta(&context, &wallet, 1);
        let cache = StateFixture::new(vec![(account.clone(), 100)]);
        let root = cache.root();
        let opening = cache.opening(&account).unwrap();
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payment(&send, &entries, &root, 0).unwrap();
        drop(store);
        let connection = Connection::open(pending.path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_pending_payment SET singleton = 2 WHERE singleton = 1;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(pending.path(), &account, &deployment(), &operator_key());
        assert!(error.contains("pending payment singleton"));
    }

    #[test]
    fn sqlite_integer_domain_is_bounded() {
        assert_eq!(sql_u64(i64::MAX as u64, "test value").unwrap(), i64::MAX);
        assert!(sql_u64(i64::MAX as u64 + 1, "test value").is_err());
        assert_eq!(
            from_sql_u64(i64::MAX, "test value").unwrap(),
            i64::MAX as u64
        );
        assert!(from_sql_u64(-1, "test value").is_err());
    }
}
