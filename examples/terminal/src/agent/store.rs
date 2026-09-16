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

use super::pay::merge_entries;
use crate::{
    chain::tx::{DepositRequest, NativeTransferRequest},
    protocol::{
        Acceptance, Ack, Entry, Key, MAX_ACCEPTANCE_BYTES, MAX_BATCH_SEND_ENTRIES,
        MAX_DESTINATION_BYTES, MAX_ENTRIES, MAX_SENDS_PER_BATCH, Receipt,
    },
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::SignedWithdrawal,
    logs::LogHead,
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
    qmdb::{StateOpening, StateRoot},
    transition::WithdrawalClaim,
    vector::{OutEntry, OutVector},
};
use commonware_codec::{Copying, Decode as _, DecodeExt as _, Encode as _, FixedSize, RangeCfg};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::Signature;
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use std::path::Path;

const SCHEMA_VERSION: i64 = 26;
const MAX_PENDING_CLAIM_BYTES: usize = 16 * 1024;
const LOG_HEAD_BYTES: usize = LogHead::<Digest>::SIZE;
const MIN_STATE_OPENING_BYTES: usize = Key::SIZE + u64::SIZE;
const MAX_STATE_OPENING_BYTES: usize = 16 * 1024;
const MAX_STATE_PROOF_DIGESTS: usize = 256;
const DEPOSIT_REQUEST_BYTES: usize = Digest::SIZE * 3 + Key::SIZE + u64::SIZE + Signature::SIZE;
const TRANSFER_REQUEST_BYTES: usize =
    Digest::SIZE * 2 + Key::SIZE * 2 + u64::SIZE + Signature::SIZE;
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
    pub(crate) acceptance: Option<VerifiedAcceptance>,
    /// Settlement proved this authorization permanently excluded. Its entries remain the
    /// durable local intent until a successor-context replacement is staged atomically.
    pub(crate) replaceable: bool,
}

/// An operator acceptance whose signatures, opening structure, and staged-body binding were
/// checked before it crossed the SQLite mutation boundary.
#[derive(Clone)]
pub(crate) struct VerifiedAcceptance(Acceptance);

impl VerifiedAcceptance {
    /// Constructs the marker after the wallet's native batch verifier or durable reopen path has
    /// checked the complete acceptance.
    pub(super) const fn from_verified(acceptance: Acceptance) -> Self {
        Self(acceptance)
    }

    pub(super) const fn acceptance(&self) -> &Acceptance {
        &self.0
    }
}

/// An operator-claimed signing context paired with an independently authenticated floor.
/// `epoch` is the first epoch the retained balance does not include.
#[derive(Clone)]
pub(crate) struct ContextCache {
    pub(crate) context: PaymentContext<Key, Digest>,
    pub(crate) root: StateRoot<Digest>,
    pub(crate) epoch: u64,
}

/// A wallet-owned payout candidate authenticated at one finalized payout head.
#[derive(Clone)]
pub(crate) struct PendingWithdrawalClaim {
    pub(crate) head: LogHead<Digest>,
    pub(crate) claim: WithdrawalClaim<Digest>,
}

pub(crate) struct State {
    /// The durable optimistic signing state, absent for a fresh wallet or after an
    /// invalidation.
    pub(crate) cache: Option<ContextCache>,
    pub(crate) pending_payments: Vec<PendingPayment>,
    pub(crate) pending_withdrawal: Option<SignedWithdrawal<Key, Digest>>,
    pub(crate) pending_deposit: Option<DepositRequest>,
    pub(crate) pending_transfer: Option<NativeTransferRequest>,
    pub(crate) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
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
/// the credited edge endpoint, the delta amount versus the previously held entry, and the
/// canonical [`Receipt`] bytes.
pub(crate) struct IncomingRecord {
    pub(crate) id: Digest,
    pub(crate) payer: Key,
    pub(crate) epoch: u64,
    pub(crate) cumulative: u64,
    pub(crate) count: u64,
    pub(crate) amount: u64,
    pub(crate) receipt: Receipt,
}

/// The wallet's highest held receipt on one payer edge of one epoch.
pub(crate) struct HeldEntry {
    pub(crate) payer: Key,
    pub(crate) cumulative: u64,
    pub(crate) count: u64,
    pub(crate) receipt: Receipt,
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
    /// The held credit reached a permanent non-clean outcome.
    TerminalNonclean = 2,
}

/// The ledger records every concluded payment as `Accepted` (operator receipts held while its
/// signing context remains live), `Retired` (its context has a permanent settlement boundary,
/// with or without held receipts), or `Abandoned`.
#[derive(Clone, Copy)]
#[repr(i64)]
enum PaymentState {
    Accepted = 3,
    Retired = 4,
    Abandoned = 5,
}

/// Payment conclusions whose deltas contribute to the wallet's balance lower bound.
const SETTLED_STATES: [i64; 2] = [PaymentState::Accepted as i64, PaymentState::Retired as i64];

/// One authenticated conclusion for the included prefix of a pending batch.
pub(crate) enum PaymentConclusion {
    /// The wallet holds the exact operator acceptance.
    Accepted(Box<VerifiedAcceptance>),
    /// Finalized activity authenticates the endpoint, but no acceptance is available.
    Retired,
}

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

    #[cfg(test)]
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

    #[cfg(test)]
    pub(crate) fn total_changes(&self) -> u64 {
        self.connection.total_changes()
    }

    pub(crate) fn recovery_opening(
        &self,
        root: &StateRoot<Digest>,
    ) -> Result<Option<StateOpening<Key, Digest>>> {
        self.ensure_usable()?;
        read_recovery_opening(&self.connection, root, &self.account)
    }

    /// Rejects a signing context retired by the wallet's permanent settlement history.
    /// This applies even when a pending withdrawal suppresses cache refresh.
    pub(crate) fn check_signing_context(
        &self,
        context: &PaymentContext<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        ensure!(
            context.operator() == &self.operator,
            "payment context has an unexpected operator"
        );

        // A certified view can predate durable local exclusions after a client restart.
        // Epochs outside SQLite's integer range have no archived conclusions.
        let mut statement = self.connection.prepare_cached(
            "SELECT length(authorization), authorization FROM agent_payments
             WHERE state IN (?1, ?2) AND epoch = ?3
             UNION ALL
             SELECT length(authorization), authorization FROM agent_pending_payment
             WHERE replaceable = 1",
        )?;
        let exclusions = statement.query_map(
            params![
                PaymentState::Retired as i64,
                PaymentState::Abandoned as i64,
                i64::try_from(context.epoch()).ok(),
            ],
            |row| read_fixed_blob(row, 0, 1, AUTHORIZATION_BYTES, "concluded authorization"),
        )?;
        for encoded in exclusions {
            let authorization = SendAuthorization::<Key, Digest>::decode(encoded?)?;
            ensure!(
                authorization.body().anchor() != context.anchor(),
                "signing context has a permanent settlement outcome"
            );
        }
        Ok(())
    }

    /// Durably caches a signing context and its verified affordability floor at `root`.
    pub(crate) fn cache_context(
        &mut self,
        context: &PaymentContext<Key, Digest>,
        root: &StateRoot<Digest>,
        floor_epoch: u64,
    ) -> Result<()> {
        self.check_signing_context(context)?;
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

    /// Saves the exact withdrawal and opens its claim intent before submission.
    pub(crate) fn stage_withdrawal(
        &mut self,
        request: &SignedWithdrawal<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_pending_withdrawal(&self.connection, &self.account, request)?;
        let encoded = request.encode();
        ensure_claim_bound(&encoded, "signed withdrawal")?;
        let result = stage_withdrawal_transaction(&mut self.connection, &encoded);
        self.finish_mutation(result)
    }

    /// Retires the active signing authorization at a certified healthy deadline.
    ///
    /// Its deadline remains as a monotonic floor for future signing contexts.
    pub(crate) fn retire_withdrawal(
        &mut self,
        request: &SignedWithdrawal<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_pending_withdrawal(&self.connection, &self.account, request)?;
        let result = retire_withdrawal_transaction(
            &mut self.connection,
            request.encode().as_ref(),
            request.body().deadline(),
        );
        self.finish_mutation(result)
    }

    /// The highest deadline of any retired authorization.
    pub(crate) fn retired_withdrawal_deadline(&self) -> Result<Option<u64>> {
        self.ensure_usable()?;
        let encoded = self.connection.query_row(
            "SELECT length(retired_withdrawal_deadline), retired_withdrawal_deadline
             FROM agent_meta WHERE singleton = 1",
            [],
            |row| read_fixed_blob(row, 0, 1, u64::SIZE, "retired withdrawal deadline"),
        )?;
        let deadline = u64::decode(encoded)?;
        Ok((deadline != 0).then_some(deadline))
    }

    /// Persists a payout candidate after verifying its finalized MMR opening.
    pub(crate) fn cache_withdrawal_claim(
        &mut self,
        candidate: &PendingWithdrawalClaim,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_claim(candidate, &self.account)?;
        let head = candidate.head.encode();
        let claim = candidate.claim.encode();
        ensure_claim_bound(claim.as_ref(), "withdrawal claim")?;
        let result = cache_claim_transaction(&mut self.connection, head.as_ref(), claim.as_ref());
        self.finish_mutation(result)
    }

    pub(crate) fn complete_withdrawal_claim(&mut self, position: u64) -> Result<()> {
        self.ensure_usable()?;
        let position = position.encode();
        let result = complete_claim_transaction(&mut self.connection, position.as_ref());
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

    #[cfg(test)]
    pub(crate) fn stage_payment(
        &mut self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
        recovery_root: &StateRoot<Digest>,
        previous_debit: u64,
    ) -> Result<()> {
        self.stage_payments(
            &[PendingPayment {
                authorization: authorization.clone(),
                entries: entries.to_vec(),
                recovery_root: *recovery_root,
                acceptance: None,
                replaceable: false,
            }],
            previous_debit,
        )
    }

    /// Persists one complete ordered payer batch before any member is submitted.
    pub(crate) fn stage_payments(
        &mut self,
        payments: &[PendingPayment],
        previous_debit: u64,
    ) -> Result<()> {
        self.ensure_usable()?;
        ensure!(
            !payments.is_empty() && payments.len() <= MAX_SENDS_PER_BATCH,
            "pending payment batch exceeds its bound"
        );
        ensure!(
            payments.iter().all(|payment| payment.acceptance.is_none()),
            "fresh pending payment batch already holds receipts"
        );
        ensure!(
            payments.iter().all(|payment| !payment.replaceable),
            "fresh pending payment batch is already replaceable"
        );
        self.validate_payment_sequence(payments, previous_debit)?;
        let recovery_root = payments[0].recovery_root;
        ensure!(
            payments
                .iter()
                .all(|payment| payment.recovery_root == recovery_root),
            "pending payments use different recovery roots"
        );
        let encoded = payments
            .iter()
            .map(|payment| {
                sql_u64(
                    payment.authorization.body().cumulative_debit(),
                    "pending cumulative debit",
                )?;
                Ok((
                    payment.authorization.encode(),
                    encode_entries(&payment.entries)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let encoded_root = recovery_root.encode();
        let result = stage_payments_transaction(
            &mut self.connection,
            &self.account,
            &recovery_root,
            previous_debit,
            encoded_root.as_ref(),
            &encoded,
        );
        self.finish_mutation(result)
    }

    /// Retains one verified receipt set while the surrounding batch remains unresolved.
    pub(crate) fn retain_payment_acceptance(
        &mut self,
        pending: &PendingPayment,
        verified: &VerifiedAcceptance,
    ) -> Result<()> {
        self.ensure_usable()?;
        let acceptance = verified.acceptance();
        validate_pending_acceptance_body(pending, acceptance)?;
        let encoded = acceptance.encode();
        ensure!(
            encoded.len() <= MAX_ACCEPTANCE_BYTES,
            "acceptance encoding exceeds its bound"
        );
        let receipts = u64::try_from(acceptance.entries.len())?;
        let result = retain_payment_acceptance_transaction(
            &mut self.connection,
            pending.authorization.encode().as_ref(),
            sql_u64(receipts, "pending receipt count")?,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Retains a verified partial or reordered response in one SQLite transaction.
    pub(crate) fn retain_indexed_payment_acceptances(
        &mut self,
        pending: &[PendingPayment],
        acceptances: &[(usize, &VerifiedAcceptance)],
    ) -> Result<()> {
        self.ensure_usable()?;
        ensure!(!acceptances.is_empty(), "receipt evidence batch is empty");
        ensure!(
            acceptances.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "receipt evidence positions are not strictly ordered"
        );
        for (position, verified) in acceptances {
            let payment = pending
                .get(*position)
                .context("receipt evidence position exceeds the pending batch")?;
            let acceptance = verified.acceptance();
            validate_pending_acceptance_body(payment, acceptance)?;
            ensure!(
                acceptance.encode().len() <= MAX_ACCEPTANCE_BYTES,
                "acceptance encoding exceeds its bound"
            );
        }
        let result =
            retain_payment_acceptances_transaction(&mut self.connection, pending, acceptances);
        self.finish_mutation(result)
    }

    /// Atomically concludes the authenticated included prefix and preserves any excluded
    /// suffix as one durable, replaceable intent batch.
    pub(crate) fn conclude_payment_prefix(
        &mut self,
        pending: &[PendingPayment],
        conclusions: &[PaymentConclusion],
        receipt_count: u64,
        retire_context: bool,
    ) -> Result<u64> {
        self.ensure_usable()?;
        ensure!(
            !pending.is_empty()
                && conclusions.len() <= pending.len()
                && pending.iter().all(|payment| !payment.replaceable),
            "pending prefix conclusion does not name one ambiguous batch"
        );
        let first_total = entry_total(&pending[0].entries)?;
        let previous_debit = pending[0]
            .authorization
            .body()
            .cumulative_debit()
            .checked_sub(first_total)
            .context("pending first delta exceeds its endpoint")?;
        self.validate_payment_sequence(pending, previous_debit)?;

        let mut added_receipts = 0_u64;
        for (payment, conclusion) in pending.iter().zip(conclusions) {
            match conclusion {
                PaymentConclusion::Accepted(acceptance) => {
                    let acceptance = acceptance.acceptance();
                    validate_pending_acceptance_body(payment, acceptance)?;
                    added_receipts = added_receipts
                        .checked_add(u64::try_from(acceptance.entries.len())?)
                        .context("agent receipt count overflow")?;
                }
                PaymentConclusion::Retired => ensure!(
                    payment.acceptance.is_none(),
                    "a held acceptance cannot be discarded at finality"
                ),
            }
        }
        let next_receipt_count = receipt_count
            .checked_add(added_receipts)
            .context("agent receipt count overflow")?;
        sql_u64(next_receipt_count, "agent receipt count")?;
        let vector = if conclusions.is_empty() {
            None
        } else {
            let terminal = &pending[conclusions.len() - 1];
            Some(VectorWrite {
                epoch: terminal.authorization.body().epoch(),
                anchor: *terminal.authorization.body().anchor(),
                seq: terminal.authorization.body().seq(),
                cumulative_debit: terminal.authorization.body().cumulative_debit(),
                entries: validate_payment_sequence(
                    &self.connection,
                    &self.account,
                    &self.operator,
                    &pending[..conclusions.len()],
                    previous_debit,
                )?,
            })
        };
        let result = conclude_payment_prefix_transaction(
            &mut self.connection,
            pending,
            conclusions,
            vector.as_ref(),
            retire_context,
        );
        self.finish_mutation(result).map(|()| next_receipt_count)
    }

    /// Atomically archives a permanently excluded suffix and installs its freshly signed
    /// successor-context replacement.
    pub(crate) fn replace_payment_suffix(
        &mut self,
        excluded: &[PendingPayment],
        replacement: &[PendingPayment],
        previous_debit: u64,
        receipt_count: u64,
    ) -> Result<u64> {
        self.ensure_usable()?;
        ensure!(
            !excluded.is_empty()
                && excluded.iter().all(|payment| payment.replaceable)
                && excluded.len() == replacement.len()
                && excluded
                    .iter()
                    .zip(replacement)
                    .all(|(old, new)| old.entries == new.entries),
            "replacement does not preserve the excluded local intent"
        );
        ensure!(
            replacement
                .iter()
                .all(|payment| !payment.replaceable && payment.acceptance.is_none()),
            "replacement batch is not fresh"
        );
        self.validate_payment_sequence(replacement, previous_debit)?;
        let added_receipts = excluded.iter().try_fold(0_u64, |sum, payment| {
            sum.checked_add(payment.acceptance.as_ref().map_or(Ok(0), |acceptance| {
                u64::try_from(acceptance.acceptance().entries.len())
            })?)
            .context("agent receipt count overflow")
        })?;
        let next_receipt_count = receipt_count
            .checked_add(added_receipts)
            .context("agent receipt count overflow")?;
        sql_u64(next_receipt_count, "agent receipt count")?;
        let result = replace_payment_suffix_transaction(
            &mut self.connection,
            &self.account,
            excluded,
            replacement,
            previous_debit,
        );
        self.finish_mutation(result).map(|()| next_receipt_count)
    }

    /// Archives a permanently excluded batch when no successor context can accept its preserved
    /// intent during the active request. The caller has already received an explicit failure;
    /// retained operator receipts remain durable evidence.
    pub(crate) fn archive_replaceable_payments(
        &mut self,
        excluded: &[PendingPayment],
        receipt_count: u64,
    ) -> Result<u64> {
        self.ensure_usable()?;
        ensure!(
            !excluded.is_empty() && excluded.iter().all(|payment| payment.replaceable),
            "only a permanently excluded payment batch can be archived"
        );
        let added_receipts = excluded.iter().try_fold(0_u64, |sum, payment| {
            sum.checked_add(payment.acceptance.as_ref().map_or(Ok(0), |acceptance| {
                u64::try_from(acceptance.acceptance().entries.len())
            })?)
            .context("agent receipt count overflow")
        })?;
        let next_receipt_count = receipt_count
            .checked_add(added_receipts)
            .context("agent receipt count overflow")?;
        sql_u64(next_receipt_count, "agent receipt count")?;
        let result = archive_replaceable_payments_transaction(&mut self.connection, excluded);
        self.finish_mutation(result).map(|()| next_receipt_count)
    }

    /// Records a staged send proven never to have committed and frees the outstanding slot.
    ///
    /// The caller must authenticate exact-epoch activity exclusion or an immutable
    /// conflicting registration that permanently invalidates the authorization. The
    /// abandoned row preserves the wallet's history, and the retained recovery opening is
    /// deliberately left in place. It is keyed by full root, can be shared with an already
    /// committed sibling payment read at the same finalized head, and stays load-bearing
    /// for frozen-root recovery.
    #[cfg(test)]
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
    #[cfg(test)]
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
    #[cfg(test)]
    fn merged_vector(
        &self,
        body: &VectorSendBody<Key, Digest>,
        entries: &[Entry],
        previous_debit: u64,
    ) -> Result<Vec<OutEntry<Key>>> {
        let prior = read_vector_state(&self.connection, body.epoch(), body.anchor())?;
        let (prior_seq, prior_entries) = match prior {
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
        let merged = merge_entries(prior_entries, entries)?;
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

    /// Validates a complete staged sequence against the durable pre-batch vector and returns
    /// the terminal cumulative vector.
    fn validate_payment_sequence(
        &self,
        payments: &[PendingPayment],
        previous_debit: u64,
    ) -> Result<Vec<OutEntry<Key>>> {
        validate_payment_sequence(
            &self.connection,
            &self.account,
            &self.operator,
            payments,
            previous_debit,
        )
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
    #[cfg(test)]
    pub(crate) fn commit_payment(
        &mut self,
        acceptance: &Acceptance,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
        previous_debit: u64,
        receipt_count: u64,
        retire_context: bool,
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
            retire_context,
        );
        self.finish_mutation(result).map(|()| next_receipt_count)
    }

    /// Persists an exact native transfer before it can debit the wallet.
    pub(crate) fn stage_transfer(&mut self, request: &NativeTransferRequest) -> Result<()> {
        self.ensure_usable()?;
        validate_transfer(request, &self.account)?;
        let result = stage_native_transaction(
            &mut self.connection,
            "agent_pending_transfer",
            &request.encode(),
        );
        self.finish_mutation(result)
    }

    /// Retires a transfer after its matching certified receipt is observed.
    pub(crate) fn complete_transfer(&mut self, request: &NativeTransferRequest) -> Result<()> {
        self.ensure_usable()?;
        let result = remove_native_transaction(
            &mut self.connection,
            "agent_pending_transfer",
            &request.encode(),
            "native transfer completion",
        );
        self.finish_mutation(result)
    }

    /// Persists the exact signed native debit before submitting its deposit.
    pub(crate) fn stage_deposit(&mut self, event: &DepositRequest) -> Result<()> {
        self.ensure_usable()?;
        validate_deposit(event, &self.account)?;
        ensure!(
            event.deployment == read_binding(&self.connection)?.deployment,
            "pending deposit belongs to another deployment"
        );
        let encoded = event.encode();
        ensure!(
            encoded.len() == DEPOSIT_REQUEST_BYTES,
            "deposit event encoding has an unexpected length"
        );
        let result = stage_native_transaction(
            &mut self.connection,
            "agent_pending_deposit",
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Removes the staged deposit after its exact custody record is certified.
    pub(crate) fn complete_deposit(&mut self, event: &DepositRequest) -> Result<()> {
        self.ensure_usable()?;
        let encoded = event.encode();
        let result = remove_native_transaction(
            &mut self.connection,
            "agent_pending_deposit",
            encoded.as_ref(),
            "pending deposit completion",
        );
        self.finish_mutation(result)
    }

    /// Discards a deposit whose identifier is certifiably consumed by another event.
    pub(crate) fn discard_deposit(&mut self, event: &DepositRequest) -> Result<()> {
        self.ensure_usable()?;
        let encoded = event.encode();
        let result = remove_native_transaction(
            &mut self.connection,
            "agent_pending_deposit",
            encoded.as_ref(),
            "pending deposit discard",
        );
        self.finish_mutation(result)
    }

    /// Atomically persists verified credits and the cursor of the processed incoming prefix.
    ///
    /// Insertion is idempotent per payer-signed body digest. The caller validates the page
    /// and authenticates receipt reliance before entering this transaction. The unsigned
    /// cursor identifies processed rows; it does not authenticate enumeration completeness.
    pub(crate) fn record_incoming(
        &mut self,
        records: &[IncomingRecord],
        next_cursor: u64,
    ) -> Result<IncomingSummary> {
        self.ensure_usable()?;
        sql_u64(next_cursor, "incoming cursor")?;
        for record in records {
            let body = record.receipt.ack.body();
            ensure!(
                record.id == body_id(body)
                    && &record.payer == body.payer()
                    && record.epoch == body.epoch()
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
            sql_u64(record.epoch, "incoming epoch")?;
            sql_u64(record.cumulative, "incoming cumulative")?;
            sql_u64(record.count, "incoming count")?;
            sql_u64(record.amount, "incoming amount")?;
        }
        let result = record_incoming_transaction(&mut self.connection, records, next_cursor);
        self.finish_mutation(result)?;
        read_incoming_summary(&self.connection)
    }

    /// Whether this wallet holds the exact verified receipt body from this payer.
    pub(crate) fn has_receipt(&self, payer: &Key, id: &Digest) -> Result<bool> {
        self.ensure_usable()?;
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_incoming WHERE payer = ?1 AND id = ?2)",
                params![payer.as_ref(), id.as_ref()],
                |row| row.get(0),
            )
            .map_err(Into::into)
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
            let payer = Key::decode(payer).context("decode held payer")?;
            let receipt = Receipt::decode(encoded).context("decode held incoming receipt")?;
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

    pub(crate) fn last_reconciled_epoch(&self) -> Result<Option<u64>> {
        self.ensure_usable()?;
        read_last_reconciled(&self.connection)
    }

    /// Durably suppresses a terminal non-clean epoch. The immediate reconciliation summary owns
    /// whether the close was invalidated or the held credit became unenforceable.
    pub(crate) fn record_terminal_nonclean(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::TerminalNonclean)
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

fn validate_pending_acceptance_body(
    pending: &PendingPayment,
    acceptance: &Acceptance,
) -> Result<()> {
    ensure!(
        acceptance.ack.body() == pending.authorization.body()
            && acceptance.entries.len() == pending.entries.len()
            && acceptance
                .entries
                .iter()
                .zip(&pending.entries)
                .all(|(opened, delta)| opened.recipient == delta.recipient),
        "acceptance does not open its staged authorization and recipients"
    );
    Ok(())
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
    let has_pending_transfer = table_exists(connection, "agent_pending_transfer")?;
    let has_pending_claims = table_exists(connection, "agent_pending_claims")?;
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
                        'agent_pending_payment', 'agent_pending_deposit', 'agent_pending_transfer',
                        'agent_pending_claims', 'agent_payments',
                        'agent_incoming_cursor', 'agent_incoming', 'agent_reconciled'
                    ))
                OR type IN ('trigger', 'view')
                OR (type = 'index'
                    AND name NOT LIKE 'sqlite_autoindex_%'
                    AND name NOT IN (
                        'agent_payments_settled',
                        'agent_incoming_epoch_payer'
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
        && !has_pending_transfer
        && !has_pending_claims
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
            && has_pending_transfer
            && has_pending_claims
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
             operator BLOB NOT NULL CHECK (length(operator) = {key_size}),
             retired_withdrawal_deadline BLOB NOT NULL CHECK (
                 length(retired_withdrawal_deadline) = {u64_size}
             )
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
             position INTEGER PRIMARY KEY CHECK (position >= 0 AND position < {max_sends}),
             recovery_root BLOB NOT NULL CHECK (length(recovery_root) = {root_size}),
             authorization BLOB NOT NULL UNIQUE CHECK (
                 length(authorization) = {authorization_size}
             ),
             entries BLOB NOT NULL CHECK (
                 length(entries) BETWEEN 1 AND {max_delta_size}
             ),
             receipts INTEGER CHECK (receipts IS NULL OR receipts > 0),
             acceptance BLOB CHECK (
                 acceptance IS NULL OR length(acceptance) BETWEEN 1 AND {max_acceptance_size}
             ),
             replaceable INTEGER NOT NULL CHECK (replaceable IN (0, 1)),
             CHECK ((receipts IS NULL) = (acceptance IS NULL)),
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );

         CREATE TABLE agent_pending_deposit (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             event BLOB NOT NULL CHECK (length(event) = {deposit_event_size}),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE
         );

         CREATE TABLE agent_pending_transfer (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             event BLOB NOT NULL CHECK (length(event) = {transfer_request_size}),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE
         );

         CREATE TABLE agent_pending_claims (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             claim_head BLOB CHECK (
                 claim_head IS NULL OR length(claim_head) = {log_head_size}
             ),
             claim BLOB CHECK (
                 claim IS NULL OR length(claim) BETWEEN 1 AND {max_claim_size}
             ),
             request BLOB CHECK (
                 request IS NULL OR length(request) BETWEEN 1 AND {max_claim_size}
             ),
             CHECK ((claim_head IS NULL) = (claim IS NULL)),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE
         );

         CREATE TABLE agent_payments (
             id BLOB PRIMARY KEY CHECK (length(id) = {digest_size}),
             cumulative_debit INTEGER NOT NULL CHECK (cumulative_debit > 0),
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
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
             cumulative INTEGER NOT NULL CHECK (cumulative > 0),
             count INTEGER NOT NULL CHECK (count > 0 AND count <= cumulative),
             amount INTEGER NOT NULL CHECK (amount > 0),
             receipt BLOB NOT NULL CHECK (length(receipt) BETWEEN 1 AND {max_receipt_size})
         );
         CREATE INDEX agent_incoming_epoch_payer ON agent_incoming (epoch, payer);

         CREATE TABLE agent_reconciled (
             epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
             status INTEGER NOT NULL CHECK (status IN (1, 2))
         );",
        key_size = Key::SIZE,
        digest_size = Digest::SIZE,
        root_size = StateRoot::<Digest>::SIZE,
        context_size = PaymentContext::<Key, Digest>::SIZE,
        authorization_size = AUTHORIZATION_BYTES,
        max_delta_size = MAX_DELTA_BYTES,
        max_sends = MAX_SENDS_PER_BATCH,
        max_acceptance_size = MAX_ACCEPTANCE_BYTES,
        min_opening_size = MIN_STATE_OPENING_BYTES,
        max_opening_size = MAX_STATE_OPENING_BYTES,
        max_claim_size = MAX_PENDING_CLAIM_BYTES,
        log_head_size = LOG_HEAD_BYTES,
        u64_size = u64::SIZE,
        max_receipt_size = MAX_RECEIPT_BYTES,
        deposit_event_size = DEPOSIT_REQUEST_BYTES,
        transfer_request_size = TRANSFER_REQUEST_BYTES,
    );
    let encoded_account = account.encode();
    let encoded_deployment = deployment.encode();
    let encoded_operator = operator.encode();
    let retired_withdrawal_deadline = 0_u64.encode();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin SQLite agent initialization")?;
    transaction
        .execute_batch(&schema)
        .context("create SQLite agent schema")?;
    transaction.execute(
        "INSERT INTO agent_meta (
             singleton, schema_version, account, deployment, operator,
             retired_withdrawal_deadline
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            SCHEMA_VERSION,
            encoded_account.as_ref(),
            encoded_deployment.as_ref(),
            encoded_operator.as_ref(),
            retired_withdrawal_deadline.as_ref(),
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
                length(operator), operator,
                length(retired_withdrawal_deadline), retired_withdrawal_deadline
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
    let retired_withdrawal_deadline =
        read_fixed_blob(row, 8, 9, u64::SIZE, "retired withdrawal deadline")?;
    u64::decode(retired_withdrawal_deadline)?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has extra metadata rows"
    );
    ensure!(
        schema_version == SCHEMA_VERSION,
        "unsupported agent database schema version {schema_version}"
    );

    Ok(Binding {
        account: Key::decode(encoded_account).context("decode agent account")?,
        deployment: Digest::decode(encoded_deployment).context("decode agent deployment")?,
        operator: Key::decode(encoded_operator).context("decode agent operator")?,
    })
}

fn read_state(connection: &Connection, account: &Key, operator: &Key) -> Result<State> {
    let receipt_count = read_receipt_state(connection, account, operator)?;
    let cache = read_context_cache(connection, account, operator)?;
    let pending_payments = read_pending_payments(connection, account, operator)?;
    let pending_deposit = read_pending_deposit(connection, account)?;
    if let Some(request) = &pending_deposit {
        ensure!(
            request.deployment == read_binding(connection)?.deployment,
            "pending deposit belongs to another deployment"
        );
    }
    let (pending_withdrawal_claim, pending_withdrawal) = read_pending_claim(connection, account)?;
    let mut previous_debit = pending_payments
        .first()
        .map(|pending| context_debit(connection, pending.authorization.body()))
        .transpose()?
        .unwrap_or(0);
    validate_payment_sequence(
        connection,
        account,
        operator,
        &pending_payments,
        previous_debit,
    )?;
    for pending in &pending_payments {
        previous_debit = pending.authorization.body().cumulative_debit();
        sql_u64(previous_debit, "pending cumulative debit")?;
    }

    let incoming = read_incoming_summary(connection)?;
    let last_reconciled_epoch = read_last_reconciled(connection)?;

    Ok(State {
        cache,
        pending_payments,
        pending_withdrawal,
        pending_deposit,
        pending_transfer: read_pending_transfer(connection, account)?,
        pending_withdrawal_claim,
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
            "SELECT COALESCE(SUM(receipts), 0) FROM agent_payments WHERE receipts IS NOT NULL",
            [],
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
             WHERE receipts IS NOT NULL
             ORDER BY rowid DESC
             LIMIT 1",
            [],
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
    let recovery_root = StateRoot::decode(encoded_root).context("decode receipt recovery root")?;
    read_recovery_opening(connection, &recovery_root, account)?
        .context("receipt recovery opening is missing")?;
    let authorization = SendAuthorization::decode(encoded_authorization)
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
            let acceptance = Acceptance::decode(encoded).context("decode retained acceptance")?;
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
    let context =
        PaymentContext::decode(encoded_context).context("decode cached payment context")?;
    ensure!(
        context.operator() == operator,
        "cached payment context has an unexpected operator"
    );
    let root = StateRoot::decode(encoded_root).context("decode cached floor root")?;
    read_recovery_opening(connection, &root, account)?
        .context("cached context floor opening is missing")?;
    Ok(Some(ContextCache {
        context,
        root,
        epoch,
    }))
}

fn read_pending_payments(
    connection: &Connection,
    account: &Key,
    operator: &Key,
) -> Result<Vec<PendingPayment>> {
    let mut statement = connection.prepare(
        "SELECT position,
                length(recovery_root), recovery_root,
                length(authorization), authorization,
                length(entries), entries,
                receipts, length(acceptance), acceptance, replaceable
         FROM agent_pending_payment
         ORDER BY position
         LIMIT ?1",
    )?;
    let mut rows = statement.query([i64::try_from(MAX_SENDS_PER_BATCH + 1)?])?;
    let mut pending = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, i64>(0)? == i64::try_from(pending.len())?,
            "agent database pending payment positions are not contiguous"
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
        let receipts = row.get::<_, Option<i64>>(7)?;
        let encoded_acceptance =
            read_optional_bounded_blob(row, 8, 9, MAX_ACCEPTANCE_BYTES, "pending acceptance")?;
        let replaceable = row.get::<_, bool>(10)?;
        let recovery_root =
            StateRoot::decode(encoded_root).context("decode pending recovery root")?;
        read_recovery_opening(connection, &recovery_root, account)?
            .context("pending recovery opening is missing")?;
        let authorization = SendAuthorization::decode(encoded_authorization)
            .context("decode pending authorization")?;
        let acceptance = match (receipts, encoded_acceptance) {
            (Some(receipts), Some(encoded)) => {
                let acceptance =
                    Acceptance::decode(encoded).context("decode pending acceptance")?;
                validate_acceptance(&acceptance, account, operator)
                    .context("verify pending acceptance")?;
                ensure!(
                    acceptance.ack.body() == authorization.body()
                        && u64::try_from(acceptance.entries.len()).ok()
                            == Some(from_sql_u64(receipts, "pending receipt count")?),
                    "pending acceptance does not match its authorization"
                );
                Some(VerifiedAcceptance::from_verified(acceptance))
            }
            (None, None) => None,
            _ => anyhow::bail!("pending receipt count and acceptance disagree"),
        };
        pending.push(PendingPayment {
            authorization,
            entries: decode_entries(encoded_entries.as_slice())?,
            recovery_root,
            acceptance,
            replaceable,
        });
        ensure!(
            pending.len() <= MAX_SENDS_PER_BATCH,
            "pending payment batch exceeds its bound"
        );
    }
    if let Some(first) = pending.first() {
        let body = first.authorization.body();
        ensure!(
            pending.iter().all(|payment| {
                let candidate = payment.authorization.body();
                candidate.payer() == body.payer()
                    && candidate.epoch() == body.epoch()
                    && candidate.anchor() == body.anchor()
                    && payment.recovery_root == first.recovery_root
            }),
            "pending payments do not form one payer and context batch"
        );
        ensure!(
            pending
                .iter()
                .all(|payment| payment.replaceable == first.replaceable),
            "pending batch mixes ambiguous and replaceable intents"
        );
    }
    Ok(pending)
}

fn validate_transfer(request: &NativeTransferRequest, account: &Key) -> Result<()> {
    ensure!(
        &request.from == account,
        "pending transfer belongs to another account"
    );
    ensure!(request.amount > 0, "pending transfer has no value");
    ensure!(
        request.verify(&request.chain_id),
        "pending transfer has an invalid signature"
    );
    Ok(())
}

fn read_pending_transfer(
    connection: &Connection,
    account: &Key,
) -> Result<Option<NativeTransferRequest>> {
    let mut statement = connection
        .prepare("SELECT length(event), event FROM agent_pending_transfer WHERE singleton = 1")?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let encoded = read_fixed_blob(row, 0, 1, TRANSFER_REQUEST_BYTES, "pending native transfer")?;
    let request =
        NativeTransferRequest::decode(encoded).context("decode pending native transfer")?;
    validate_transfer(&request, account)?;
    Ok(Some(request))
}

fn read_pending_deposit(connection: &Connection, account: &Key) -> Result<Option<DepositRequest>> {
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
    let encoded = read_fixed_blob(row, 1, 2, DEPOSIT_REQUEST_BYTES, "pending deposit event")?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending deposits"
    );
    let event = DepositRequest::decode(encoded).context("decode pending deposit event")?;
    validate_deposit(&event, account)?;
    Ok(Some(event))
}

#[allow(clippy::type_complexity)]
fn read_pending_claim(
    connection: &Connection,
    account: &Key,
) -> Result<(
    Option<PendingWithdrawalClaim>,
    Option<SignedWithdrawal<Key, Digest>>,
)> {
    let mut statement = connection.prepare(
        "SELECT singleton,
                length(claim_head), claim_head,
                length(claim), claim,
                length(request), request
         FROM agent_pending_claims ORDER BY singleton LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok((None, None));
    };
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database pending claim singleton is not canonical"
    );
    let claim_head = read_optional_fixed_blob(row, 1, 2, LOG_HEAD_BYTES, "withdrawal claim head")?
        .map(LogHead::decode)
        .transpose()?;
    let claim = read_optional_bounded_blob(row, 3, 4, MAX_PENDING_CLAIM_BYTES, "withdrawal claim")?
        .map(|encoded| WithdrawalClaim::decode_cfg(encoded, &(..=MAX_DESTINATION_BYTES).into()))
        .transpose()?;
    let candidate = match (claim_head, claim) {
        (Some(head), Some(claim)) => {
            let candidate = PendingWithdrawalClaim { head, claim };
            validate_withdrawal_claim(&candidate, account)?;
            Some(candidate)
        }
        (None, None) => None,
        _ => anyhow::bail!("withdrawal claim fields are incomplete"),
    };
    let request =
        read_optional_bounded_blob(row, 5, 6, MAX_PENDING_CLAIM_BYTES, "pending withdrawal")?
            .map(|encoded| {
                SignedWithdrawal::decode_cfg(encoded, &(..=MAX_DESTINATION_BYTES).into())
            })
            .transpose()?;
    if let Some(request) = &request {
        validate_pending_withdrawal(connection, account, request)?;
    }
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending withdrawal claims"
    );
    Ok((candidate, request))
}

fn validate_pending_withdrawal(
    connection: &Connection,
    account: &Key,
    request: &SignedWithdrawal<Key, Digest>,
) -> Result<()> {
    ensure!(
        request.account() == account,
        "pending withdrawal belongs to another account"
    );
    ensure!(
        request.body().destination().as_ref() == account.as_ref(),
        "pending withdrawal has another destination"
    );
    request.verify_deployment(&read_binding(connection)?.deployment)?;
    let root = StateRoot::new(*request.body().state_root());
    read_recovery_opening(connection, &root, account)?
        .context("pending withdrawal recovery opening is missing")?;
    Ok(())
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

fn validate_deposit(event: &DepositRequest, account: &Key) -> Result<()> {
    ensure!(
        &event.event.account == account,
        "pending deposit belongs to another account"
    );
    ensure!(event.event.amount > 0, "pending deposit has no value");
    ensure!(
        event.verify(&event.chain_id),
        "pending deposit has an invalid signature"
    );
    Ok(())
}

fn validate_withdrawal_claim(candidate: &PendingWithdrawalClaim, account: &Key) -> Result<()> {
    let output = candidate
        .claim
        .verify::<Sha256>(&candidate.head)
        .context("verify cached withdrawal proof")?;
    ensure!(
        output.destination().as_ref() == account.as_ref(),
        "cached withdrawal proof has another destination"
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
    let opening = StateOpening::decode_cfg(encoded, &MAX_STATE_PROOF_DIGESTS)
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

/// Verifies one bounded, context-scoped pending sequence against its durable vector base.
fn validate_payment_sequence(
    connection: &Connection,
    account: &Key,
    operator: &Key,
    payments: &[PendingPayment],
    previous_debit: u64,
) -> Result<Vec<OutEntry<Key>>> {
    if payments.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        payments.len() <= MAX_SENDS_PER_BATCH,
        "pending payment batch exceeds its bound"
    );
    ensure!(
        payments
            .iter()
            .try_fold(0_usize, |sum, payment| sum
                .checked_add(payment.entries.len()))
            .is_some_and(|entries| entries <= MAX_BATCH_SEND_ENTRIES),
        "pending payment batch exceeds its aggregate entry bound"
    );
    let first = &payments[0];
    let first_body = first.authorization.body();
    let prior = read_vector_state(connection, first_body.epoch(), first_body.anchor())?;
    let (mut previous_seq, mut debit, mut entries) = match prior {
        Some(state) => {
            ensure!(
                state.cumulative_debit == previous_debit,
                "the durable vector state is not at the staging endpoint"
            );
            (Some(state.seq), state.cumulative_debit, state.entries)
        }
        None => {
            ensure!(previous_debit == 0, "new context has nonzero prior debit");
            (None, 0, Vec::new())
        }
    };
    for payment in payments {
        let body = payment.authorization.body();
        ensure!(
            body.payer() == first_body.payer()
                && body.epoch() == first_body.epoch()
                && body.anchor() == first_body.anchor()
                && payment.recovery_root == first.recovery_root,
            "pending payments do not form one payer, context, and recovery batch"
        );
        validate_authorization(
            &payment.authorization,
            &payment.entries,
            account,
            operator,
            debit,
        )?;
        ensure!(
            previous_seq.map_or(Some(1), |seq| seq.checked_add(1)) == Some(body.seq()),
            "pending payment sequence is not contiguous"
        );
        entries = merge_entries(entries, &payment.entries)?;
        let vector = OutVector::new(body.epoch(), account.clone(), entries)
            .context("assemble pending out vector")?;
        ensure!(
            vector
                .root::<Sha256, Digest>()
                .context("commit pending out vector")?
                == body.send_root(),
            "pending payment does not extend the staged vector"
        );
        if let Some(acceptance) = &payment.acceptance {
            let acceptance = acceptance.acceptance();
            ensure!(
                acceptance.ack.body() == body
                    && acceptance.entries.len() == payment.entries.len()
                    && acceptance
                        .entries
                        .iter()
                        .zip(&payment.entries)
                        .all(|(opened, delta)| opened.recipient == delta.recipient),
                "pending acceptance does not open its staged recipients"
            );
        }
        entries = vector.entries().to_vec();
        previous_seq = Some(body.seq());
        debit = body.cumulative_debit();
    }
    Ok(entries)
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
    Vec::<Entry>::decode_cfg(Copying(encoded), &(RangeCfg::new(1..=MAX_ENTRIES), ()))
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
                recipient: Key::decode(recipient).context("decode vector recipient")?,
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

fn stage_payments_transaction(
    connection: &mut Connection,
    account: &Key,
    recovery_root: &StateRoot<Digest>,
    previous_debit: u64,
    encoded_root: &[u8],
    encoded: &[(impl AsRef<[u8]>, impl AsRef<[u8]>)],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending payment stage")?;
    ensure!(
        context_debit(
            &transaction,
            SendAuthorization::<Key, Digest>::decode(Copying(encoded[0].0.as_ref()))?.body()
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
    let mut insert = transaction.prepare_cached(
        "INSERT INTO agent_pending_payment (
             position, recovery_root, authorization, entries, replaceable
         ) VALUES (?1, ?2, ?3, ?4, 0)",
    )?;
    for (position, (authorization, entries)) in encoded.iter().enumerate() {
        insert.execute(params![
            sql_u64(u64::try_from(position)?, "pending payment position")?,
            encoded_root,
            authorization.as_ref(),
            entries.as_ref(),
        ])?;
    }
    drop(insert);
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending payment stage", source))?;
    Ok(())
}

fn ensure_pending_matches(connection: &Connection, expected: &[PendingPayment]) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT position, recovery_root, authorization, entries, acceptance, replaceable
         FROM agent_pending_payment ORDER BY position",
    )?;
    let mut rows = statement.query([])?;
    for (position, payment) in expected.iter().enumerate() {
        let row = rows
            .next()?
            .context("pending payment batch was truncated")?;
        let stored_position: i64 = row.get(0)?;
        let stored_root: Vec<u8> = row.get(1)?;
        let stored_authorization: Vec<u8> = row.get(2)?;
        let stored_entries: Vec<u8> = row.get(3)?;
        let stored_acceptance: Option<Vec<u8>> = row.get(4)?;
        let stored_replaceable: bool = row.get(5)?;
        ensure!(
            stored_position == i64::try_from(position)?
                && stored_root == payment.recovery_root.encode().as_ref()
                && stored_authorization == payment.authorization.encode().as_ref()
                && stored_entries == encode_entries(&payment.entries)?
                && stored_acceptance
                    == payment
                        .acceptance
                        .as_ref()
                        .map(|acceptance| acceptance.acceptance().encode().to_vec())
                && stored_replaceable == payment.replaceable,
            "pending payment batch changed before mutation"
        );
    }
    ensure!(
        rows.next()?.is_none(),
        "pending payment batch grew before mutation"
    );
    Ok(())
}

fn retain_payment_acceptance_transaction(
    connection: &mut Connection,
    encoded_authorization: &[u8],
    receipts: i64,
    encoded_acceptance: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending receipt retention")?;
    ensure!(
        transaction.execute(
            "UPDATE agent_pending_payment SET receipts = ?1, acceptance = ?2
             WHERE authorization = ?3
               AND (acceptance IS NULL OR acceptance = ?2)",
            params![receipts, encoded_acceptance, encoded_authorization],
        )? == 1,
        "pending payment changed before receipt retention"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending receipt retention", source))?;
    Ok(())
}

fn retain_payment_acceptances_transaction(
    connection: &mut Connection,
    pending: &[PendingPayment],
    acceptances: &[(usize, &VerifiedAcceptance)],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending receipt batch retention")?;
    ensure_pending_matches(&transaction, pending)?;
    let mut update = transaction.prepare_cached(
        "UPDATE agent_pending_payment SET receipts = ?1, acceptance = ?2
         WHERE position = ?3 AND authorization = ?4
           AND (acceptance IS NULL OR acceptance = ?2)",
    )?;
    for (position, verified) in acceptances {
        let payment = &pending[*position];
        let acceptance = verified.acceptance();
        ensure!(
            update.execute(params![
                sql_u64(
                    u64::try_from(acceptance.entries.len())?,
                    "pending receipt count"
                )?,
                acceptance.encode().as_ref(),
                i64::try_from(*position)?,
                payment.authorization.encode().as_ref(),
            ])? == 1,
            "pending payment changed before receipt batch retention"
        );
    }
    drop(update);
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending receipt batch retention", source))?;
    Ok(())
}

fn insert_concluded_payment(
    transaction: &rusqlite::Transaction<'_>,
    position: usize,
    payment: &PendingPayment,
    state: PaymentState,
    acceptance: Option<&Acceptance>,
) -> Result<()> {
    let body = payment.authorization.body();
    let encoded_acceptance = acceptance.map(|acceptance| acceptance.encode());
    let receipts = acceptance
        .map(|acceptance| sql_u64(u64::try_from(acceptance.entries.len())?, "receipt count"))
        .transpose()?;
    ensure!(
        transaction.execute(
            "INSERT INTO agent_payments (
                 id, cumulative_debit, recovery_root, authorization, entries,
                 state, receipts, acceptance, epoch, total
             )
             SELECT ?1, ?2, recovery_root, authorization, entries, ?3, ?4, ?5, ?6, ?7
             FROM agent_pending_payment
             WHERE position = ?8 AND authorization = ?9",
            params![
                body_id(body).as_ref(),
                sql_u64(body.cumulative_debit(), "concluded cumulative debit")?,
                state as i64,
                receipts,
                encoded_acceptance.as_ref().map(AsRef::<[u8]>::as_ref),
                sql_u64(body.epoch(), "payment epoch")?,
                sql_u64(entry_total(&payment.entries)?, "payment total")?,
                i64::try_from(position)?,
                payment.authorization.encode().as_ref(),
            ],
        )? == 1,
        "pending payment changed before conclusion"
    );
    Ok(())
}

fn conclude_payment_prefix_transaction(
    connection: &mut Connection,
    pending: &[PendingPayment],
    conclusions: &[PaymentConclusion],
    vector: Option<&VectorWrite>,
    retire_context: bool,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending payment prefix conclusion")?;
    ensure_pending_matches(&transaction, pending)?;
    for (position, (payment, conclusion)) in pending.iter().zip(conclusions).enumerate() {
        match conclusion {
            PaymentConclusion::Accepted(acceptance) => insert_concluded_payment(
                &transaction,
                position,
                payment,
                if retire_context {
                    PaymentState::Retired
                } else {
                    PaymentState::Accepted
                },
                Some(acceptance.acceptance()),
            )?,
            PaymentConclusion::Retired => insert_concluded_payment(
                &transaction,
                position,
                payment,
                PaymentState::Retired,
                None,
            )?,
        }
    }
    let prefix = i64::try_from(conclusions.len())?;
    let deleted = transaction.execute(
        "DELETE FROM agent_pending_payment WHERE position < ?1",
        [prefix],
    )?;
    ensure!(
        deleted == conclusions.len(),
        "pending prefix changed before conclusion"
    );
    for old_position in conclusions.len()..pending.len() {
        ensure!(
            transaction.execute(
                "UPDATE agent_pending_payment
                 SET position = ?1, replaceable = 1
                 WHERE position = ?2",
                params![
                    i64::try_from(old_position - conclusions.len())?,
                    i64::try_from(old_position)?,
                ],
            )? == 1,
            "pending suffix changed before conclusion"
        );
    }
    if retire_context
        || pending.len() != conclusions.len()
        || conclusions
            .iter()
            .any(|conclusion| matches!(conclusion, PaymentConclusion::Retired))
    {
        let context = context_for_body(
            pending[0].authorization.body(),
            &read_binding(&transaction)?.operator,
        );
        transaction.execute(
            "DELETE FROM agent_context WHERE context = ?1",
            [context.encode().as_ref()],
        )?;
    }
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
        .map_err(|source| CommitUnknown::new("pending payment prefix conclusion", source))?;
    Ok(())
}

fn replace_payment_suffix_transaction(
    connection: &mut Connection,
    account: &Key,
    excluded: &[PendingPayment],
    replacement: &[PendingPayment],
    previous_debit: u64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin excluded payment suffix replacement")?;
    ensure_pending_matches(&transaction, excluded)?;
    ensure!(
        context_debit(&transaction, replacement[0].authorization.body())? == previous_debit,
        "agent debit changed before suffix replacement"
    );
    let recovery_root = replacement[0].recovery_root;
    read_recovery_opening(&transaction, &recovery_root, account)?
        .context("replacement recovery opening is missing")?;
    for (position, payment) in excluded.iter().enumerate() {
        insert_concluded_payment(
            &transaction,
            position,
            payment,
            PaymentState::Abandoned,
            payment
                .acceptance
                .as_ref()
                .map(VerifiedAcceptance::acceptance),
        )?;
    }
    ensure!(
        transaction.execute("DELETE FROM agent_pending_payment", [])? == excluded.len(),
        "excluded payment suffix changed before replacement"
    );
    let encoded_root = recovery_root.encode();
    let mut insert = transaction.prepare_cached(
        "INSERT INTO agent_pending_payment (
             position, recovery_root, authorization, entries, replaceable
         ) VALUES (?1, ?2, ?3, ?4, 0)",
    )?;
    for (position, payment) in replacement.iter().enumerate() {
        insert.execute(params![
            i64::try_from(position)?,
            encoded_root.as_ref(),
            payment.authorization.encode().as_ref(),
            encode_entries(&payment.entries)?,
        ])?;
    }
    drop(insert);
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("excluded payment suffix replacement", source))?;
    Ok(())
}

fn archive_replaceable_payments_transaction(
    connection: &mut Connection,
    excluded: &[PendingPayment],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin excluded payment batch archive")?;
    ensure_pending_matches(&transaction, excluded)?;
    for (position, payment) in excluded.iter().enumerate() {
        insert_concluded_payment(
            &transaction,
            position,
            payment,
            PaymentState::Abandoned,
            payment
                .acceptance
                .as_ref()
                .map(VerifiedAcceptance::acceptance),
        )?;
    }
    ensure!(
        transaction.execute("DELETE FROM agent_pending_payment", [])? == excluded.len(),
        "excluded payment batch changed before archive"
    );
    let context = context_for_body(
        excluded[0].authorization.body(),
        &read_binding(&transaction)?.operator,
    );
    transaction.execute(
        "DELETE FROM agent_context WHERE context = ?1",
        [context.encode().as_ref()],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("excluded payment batch archive", source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
    let authorization = SendAuthorization::<Key, Digest>::decode(Copying(encoded_authorization))?;
    let body = authorization.body();
    if let Some(previous_debit) = previous_debit {
        ensure!(
            context_debit(&transaction, body)? == previous_debit,
            "agent debit changed before {operation}"
        );
    }
    let encoded_entries: Vec<u8> = transaction.query_row(
        "SELECT entries FROM agent_pending_payment WHERE position = 0 AND authorization = ?1",
        [encoded_authorization],
        |row| row.get(0),
    )?;
    let total = entry_total(&decode_entries(&encoded_entries)?)?;
    ensure!(
        transaction.execute(
            "INSERT INTO agent_payments (
                 id, cumulative_debit, recovery_root, authorization, entries,
                 state, receipts, acceptance, epoch, total
             )
             SELECT ?1, ?2, recovery_root, authorization, entries, ?3, ?4, ?5, ?7, ?8
             FROM agent_pending_payment WHERE position = 0 AND authorization = ?6",
            params![
                id,
                endpoint,
                state as i64,
                receipts,
                encoded_acceptance,
                encoded_authorization,
                sql_u64(body.epoch(), "payment epoch")?,
                sql_u64(total, "payment total")?,
            ],
        )? == 1,
        "pending payment changed before {operation}"
    );
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_payment WHERE position = 0 AND authorization = ?1",
            [encoded_authorization],
        )? == 1,
        "pending payment changed before {operation}"
    );
    if !matches!(state, PaymentState::Accepted) {
        transaction.execute("DELETE FROM agent_context WHERE singleton = 1", [])?;
    }
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

#[cfg(test)]
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

#[cfg(test)]
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
        PaymentState::Retired,
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
#[cfg(test)]
fn commit_payment_transaction(
    connection: &mut Connection,
    previous_debit: u64,
    id: &[u8],
    endpoint: i64,
    receipts: u64,
    encoded_authorization: &[u8],
    encoded_acceptance: &[u8],
    vector: &VectorWrite,
    retire_context: bool,
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "accepted payment",
        Some(previous_debit),
        id,
        endpoint,
        if retire_context {
            PaymentState::Retired
        } else {
            PaymentState::Accepted
        },
        Some(sql_u64(receipts, "retained receipt count")?),
        encoded_authorization,
        Some(encoded_acceptance),
        Some(vector),
    )
}

fn stage_native_transaction(
    connection: &mut Connection,
    table: &str,
    encoded_event: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending native operation stage")?;
    transaction.execute(
        &format!("INSERT INTO {table} (singleton, event) VALUES (1, ?1) ON CONFLICT(singleton) DO NOTHING"),
        [encoded_event],
    )?;
    let stored = transaction
        .query_row(
            &format!("SELECT event FROM {table} WHERE singleton = 1"),
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .context("staged native operation is missing")?;
    ensure!(
        stored == encoded_event,
        "another native operation is already staged"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending native operation stage", source))?;
    Ok(())
}

fn remove_native_transaction(
    connection: &mut Connection,
    table: &str,
    encoded_event: &[u8],
    operation: &'static str,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .with_context(|| format!("begin {operation}"))?;
    ensure!(
        transaction.execute(
            &format!("DELETE FROM {table} WHERE singleton = 1 AND event = ?1"),
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
                 id, payer, epoch, cumulative, count, amount, receipt
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO NOTHING",
        )?;
        for record in records {
            let encoded = record.receipt.encode();
            let inserted = insert.execute(params![
                record.id.as_ref(),
                record.payer.as_ref(),
                sql_u64(record.epoch, "incoming epoch")?,
                sql_u64(record.cumulative, "incoming cumulative")?,
                sql_u64(record.count, "incoming count")?,
                sql_u64(record.amount, "incoming amount")?,
                encoded.as_ref(),
            ])?;
            if inserted > 0 {
                transaction.execute(
                    "DELETE FROM agent_reconciled WHERE epoch = ?1 AND status = ?2",
                    params![
                        sql_u64(record.epoch, "incoming epoch")?,
                        ReconcileOutcome::Reconciled as i64
                    ],
                )?;
            }
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

    // Repeated outcomes are idempotent; incoming evidence retires only a clean assessment.
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

fn stage_withdrawal_transaction(connection: &mut Connection, request: &[u8]) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        transaction.execute(
            "INSERT INTO agent_pending_claims (
                 singleton, claim_head, claim, request
             ) VALUES (1, NULL, NULL, ?1)
             ON CONFLICT(singleton) DO UPDATE SET request = excluded.request
             WHERE request IS NULL OR request = excluded.request",
            [request],
        )? == 1,
        "another withdrawal authorization is active"
    );
    transaction.execute("DELETE FROM agent_context WHERE singleton = 1", [])?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("withdrawal stage", source))?;
    Ok(())
}

fn retire_withdrawal_transaction(
    connection: &mut Connection,
    request: &[u8],
    deadline: u64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin withdrawal authorization retirement")?;
    ensure!(
        transaction.execute(
            "UPDATE agent_pending_claims SET request = NULL
             WHERE singleton = 1 AND request = ?1",
            [request],
        )? == 1,
        "withdrawal retirement does not match the active authorization"
    );
    let encoded = transaction.query_row(
        "SELECT length(retired_withdrawal_deadline), retired_withdrawal_deadline
         FROM agent_meta WHERE singleton = 1",
        [],
        |row| read_fixed_blob(row, 0, 1, u64::SIZE, "retired withdrawal deadline"),
    )?;
    let retired = u64::decode(encoded)?.max(deadline).encode();
    ensure!(
        transaction.execute(
            "UPDATE agent_meta SET retired_withdrawal_deadline = ?1 WHERE singleton = 1",
            [retired.as_ref()],
        )? == 1,
        "agent metadata is missing"
    );
    transaction.execute("DELETE FROM agent_context WHERE singleton = 1", [])?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("withdrawal authorization retirement", source))?;
    Ok(())
}

fn cache_claim_transaction(connection: &mut Connection, head: &[u8], claim: &[u8]) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin claim evidence cache")?;
    ensure!(
        transaction.execute(
            "INSERT INTO agent_pending_claims (
                 singleton, claim_head, claim, request
             ) VALUES (1, ?1, ?2, NULL)
             ON CONFLICT(singleton) DO UPDATE SET
                 claim_head = ?1, claim = ?2",
            params![head, claim],
        )? == 1,
        "withdrawal payout candidate was not cached"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("claim evidence cache", source))?;
    Ok(())
}

/// Clears the matching delivered payout without changing the active authorization.
fn complete_claim_transaction(connection: &mut Connection, position: &[u8]) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending claim completion")?;
    if let Some(encoded) = transaction
        .query_row(
            "SELECT claim FROM agent_pending_claims
             WHERE singleton = 1 AND claim IS NOT NULL",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    {
        let claim =
            WithdrawalClaim::<Digest>::decode_cfg(encoded, &(..=MAX_DESTINATION_BYTES).into())?;
        ensure!(
            claim.position().encode().as_ref() == position,
            "claim completion conflicts with another cached payout candidate"
        );
        transaction.execute(
            "UPDATE agent_pending_claims SET claim_head = NULL, claim = NULL
             WHERE singleton = 1",
            [],
        )?;
    }
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending claim completion", source))?;
    Ok(())
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

fn read_optional_fixed_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    expected: usize,
    field: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let value = read_optional_bounded_blob(row, length_column, value_column, expected, field)?;
    if let Some(value) = &value
        && value.len() != expected
    {
        return Err(to_sqlite_error(anyhow::anyhow!(
            "invalid {field} length {}, expected {expected}",
            value.len()
        )));
    }
    Ok(value)
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
    use super::{
        super::{
            fixtures::{StateFixture, TempDatabase},
            tests::{issue_acceptance, issued_receipt},
        },
        *,
    };
    use crate::protocol::{Wallet, deployment, identities, operator_key, wallets};
    use commonware_clearing::bajillion::boundary::WithdrawalAction;
    use std::num::NonZeroU64;

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

    fn pending_batch(
        context: &PaymentContext<Key, Digest>,
        wallet: &Wallet,
        root: StateRoot<Digest>,
        amounts: &[u64],
    ) -> Vec<PendingPayment> {
        let recipient = identities().remove(1).key;
        let mut cumulative = 0_u64;
        amounts
            .iter()
            .enumerate()
            .map(|(position, amount)| {
                cumulative += amount;
                let entries = vec![Entry {
                    recipient: recipient.clone(),
                    amount: *amount,
                }];
                let vector = OutVector::new(
                    context.epoch(),
                    wallet.public_key(),
                    vec![OutEntry {
                        recipient: recipient.clone(),
                        cumulative,
                        count: u64::try_from(position + 1).unwrap(),
                    }],
                )
                .unwrap();
                let body = VectorSendBody::new(
                    context,
                    wallet.public_key(),
                    u64::try_from(position + 1).unwrap(),
                    cumulative,
                    vector.root::<Sha256, Digest>().unwrap(),
                );
                PendingPayment {
                    authorization: SendAuthorization::sign(body, wallet.signer()),
                    entries,
                    recovery_root: root,
                    acceptance: None,
                    replaceable: false,
                }
            })
            .collect()
    }

    fn signed_send(wallet: &Wallet, anchor: &[u8]) -> (SendAuthorization<Key, Digest>, Vec<Entry>) {
        let context = PaymentContext::new(Sha256::hash(&[anchor]), 1, operator_key());
        sign_delta(&context, wallet, 1)
    }

    fn signed_withdrawal(
        wallet: &Wallet,
        root: &StateRoot<Digest>,
        amount: u64,
        deadline: u64,
    ) -> SignedWithdrawal<Key, Digest> {
        SignedWithdrawal::sign(
            deployment(),
            root.digest,
            wallet.public_key().encode(),
            WithdrawalAction::Amount(NonZeroU64::new(amount).unwrap()),
            deadline,
            wallet.signer(),
        )
    }

    #[test]
    fn withdrawal_authorization_floor_is_monotonic_across_reopen() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        let request = signed_withdrawal(&wallet, &root, 7, 10);
        store.stage_withdrawal(&request).unwrap();
        store.retire_withdrawal(&request).unwrap();
        drop(store);

        let (mut store, state) = open_store(database.path(), &account);
        assert!(state.pending_withdrawal.is_none());
        assert!(state.pending_withdrawal_claim.is_none());
        assert_eq!(store.retired_withdrawal_deadline().unwrap(), Some(10));

        let later = signed_withdrawal(&wallet, &root, 7, 75);
        store.stage_withdrawal(&later).unwrap();
        store.retire_withdrawal(&later).unwrap();
        let earlier = signed_withdrawal(&wallet, &root, 7, 20);
        store.stage_withdrawal(&earlier).unwrap();
        store.retire_withdrawal(&earlier).unwrap();
        assert_eq!(store.retired_withdrawal_deadline().unwrap(), Some(75));
        drop(store);

        let (_, state) = open_store(database.path(), &account);
        assert!(state.pending_withdrawal.is_none());
        assert!(state.pending_withdrawal_claim.is_none());
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
        let (_store, state) = open_store(database.path(), &account);
        let cache = state.cache.unwrap();
        assert_eq!(cache.context, context);
        assert_eq!(cache.root, root);
        assert_eq!(cache.epoch, 0);
    }

    #[test]
    fn pending_intent_cannot_be_replaced_by_another_epoch() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        let (original, entries) = signed_send(&wallet, b"original");
        store.stage_payment(&original, &entries, &root, 0).unwrap();
        let next = PaymentContext::new(Sha256::hash(&[b"next"]), 2, operator_key());
        let (replacement, _) = sign_delta(&next, &wallet, 1);
        assert!(
            store
                .stage_payment(&replacement, &entries, &root, 0)
                .is_err()
        );
        drop(store);
        let (_, state) = open_store(database.path(), &account);
        let retained = state.pending_payments.into_iter().next().unwrap();
        assert_eq!(retained.authorization.encode(), original.encode());
        assert_eq!(retained.entries, entries);
        assert_eq!(retained.recovery_root, root);
    }

    #[test]
    fn pending_payment_batch_stages_ordered_authorizations() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let recipient = identities().remove(1).key;
        let (root, opening) = recovery_evidence(&account, 100);
        let context = PaymentContext::new(Sha256::hash(&[b"pending-batch"]), 1, operator_key());
        let (first, first_entries) = sign_delta(&context, &wallet, 7);
        let second_entries = vec![Entry {
            recipient: recipient.clone(),
            amount: 3,
        }];
        let vector = OutVector::new(
            context.epoch(),
            account.clone(),
            vec![OutEntry {
                recipient,
                cumulative: 10,
                count: 2,
            }],
        )
        .unwrap();
        let second = SendAuthorization::sign(
            VectorSendBody::new(
                &context,
                account,
                2,
                10,
                vector.root::<Sha256, Digest>().unwrap(),
            ),
            wallet.signer(),
        );

        let (mut store, _) = open_store(database.path(), first.body().payer());
        store.retain_recovery_opening(&root, &opening).unwrap();
        let expected = vec![
            PendingPayment {
                authorization: first,
                entries: first_entries,
                recovery_root: root,
                acceptance: None,
                replaceable: false,
            },
            PendingPayment {
                authorization: second,
                entries: second_entries,
                recovery_root: root,
                acceptance: None,
                replaceable: false,
            },
        ];
        store.stage_payments(&expected, 0).unwrap();

        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM agent_pending_payment", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
        drop(store);

        let (_, state) = open_store(database.path(), expected[0].authorization.body().payer());
        assert_eq!(state.pending_payments.len(), 2);
        for (reopened, expected) in state.pending_payments.iter().zip(expected) {
            assert_eq!(reopened.authorization, expected.authorization);
            assert_eq!(reopened.entries, expected.entries);
            assert_eq!(reopened.recovery_root, expected.recovery_root);
            assert!(reopened.acceptance.is_none());
            assert!(!reopened.replaceable);
        }
    }

    #[test]
    fn accepted_payment_batch_commits_receipts_and_terminal_vector_atomically() {
        let database = TempDatabase::new();
        let payer = wallets().remove(0);
        let operator = Wallet::from_seed("operator", 1);
        let account = payer.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let context = PaymentContext::new(Sha256::hash(&[b"accepted-batch"]), 1, operator_key());
        let pending = pending_batch(&context, &payer, root, &[7, 3]);
        let first = issue_acceptance(
            &operator,
            &[],
            &pending[0].authorization,
            &pending[0].entries,
        );
        let prior = vec![OutEntry {
            recipient: pending[0].entries[0].recipient.clone(),
            cumulative: 7,
            count: 1,
        }];
        let second = issue_acceptance(
            &operator,
            &prior,
            &pending[1].authorization,
            &pending[1].entries,
        );

        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payments(&pending, 0).unwrap();
        assert_eq!(
            store
                .conclude_payment_prefix(
                    &pending,
                    &[
                        PaymentConclusion::Accepted(Box::new(VerifiedAcceptance::from_verified(
                            first
                        ),)),
                        PaymentConclusion::Accepted(Box::new(VerifiedAcceptance::from_verified(
                            second
                        ),)),
                    ],
                    0,
                    false,
                )
                .unwrap(),
            2
        );
        drop(store);

        let (store, state) = open_store(database.path(), &account);
        assert!(state.pending_payments.is_empty());
        assert_eq!(state.receipt_count, 2);
        let vector = store.vector_state(&context).unwrap().unwrap();
        assert_eq!(vector.seq, 2);
        assert_eq!(vector.cumulative_debit, 10);
        assert_eq!(vector.entries[0].count, 2);
        assert_eq!(vector.entries[0].cumulative, 10);
    }

    #[test]
    fn accepted_payment_batch_retirement_survives_reopen() {
        for retire_context in [false, true] {
            let database = TempDatabase::new();
            let payer = wallets().remove(0);
            let operator = Wallet::from_seed("operator", 1);
            let account = payer.public_key();
            let (root, opening) = recovery_evidence(&account, 100);
            let context = PaymentContext::new(
                Sha256::hash(&[b"accepted-batch-retirement"]),
                1,
                operator_key(),
            );
            let pending = pending_batch(&context, &payer, root, &[7, 3]);
            let first = issue_acceptance(
                &operator,
                &[],
                &pending[0].authorization,
                &pending[0].entries,
            );
            let prior = vec![OutEntry {
                recipient: pending[0].entries[0].recipient.clone(),
                cumulative: 7,
                count: 1,
            }];
            let second = issue_acceptance(
                &operator,
                &prior,
                &pending[1].authorization,
                &pending[1].entries,
            );
            let conclusions = [
                PaymentConclusion::Accepted(Box::new(VerifiedAcceptance::from_verified(first))),
                PaymentConclusion::Accepted(Box::new(VerifiedAcceptance::from_verified(second))),
            ];

            let (mut store, _) = open_store(database.path(), &account);
            store.retain_recovery_opening(&root, &opening).unwrap();
            store.stage_payments(&pending, 0).unwrap();
            store
                .conclude_payment_prefix(&pending, &conclusions, 0, retire_context)
                .unwrap();
            drop(store);

            let (store, state) = open_store(database.path(), &account);
            assert!(state.pending_payments.is_empty());
            assert_eq!(state.receipt_count, 2);
            assert_eq!(
                store.check_signing_context(&context).is_err(),
                retire_context
            );
            let expected_state = if retire_context {
                PaymentState::Retired
            } else {
                PaymentState::Accepted
            };
            let retained: i64 = store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM agent_payments
                     WHERE state = ?1 AND acceptance IS NOT NULL",
                    [expected_state as i64],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained, 2);
        }
    }

    #[test]
    fn prefix_conclusion_preserves_and_replaces_exact_suffix_across_reopen() {
        let database = TempDatabase::new();
        let payer = wallets().remove(0);
        let account = payer.public_key();
        let operator = Wallet::from_seed("operator", 1);
        let (root, opening) = recovery_evidence(&account, 100);
        let old_context = PaymentContext::new(Sha256::hash(&[b"old-batch"]), 1, operator_key());
        let mut old = pending_batch(&old_context, &payer, root, &[7, 3, 2]);
        let omitted = issue_acceptance(
            &operator,
            &[OutEntry {
                recipient: old[2].entries[0].recipient.clone(),
                cumulative: 10,
                count: 2,
            }],
            &old[2].authorization,
            &old[2].entries,
        );
        let omitted = VerifiedAcceptance::from_verified(omitted);

        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payments(&old, 0).unwrap();
        store.retain_payment_acceptance(&old[2], &omitted).unwrap();
        old[2].acceptance = Some(omitted);
        let excluded = old[1..].to_vec();
        store
            .conclude_payment_prefix(&old, &[PaymentConclusion::Retired], 0, true)
            .unwrap();
        drop(store);

        let (mut store, state) = open_store(database.path(), &account);
        assert_eq!(state.pending_payments.len(), 2);
        assert!(
            state
                .pending_payments
                .iter()
                .all(|payment| payment.replaceable)
        );
        assert_eq!(
            state.pending_payments[0].authorization,
            excluded[0].authorization
        );
        assert_eq!(
            state.pending_payments[1].authorization,
            excluded[1].authorization
        );
        let old_vector = store.vector_state(&old_context).unwrap().unwrap();
        assert_eq!(old_vector.seq, 1);
        assert_eq!(old_vector.cumulative_debit, 7);

        let new_context = PaymentContext::new(Sha256::hash(&[b"new-batch"]), 2, operator_key());
        let replacement = pending_batch(&new_context, &payer, root, &[3, 2]);
        assert_eq!(
            store
                .replace_payment_suffix(&state.pending_payments, &replacement, 0, 0)
                .unwrap(),
            1
        );
        drop(store);

        let (store, state) = open_store(database.path(), &account);
        assert_eq!(state.pending_payments.len(), 2);
        assert_eq!(state.receipt_count, 1);
        assert!(
            state
                .pending_payments
                .iter()
                .all(|payment| !payment.replaceable)
        );
        assert_eq!(
            state.pending_payments[0].authorization,
            replacement[0].authorization
        );
        let abandoned: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_payments WHERE state = ?1",
                [PaymentState::Abandoned as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(abandoned, 2);
    }

    #[test]
    fn failed_batch_conclusion_rolls_back_every_member() {
        let database = TempDatabase::new();
        let payer = wallets().remove(0);
        let operator = Wallet::from_seed("operator", 1);
        let account = payer.public_key();
        let (root, opening) = recovery_evidence(&account, 100);
        let context = PaymentContext::new(Sha256::hash(&[b"rollback-batch"]), 1, operator_key());
        let pending = pending_batch(&context, &payer, root, &[7, 3]);
        let first = issue_acceptance(
            &operator,
            &[],
            &pending[0].authorization,
            &pending[0].entries,
        );
        let prior = vec![OutEntry {
            recipient: pending[0].entries[0].recipient.clone(),
            cumulative: 7,
            count: 1,
        }];
        let second = issue_acceptance(
            &operator,
            &prior,
            &pending[1].authorization,
            &pending[1].entries,
        );
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payments(&pending, 0).unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_batch_conclusion
                 BEFORE INSERT ON agent_payments
                 BEGIN
                     SELECT RAISE(ABORT, 'injected batch conclusion failure');
                 END;",
            )
            .unwrap();

        assert!(
            store
                .conclude_payment_prefix(
                    &pending,
                    &[
                        PaymentConclusion::Accepted(Box::new(VerifiedAcceptance::from_verified(
                            first
                        ),)),
                        PaymentConclusion::Accepted(Box::new(VerifiedAcceptance::from_verified(
                            second
                        ),)),
                    ],
                    0,
                    false,
                )
                .is_err()
        );
        assert!(store.poisoned);
        let (pending_count, concluded_count): (i64, i64) = store
            .connection
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM agent_pending_payment),
                     (SELECT COUNT(*) FROM agent_payments)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((pending_count, concluded_count), (2, 0));
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
        store.cache_context(&context, &root, 0).unwrap();
        store
            .stage_payment(&authorization, &entries, &root, 0)
            .unwrap();
        store
            .finalize_payment_unheld(&authorization, &entries, 0)
            .unwrap();
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
        drop(store);
        let (mut store, state) = open_store(database.path(), &account);
        assert_eq!(
            state
                .pending_payments
                .into_iter()
                .next()
                .unwrap()
                .authorization,
            next
        );
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
                         id, payer, epoch, cumulative, count, amount, receipt
                     ) VALUES (?1, ?2, ?3, ?4, 1, ?4, x'01')",
                    params![
                        Sha256::hash(&[b"credit-id", &[tag]]).as_ref(),
                        payer.as_ref(),
                        epoch,
                        amount,
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
        assert!(state.pending_payments.is_empty());
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
        let pending = state.pending_payments.into_iter().next().unwrap();
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
            Sha256::hash(&[b"noncanonical-pending-position"]),
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
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_pending_payment SET position = 2 WHERE position = 0;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(pending.path(), &account, &deployment(), &operator_key());
        assert!(error.contains("pending payment positions are not contiguous"));
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

    #[test]
    fn incoming_cursor_domain_rejection_precedes_mutation() {
        let database = TempDatabase::new();
        let account = wallets().remove(1).public_key();
        let (mut store, _) = open_store(database.path(), &account);
        let payer = wallets().remove(0);
        let context = PaymentContext::new(Sha256::hash(&[b"incoming-record"]), 0, operator_key());
        let receipt = issued_receipt(&context, &payer, &account, 5);
        let records = [IncomingRecord {
            id: body_id(receipt.ack.body()),
            payer: payer.public_key(),
            epoch: 0,
            cumulative: 5,
            count: 1,
            amount: 5,
            receipt,
        }];

        let error = store.record_incoming(&records, u64::MAX).unwrap_err();
        assert!(format!("{error:#}").contains("incoming cursor exceeds SQLite INTEGER range"));
        assert!(!store.poisoned);
        assert_eq!(
            read_incoming_summary(&store.connection).unwrap(),
            IncomingSummary::default()
        );

        let summary = store.record_incoming(&records, 1).unwrap();
        assert_eq!(
            summary,
            IncomingSummary {
                total: 5,
                count: 1,
                cursor: 1
            }
        );
    }
}
