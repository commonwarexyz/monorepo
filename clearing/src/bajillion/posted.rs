//! Wire form of the posted sender-vector corpus.
//!
//! The posted corpus carries only what a chain-following reader cannot derive, and its
//! readers hold the previous certified state (a [Replica]), so almost everything leaves
//! the wire:
//!
//! - **Predecessor states and the unchanged vector**: supplied by the reader's replica.
//! - **Live-account keys**: replaced by rank gaps, the count of live accounts skipped in
//!   key order, one or two bytes each. Full 32 B keys appear only for accounts not yet
//!   live (first activations and external payouts), and a full-key row for a live account
//!   is rejected, so each close has exactly one wire form.
//! - **Row prefixes, successor states, and settlement outputs**: equation-pinned by row
//!   validation, so decoding re-derives them instead of reading them.
//! - **Acknowledgment bodies**: every field other than the sequence number is checked
//!   equal to context or row material during validation, so the wire carries only the
//!   sequence number and the payer signature. The operator's acceptance rides as one
//!   combined countersignature per proof slice.
//! - **Recipient keys in out entries**: entries reference recipients by row index,
//!   resolved through the decoded rows.
//! - **The transpose**: rebuilt entirely from the posted vectors.
//! - **Fixed-width integers**: sequence numbers, cumulative amounts, and counts ride as
//!   varints. The hash preimages they are checked against stay fixed-width.
//!
//! Decoding is reconstruction, not validation: [read] rebuilds the exact in-memory
//! [Close] and the caller MUST validate it
//! ([validate_close_with_strategy](crate::bajillion::transition::validate_close_with_strategy))
//! before applying it to the replica with [Replica::apply]. A replica that diverges from
//! the sealed close produces a close whose roots fail that validation. Reading is
//! sequential by construction: a posted close is only meaningful against the replica its
//! writer held, so cold readers bootstrap from a state snapshot checked against a
//! certified root and stream forward.
//!
//! Dealt slices keep full-key vectors and their transpose ranges: a slice validator
//! holds only its span and cannot resolve global row indices, so the collation
//! redundancy belongs in dealings, never in the posted corpus.

use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    commitment::VectorRoot,
    payment::{SendAuthorization, VectorSendBody},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Close, CloseContext, Header, OperatorAggregate, RootBundle, TransitionError, validate_row,
    },
    vector::{OutEntry, OutVector},
};
use alloc::{collections::BTreeMap, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Verifier};

pub(crate) fn vectors_size<P: PublicKey>(
    out_vectors: &[OutVector<P>],
    indices: &[Vec<usize>],
) -> usize {
    out_vectors
        .iter()
        .zip(indices)
        .map(|(vector, resolved)| {
            vector.entries().len().encode_size()
                + vector
                    .entries()
                    .iter()
                    .zip(resolved)
                    .map(|(entry, index)| {
                        index.encode_size()
                            + UInt(entry.cumulative).encode_size()
                            + UInt(entry.count).encode_size()
                    })
                    .sum::<usize>()
        })
        .sum::<usize>()
}

/// Resolves each vector's recipients to their row indices in the posted ordering.
pub fn resolve_indices<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
) -> Result<Vec<Vec<usize>>, TransitionError> {
    close
        .out_vectors
        .iter()
        .map(|vector| {
            vector
                .entries()
                .iter()
                .map(|entry| {
                    close
                        .rows
                        .binary_search_by(|row| row.account.cmp(&entry.recipient))
                        .map_err(|_| TransitionError::TransposeAlignment)
                })
                .collect()
        })
        .collect()
}

/// One decoded row before derivation: account, predecessor, and the optional outgoing
/// sequence number and payer signature.
pub(crate) type SkeletonRow<P> = (P, AccountState, Option<(u64, <P as Verifier>::Signature)>);

/// Reads the row-index-encoded vectors section against a decoded skeleton.
pub(crate) fn read_vectors<P: PublicKey, D: Digest>(
    buf: &mut impl Buf,
    context: &CloseContext<P, D>,
    skeleton: &[SkeletonRow<P>],
    max_entries: usize,
) -> Result<Vec<OutVector<P>>, CodecError> {
    let invalid = |reason| CodecError::Invalid("PostedClose", reason);
    let mut remaining = max_entries;
    let mut out_vectors = Vec::with_capacity(skeleton.len());
    for (payer, ..) in skeleton {
        let len = usize::read_cfg(buf, &RangeCfg::new(..=remaining))?;
        remaining -= len;
        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            let index = usize::read_cfg(buf, &RangeCfg::new(..skeleton.len()))?;
            entries.push(OutEntry {
                recipient: skeleton[index].0.clone(),
                cumulative: UInt::read(buf)?.into(),
                count: UInt::read(buf)?.into(),
            });
        }
        out_vectors.push(
            OutVector::new(context.payment().epoch(), payer.clone(), entries)
                .map_err(|_| invalid("outgoing vector is not canonical"))?,
        );
    }
    Ok(out_vectors)
}

/// Reads the per-slice operator aggregates section: exactly one per slice.
pub(crate) fn read_aggregates(
    buf: &mut impl Buf,
    slice_count: u16,
) -> Result<Vec<Option<OperatorAggregate>>, CodecError> {
    Vec::<Option<OperatorAggregate>>::read_cfg(
        buf,
        &(RangeCfg::exact(usize::from(slice_count)), ()),
    )
}

/// Derives the full in-memory close from decoded parts, shared by every wire form.
///
/// Forward-derives each row's successor state and output from its predecessor, its vector
/// totals, and its rebuilt incoming range, then chains the prefix column. The caller has
/// already established where `unchanged`, the skeleton, and the vectors came from; any
/// divergence from the sealed close surfaces when the caller validates the result.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    header: Header<D>,
    roots: RootBundle<D>,
    unchanged: Vec<StateLeaf<P>>,
    skeleton: Vec<SkeletonRow<P>>,
    out_vectors: Vec<OutVector<P>>,
    operator_aggregates: Vec<Option<OperatorAggregate>>,
) -> Result<Close<P, D>, CodecError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let invalid = |reason| CodecError::Invalid("PostedClose", reason);
    let row_count = skeleton.len();

    // Recipient credit sums come straight from the vectors, grouped per recipient index.
    let mut in_credit = vec![(0_u64, 0_u64); row_count];
    for vector in &out_vectors {
        for (entry, credited) in vector
            .entries()
            .iter()
            .zip(resolve_entry_targets(&skeleton, vector)?)
        {
            let slot = &mut in_credit[credited];
            slot.0 = slot
                .0
                .checked_add(entry.cumulative)
                .ok_or_else(|| invalid("credit totals overflow"))?;
            slot.1 = slot
                .1
                .checked_add(entry.count)
                .ok_or_else(|| invalid("credit totals overflow"))?;
        }
    }
    let mut rows = Vec::with_capacity(row_count);
    for (index, ((account, predecessor, outgoing), vector)) in
        skeleton.into_iter().zip(&out_vectors).enumerate()
    {
        let (credit, receipts) = in_credit[index];
        rows.push(derive_row::<H, P, D>(
            context,
            deposits,
            withdrawals,
            account,
            predecessor,
            outgoing,
            vector,
            credit,
            receipts,
        )?);
    }
    let close = Close {
        header,
        roots,
        unchanged,
        rows,
        out_vectors,
        operator_aggregates,
    };
    derive_prefixes::<H, P, D>(context, deposits, withdrawals, close)
        .map_err(|_| invalid("derived close material is not internally valid"))
}

/// Resolves one vector's entries back to row indices through the decoded row keys.
fn resolve_entry_targets<P: PublicKey, S>(
    skeleton: &[(P, AccountState, S)],
    vector: &OutVector<P>,
) -> Result<Vec<usize>, CodecError> {
    vector
        .entries()
        .iter()
        .map(|entry| {
            skeleton
                .binary_search_by(|(account, ..)| account.cmp(&entry.recipient))
                .map_err(|_| CodecError::Invalid("PostedClose", "credited recipient has no row"))
        })
        .collect()
}

/// Derives one row from its wire material, with an unset prefix: the successor state and
/// settlement output from the row equations, and the acknowledgment body from context and
/// the sequence number, so the payer signature is checked against exactly what the operator
/// committed.
///
/// Shared by posted decoding, which sources credit from the global vectors, and dealt-slice
/// hydration, which sources it from the transpose range.
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_row<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    account: P,
    predecessor: AccountState,
    outgoing: Option<(u64, <P as Verifier>::Signature)>,
    vector: &OutVector<P>,
    credit: u64,
    receipts: u64,
) -> Result<AccountRow<P, D>, CodecError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let invalid = |reason| CodecError::Invalid("PostedClose", reason);
    let (successor, output) = derive_successor(
        &account,
        &predecessor,
        deposits,
        withdrawals,
        vector,
        credit,
        receipts,
    )
    .map_err(|_| invalid("successor state is not derivable"))?;
    let outgoing = match outgoing {
        Some((seq, payer_signature)) => {
            let send_root: VectorRoot<D> = vector
                .root::<H, D>()
                .map_err(|_| invalid("outgoing vector root is not derivable"))?;
            Some(SendAuthorization::from_raw_unchecked(
                VectorSendBody::new(
                    context.payment(),
                    account.clone(),
                    seq,
                    successor.cumulative_debit,
                    send_root,
                ),
                payer_signature,
            ))
        }
        None => None,
    };
    Ok(AccountRow {
        account,
        predecessor,
        successor,
        outgoing,
        output,
        prefix: Prefix::default(),
    })
}

/// Forward-derives one row's successor state and settlement output.
///
/// Every derived field is equation-pinned by row validation, and decode's final pass runs
/// [validate_row] over the derived rows, so any divergence here fails decode instead of
/// producing a close validation would reject.
pub(crate) fn derive_successor<P: PublicKey, D: Digest>(
    account: &P,
    predecessor: &AccountState,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    out_vector: &OutVector<P>,
    credit: u64,
    receipts: u64,
) -> Result<(AccountState, SettlementOutput), TransitionError> {
    use crate::bajillion::boundary::WithdrawalAction;
    let (debit, _) = out_vector.totals()?;
    let deposit = deposits.amount_for(account);
    let withdrawal = withdrawals.request_for(account);
    let available = u128::from(predecessor.balance) + u128::from(deposit) + u128::from(credit);
    let tail = available
        .checked_sub(u128::from(debit))
        .ok_or(TransitionError::BalanceEquation)?;
    let withdrawal_amount = match withdrawal {
        Some(request) => match request.body().action() {
            WithdrawalAction::Amount(amount) if u128::from(amount.get()) <= tail => amount.get(),
            WithdrawalAction::Amount(_) => 0,
            WithdrawalAction::Close => {
                u64::try_from(tail).map_err(|_| TransitionError::PrefixOverflow)?
            }
        },
        None => 0,
    };
    let registered = predecessor.active || deposit != 0;
    let payout = if registered { 0 } else { credit };
    let balance = tail
        .checked_sub(u128::from(withdrawal_amount))
        .and_then(|rest| rest.checked_sub(u128::from(payout)))
        .and_then(|rest| u64::try_from(rest).ok())
        .ok_or(TransitionError::BalanceEquation)?;
    let successor = AccountState {
        balance,
        cumulative_debit: predecessor
            .cumulative_debit
            .checked_add(debit)
            .ok_or(TransitionError::PrefixOverflow)?,
        cumulative_credit: predecessor
            .cumulative_credit
            .checked_add(credit)
            .ok_or(TransitionError::PrefixOverflow)?,
        receipt_count: predecessor
            .receipt_count
            .checked_add(receipts)
            .ok_or(TransitionError::PrefixOverflow)?,
        active: balance > 0,
    };
    let output = match withdrawal {
        Some(_) => SettlementOutput::Withdrawal(withdrawal_amount),
        None if payout != 0 => SettlementOutput::ExternalPayout(payout),
        None => SettlementOutput::None,
    };
    Ok((successor, output))
}

/// Chains each row's validated delta into the derived prefix column.
fn derive_prefixes<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    mut close: Close<P, D>,
) -> Result<Close<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let transpose = close.rebuild_transpose()?;
    let mut cursor = 0_usize;
    let mut prefix = Prefix::default();
    let mut prefixes = Vec::with_capacity(close.rows.len());
    for (row, out_vector) in close.rows.iter().zip(&close.out_vectors) {
        let start = cursor;
        while transpose
            .get(cursor)
            .is_some_and(|entry| entry.recipient == row.account)
        {
            cursor += 1;
        }
        let delta = validate_row::<H, P, D>(
            context,
            deposits,
            withdrawals,
            row,
            out_vector,
            &transpose[start..cursor],
        )?;
        prefix = prefix
            .checked_extend(delta)
            .ok_or(TransitionError::PrefixOverflow)?;
        prefixes.push(prefix);
    }
    if cursor != transpose.len() {
        return Err(TransitionError::TransposeAlignment);
    }
    for (row, prefix) in close.rows.iter_mut().zip(prefixes) {
        row.prefix = prefix;
    }
    Ok(close)
}

/// A replica reader's state: the live account map, exactly the state vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Replica<P: PublicKey> {
    states: BTreeMap<P, AccountState>,
}

impl<P: PublicKey> Replica<P> {
    /// Builds a replica from a state snapshot.
    ///
    /// The snapshot must be strictly key-sorted live leaves (the state vector of some
    /// certified close). Callers are responsible for having checked the snapshot against
    /// that close's certified state root.
    pub fn genesis(leaves: &[StateLeaf<P>]) -> Result<Self, TransitionError> {
        if leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
            || leaves
                .iter()
                .any(|leaf| !leaf.state.active || leaf.state.balance == 0)
        {
            return Err(TransitionError::NonCanonicalStateOrder);
        }
        Ok(Self {
            states: leaves
                .iter()
                .map(|leaf| (leaf.account.clone(), leaf.state))
                .collect(),
        })
    }

    /// The number of live accounts (the state vector length).
    pub fn live(&self) -> usize {
        self.states.len()
    }

    /// The account's predecessor state for the next close: its live state, or the default
    /// inactive state if it is not live.
    fn predecessor(&self, account: &P) -> AccountState {
        self.states.get(account).copied().unwrap_or_default()
    }

    /// The unchanged state vector for a close whose rows cover `rows` (strictly key-sorted):
    /// every live account without a row.
    fn unchanged(&self, rows: &[SkeletonRow<P>]) -> Vec<StateLeaf<P>> {
        let mut rows = rows.iter().map(|(account, ..)| account).peekable();
        let mut unchanged = Vec::with_capacity(self.states.len());
        for (account, state) in &self.states {
            while rows.peek().is_some_and(|row| *row < account) {
                rows.next();
            }
            if rows.peek().is_some_and(|row| *row == account) {
                continue;
            }
            unchanged.push(StateLeaf {
                account: account.clone(),
                state: *state,
            });
        }
        unchanged
    }

    /// Rolls the replica forward over one validated close.
    ///
    /// Must be called with a close that has passed full validation against this replica's
    /// state (see [read]); applying anything else desynchronizes the replica, which the next
    /// close's validation then rejects.
    pub fn apply<D: Digest>(&mut self, close: &Close<P, D>) {
        for row in &close.rows {
            assert!(
                self.predecessor(&row.account) == row.predecessor,
                "close predecessor diverges from the replica"
            );
            if row.successor.active {
                self.states.insert(row.account.clone(), row.successor);
            } else {
                self.states.remove(&row.account);
            }
        }
    }
}

/// Row tags: bit 0 carries the outgoing flag, bit 1 marks a full-key (not-live) account.
const OUTGOING: u8 = 0b01;
const FRESH: u8 = 0b10;

/// Per-row wire material: a rank gap for live accounts, a full key otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Reference<P> {
    Live(usize),
    Fresh(P),
}

/// One row as it travels on the posted and dealt wires: its reference and, for senders,
/// the sequence number and payer signature, the only signed material the acknowledgment
/// body does not derive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RowWire<P: PublicKey> {
    pub(crate) reference: Reference<P>,
    pub(crate) outgoing: Option<(u64, <P as Verifier>::Signature)>,
}

impl<P: PublicKey> RowWire<P> {
    pub(crate) fn write(&self, buf: &mut impl BufMut) {
        let mut tag = 0_u8;
        if self.outgoing.is_some() {
            tag |= OUTGOING;
        }
        if matches!(self.reference, Reference::Fresh(_)) {
            tag |= FRESH;
        }
        tag.write(buf);
        match &self.reference {
            Reference::Live(gap) => gap.write(buf),
            Reference::Fresh(account) => account.write(buf),
        }
        if let Some((seq, payer_signature)) = &self.outgoing {
            UInt(*seq).write(buf);
            payer_signature.write(buf);
        }
    }

    /// Reads one row whose rank gap, if any, must fall short of `live` retained accounts.
    pub(crate) fn read(buf: &mut impl Buf, live: usize) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        if tag & !(OUTGOING | FRESH) != 0 {
            return Err(CodecError::InvalidEnum(tag));
        }
        let reference = if tag & FRESH != 0 {
            Reference::Fresh(P::read(buf)?)
        } else {
            Reference::Live(usize::read_cfg(buf, &RangeCfg::new(..live))?)
        };
        let outgoing = if tag & OUTGOING != 0 {
            Some((
                UInt::read(buf)?.into(),
                <P as Verifier>::Signature::read(buf)?,
            ))
        } else {
            None
        };
        Ok(Self {
            reference,
            outgoing,
        })
    }

    pub(crate) fn encode_size(&self) -> usize {
        1 + match &self.reference {
            Reference::Live(gap) => gap.encode_size(),
            Reference::Fresh(_) => P::SIZE,
        } + self.outgoing.as_ref().map_or(0, |(seq, _)| {
            UInt(*seq).encode_size() + <P as Verifier>::Signature::SIZE
        })
    }
}

/// The wire form of one close row against its resolved reference.
pub(crate) fn row_wire<P: PublicKey, D: Digest>(
    row: &AccountRow<P, D>,
    reference: Reference<P>,
) -> RowWire<P> {
    RowWire {
        reference,
        outgoing: row
            .outgoing
            .as_ref()
            .map(|send| (send.body().seq(), send.payer_signature().clone())),
    }
}

/// Resolves each row to its wire reference against the key-sorted `live` accounts it was
/// built on: live accounts become rank gaps (live accounts skipped since the previous row,
/// or since the first live account for the first row).
///
/// The posted corpus resolves against the whole replica. A dealt chunk resolves each
/// slice's rows against that slice's retained leaves alone, so its bytes do not depend on
/// the span carrying it.
pub(crate) fn resolve_references<'a, P: PublicKey, D: Digest>(
    rows: &[AccountRow<P, D>],
    live: impl Iterator<Item = &'a P>,
) -> Vec<Reference<P>> {
    let mut live = live.peekable();
    let mut references = Vec::with_capacity(rows.len());
    for row in rows {
        let mut gap = 0_usize;
        while live.peek().is_some_and(|key| **key < row.account) {
            live.next();
            gap += 1;
        }
        if live.peek().is_some_and(|key| **key == row.account) {
            live.next();
            references.push(Reference::Live(gap));
        } else {
            references.push(Reference::Fresh(row.account.clone()));
        }
    }
    references
}

/// Returns the exact posted wire size of one close against `replica`.
pub fn encoded_size<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
    replica: &Replica<P>,
) -> Result<usize, TransitionError> {
    let indices = resolve_indices(close)?;
    let rows = close
        .rows
        .iter()
        .zip(resolve_references(&close.rows, replica.states.keys()))
        .map(|(row, reference)| row_wire(row, reference).encode_size())
        .sum::<usize>();
    Ok(Header::<D>::SIZE
        + RootBundle::<D>::SIZE
        + close.rows.len().encode_size()
        + rows
        + vectors_size(&close.out_vectors, &indices)
        + close.operator_aggregates.encode_size())
}

/// Writes the posted wire form of one close against the pre-close `replica`.
///
/// `indices` are the entry row indices from [resolve_indices]. The replica must be
/// the state the close was built on (the writer applies the close only afterward).
pub fn write<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
    indices: &[Vec<usize>],
    replica: &Replica<P>,
    buf: &mut impl BufMut,
) {
    close.header.write(buf);
    close.roots.write(buf);
    close.rows.len().write(buf);
    for (row, reference) in close
        .rows
        .iter()
        .zip(resolve_references(&close.rows, replica.states.keys()))
    {
        row_wire(row, reference).write(buf);
    }
    for (vector, resolved) in close.out_vectors.iter().zip(indices) {
        resolved.len().write(buf);
        for (entry, index) in vector.entries().iter().zip(resolved) {
            index.write(buf);
            UInt(entry.cumulative).write(buf);
            UInt(entry.count).write(buf);
        }
    }
    close.operator_aggregates.write(buf);
}

/// Reads a posted close against the pre-close `replica` back into the exact in-memory close.
///
/// This is reconstruction, not validation: predecessor states and
/// the unchanged vector come from the replica, and the caller MUST pass the result to
/// [validate_close_with_strategy](crate::bajillion::transition::validate_close_with_strategy)
/// before applying it to the replica. A replica that diverges from the sealed close (wrong
/// predecessor, stale account map) produces a close whose roots fail that validation.
pub fn read<H, P, D>(
    buf: &mut impl Buf,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    replica: &Replica<P>,
    max_rows: usize,
    max_entries: usize,
) -> Result<Close<P, D>, CodecError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let invalid = |reason| CodecError::Invalid("PostedClose", reason);
    let header = Header::read(buf)?;
    let roots = RootBundle::read(buf)?;
    let row_count = usize::read_cfg(buf, &RangeCfg::new(..=max_rows))?;
    let mut live = replica.states.iter().peekable();
    let mut skeleton: Vec<SkeletonRow<P>> = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let wire = RowWire::<P>::read(buf, replica.live())?;
        let (account, predecessor) = match wire.reference {
            Reference::Fresh(account) => {
                if replica.states.contains_key(&account) {
                    return Err(invalid("live account carried as a full key"));
                }
                (account, AccountState::default())
            }
            Reference::Live(gap) => {
                for _ in 0..gap {
                    live.next()
                        .ok_or_else(|| invalid("rank gap beyond state"))?;
                }
                let (account, state) = live
                    .next()
                    .ok_or_else(|| invalid("rank gap beyond state"))?;
                (account.clone(), *state)
            }
        };
        skeleton.push((account, predecessor, wire.outgoing));
    }
    if skeleton.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(invalid("rows are not strictly account-sorted"));
    }
    let out_vectors = read_vectors(buf, context, &skeleton, max_entries)?;
    let operator_aggregates = read_aggregates(buf, context.assignment().slice_count())?;
    if buf.has_remaining() {
        return Err(invalid("trailing bytes after the posted corpus"));
    }
    let unchanged = replica.unchanged(&skeleton);
    assemble::<H, P, D>(
        context,
        deposits,
        withdrawals,
        header,
        roots,
        unchanged,
        skeleton,
        out_vectors,
        operator_aggregates,
    )
}
