//! Per-account service from one sealed proof slice.
//!
//! A holder retains one [ProofSlice] per assigned span through the challenge deadline, and
//! wallets ask it for what the whole-close constructors produce from the full corpus: state
//! openings ([StateCache::opening](crate::bajillion::transition::StateCache::opening)),
//! challenge lookups ([account_lookup](crate::bajillion::challenge::account_lookup) and
//! [higher_entry_lookup](crate::bajillion::challenge::higher_entry_lookup)), claims
//! ([PreparedClose::withdrawal_claim](crate::bajillion::transition::PreparedClose::withdrawal_claim)
//! and
//! [PreparedClose::external_payout_claim](crate::bajillion::transition::PreparedClose::external_payout_claim)),
//! and a recipient's credited transpose range. [SpanIndex] derives each from the slice alone
//! by narrowing the slice's range openings ([RangeOpening::narrow]) over the values the slice
//! discloses and the guards at the span's ends, so every answer is byte for byte the opening
//! the full tree produces, and verifies it against the certified roots before returning it.
//!
//! The holder's retained predecessor [Interval] must be the span's predecessor live set,
//! which the slice's unchanged leaves merged with its live predecessor rows reproduce. The
//! index rejects any other interval, so a holder never serves state it did not validate.
//!
//! A holder also hands intervals to validators joining the committee. [slice_interval]
//! extracts one slice's exact successor live set from a sealed slice as a [SliceInterval],
//! bracketed and opened under the successor root, and [verified_interval] checks such an
//! answer on the receiving side before it becomes the joiner's retained [Interval]. When the
//! committee change also changes the slice count, [narrow_interval] cuts a verified coarser
//! slice down to one of the finer slices it covers and [merge_intervals] joins two verified
//! adjacent halves into the slice they halve.

use crate::bajillion::{
    boundary::WithdrawalBatch,
    challenge::{
        AccountLookup, ChangeAbsence, ChangeOpening, HigherEntryLookup, StateAbsence, StateLookup,
        StateOpening, StateValueOpening,
    },
    commitment::{self, Opening, RangeOpening, VectorKind, VectorRoot},
    retained::Interval,
    state::{AccountChange, ChangeGuard, SettlementOutput, StateLeaf},
    transition::{
        CloseContext, ExternalPayoutClaim, MAX_SLICE_BITS, ProofSlice, RootBundle, StateRange,
        TransitionError, WithdrawalClaim, WithdrawalOutput, account_slice, derive_state_vectors,
        transpose_groups, valid_span,
    },
    vector::{self, TransposeEntry},
};
use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use core::ops::Range;
use thiserror::Error;

/// One contiguous member interval's adjacent neighbors and shared opening.
type Bracket<T, D> = (Option<T>, Option<T>, RangeOpening<D>);

/// One of the slice's range openings with its covered values encoded once: the predecessor
/// guard when one exists, the span's members, then the successor guard when one exists.
struct Covered<'a, T: Clone, D: Digest> {
    kind: VectorKind,
    opening: &'a RangeOpening<D>,
    predecessor: Option<&'a T>,
    members: Cow<'a, [T]>,
    successor: Option<&'a T>,
    encoded: Vec<Bytes>,
}

impl<'a, T: Clone + Encode, D: Digest> Covered<'a, T, D> {
    fn new(
        kind: VectorKind,
        opening: &'a RangeOpening<D>,
        predecessor: Option<&'a T>,
        members: Cow<'a, [T]>,
        successor: Option<&'a T>,
    ) -> Self {
        let encoded = predecessor
            .into_iter()
            .chain(members.iter())
            .chain(successor)
            .map(Encode::encode)
            .collect();
        Self {
            kind,
            opening,
            predecessor,
            members,
            successor,
            encoded,
        }
    }

    /// Vector position of the member at `index`, or of the insertion point `index`.
    fn position(&self, index: usize) -> Result<u32, ServeError> {
        u32::try_from(index)
            .ok()
            .and_then(|index| {
                self.opening
                    .start
                    .checked_add(u32::from(self.predecessor.is_some()))?
                    .checked_add(index)
            })
            .ok_or(ServeError::Corrupt)
    }

    /// Opens the member at `index`.
    fn open<H: Hasher<Digest = D>>(&self, index: usize) -> Result<Opening<D>, ServeError> {
        Ok(self
            .opening
            .open::<H, _>(self.kind, &self.encoded, self.position(index)?)?)
    }

    /// Opens `count` members from `index`.
    fn narrow<H: Hasher<Digest = D>>(
        &self,
        index: usize,
        count: usize,
    ) -> Result<RangeOpening<D>, ServeError> {
        let count = u32::try_from(count).map_err(|_| ServeError::Corrupt)?;
        Ok(self
            .opening
            .narrow::<H, _>(self.kind, &self.encoded, self.position(index)?, count)?)
    }

    /// Brackets the insertion point `index` with the neighbors that exist in the vector, as
    /// the whole tree brackets an empty member interval.
    fn bracket<H: Hasher<Digest = D>>(&self, index: usize) -> Result<Bracket<T, D>, ServeError> {
        self.interval::<H>(index..index)
    }

    /// Brackets the members in `range` with the neighbors that exist in the vector and opens
    /// neighbors and members together, as the whole tree brackets a member interval. The
    /// empty range brackets the insertion point `range.start`.
    fn interval<H: Hasher<Digest = D>>(
        &self,
        range: Range<usize>,
    ) -> Result<Bracket<T, D>, ServeError> {
        let start = self.position(range.start)?;
        let end = self.position(range.end)?;
        let len = self.opening.proof.leaf_count;
        let predecessor = match range.start.checked_sub(1) {
            Some(previous) => Some(&self.members[previous]),
            None if start == 0 => None,
            None => Some(self.predecessor.ok_or(ServeError::Corrupt)?),
        };
        let successor = match self.members.get(range.end) {
            Some(member) => Some(member),
            None if end >= len => None,
            None => Some(self.successor.ok_or(ServeError::Corrupt)?),
        };
        let first = start
            .checked_sub(u32::from(predecessor.is_some()))
            .ok_or(ServeError::Corrupt)?;
        let count = end
            .checked_sub(first)
            .and_then(|count| count.checked_add(u32::from(successor.is_some())))
            .ok_or(ServeError::Corrupt)?;

        // An empty vector has nothing to narrow to: its bracket is the slice's own empty
        // opening.
        let opening = if count == 0 {
            self.opening.clone()
        } else {
            self.opening
                .narrow::<H, _>(self.kind, &self.encoded, first, count)?
        };
        Ok((predecessor.cloned(), successor.cloned(), opening))
    }
}

/// Per-account openings for one span, derived from its sealed proof slice.
///
/// Every answer equals what the whole-close constructor produces from the full corpus and is
/// verified against the certified roots before it is returned. An account outside the span
/// fails with [ServeError::NotHeld], naming the slice another holder must serve.
pub struct SpanIndex<'a, P: PublicKey, D: Digest> {
    slice: &'a ProofSlice<P, D>,
    roots: &'a RootBundle<D>,
    predecessor_root: VectorRoot<D>,
    slice_bits: u8,
    predecessor: Covered<'a, StateLeaf<P>, D>,
    successor: Covered<'a, StateLeaf<P>, D>,
    changes: Covered<'a, ChangeGuard<P, D>, D>,
    /// Compact change leaves aligned with the slice's rows.
    leaves: Vec<AccountChange<P, D>>,
    /// The slice's transpose, present exactly when it is nonempty.
    transpose: Option<Covered<'a, TransposeEntry<P>, D>>,
    /// Each row's incoming range in the slice's transpose.
    groups: Vec<(usize, usize)>,
    /// The span's withdrawal outputs, present exactly when there are any.
    withdrawals: Option<Covered<'a, WithdrawalOutput, D>>,
    /// The row index of each withdrawal output, aligned with `withdrawals`.
    output_rows: Vec<usize>,
}

impl<'a, P: PublicKey, D: Digest> SpanIndex<'a, P, D> {
    /// Indexes one sealed slice against the holder's retained predecessor interval.
    ///
    /// The slice must have passed
    /// [validate_slice](crate::bajillion::transition::validate_slice) against `roots` and
    /// `context`. `interval` must be the span's predecessor live set, the slice's unchanged
    /// leaves merged with its live predecessor rows, or construction fails with
    /// [ServeError::Interval]. A slice inconsistent with itself fails with
    /// [ServeError::Corrupt] or the underlying typed error.
    pub fn new<H: Hasher<Digest = D>>(
        slice: &'a ProofSlice<P, D>,
        interval: &'a Interval<P>,
        context: &CloseContext<P, D>,
        roots: &'a RootBundle<D>,
        withdrawals: &WithdrawalBatch<P, D>,
    ) -> Result<Self, ServeError> {
        let assignment = context.assignment();
        if !valid_span(&slice.span, assignment.slice_count()) {
            return Err(ServeError::Corrupt);
        }
        let rows = &slice.changes.rows;
        if rows.len() != slice.out_vectors.len() {
            return Err(ServeError::Corrupt);
        }

        // The span's predecessor live set is the unchanged leaves merged with the live
        // predecessor rows. The holder's interval must be exactly that set.
        let (predecessor, successor) =
            derive_state_vectors(&slice.unchanged, rows, context.limits().max_states())?;
        if predecessor.as_slice() != interval.leaves() {
            return Err(ServeError::Interval);
        }

        // Compact change leaves and their guards, as the change root commits them.
        let mut leaves = Vec::with_capacity(rows.len());
        for (row, out_vector) in rows.iter().zip(&slice.out_vectors) {
            if out_vector.payer() != &row.account {
                return Err(ServeError::Corrupt);
            }
            leaves.push(AccountChange::from_row::<H>(
                row,
                out_vector.root::<H, D>()?,
            ));
        }
        let guards = leaves
            .iter()
            .map(AccountChange::guard::<H>)
            .collect::<Vec<_>>();

        let groups = transpose_groups(rows, &slice.transpose)?;
        let transpose = match (&slice.transpose_opening, slice.transpose.is_empty()) {
            (None, true) => None,
            (Some(opening), false) => Some(Covered::new(
                VectorKind::Transpose,
                opening,
                None,
                Cow::Borrowed(slice.transpose.as_slice()),
                None,
            )),
            _ => return Err(ServeError::Corrupt),
        };

        // Withdrawal outputs derive from the rows carrying a request, in row order, exactly
        // as validation derives them.
        let mut outputs = Vec::new();
        let mut output_rows = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            if let Some(request) = withdrawals.request_for(&row.account) {
                let SettlementOutput::Withdrawal(amount) = row.output else {
                    return Err(ServeError::Corrupt);
                };
                outputs.push(WithdrawalOutput::from_request(request, amount));
                output_rows.push(index);
            }
        }
        let withdrawals = match (&slice.withdrawal_opening, outputs.is_empty()) {
            (None, true) => None,
            (Some(opening), false) => Some(Covered::new(
                VectorKind::WithdrawalOutput,
                opening,
                None,
                Cow::Owned(outputs),
                None,
            )),
            _ => return Err(ServeError::Corrupt),
        };

        Ok(Self {
            slice,
            roots,
            predecessor_root: *context.predecessor_root(),
            slice_bits: assignment.slice_bits(),
            predecessor: Covered::new(
                VectorKind::State,
                &slice.predecessor.opening,
                slice.predecessor.predecessor.as_ref(),
                Cow::Borrowed(interval.leaves()),
                slice.predecessor.successor.as_ref(),
            ),
            successor: Covered::new(
                VectorKind::State,
                &slice.successor.opening,
                slice.successor.predecessor.as_ref(),
                Cow::Owned(successor),
                slice.successor.successor.as_ref(),
            ),
            changes: Covered::new(
                VectorKind::Change,
                &slice.changes.opening,
                slice.changes.predecessor.as_ref(),
                Cow::Owned(guards),
                slice.changes.successor.as_ref(),
            ),
            leaves,
            transpose,
            groups,
            withdrawals,
            output_rows,
        })
    }

    /// Returns the span this index serves.
    pub const fn span(&self) -> &Range<u16> {
        &self.slice.span
    }

    /// Fails with [ServeError::NotHeld] for an account outside the span.
    fn held(&self, account: &P) -> Result<(), ServeError> {
        let slice = account_slice(account, self.slice_bits)?;
        if self.slice.span.contains(&slice) {
            Ok(())
        } else {
            Err(ServeError::NotHeld { slice })
        }
    }

    /// Locates the account's row in the slice, or its insertion point among the rows.
    fn row(&self, account: &P) -> Result<usize, usize> {
        self.slice
            .changes
            .rows
            .binary_search_by(|row| row.account.cmp(account))
    }

    /// Opens the account's leaf under the predecessor state root.
    ///
    /// Fails with [ServeError::Absent] when the account is not live in the predecessor state.
    pub fn predecessor_opening<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<StateOpening<P, D>, ServeError> {
        self.held(account)?;
        state_opening::<H, P, D>(&self.predecessor, &self.predecessor_root, account)
    }

    /// Opens the account's leaf under the successor state root.
    ///
    /// Fails with [ServeError::Absent] when the account is not live in the successor state.
    pub fn successor_opening<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<StateOpening<P, D>, ServeError> {
        self.held(account)?;
        state_opening::<H, P, D>(&self.successor, &self.roots.successor, account)
    }

    /// Builds the payer lookup for a higher-debit challenge: the account's compact change
    /// opening, or its authenticated absence from the change vector with its predecessor
    /// state membership or absence.
    pub fn account_lookup<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<AccountLookup<P, D>, ServeError> {
        self.held(account)?;
        let lookup = match self.row(account) {
            Ok(index) => AccountLookup::Present(Box::new(ChangeOpening {
                value: self.leaves[index].value(),
                proof: self.changes.open::<H>(index)?,
            })),
            Err(insertion) => AccountLookup::Absent {
                state: Box::new(state_lookup::<H, P, D>(&self.predecessor, account)?),
                change: self.change_absence::<H>(insertion)?,
            },
        };
        lookup
            .resolve::<H>(&self.predecessor_root, &self.roots.change, account)
            .map_err(|_| ServeError::Corrupt)?;
        Ok(lookup)
    }

    /// Opens the account's compact change value under the change root.
    ///
    /// Fails with [ServeError::Unchanged] when the account has no changed row.
    pub fn change_opening<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<ChangeOpening<D>, ServeError> {
        self.held(account)?;
        let index = self.row(account).map_err(|_| ServeError::Unchanged)?;
        let opening = ChangeOpening {
            value: self.leaves[index].value(),
            proof: self.changes.open::<H>(index)?,
        };
        opening
            .proof
            .verify::<H>(
                VectorKind::Change,
                &self.roots.change,
                self.changes.members[index].encode().as_ref(),
            )
            .map_err(|_| ServeError::Corrupt)?;
        Ok(opening)
    }

    /// Builds the composed sender lookup for a higher-entry challenge against `payer`'s
    /// public terminal entry for `recipient`.
    pub fn higher_entry_lookup<H: Hasher<Digest = D>>(
        &self,
        payer: &P,
        recipient: &P,
    ) -> Result<HigherEntryLookup<P, D>, ServeError> {
        self.held(payer)?;
        let lookup = match self.row(payer) {
            Ok(index) => HigherEntryLookup::Present {
                value: self.leaves[index].value().core(),
                proof: self.changes.open::<H>(index)?,
                entry: self.slice.out_vectors[index].lookup::<H, D>(recipient)?,
            },
            Err(insertion) => HigherEntryLookup::Absent(self.change_absence::<H>(insertion)?),
        };
        lookup
            .resolve::<H>(&self.roots.change, payer, recipient)
            .map_err(|_| ServeError::Corrupt)?;
        Ok(lookup)
    }

    /// Opens the account's validator-derived withdrawal output for later claiming.
    ///
    /// Fails with [ServeError::NoWithdrawal] when the close carries no withdrawal request for
    /// the account.
    pub fn withdrawal_claim<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<WithdrawalClaim<D>, ServeError> {
        self.held(account)?;
        let withdrawals = self.withdrawals.as_ref().ok_or(ServeError::NoWithdrawal)?;
        let row = self.row(account).map_err(|_| ServeError::NoWithdrawal)?;
        let index = self
            .output_rows
            .binary_search(&row)
            .map_err(|_| ServeError::NoWithdrawal)?;
        let claim = WithdrawalClaim::new(
            withdrawals.members[index].clone(),
            withdrawals.open::<H>(index)?,
        );
        claim
            .verify::<H>(&self.roots.withdrawal_outputs)
            .map_err(|_| ServeError::Corrupt)?;
        Ok(claim)
    }

    /// Opens the recipient's external payout for later claiming.
    ///
    /// Fails with [ServeError::NoPayout] when the recipient's row carries no positive payout.
    pub fn external_payout_claim<H: Hasher<Digest = D>>(
        &self,
        recipient: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, ServeError> {
        self.held(recipient)?;
        let index = self.row(recipient).map_err(|_| ServeError::NoPayout)?;
        let leaf = &self.leaves[index];
        if !matches!(leaf.output(), SettlementOutput::ExternalPayout(amount) if amount != 0) {
            return Err(ServeError::NoPayout);
        }
        let claim = ExternalPayoutClaim::new(leaf.clone(), self.changes.open::<H>(index)?);
        claim
            .verify::<H>(&self.roots.change)
            .map_err(|_| ServeError::Corrupt)?;
        Ok(claim)
    }

    /// Returns the recipient's contiguous credited transpose entries with their opening under
    /// the transpose root.
    ///
    /// Fails with [ServeError::NoCredit] when nothing credits the recipient in this close.
    pub fn credits<H: Hasher<Digest = D>>(
        &self,
        recipient: &P,
    ) -> Result<(&[TransposeEntry<P>], RangeOpening<D>), ServeError> {
        self.held(recipient)?;
        let row = self.row(recipient).map_err(|_| ServeError::NoCredit)?;
        let (start, end) = self.groups[row];
        let transpose = self
            .transpose
            .as_ref()
            .filter(|_| start < end)
            .ok_or(ServeError::NoCredit)?;
        let opening = transpose.narrow::<H>(start, end - start)?;

        // Verification below already binds the leaf count into the root. This is only a
        // cheaper typed rejection of a slice whose transpose length disagrees with the header.
        if opening.proof.leaf_count != self.roots.transpose_len {
            return Err(ServeError::Corrupt);
        }
        opening
            .verify::<H, _>(
                VectorKind::Transpose,
                &self.roots.transpose,
                &transpose.encoded[start..end],
            )
            .map_err(|_| ServeError::Corrupt)?;
        Ok((&self.slice.transpose[start..end], opening))
    }

    /// Authenticates the account's absence from the change vector at `insertion`.
    fn change_absence<H: Hasher<Digest = D>>(
        &self,
        insertion: usize,
    ) -> Result<ChangeAbsence<P, D>, ServeError> {
        let (predecessor, successor, opening) = self.changes.bracket::<H>(insertion)?;
        Ok(ChangeAbsence {
            predecessor,
            successor,
            opening,
        })
    }
}

/// Opens one live leaf and verifies it under `root`.
fn state_opening<H, P, D>(
    state: &Covered<'_, StateLeaf<P>, D>,
    root: &VectorRoot<D>,
    account: &P,
) -> Result<StateOpening<P, D>, ServeError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let index = state
        .members
        .binary_search_by(|leaf| leaf.account.cmp(account))
        .map_err(|_| ServeError::Absent)?;
    let leaf = state.members[index].clone();
    let proof = state.open::<H>(index)?;
    proof
        .verify::<H>(VectorKind::State, root, leaf.encode().as_ref())
        .map_err(|_| ServeError::Corrupt)?;
    Ok(StateOpening { leaf, proof })
}

/// Opens membership or ordered nonmembership for one account.
fn state_lookup<H, P, D>(
    state: &Covered<'_, StateLeaf<P>, D>,
    account: &P,
) -> Result<StateLookup<P, D>, ServeError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    match state
        .members
        .binary_search_by(|leaf| leaf.account.cmp(account))
    {
        Ok(index) => Ok(StateLookup::Present(Box::new(StateValueOpening {
            state: state.members[index].state,
            proof: state.open::<H>(index)?,
        }))),
        Err(insertion) => {
            let (predecessor, successor, opening) = state.bracket::<H>(insertion)?;
            Ok(StateLookup::Absent(StateAbsence {
                predecessor,
                successor,
                opening,
            }))
        }
    }
}

/// One slice's live leaves under a certified state root with the neighbors and opening that
/// prove the set exact.
///
/// A holder extracts it from a sealed slice with [slice_interval] and hands it to a validator
/// joining the committee, whose [verified_interval] turns it into a retained [Interval] once
/// it verifies under the certified root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceInterval<P: PublicKey, D: Digest> {
    /// The slice's live leaves, key-sorted.
    pub members: Vec<StateLeaf<P>>,
    /// The nearest live leaves outside the slice, when they exist, and the opening covering
    /// them together with the members.
    pub range: StateRange<P, D>,
}

/// Extracts slice `index`'s exact successor live set from a sealed proof slice covering it.
///
/// The members are the span's successor leaves in the slice, in order. The neighbors are the
/// leaf just before and just after them: a member of a neighboring slice inside the span, the
/// span's own successor-side guard at the span's ends, or nothing at the vector's ends. The
/// opening is the span's successor opening narrowed with [RangeOpening::narrow] to exactly
/// the neighbors and members, byte for byte what the whole tree opens for that bracket, and
/// verifies under the successor root. An empty slice brackets its insertion point the way the
/// validator brackets an empty member interval.
///
/// Fails with [ServeError::NotHeld] for a slice outside the span and with
/// [ServeError::Corrupt] when the slice cannot bracket the interval.
pub fn slice_interval<H, P, D>(
    slice: &ProofSlice<P, D>,
    index: u16,
    slice_bits: u8,
) -> Result<SliceInterval<P, D>, ServeError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if !slice.span.contains(&index) {
        return Err(ServeError::NotHeld { slice: index });
    }
    let (_, members) = derive_state_vectors(
        &slice.unchanged,
        &slice.changes.rows,
        u64::from(commitment::MAX_VECTOR_LENGTH),
    )?;
    let slices = members
        .iter()
        .map(|leaf| account_slice(&leaf.account, slice_bits))
        .collect::<Result<Vec<_>, _>>()?;
    let start = slices.partition_point(|slice| *slice < index);
    let end = slices.partition_point(|slice| *slice <= index);
    let covered = Covered::new(
        VectorKind::State,
        &slice.successor.opening,
        slice.successor.predecessor.as_ref(),
        Cow::Owned(members),
        slice.successor.successor.as_ref(),
    );
    let (predecessor, successor, opening) = covered.interval::<H>(start..end)?;
    Ok(SliceInterval {
        members: covered.members[start..end].to_vec(),
        range: StateRange {
            predecessor,
            successor,
            opening,
        },
    })
}

/// Verifies a served slice interval under the certified `root` and returns its members as
/// the receiver's retained [Interval].
///
/// The check is the validator's state-range rule for the single-slice span `index`: a
/// neighbor is present exactly when leaves exist beyond the members on that side, every leaf
/// is live and strictly key-ordered, every member belongs to slice `index` while the
/// predecessor comes from a lower slice and the successor from a higher one, and the opening
/// reproduces `root` over neighbors and members. Together these prove the members are exactly
/// the slice's live leaves at `root`: none missing, none foreign.
///
/// Fails with [ServeError::Range] when the shape, order, liveness, or slices are wrong and
/// with [ServeError::Commitment] when the opening does not reproduce `root`. Peer input never
/// panics.
pub fn verified_interval<H, P, D>(
    interval: &SliceInterval<P, D>,
    root: &VectorRoot<D>,
    index: u16,
    slice_bits: u8,
) -> Result<Interval<P>, ServeError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if slice_bits > MAX_SLICE_BITS {
        return Err(TransitionError::SliceBits.into());
    }
    if index >= 1_u16 << slice_bits {
        return Err(TransitionError::SliceIndex.into());
    }
    let range = &interval.range;
    let count = u32::try_from(interval.members.len()).map_err(|_| ServeError::Range)?;
    if range
        .opening
        .bracket(
            range.predecessor.is_some(),
            count,
            range.successor.is_some(),
        )
        .is_none()
    {
        return Err(ServeError::Range);
    }
    let leaves = range
        .predecessor
        .iter()
        .chain(&interval.members)
        .chain(range.successor.iter())
        .collect::<Vec<_>>();
    if leaves
        .iter()
        .any(|leaf| !leaf.state.active || leaf.state.balance == 0)
        || leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(ServeError::Range);
    }
    for member in &interval.members {
        if account_slice(&member.account, slice_bits)? != index {
            return Err(ServeError::Range);
        }
    }
    if let Some(predecessor) = &range.predecessor
        && account_slice(&predecessor.account, slice_bits)? >= index
    {
        return Err(ServeError::Range);
    }
    if let Some(successor) = &range.successor
        && account_slice(&successor.account, slice_bits)? <= index
    {
        return Err(ServeError::Range);
    }
    let encoded = leaves.into_iter().map(Encode::encode).collect::<Vec<_>>();
    range
        .opening
        .verify::<H, _>(VectorKind::State, root, &encoded)?;
    Ok(Interval::new(interval.members.clone())?)
}

/// Narrows the live set of a coarser slice to slice `slice` under `slice_bits`, one of the
/// finer slices it covers.
///
/// A slice is the accounts whose keys start with `slice_bits` bits, so a slice under fewer
/// bits is the union of the finer slices sharing its prefix, and a finer slice's exact live
/// set is the members carrying its prefix. `interval` must be the exact live set of a coarser
/// slice containing `slice`, from the caller's own validation or from [verified_interval].
/// Any other interval yields a subset that is not the slice's live set.
///
/// Fails with [TransitionError::SliceBits] or [TransitionError::SliceIndex] for a slice
/// outside the partition.
pub fn narrow_interval<P: PublicKey>(
    interval: &Interval<P>,
    slice: u16,
    slice_bits: u8,
) -> Result<Interval<P>, ServeError> {
    if slice_bits > MAX_SLICE_BITS {
        return Err(TransitionError::SliceBits.into());
    }
    if slice >= 1_u16 << slice_bits {
        return Err(TransitionError::SliceIndex.into());
    }
    let mut members = Vec::new();
    for leaf in interval.leaves() {
        if account_slice(&leaf.account, slice_bits)? == slice {
            members.push(leaf.clone());
        }
    }
    Ok(Interval::new(members)?)
}

/// Joins the live sets of two adjacent slices under `slice_bits + 1` into the live set of
/// slice `slice` under `slice_bits`, the slice they halve.
///
/// `first` must be slice `2 * slice` and `second` slice `2 * slice + 1`, each already checked
/// with [verified_interval] for that index under the same root. Their seam is checked before
/// joining: every member carries its half's prefix, the leaf after `first` (its successor
/// guard) is the first leaf of `second` (its first member, or its successor guard when it is
/// empty), and the leaf before `second` (its predecessor guard) is the last leaf of `first`
/// (its last member, or its predecessor guard when it is empty). Two halves verified under
/// one root always meet, so a mismatch means a half was not verified as claimed or the pair
/// is not adjacent. The seam check alone proves nothing: an unverified empty half fits any
/// seam.
///
/// Fails with [ServeError::Range] on a prefix or seam mismatch and with
/// [TransitionError::SliceBits] or [TransitionError::SliceIndex] for a slice outside the
/// partition.
pub fn merge_intervals<P: PublicKey, D: Digest>(
    first: &SliceInterval<P, D>,
    second: &SliceInterval<P, D>,
    slice: u16,
    slice_bits: u8,
) -> Result<Interval<P>, ServeError> {
    let halves = slice_bits
        .checked_add(1)
        .filter(|bits| *bits <= MAX_SLICE_BITS)
        .ok_or(TransitionError::SliceBits)?;
    if slice >= 1_u16 << slice_bits {
        return Err(TransitionError::SliceIndex.into());
    }
    let lower = slice << 1;
    for (half, index) in [(first, lower), (second, lower + 1)] {
        for member in &half.members {
            if account_slice(&member.account, halves)? != index {
                return Err(ServeError::Range);
            }
        }
    }
    let after_first = first.range.successor.as_ref();
    let second_start = second.members.first().or(second.range.successor.as_ref());
    let before_second = second.range.predecessor.as_ref();
    let first_end = first.members.last().or(first.range.predecessor.as_ref());
    if after_first != second_start || before_second != first_end {
        return Err(ServeError::Range);
    }
    let members = first
        .members
        .iter()
        .chain(&second.members)
        .cloned()
        .collect();
    Ok(Interval::new(members)?)
}

/// A request one span index cannot answer.
#[derive(Debug, Error)]
pub enum ServeError {
    /// The account belongs to a slice outside the served span.
    #[error("account belongs to slice {slice}, outside the served span")]
    NotHeld {
        /// The slice whose holders serve the account.
        slice: u16,
    },
    /// The retained interval is not the span's predecessor live set.
    #[error("retained interval is not the span's predecessor live set")]
    Interval,
    /// A served state range is not one slice's exact live set: a neighbor is missing or
    /// misplaced, a leaf is out of order or not live, a leaf is from the wrong slice, or two
    /// halves do not meet at their seam.
    #[error("state range is not the slice's exact live set")]
    Range,
    /// The slice is inconsistent with itself or does not reproduce the certified roots.
    #[error("slice does not reproduce the certified roots")]
    Corrupt,
    /// The account is not live in the requested state.
    #[error("account is absent from the requested live state")]
    Absent,
    /// The account has no changed row.
    #[error("account has no changed row")]
    Unchanged,
    /// The account has no withdrawal in this close.
    #[error("account has no withdrawal in this close")]
    NoWithdrawal,
    /// The account has no positive external payout in this close.
    #[error("account has no external payout in this close")]
    NoPayout,
    /// Nothing credits the recipient in this close.
    #[error("recipient has no credit in this close")]
    NoCredit,
    /// The slice's rows, leaves, or transpose are not canonical.
    #[error("invalid slice material: {0}")]
    Transition(#[from] TransitionError),
    /// A slice opening could not be narrowed.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
    /// An outgoing vector is invalid.
    #[error("invalid edge vector: {0}")]
    Vector(#[from] vector::Error),
}
