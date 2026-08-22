//! Proof slices for authenticating deterministic account intervals from one public close corpus.

use super::{
    Assignment, Close, CloseContext, CloseLimits, Header, PreparedClose, RootBundle, StateCache,
    TransitionError, account_slice, change_tree_with_strategy, derive_state_vectors, is_live_state,
    read_shard_sets, state_tree_with_strategy, validate_boundary_roots, validate_header,
    validate_row, validate_row_structure, validate_terminal_prefix,
};
use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    commitment::{self, RangeOpening, VectorKind},
    credit::ShardSet,
    state::{AccountRow, Prefix, StateLeaf},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use core::ops::Range;

/// Header-committed positions and cumulative prefix before one deterministic slice.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SliceBoundary {
    /// Position in the opening live-state vector.
    pub opening: u32,
    /// Position in the changed-row vector.
    pub change: u32,
    /// Position in the closing live-state vector.
    pub closing: u32,
    /// Exact cumulative row prefix before `change`.
    pub prefix: Prefix,
}

impl Write for SliceBoundary {
    fn write(&self, writer: &mut impl BufMut) {
        self.opening.write(writer);
        self.change.write(writer);
        self.closing.write(writer);
        self.prefix.write(writer);
    }
}

impl FixedSize for SliceBoundary {
    const SIZE: usize = u32::SIZE * 3 + Prefix::SIZE;
}

impl Read for SliceBoundary {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            opening: u32::read(reader)?,
            change: u32::read(reader)?,
            closing: u32::read(reader)?,
            prefix: Prefix::read(reader)?,
        })
    }
}

/// Two adjacent authenticated layout boundaries defining one slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayoutRange<D: Digest> {
    /// Boundary before this slice.
    pub start: SliceBoundary,
    /// Boundary after this slice.
    pub end: SliceBoundary,
    /// Authentication of the two adjacent boundary values.
    pub opening: RangeOpening<D>,
}

impl<D: Digest> Write for LayoutRange<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.start.write(writer);
        self.end.write(writer);
        self.opening.write(writer);
    }
}

impl<D: Digest> EncodeSize for LayoutRange<D> {
    fn encode_size(&self) -> usize {
        SliceBoundary::SIZE * 2 + self.opening.encode_size()
    }
}

impl<D: Digest> Read for LayoutRange<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Self::read_bounded(reader, usize::MAX)
    }
}

impl<D: Digest> LayoutRange<D> {
    fn read_bounded(reader: &mut impl Buf, max_hashes: usize) -> Result<Self, CodecError> {
        Ok(Self {
            start: SliceBoundary::read(reader)?,
            end: SliceBoundary::read(reader)?,
            opening: RangeOpening::read_bounded(reader, 2, max_hashes)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for LayoutRange<D>
where
    D: Digest,
    RangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            start: u.arbitrary()?,
            end: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
    }
}

/// Exact contiguous changed-row slice for one account-key interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeRange<P: PublicKey, D: Digest> {
    /// Immediate row before this interval, when one exists.
    pub predecessor: Option<AccountRow<P, D>>,
    /// Every changed row whose account belongs to this interval.
    pub rows: Vec<AccountRow<P, D>>,
    /// Immediate row after this interval, when one exists.
    pub successor: Option<AccountRow<P, D>>,
    /// Authentication of the contiguous guard-and-row slice.
    pub opening: RangeOpening<D>,
}

impl<P: PublicKey, D: Digest> Write for ChangeRange<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.predecessor.write(writer);
        self.rows.write(writer);
        self.successor.write(writer);
        self.opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ChangeRange<P, D> {
    fn encode_size(&self) -> usize {
        self.predecessor.encode_size()
            + self.rows.encode_size()
            + self.successor.encode_size()
            + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for ChangeRange<P, D> {
    /// Maximum number of member rows.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, maximum: &Self::Cfg) -> Result<Self, CodecError> {
        Self::read_bounded(reader, *maximum, usize::MAX)
    }
}

impl<P: PublicKey, D: Digest> ChangeRange<P, D> {
    fn read_bounded(
        reader: &mut impl Buf,
        maximum: usize,
        max_hashes: usize,
    ) -> Result<Self, CodecError> {
        let predecessor = Option::<AccountRow<P, D>>::read(reader)?;
        let rows = Vec::<AccountRow<P, D>>::read_cfg(reader, &(RangeCfg::new(..=maximum), ()))?;
        let successor = Option::<AccountRow<P, D>>::read(reader)?;
        let values = rows
            .len()
            .saturating_add(usize::from(predecessor.is_some()))
            .saturating_add(usize::from(successor.is_some()));
        let opening = RangeOpening::read_bounded(reader, values, max_hashes)?;
        Ok(Self {
            predecessor,
            rows,
            successor,
            opening,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ChangeRange<P, D>
where
    P: PublicKey,
    D: Digest,
    AccountRow<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    RangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            predecessor: u.arbitrary()?,
            rows: u.arbitrary()?,
            successor: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
    }
}

/// Authentication of one exact live-state interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRange<P: PublicKey, D: Digest> {
    /// Immediate live-state predecessor, when one exists.
    pub predecessor: Option<StateLeaf<P>>,
    /// Immediate live-state successor, when one exists.
    pub successor: Option<StateLeaf<P>>,
    /// Authentication of the contiguous guard-and-member slice.
    pub opening: RangeOpening<D>,
}

impl<P: PublicKey, D: Digest> Write for StateRange<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.predecessor.write(writer);
        self.successor.write(writer);
        self.opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for StateRange<P, D> {
    fn encode_size(&self) -> usize {
        self.predecessor.encode_size() + self.successor.encode_size() + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for StateRange<P, D> {
    /// Exact number of projected member leaves.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, members: &Self::Cfg) -> Result<Self, CodecError> {
        Self::read_bounded(reader, *members, usize::MAX)
    }
}

impl<P: PublicKey, D: Digest> StateRange<P, D> {
    fn read_bounded(
        reader: &mut impl Buf,
        members: usize,
        max_hashes: usize,
    ) -> Result<Self, CodecError> {
        let predecessor = Option::<StateLeaf<P>>::read(reader)?;
        let successor = Option::<StateLeaf<P>>::read(reader)?;
        let values = members
            .checked_add(usize::from(predecessor.is_some()))
            .and_then(|values| values.checked_add(usize::from(successor.is_some())))
            .ok_or(CodecError::Invalid(
                "StateRange",
                "range value count overflows",
            ))?;
        Ok(Self {
            predecessor,
            successor,
            opening: RangeOpening::read_bounded(reader, values, max_hashes)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for StateRange<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    RangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            predecessor: u.arbitrary()?,
            successor: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
    }
}

/// One proof slice for independently authenticating an account interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSlice<P: PublicKey, D: Digest> {
    /// Deterministic interval index.
    pub index: u16,
    /// Header-bound positions and prefix for this interval.
    pub layout: LayoutRange<D>,
    /// Exact changed rows in this interval.
    pub changes: ChangeRange<P, D>,
    /// Terminal shard sets aligned one-for-one with [`ChangeRange::rows`].
    pub shard_sets: Vec<ShardSet<P, D>>,
    /// Live leaves unchanged across both roots in this interval.
    pub unchanged: Vec<StateLeaf<P>>,
    /// Exact guarded opening-state interval.
    pub opening: StateRange<P, D>,
    /// Exact guarded closing-state interval.
    pub closing: StateRange<P, D>,
}

impl<P: PublicKey, D: Digest> Write for ProofSlice<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.index.write(writer);
        self.layout.write(writer);
        self.changes.write(writer);
        self.shard_sets.write(writer);
        self.unchanged.write(writer);
        self.opening.write(writer);
        self.closing.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ProofSlice<P, D> {
    fn encode_size(&self) -> usize {
        self.index.encode_size()
            + self.layout.encode_size()
            + self.changes.encode_size()
            + self.shard_sets.encode_size()
            + self.unchanged.encode_size()
            + self.opening.encode_size()
            + self.closing.encode_size()
    }
}

/// Adversarial decode limits for one proof slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SliceCodecConfig {
    /// Anchor-bound close limits.
    pub close: CloseLimits,
    /// Maximum proof hashes accepted within the outer byte bound.
    pub max_proof_hashes: usize,
}

impl SliceCodecConfig {
    /// Creates slice decode limits.
    pub const fn new(close: CloseLimits, max_proof_hashes: usize) -> Self {
        Self {
            close,
            max_proof_hashes,
        }
    }
}

impl<P: PublicKey, D: Digest> Read for ProofSlice<P, D> {
    /// Anchor-bound close limits and the maximum hashes accepted by each proof frontier.
    type Cfg = SliceCodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let row_limit = config
            .close
            .max_rows()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let row_limit = usize::try_from(row_limit)
            .map_err(|_| CodecError::Invalid("ProofSlice", "row limit is not representable"))?;
        let index = u16::read(reader)?;
        let layout = LayoutRange::read_bounded(reader, config.max_proof_hashes)?;
        let changes = ChangeRange::read_bounded(reader, row_limit, config.max_proof_hashes)?;
        let shard_sets = read_shard_sets(reader, changes.rows.len(), &config.close)?;
        let state_limit = config
            .close
            .max_states()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let state_limit = usize::try_from(state_limit)
            .map_err(|_| CodecError::Invalid("ProofSlice", "state limit is not representable"))?;
        let unchanged =
            Vec::<StateLeaf<P>>::read_cfg(reader, &(RangeCfg::new(..=state_limit), ()))?;
        let opening_members = unchanged
            .len()
            .checked_add(changes.rows.iter().filter(|row| row.opening.active).count())
            .ok_or(CodecError::Invalid(
                "ProofSlice",
                "opening member count overflows",
            ))?;
        let closing_members = unchanged
            .len()
            .checked_add(changes.rows.iter().filter(|row| row.closing.active).count())
            .ok_or(CodecError::Invalid(
                "ProofSlice",
                "closing member count overflows",
            ))?;
        let opening = StateRange::read_bounded(reader, opening_members, config.max_proof_hashes)?;
        let closing = StateRange::read_bounded(reader, closing_members, config.max_proof_hashes)?;
        Ok(Self {
            index,
            layout,
            changes,
            shard_sets,
            unchanged,
            opening,
            closing,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ProofSlice<P, D>
where
    P: PublicKey,
    D: Digest,
    LayoutRange<D>: for<'a> arbitrary::Arbitrary<'a>,
    ChangeRange<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    ShardSet<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    StateLeaf<P>: for<'a> arbitrary::Arbitrary<'a>,
    StateRange<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            index: u.arbitrary()?,
            layout: u.arbitrary()?,
            changes: u.arbitrary()?,
            shard_sets: u.arbitrary()?,
            unchanged: u.arbitrary()?,
            opening: u.arbitrary()?,
            closing: u.arbitrary()?,
        })
    }
}

/// Decodes one slice only after enforcing a caller-selected byte limit.
pub fn decode_slice_bounded<P: PublicKey, D: Digest>(
    encoded: &[u8],
    limits: CloseLimits,
    max_bytes: usize,
) -> Result<ProofSlice<P, D>, CodecError> {
    if encoded.len() > max_bytes {
        return Err(CodecError::Invalid(
            "ProofSlice",
            "encoded slice exceeds configured byte limit",
        ));
    }
    let max_hashes = max_proof_hashes(D::SIZE, max_bytes)?;
    ProofSlice::decode_cfg(encoded, &SliceCodecConfig::new(limits, max_hashes))
}

const fn max_proof_hashes(digest_size: usize, max_bytes: usize) -> Result<usize, CodecError> {
    if digest_size == 0 {
        return Err(CodecError::Invalid(
            "ProofSlice",
            "digest encoded size is zero",
        ));
    }
    Ok(max_bytes / digest_size)
}

/// Authenticates the two header-bound boundaries assigned to one slice.
fn validate_layout_range<H, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &commitment::VectorRoot<D>,
    range: &LayoutRange<D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let expected_len = u32::from(assignment.slice_count()) + 1;
    if range.opening.start != u32::from(index)
        || range.opening.proof.leaf_count != expected_len
        || range.start.opening > range.end.opening
        || range.start.change > range.end.change
        || range.start.closing > range.end.closing
        || (index == 0 && range.start != SliceBoundary::default())
    {
        return Err(TransitionError::SliceLayout);
    }
    range.opening.verify::<H, _>(
        VectorKind::Layout,
        root,
        &[range.start.encode(), range.end.encode()],
    )?;
    Ok(())
}

/// Authenticates the exact changed-row interval and its deterministic slice membership.
fn validate_change_range<H, P, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &commitment::VectorRoot<D>,
    range: &ChangeRange<P, D>,
    start: u32,
    end: u32,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = range.opening.proof.leaf_count;
    let actual_start = range
        .opening
        .start
        .checked_add(u32::from(range.predecessor.is_some()))
        .ok_or(TransitionError::SliceRange)?;
    let members = u32::try_from(range.rows.len()).map_err(|_| TransitionError::SliceRange)?;
    let actual_end = actual_start
        .checked_add(members)
        .filter(|end| *end <= len)
        .ok_or(TransitionError::SliceRange)?;
    if actual_start != start
        || actual_end != end
        || range.predecessor.is_some() != (start > 0)
        || range.successor.is_some() != (end < len)
        || range
            .predecessor
            .iter()
            .chain(&range.rows)
            .chain(range.successor.iter())
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::SliceRange);
    }
    for row in &range.rows {
        if account_slice(&row.account, assignment.slice_bits())? != index {
            return Err(TransitionError::SliceRange);
        }
    }
    if let Some(predecessor) = &range.predecessor
        && account_slice(&predecessor.account, assignment.slice_bits())? >= index
    {
        return Err(TransitionError::SliceRange);
    }
    if let Some(successor) = &range.successor
        && account_slice(&successor.account, assignment.slice_bits())? <= index
    {
        return Err(TransitionError::SliceRange);
    }
    let encoded = range
        .predecessor
        .iter()
        .chain(&range.rows)
        .chain(range.successor.iter())
        .map(Encode::encode)
        .collect::<Vec<_>>();
    range
        .opening
        .verify::<H, _>(VectorKind::Change, root, &encoded)?;
    Ok(())
}

/// Authenticates one exact live-state interval.
fn validate_state_range<H, P, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &commitment::VectorRoot<D>,
    range: &StateRange<P, D>,
    members: &[StateLeaf<P>],
    max_states: u64,
    positions: Range<u32>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = range.opening.proof.leaf_count;
    if u64::from(len) > max_states || len > commitment::MAX_VECTOR_LENGTH {
        return Err(TransitionError::SliceStateRange);
    }
    let actual_start = range
        .opening
        .start
        .checked_add(u32::from(range.predecessor.is_some()))
        .ok_or(TransitionError::SliceStateRange)?;
    let count = u32::try_from(members.len()).map_err(|_| TransitionError::SliceStateRange)?;
    let actual_end = actual_start
        .checked_add(count)
        .filter(|end| *end <= len)
        .ok_or(TransitionError::SliceStateRange)?;
    if actual_start != positions.start
        || actual_end != positions.end
        || range.predecessor.is_some() != (positions.start > 0)
        || range.successor.is_some() != (positions.end < len)
    {
        return Err(TransitionError::SliceStateRange);
    }

    let leaves = range
        .predecessor
        .iter()
        .chain(members)
        .chain(range.successor.iter())
        .collect::<Vec<_>>();
    if leaves.iter().any(|leaf| !is_live_state(&leaf.state))
        || leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::SliceStateRange);
    }
    for leaf in members {
        if account_slice(&leaf.account, assignment.slice_bits())? != index {
            return Err(TransitionError::SliceStateRange);
        }
    }
    if let Some(predecessor) = &range.predecessor
        && account_slice(&predecessor.account, assignment.slice_bits())? >= index
    {
        return Err(TransitionError::SliceStateRange);
    }
    if let Some(successor) = &range.successor
        && account_slice(&successor.account, assignment.slice_bits())? <= index
    {
        return Err(TransitionError::SliceStateRange);
    }
    let encoded = leaves.into_iter().map(Encode::encode).collect::<Vec<_>>();
    range
        .opening
        .verify::<H, _>(VectorKind::State, root, &encoded)?;
    Ok(())
}

/// Establishes the shared header and boundary precondition for one or more slices.
pub(crate) fn validate_slice_header<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_header::<H, P, D>(context, header, roots)?;
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
    withdrawals.verify_deployment(context.deployment())?;
    Ok(())
}

/// Authenticates one slice after the shared header and boundary precondition is established.
fn validate_slice_after_header<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    roots: &RootBundle<D>,
    slice: &ProofSlice<P, D>,
    verify_signatures: bool,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    // The three authenticated intervals describe one deterministic account slice. State ranges
    // are independent because creation and destruction can shift every following position.
    let assignment = context.assignment();
    if slice.index >= assignment.slice_count() {
        return Err(TransitionError::SliceIndex);
    }
    validate_layout_range::<H, D>(assignment, slice.index, &roots.layout, &slice.layout)?;
    validate_change_range::<H, P, D>(
        assignment,
        slice.index,
        &roots.change,
        &slice.changes,
        slice.layout.start.change,
        slice.layout.end.change,
    )?;
    if slice.shard_sets.len() != slice.changes.rows.len() {
        return Err(TransitionError::ShardAlignment);
    }

    let (opening, closing) = derive_state_vectors(
        &slice.unchanged,
        &slice.changes.rows,
        context.limits().max_states(),
    )?;
    validate_state_range::<H, P, D>(
        assignment,
        slice.index,
        &roots.opening,
        &slice.opening,
        &opening,
        context.limits().max_states(),
        slice.layout.start.opening..slice.layout.end.opening,
    )?;
    validate_state_range::<H, P, D>(
        assignment,
        slice.index,
        &roots.closing,
        &slice.closing,
        &closing,
        context.limits().max_states(),
        slice.layout.start.closing..slice.layout.end.closing,
    )?;

    // Row equations advance the predecessor prefix through the interval. Admission defers only
    // signature checks so every distinct payment envelope can share one randomized batch.
    let mut prefix = slice.layout.start.prefix;
    let mut total_shards = 0_u64;
    for (row, shards) in slice.changes.rows.iter().zip(&slice.shard_sets) {
        let shard_count =
            u64::try_from(shards.heads().len()).map_err(|_| TransitionError::CloseLimit)?;
        if shard_count > context.limits().max_shards_per_account() {
            return Err(TransitionError::CloseLimit);
        }
        total_shards = total_shards
            .checked_add(shard_count)
            .filter(|total| *total <= context.limits().max_total_shards())
            .ok_or(TransitionError::CloseLimit)?;
        let delta = if verify_signatures {
            validate_row::<H, P, D>(context, deposits, withdrawals, row, shards)?
        } else {
            validate_row_structure::<H, P, D>(context, deposits, withdrawals, row, shards)?
        };
        prefix = prefix
            .checked_extend(delta)
            .ok_or(TransitionError::PrefixOverflow)?;
        if prefix != row.prefix {
            return Err(TransitionError::Prefix);
        }
    }
    if prefix != slice.layout.end.prefix {
        return Err(TransitionError::Prefix);
    }

    // The final authenticated boundary binds all vector lengths and corpus-wide totals.
    let change_len = slice.changes.opening.proof.leaf_count;
    if slice.index + 1 == assignment.slice_count() {
        if slice.layout.end.opening != slice.opening.opening.proof.leaf_count
            || slice.layout.end.change != change_len
            || slice.layout.end.closing != slice.closing.opening.proof.leaf_count
        {
            return Err(TransitionError::SliceLayout);
        }
        validate_terminal_prefix(context, deposits, withdrawals, change_len, prefix)?;
    }
    Ok(())
}

/// Authenticates one proof slice against its registered header and boundaries.
pub fn validate_slice<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
    slice: &ProofSlice<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_slice_header::<H, P, D>(context, deposits, withdrawals, header, roots)?;
    validate_slice_after_header::<H, P, D>(context, deposits, withdrawals, roots, slice, true)
}

/// Authenticates slice structure while deferring payment signatures to admission's shared batch.
pub(crate) fn validate_slice_structure_after_header<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    roots: &RootBundle<D>,
    slice: &ProofSlice<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_slice_after_header::<H, P, D>(context, deposits, withdrawals, roots, slice, false)
}

fn state_boundaries<P: PublicKey>(
    leaves: &[StateLeaf<P>],
    slice_bits: u8,
) -> Result<Vec<u32>, TransitionError> {
    if slice_bits > super::MAX_SLICE_BITS {
        return Err(TransitionError::SliceBits);
    }
    let slice_count = 1_u16 << slice_bits;
    let mut boundaries = Vec::with_capacity(usize::from(slice_count) + 1);
    boundaries.push(0);
    let mut cursor = 0_usize;
    for index in 0..slice_count {
        while let Some(leaf) = leaves.get(cursor) {
            let member = account_slice(&leaf.account, slice_bits)?;
            if member < index {
                return Err(TransitionError::NonCanonicalSliceOrder);
            }
            if member != index {
                break;
            }
            cursor += 1;
        }
        boundaries.push(u32::try_from(cursor).map_err(|_| TransitionError::TooManyStates)?);
    }
    if cursor != leaves.len() {
        return Err(TransitionError::NonCanonicalSliceOrder);
    }
    Ok(boundaries)
}

fn row_boundaries<P: PublicKey, D: Digest>(
    rows: &[AccountRow<P, D>],
    slice_bits: u8,
) -> Result<Vec<u32>, TransitionError> {
    let slice_count = 1_u16 << slice_bits;
    let mut boundaries = Vec::with_capacity(usize::from(slice_count) + 1);
    boundaries.push(0);
    let mut cursor = 0_usize;
    for index in 0..slice_count {
        while let Some(row) = rows.get(cursor) {
            let member = account_slice(&row.account, slice_bits)?;
            if member < index {
                return Err(TransitionError::NonCanonicalSliceOrder);
            }
            if member != index {
                break;
            }
            cursor += 1;
        }
        boundaries.push(u32::try_from(cursor).map_err(|_| TransitionError::TooManyRows)?);
    }
    if cursor != rows.len() {
        return Err(TransitionError::NonCanonicalSliceOrder);
    }
    Ok(boundaries)
}

pub(super) fn derive_layout<P: PublicKey, D: Digest>(
    rows: &[AccountRow<P, D>],
    opening: &[StateLeaf<P>],
    closing: &[StateLeaf<P>],
    slice_bits: u8,
) -> Result<Vec<SliceBoundary>, TransitionError> {
    let opening = state_boundaries(opening, slice_bits)?;
    let changes = row_boundaries(rows, slice_bits)?;
    let closing = state_boundaries(closing, slice_bits)?;
    opening
        .into_iter()
        .zip(changes)
        .zip(closing)
        .map(|((opening, change), closing)| {
            let prefix = if change == 0 {
                Prefix::default()
            } else {
                rows[change as usize - 1].prefix
            };
            Ok(SliceBoundary {
                opening,
                change,
                closing,
                prefix,
            })
        })
        .collect()
}

pub(super) fn layout_tree_with_strategy<H, D>(
    layout: &[SliceBoundary],
    strategy: &impl Strategy,
) -> Result<commitment::Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let len = u32::try_from(layout.len()).map_err(|_| TransitionError::SliceLayout)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::Layout, len)?;
    builder.add_values(layout, strategy)?;
    Ok(builder.build(strategy)?)
}

/// Opens the canonical guards and members for one retained state interval.
fn build_state_range<P: PublicKey, D: Digest>(
    leaves: &[StateLeaf<P>],
    tree: &commitment::Tree<D>,
    start: u32,
    end: u32,
) -> Result<StateRange<P, D>, TransitionError> {
    let len = u32::try_from(leaves.len()).map_err(|_| TransitionError::TooManyStates)?;
    if start > end || end > len {
        return Err(TransitionError::SliceStateRange);
    }
    let predecessor = start
        .checked_sub(1)
        .map(|position| leaves[position as usize].clone());
    let successor = (end < len).then(|| leaves[end as usize].clone());
    let proof_start = start.saturating_sub(u32::from(predecessor.is_some()));
    let proof_end = end
        .checked_add(u32::from(successor.is_some()))
        .ok_or(TransitionError::SliceStateRange)?;
    Ok(StateRange {
        predecessor,
        successor,
        opening: tree.range_opening(proof_start, proof_end - proof_start)?,
    })
}

/// Deals every deterministic proof slice for dissemination.
///
/// This convenience function reconstructs the Merkle material before dealing. Close producers can
/// retain that work with [`super::PreparedClose`] and avoid rebuilding it.
pub fn assemble_slices<H, P, D>(
    cache: &StateCache<P, D>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
    strategy: &impl Strategy,
) -> Result<Vec<ProofSlice<P, D>>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_slice_header::<H, P, D>(context, deposits, withdrawals, &close.header, &close.roots)?;
    if cache.root() != close.roots.opening || close.rows.len() != close.shard_sets.len() {
        return Err(TransitionError::RowCount);
    }
    let changes = change_tree_with_strategy::<H, P, D>(&close.rows, strategy)?;
    if changes.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    let (opening, closing_leaves) =
        derive_state_vectors(&close.unchanged, &close.rows, context.limits().max_states())?;
    if opening != cache.leaves {
        return Err(TransitionError::OpeningLinkage);
    }
    let closing = state_tree_with_strategy::<H, P, D>(&closing_leaves, strategy)?;
    if closing.root() != close.roots.closing {
        return Err(TransitionError::ClosingRoot);
    }
    let layout_boundaries = derive_layout(
        &close.rows,
        &opening,
        &closing_leaves,
        context.assignment().slice_bits(),
    )?;
    let layout = layout_tree_with_strategy::<H, D>(&layout_boundaries, strategy)?;
    if layout.root() != close.roots.layout {
        return Err(TransitionError::SliceLayout);
    }
    assemble_slice_material(
        cache,
        context.assignment().slice_bits(),
        SliceMaterial {
            close,
            changes: &changes,
            closing_leaves: &closing_leaves,
            closing: &closing,
            layout_boundaries: &layout_boundaries,
            layout: &layout,
        },
        strategy,
    )
}

struct SliceMaterial<'a, P: PublicKey, D: Digest> {
    close: &'a Close<P, D>,
    changes: &'a commitment::Tree<D>,
    closing_leaves: &'a [StateLeaf<P>],
    closing: &'a commitment::Tree<D>,
    layout_boundaries: &'a [SliceBoundary],
    layout: &'a commitment::Tree<D>,
}

/// Builds slices from the Merkle material retained by a prepared close.
pub(super) fn assemble_prepared_slices<P, D>(
    cache: &StateCache<P, D>,
    prepared: &PreparedClose<P, D>,
    strategy: &impl Strategy,
) -> Result<Vec<ProofSlice<P, D>>, TransitionError>
where
    P: PublicKey,
    D: Digest,
{
    assemble_slice_material(
        cache,
        prepared.slice_bits,
        SliceMaterial {
            close: &prepared.close,
            changes: &prepared.changes,
            closing_leaves: &prepared.closing_leaves,
            closing: &prepared.closing,
            layout_boundaries: &prepared.layout_boundaries,
            layout: &prepared.layout,
        },
        strategy,
    )
}

fn assemble_slice_material<P, D>(
    cache: &StateCache<P, D>,
    slice_bits: u8,
    material: SliceMaterial<'_, P, D>,
    strategy: &impl Strategy,
) -> Result<Vec<ProofSlice<P, D>>, TransitionError>
where
    P: PublicKey,
    D: Digest,
{
    let SliceMaterial {
        close,
        changes,
        closing_leaves,
        closing,
        layout_boundaries,
        layout,
    } = material;
    if cache.root() != close.roots.opening
        || closing.root() != close.roots.closing
        || changes.root() != close.roots.change
        || layout.root() != close.roots.layout
    {
        return Err(TransitionError::OpeningRoot);
    }
    let (opening, derived_closing) = derive_state_vectors(
        &close.unchanged,
        &close.rows,
        commitment::MAX_VECTOR_LENGTH.into(),
    )?;
    if opening != cache.leaves || derived_closing != closing_leaves {
        return Err(TransitionError::OpeningLinkage);
    }
    let expected_layout = derive_layout(&close.rows, &opening, closing_leaves, slice_bits)?;
    if layout_boundaries != expected_layout {
        return Err(TransitionError::SliceLayout);
    }

    let unchanged_boundaries = state_boundaries(&close.unchanged, slice_bits)?;
    let slice_count = 1_u16 << slice_bits;

    // Each slice carries unchanged values once and independently opens both live-state ranges.
    strategy.try_map_collect_vec(0..slice_count, |index| {
        let slice = usize::from(index);
        let start_boundary = layout_boundaries[slice];
        let end_boundary = layout_boundaries[slice + 1];
        let start = start_boundary.change as usize;
        let end = end_boundary.change as usize;
        let predecessor = start
            .checked_sub(1)
            .map(|position| close.rows[position].clone());
        let successor = close.rows.get(end).cloned();
        let proof_start = start.saturating_sub(usize::from(predecessor.is_some()));
        let proof_end = end
            .checked_add(usize::from(successor.is_some()))
            .ok_or(TransitionError::SliceRange)?;
        let opening = changes.range_opening(
            u32::try_from(proof_start).map_err(|_| TransitionError::SliceRange)?,
            u32::try_from(proof_end - proof_start).map_err(|_| TransitionError::SliceRange)?,
        )?;
        Ok(ProofSlice {
            index,
            layout: LayoutRange {
                start: start_boundary,
                end: end_boundary,
                opening: layout.range_opening(u32::from(index), 2)?,
            },
            changes: ChangeRange {
                predecessor,
                rows: close.rows[start..end].to_vec(),
                successor,
                opening,
            },
            shard_sets: close.shard_sets[start..end].to_vec(),
            unchanged: close.unchanged
                [unchanged_boundaries[slice] as usize..unchanged_boundaries[slice + 1] as usize]
                .to_vec(),
            opening: build_state_range(
                cache.leaves(),
                &cache.tree,
                start_boundary.opening,
                end_boundary.opening,
            )?,
            closing: build_state_range(
                closing_leaves,
                closing,
                start_boundary.closing,
                end_boundary.closing,
            )?,
        })
    })
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use crate::bajillion::{credit::ShardSet, state::AccountState};
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as ShaDigest};
    use commonware_cryptography_curve25519::signing::{
        SigningKey, StrictVerifyingKey as VerifyingKey,
    };
    use commonware_parallel::Sequential;

    fn partitioned_accounts() -> (VerifyingKey, VerifyingKey) {
        let mut low = None;
        let mut high = None;
        for seed in 0..1_000 {
            let account = SigningKey::from_seed(seed).public_key();
            match account_slice(&account, 1).unwrap() {
                0 if low.is_none() => low = Some(account),
                1 if high.is_none() => high = Some(account),
                _ => {}
            }
            if low.is_some() && high.is_some() {
                break;
            }
        }
        (low.unwrap(), high.unwrap())
    }

    fn test_assignment() -> Assignment<ShaDigest> {
        Assignment::new(Sha256::hash(&[b"layout-regression"]), 1).unwrap()
    }

    fn live_leaf(account: VerifyingKey) -> StateLeaf<VerifyingKey> {
        StateLeaf {
            account,
            state: AccountState {
                balance: 1,
                active: true,
                ..AccountState::default()
            },
        }
    }

    fn changed_row(account: VerifyingKey) -> AccountRow<VerifyingKey, ShaDigest> {
        let shards = ShardSet::empty(0, account.clone());
        AccountRow {
            account,
            opening: AccountState {
                balance: 1,
                active: true,
                ..AccountState::default()
            },
            closing: AccountState {
                balance: 2,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            credit_root: shards.root::<Sha256>().unwrap(),
            prefix: Prefix::default(),
        }
    }

    #[test]
    fn bounded_slice_decode_rejects_zero_sized_digests() {
        assert!(matches!(
            max_proof_hashes(0, 1),
            Err(CodecError::Invalid("ProofSlice", _))
        ));
    }

    #[test]
    fn layout_positions_reject_reversed_state_guards() {
        let (low, high) = partitioned_accounts();
        let low = live_leaf(low);
        let high = live_leaf(high);
        let reversed = vec![high.clone(), low.clone()];
        let tree = state_tree_with_strategy::<Sha256, _, _>(&reversed, &Sequential).unwrap();
        let low_guard = StateRange {
            predecessor: None,
            successor: Some(high),
            opening: tree.range_opening(0, 1).unwrap(),
        };
        let high_guard = StateRange {
            predecessor: Some(low),
            successor: None,
            opening: tree.range_opening(1, 1).unwrap(),
        };
        let assignment = test_assignment();

        for shared_boundary in 0..=2 {
            let low = validate_state_range::<Sha256, _, _>(
                &assignment,
                0,
                &tree.root(),
                &low_guard,
                &[],
                2,
                0..shared_boundary,
            );
            let high = validate_state_range::<Sha256, _, _>(
                &assignment,
                1,
                &tree.root(),
                &high_guard,
                &[],
                2,
                shared_boundary..2,
            );
            assert!(low.is_err() || high.is_err());
        }
    }

    #[test]
    fn layout_positions_reject_reversed_change_guards() {
        let (low, high) = partitioned_accounts();
        let low = changed_row(low);
        let high = changed_row(high);
        let reversed = vec![high.clone(), low.clone()];
        let tree = change_tree_with_strategy::<Sha256, _, _>(&reversed, &Sequential).unwrap();
        let low_guard = ChangeRange {
            predecessor: None,
            rows: Vec::new(),
            successor: Some(high),
            opening: tree.range_opening(0, 1).unwrap(),
        };
        let high_guard = ChangeRange {
            predecessor: Some(low),
            rows: Vec::new(),
            successor: None,
            opening: tree.range_opening(1, 1).unwrap(),
        };
        let assignment = test_assignment();

        for shared_boundary in 0..=2 {
            let low = validate_change_range::<Sha256, _, _>(
                &assignment,
                0,
                &tree.root(),
                &low_guard,
                0,
                shared_boundary,
            );
            let high = validate_change_range::<Sha256, _, _>(
                &assignment,
                1,
                &tree.root(),
                &high_guard,
                shared_boundary,
                2,
            );
            assert!(low.is_err() || high.is_err());
        }
    }
}
