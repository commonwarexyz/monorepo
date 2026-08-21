//! Proof slices for authenticating deterministic account intervals from one public close corpus.

use super::{
    Assignment, Close, CloseContext, CloseLimits, Header, RootBundle, StateCache, TransitionError,
    account_slice, change_tree_with_strategy, read_shard_sets, validate_boundary_roots,
    validate_header, validate_row, validate_row_structure, validate_terminal_prefix,
};
use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    commitment::{self, RangeOpening, RangeUpdate, VectorKind},
    credit::ShardSet,
    state::{AccountRow, Prefix, StateLeaf},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_storage::bmt;

const STATE_BOUNDARY_VALUES: usize = 4;

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
        let predecessor = Option::<AccountRow<P, D>>::read(reader)?;
        let rows = Vec::<AccountRow<P, D>>::read_cfg(reader, &(RangeCfg::new(..=*maximum), ()))?;
        let successor = Option::<AccountRow<P, D>>::read(reader)?;
        let proof_values = rows
            .len()
            .saturating_add(usize::from(predecessor.is_some()))
            .saturating_add(usize::from(successor.is_some()));
        let opening = RangeOpening::read_cfg(reader, &proof_values)?;
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

/// Authenticated opening-state guards defining one exact account-key interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateBounds<P: PublicKey, D: Digest> {
    /// First state-vector position in the interval.
    pub start: u32,
    /// Exclusive state-vector end position.
    pub end: u32,
    /// Existing predecessor, first, last, and successor leaves in position order.
    pub leaves: Vec<StateLeaf<P>>,
    /// One BMT multiproof authenticating the boundary leaves.
    pub proof: bmt::Proof<D>,
}

impl<P: PublicKey, D: Digest> Write for StateBounds<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.start.write(writer);
        self.end.write(writer);
        self.leaves.write(writer);
        self.proof.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for StateBounds<P, D> {
    fn encode_size(&self) -> usize {
        self.start.encode_size()
            + self.end.encode_size()
            + self.leaves.encode_size()
            + self.proof.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for StateBounds<P, D> {
    /// No caller-supplied limits are needed because an interval has at most four boundary leaves.
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            start: u32::read(reader)?,
            end: u32::read(reader)?,
            leaves: Vec::<StateLeaf<P>>::read_cfg(
                reader,
                &(RangeCfg::new(..=STATE_BOUNDARY_VALUES), ()),
            )?,
            proof: bmt::Proof::read_cfg(reader, &STATE_BOUNDARY_VALUES)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for StateBounds<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let count = usize::from(u.int_in_range(0..=STATE_BOUNDARY_VALUES as u8)?);
        let mut leaves = Vec::with_capacity(count);
        for _ in 0..count {
            leaves.push(u.arbitrary()?);
        }
        Ok(Self {
            start: u.arbitrary()?,
            end: u.arbitrary()?,
            leaves,
            proof: u.arbitrary()?,
        })
    }
}

/// One proof slice for independently authenticating an account interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSlice<P: PublicKey, D: Digest> {
    /// Deterministic interval index.
    pub index: u16,
    /// Exact changed rows in this interval.
    pub changes: ChangeRange<P, D>,
    /// Terminal shard sets aligned one-for-one with [`ChangeRange::rows`].
    pub shard_sets: Vec<ShardSet<P, D>>,
    /// Exact positions occupied by this interval in the opening state vector.
    pub state_bounds: StateBounds<P, D>,
    /// Exact opening-to-closing state update within this interval.
    pub update: RangeUpdate<D>,
}

impl<P: PublicKey, D: Digest> Write for ProofSlice<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.index.write(writer);
        self.changes.write(writer);
        self.shard_sets.write(writer);
        self.state_bounds.write(writer);
        self.update.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ProofSlice<P, D> {
    fn encode_size(&self) -> usize {
        self.index.encode_size()
            + self.changes.encode_size()
            + self.shard_sets.encode_size()
            + self.state_bounds.encode_size()
            + self.update.encode_size()
    }
}

/// Adversarial decode limits for one proof slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SliceCodecConfig {
    /// Anchor-bound close limits.
    pub close: CloseLimits,
    /// Maximum hashes accepted in either range-update frontier.
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
        let changes = ChangeRange::read_cfg(reader, &row_limit)?;
        let shard_sets = read_shard_sets(reader, changes.rows.len(), &config.close)?;
        let state_bounds = StateBounds::read(reader)?;
        let update = RangeUpdate::read_cfg(
            reader,
            &(
                changes.rows.len(),
                config.max_proof_hashes,
                config.max_proof_hashes,
            ),
        )?;
        Ok(Self {
            index,
            changes,
            shard_sets,
            state_bounds,
            update,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ProofSlice<P, D>
where
    P: PublicKey,
    D: Digest,
    ChangeRange<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    ShardSet<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    StateBounds<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    RangeUpdate<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            index: u.arbitrary()?,
            changes: u.arbitrary()?,
            shard_sets: u.arbitrary()?,
            state_bounds: u.arbitrary()?,
            update: u.arbitrary()?,
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

/// Returns the canonical predecessor, first, last, and successor positions for an interval.
fn state_boundary_positions(start: u32, end: u32, len: u32) -> Result<Vec<u32>, TransitionError> {
    if start > end || end > len {
        return Err(TransitionError::SliceStateBounds);
    }
    let mut positions = Vec::with_capacity(STATE_BOUNDARY_VALUES);
    if let Some(predecessor) = start.checked_sub(1) {
        positions.push(predecessor);
    }
    if start < end {
        positions.push(start);
        if end - start > 1 {
            positions.push(end - 1);
        }
    }
    if end < len {
        positions.push(end);
    }
    Ok(positions)
}

/// Authenticates the guarded changed-row interval and its deterministic slice membership.
fn validate_change_range<H, P, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &commitment::VectorRoot<D>,
    range: &ChangeRange<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = range.opening.proof.leaf_count;
    let start = range
        .opening
        .start
        .checked_add(u32::from(range.predecessor.is_some()))
        .ok_or(TransitionError::SliceRange)?;
    let members = u32::try_from(range.rows.len()).map_err(|_| TransitionError::SliceRange)?;
    let end = start
        .checked_add(members)
        .filter(|end| *end <= len)
        .ok_or(TransitionError::SliceRange)?;
    if range.predecessor.is_some() != (start > 0) || range.successor.is_some() != (end < len) {
        return Err(TransitionError::SliceRange);
    }
    if range
        .rows
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
        && (account_slice(&predecessor.account, assignment.slice_bits())? >= index
            || range
                .rows
                .first()
                .is_some_and(|row| predecessor.account >= row.account))
    {
        return Err(TransitionError::SliceRange);
    }
    if let Some(successor) = &range.successor
        && (account_slice(&successor.account, assignment.slice_bits())? <= index
            || range
                .rows
                .last()
                .is_some_and(|row| row.account >= successor.account))
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

/// Authenticates the opening-state guards that prove the slice's exact key interval.
fn validate_state_bounds<H, P, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &commitment::VectorRoot<D>,
    bounds: &StateBounds<P, D>,
) -> Result<Vec<u32>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = bounds.proof.leaf_count;
    let positions = state_boundary_positions(bounds.start, bounds.end, len)?;
    if positions.len() != bounds.leaves.len()
        || bounds
            .leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::SliceStateBounds);
    }
    let encoded = bounds.leaves.iter().map(Encode::encode).collect::<Vec<_>>();
    commitment::verify_multi_opening::<H, D, _>(
        VectorKind::State,
        &positions,
        &bounds.proof,
        root,
        &encoded,
    )?;

    let mut leaf = 0_usize;
    if bounds.start > 0 {
        if account_slice(&bounds.leaves[leaf].account, assignment.slice_bits())? >= index {
            return Err(TransitionError::SliceStateBounds);
        }
        leaf += 1;
    }
    if bounds.start < bounds.end {
        if account_slice(&bounds.leaves[leaf].account, assignment.slice_bits())? != index {
            return Err(TransitionError::SliceStateBounds);
        }
        leaf += 1;
        if bounds.end - bounds.start > 1 {
            if account_slice(&bounds.leaves[leaf].account, assignment.slice_bits())? != index {
                return Err(TransitionError::SliceStateBounds);
            }
            leaf += 1;
        }
    }
    if bounds.end < len
        && account_slice(&bounds.leaves[leaf].account, assignment.slice_bits())? <= index
    {
        return Err(TransitionError::SliceStateBounds);
    }
    Ok(positions)
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
    // The two authenticated intervals must describe the requested deterministic slice and align
    // every changed row with one shard set and one sparse state update.
    let assignment = context.assignment();
    if slice.index >= assignment.slice_count() {
        return Err(TransitionError::SliceIndex);
    }
    validate_change_range::<H, P, D>(assignment, slice.index, &roots.change, &slice.changes)?;
    validate_state_bounds::<H, P, D>(assignment, slice.index, &roots.opening, &slice.state_bounds)?;
    if slice.shard_sets.len() != slice.changes.rows.len()
        || slice.update.start != slice.state_bounds.start
        || slice.update.end != slice.state_bounds.end
        || slice.update.positions.len() != slice.changes.rows.len()
    {
        return Err(TransitionError::ShardAlignment);
    }

    // Reconstruct both state roots from the exact opening and closing values carried by the rows.
    let opening = slice
        .changes
        .rows
        .iter()
        .map(|row| {
            StateLeaf {
                account: row.account.clone(),
                state: row.opening,
            }
            .encode()
        })
        .collect::<Vec<_>>();
    let closing = slice
        .changes
        .rows
        .iter()
        .map(|row| {
            StateLeaf {
                account: row.account.clone(),
                state: row.closing,
            }
            .encode()
        })
        .collect::<Vec<_>>();
    slice.update.verify::<H, _, _>(
        VectorKind::State,
        &roots.opening,
        &roots.closing,
        &opening,
        &closing,
    )?;

    // Row equations advance the predecessor prefix through the interval. Admission defers only
    // signature checks so every distinct payment envelope can share one randomized batch.
    let mut prefix = slice
        .changes
        .predecessor
        .as_ref()
        .map_or_else(Prefix::default, |row| row.prefix);
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

    // The last nonempty change interval owns the corpus-wide terminal totals check.
    let member_start = slice
        .changes
        .opening
        .start
        .checked_add(u32::from(slice.changes.predecessor.is_some()))
        .ok_or(TransitionError::SliceRange)?;
    let end = member_start
        .checked_add(
            u32::try_from(slice.changes.rows.len()).map_err(|_| TransitionError::SliceRange)?,
        )
        .ok_or(TransitionError::SliceRange)?;
    let change_len = slice.changes.opening.proof.leaf_count;
    if end == change_len {
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

/// Opens the canonical state guards for one interval from the retained opening tree.
fn build_state_bounds<P: PublicKey, D: Digest>(
    cache: &StateCache<P, D>,
    start: u32,
    end: u32,
) -> Result<StateBounds<P, D>, TransitionError> {
    let len = u32::try_from(cache.len()).map_err(|_| TransitionError::TooManyStates)?;
    let positions = state_boundary_positions(start, end, len)?;
    let leaves = positions
        .iter()
        .map(|position| cache.leaves[*position as usize].clone())
        .collect::<Vec<_>>();
    let proof = cache.tree.multi_opening(&positions)?.proof;
    Ok(StateBounds {
        start,
        end,
        leaves,
        proof,
    })
}

/// Deals every deterministic proof slice for dissemination.
///
/// This convenience function reconstructs the roots before dealing. Close producers can retain
/// that work with [`super::PreparedClose`] and avoid rebuilding either root.
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
    if cache.root() != close.roots.opening
        || close.rows.len() != close.shard_sets.len()
        || close.update.positions.len() != close.rows.len()
    {
        return Err(TransitionError::RowCount);
    }
    let changes = change_tree_with_strategy::<H, P, D>(&close.rows, strategy)?;
    if changes.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    let closing_values = strategy.map_collect_vec(&close.rows, |row| {
        StateLeaf {
            account: row.account.clone(),
            state: row.closing,
        }
        .encode()
    });
    let closing =
        cache
            .tree
            .prepare_update::<H, _>(&close.update.positions, &closing_values, strategy)?;
    if closing.root() != close.roots.closing {
        return Err(TransitionError::Commitment(commitment::Error::HiddenChange));
    }
    assemble_prepared_slices(
        cache,
        context.assignment().slice_bits(),
        close,
        &changes,
        &closing,
        strategy,
    )
}

/// Builds slices from roots already reconstructed and matched to the close.
pub(super) fn assemble_prepared_slices<P, D>(
    cache: &StateCache<P, D>,
    slice_bits: u8,
    close: &Close<P, D>,
    changes: &commitment::Tree<D>,
    closing: &commitment::PreparedUpdate<D>,
    strategy: &impl Strategy,
) -> Result<Vec<ProofSlice<P, D>>, TransitionError>
where
    P: PublicKey,
    D: Digest,
{
    if cache.root() != close.roots.opening {
        return Err(TransitionError::OpeningRoot);
    }

    // State boundaries partition the complete registry and share one prepared sparse update.
    let state_boundaries = cache.slice_boundaries(slice_bits)?;
    let updates = cache
        .tree
        .range_updates_from_prepared(closing, &state_boundaries, strategy)?;

    // Canonical row order yields one contiguous changed-row interval per slice.
    let mut row_boundaries = Vec::with_capacity(state_boundaries.len());
    row_boundaries.push(0_usize);
    let mut cursor = 0_usize;
    let slice_count = 1_u16 << slice_bits;
    for index in 0..slice_count {
        while let Some(row) = close.rows.get(cursor) {
            let row_slice = account_slice(&row.account, slice_bits)?;
            if row_slice < index {
                return Err(TransitionError::NonCanonicalSliceOrder);
            }
            if row_slice != index {
                break;
            }
            cursor += 1;
        }
        row_boundaries.push(cursor);
    }
    if cursor != close.rows.len() {
        return Err(TransitionError::NonCanonicalSliceOrder);
    }

    // Each slice reuses the prepared roots and owns only its range openings and local values.
    strategy.try_map_collect_vec(0..slice_count, |index| {
        let slice = usize::from(index);
        let start = row_boundaries[slice];
        let end = row_boundaries[slice + 1];
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
            changes: ChangeRange {
                predecessor,
                rows: close.rows[start..end].to_vec(),
                successor,
                opening,
            },
            shard_sets: close.shard_sets[start..end].to_vec(),
            state_bounds: build_state_bounds(
                cache,
                state_boundaries[slice],
                state_boundaries[slice + 1],
            )?,
            update: updates[slice].clone(),
        })
    })
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn bounded_slice_decode_rejects_zero_sized_digests() {
        assert!(matches!(
            max_proof_hashes(0, 1),
            Err(CodecError::Invalid("ProofSlice", _))
        ));
    }
}
