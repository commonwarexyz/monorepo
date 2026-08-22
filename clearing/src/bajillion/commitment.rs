//! Exact-length, domain-separated vector commitments.
//!
//! Values are supplied in their canonical encoded form. This module hashes those bytes into
//! typed leaves and delegates all tree construction and proof reconstruction to
//! [`commonware_storage::bmt`].

use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_storage::bmt;
use thiserror::Error;

const STATE_LEAF_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_STATE_LEAF";
const STATE_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_STATE_ROOT";
const CHANGE_LEAF_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_CHANGE_LEAF";
const CHANGE_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_CHANGE_ROOT";
const CREDIT_LEAF_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_CREDIT_LEAF";
const CREDIT_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_CREDIT_VECTOR_ROOT";
const DEPOSIT_LEAF_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_DEPOSIT_LEAF";
const DEPOSIT_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_DEPOSIT_ROOT";
const WITHDRAWAL_LEAF_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_WITHDRAWAL_LEAF";
const WITHDRAWAL_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_WITHDRAWAL_ROOT";
const LAYOUT_LEAF_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_LAYOUT_LEAF";
const LAYOUT_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_LAYOUT_ROOT";

/// Maximum number of values in a committed vector or disclosed in one proof.
///
/// The bound limits decoding and verification work while covering the protocol's largest live
/// state and public corpus.
pub const MAX_VECTOR_LENGTH: u32 = 1 << 24;

/// The semantic type of an exact-length vector commitment.
///
/// The kind selects distinct leaf and root hash domains, preventing a commitment from being
/// reinterpreted as another protocol vector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum VectorKind {
    /// Complete account-state vector.
    State = 1,
    /// Sorted vector of changed-account rows.
    Change = 2,
    /// Sorted vector of terminal receive-shard heads.
    Credit = 3,
    /// Chain-sealed deposit vector.
    Deposit = 4,
    /// Chain-sealed withdrawal vector.
    Withdrawal = 5,
    /// Gap-free deterministic proof-slice boundaries.
    Layout = 6,
}

impl VectorKind {
    const fn leaf_domain(self) -> &'static [u8] {
        match self {
            Self::State => STATE_LEAF_DOMAIN,
            Self::Change => CHANGE_LEAF_DOMAIN,
            Self::Credit => CREDIT_LEAF_DOMAIN,
            Self::Deposit => DEPOSIT_LEAF_DOMAIN,
            Self::Withdrawal => WITHDRAWAL_LEAF_DOMAIN,
            Self::Layout => LAYOUT_LEAF_DOMAIN,
        }
    }

    const fn root_domain(self) -> &'static [u8] {
        match self {
            Self::State => STATE_ROOT_DOMAIN,
            Self::Change => CHANGE_ROOT_DOMAIN,
            Self::Credit => CREDIT_ROOT_DOMAIN,
            Self::Deposit => DEPOSIT_ROOT_DOMAIN,
            Self::Withdrawal => WITHDRAWAL_ROOT_DOMAIN,
            Self::Layout => LAYOUT_ROOT_DOMAIN,
        }
    }
}

impl Write for VectorKind {
    fn write(&self, writer: &mut impl BufMut) {
        (*self as u8).write(writer);
    }
}

impl Read for VectorKind {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            1 => Ok(Self::State),
            2 => Ok(Self::Change),
            3 => Ok(Self::Credit),
            4 => Ok(Self::Deposit),
            5 => Ok(Self::Withdrawal),
            6 => Ok(Self::Layout),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl FixedSize for VectorKind {
    const SIZE: usize = u8::SIZE;
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for VectorKind {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(1..=6)? {
            1 => Self::State,
            2 => Self::Change,
            3 => Self::Credit,
            4 => Self::Deposit,
            5 => Self::Withdrawal,
            6 => Self::Layout,
            _ => unreachable!("range contains every vector kind"),
        })
    }
}

/// A digest commitment to a domain-separated, exact-length vector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VectorRoot<D: Digest> {
    /// Domain-separated digest wrapping the length-bound BMT root.
    pub digest: D,
}

impl<D: Digest> Write for VectorRoot<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for VectorRoot<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            digest: D::read(reader)?,
        })
    }
}

impl<D: Digest> FixedSize for VectorRoot<D> {
    const SIZE: usize = D::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for VectorRoot<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            digest: u.arbitrary()?,
        })
    }
}

/// Errors returned while constructing or verifying vector commitments.
#[derive(Debug, Error)]
pub enum Error {
    /// A requested vector or proof exceeds [`MAX_VECTOR_LENGTH`].
    #[error("vector length {0} exceeds the protocol bound")]
    TooManyValues(u64),
    /// A builder did not receive exactly its declared number of values.
    #[error("builder expected {expected} values but received {actual}")]
    LengthMismatch {
        /// Declared vector length.
        expected: u32,
        /// Number of values supplied to the builder.
        actual: u32,
    },
    /// An encoded value cannot be length-framed by this protocol.
    #[error("encoded value is too large")]
    EncodedValueTooLarge,
    /// An opening supplies a different number of positions and values.
    #[error("opening has {positions} positions but {values} values")]
    OpeningLengthMismatch {
        /// Number of disclosed positions.
        positions: usize,
        /// Number of disclosed values.
        values: usize,
    },
    /// Positions are not strictly increasing, unique, and in range.
    #[error("proof positions are not in canonical order")]
    NonCanonicalPositions,
    /// The disclosed value does not authenticate to the expected root.
    #[error("opening does not authenticate to the expected root")]
    InvalidOpening,
    /// The opening side of a sparse update does not authenticate.
    #[error("sparse update does not authenticate to the opening root")]
    InvalidOpeningRoot,
    /// The shared frontier cannot produce the claimed closing root.
    #[error("sparse update changes a hidden or incorrectly disclosed position")]
    HiddenChange,
    /// A disclosed sparse-update position has identical opening and closing values.
    #[error("position {0} is disclosed as changed but its value is unchanged")]
    UnchangedPosition(u32),
    /// An empty opening or update is not in its one canonical form.
    #[error("malformed empty proof")]
    MalformedEmpty,
    /// The underlying BMT proof is structurally invalid.
    #[error("invalid BMT proof: {0}")]
    Bmt(#[from] bmt::Error),
}

fn check_len(len: u32) -> Result<(), Error> {
    if len > MAX_VECTOR_LENGTH {
        Err(Error::TooManyValues(u64::from(len)))
    } else {
        Ok(())
    }
}

fn leaf_digest<H: Hasher>(
    kind: VectorKind,
    len: u32,
    position: u32,
    encoded: &[u8],
) -> Result<H::Digest, Error> {
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| Error::EncodedValueTooLarge)?
        .to_be_bytes();
    Ok(H::hash(&[
        kind.leaf_domain(),
        &len.to_be_bytes(),
        &position.to_be_bytes(),
        &encoded_len,
        encoded,
    ]))
}

fn leaf_digest_pair<H: Hasher>(
    kind: VectorKind,
    len: u32,
    first_position: u32,
    first: &[u8],
    second_position: u32,
    second: &[u8],
) -> Result<(H::Digest, H::Digest), Error> {
    let first_len = u64::try_from(first.len())
        .map_err(|_| Error::EncodedValueTooLarge)?
        .to_be_bytes();
    let second_len = u64::try_from(second.len())
        .map_err(|_| Error::EncodedValueTooLarge)?
        .to_be_bytes();
    Ok(H::hash_pair(
        &[
            kind.leaf_domain(),
            &len.to_be_bytes(),
            &first_position.to_be_bytes(),
            &first_len,
            first,
        ],
        &[
            kind.leaf_domain(),
            &len.to_be_bytes(),
            &second_position.to_be_bytes(),
            &second_len,
            second,
        ],
    ))
}

fn bind_root<H: Hasher>(kind: VectorKind, len: u32, bmt_root: &H::Digest) -> VectorRoot<H::Digest> {
    VectorRoot {
        digest: H::hash(&[kind.root_domain(), &len.to_be_bytes(), bmt_root.as_ref()]),
    }
}

fn check_positions(positions: &[u32], len: u32, allow_empty: bool) -> Result<(), Error> {
    if positions.len() > MAX_VECTOR_LENGTH as usize {
        return Err(Error::TooManyValues(positions.len() as u64));
    }
    if positions.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(Error::MalformedEmpty)
        };
    }
    if positions[0] >= len
        || positions.windows(2).any(|pair| {
            let [left, right] = pair else {
                unreachable!("windows of two always contain two positions");
            };
            left >= right || *right >= len
        })
    {
        return Err(Error::NonCanonicalPositions);
    }
    Ok(())
}

/// Returns the canonical root of an empty vector of `kind`.
#[must_use]
pub fn empty_root<H: Hasher>(kind: VectorKind) -> VectorRoot<H::Digest> {
    let tree = bmt::Builder::<H>::new(0).build(&Sequential);
    bind_root::<H>(kind, 0, &tree.root())
}

/// Incrementally constructs a commitment from already-encoded values.
pub struct Builder<H: Hasher> {
    kind: VectorKind,
    len: u32,
    added: u32,
    inner: bmt::Builder<H>,
}

impl<H: Hasher> Builder<H> {
    /// Creates a builder that accepts exactly `len` encoded values.
    pub fn new(kind: VectorKind, len: u32) -> Result<Self, Error> {
        check_len(len)?;
        Ok(Self {
            kind,
            len,
            added: 0,
            inner: bmt::Builder::new(len as usize),
        })
    }

    /// Hashes and appends one already-encoded value, returning its position.
    pub fn add_encoded(&mut self, encoded: &[u8]) -> Result<u32, Error> {
        if self.added >= self.len {
            return Err(Error::LengthMismatch {
                expected: self.len,
                actual: self.added.saturating_add(1),
            });
        }
        let position = self.added;
        let digest = leaf_digest::<H>(self.kind, self.len, position, encoded)?;
        let bmt_position = self.inner.add(&digest);
        debug_assert_eq!(position, bmt_position);
        self.added += 1;
        Ok(position)
    }

    /// Canonically encodes and appends a slice using the supplied execution strategy.
    pub fn add_values<T>(&mut self, values: &[T], strategy: &impl Strategy) -> Result<(), Error>
    where
        T: Encode + Sync,
    {
        let requested = u64::try_from(values.len()).unwrap_or(u64::MAX);
        let count = u32::try_from(values.len()).map_err(|_| Error::TooManyValues(requested))?;
        let actual = self
            .added
            .checked_add(count)
            .ok_or(Error::TooManyValues(requested))?;
        if actual > self.len {
            return Err(Error::LengthMismatch {
                expected: self.len,
                actual,
            });
        }
        let start = self.added;
        let pairs = strategy.try_map_collect_vec(
            values.chunks(2).enumerate(),
            |(pair_index, values)| -> Result<(H::Digest, Option<H::Digest>), Error> {
                let offset = u32::try_from(pair_index)
                    .expect("validated value count fits in u32")
                    .checked_mul(2)
                    .expect("validated value count fits in u32");
                let first_position = start
                    .checked_add(offset)
                    .expect("validated builder range fits in u32");
                let first = values[0].encode();
                match values.get(1) {
                    Some(second_value) => {
                        let second_position = first_position + 1;
                        let second = second_value.encode();
                        let (first, second) = leaf_digest_pair::<H>(
                            self.kind,
                            self.len,
                            first_position,
                            first.as_ref(),
                            second_position,
                            second.as_ref(),
                        )?;
                        Ok((first, Some(second)))
                    }
                    None => Ok((
                        leaf_digest::<H>(self.kind, self.len, first_position, first.as_ref())?,
                        None,
                    )),
                }
            },
        )?;
        for (first, second) in pairs {
            self.inner.add(&first);
            if let Some(second) = second {
                self.inner.add(&second);
            }
        }
        self.added = actual;
        Ok(())
    }

    /// Finishes construction with the supplied strategy after checking the declared exact length.
    pub fn build(self, strategy: &impl Strategy) -> Result<Tree<H::Digest>, Error> {
        if self.added != self.len {
            return Err(Error::LengthMismatch {
                expected: self.len,
                actual: self.added,
            });
        }
        let inner = self.inner.build(strategy);
        let root = bind_root::<H>(self.kind, self.len, &inner.root());
        Ok(Tree {
            kind: self.kind,
            len: self.len,
            root,
            inner,
        })
    }
}

/// A constructed vector commitment capable of producing bounded BMT openings.
#[derive(Clone, Debug)]
pub struct Tree<D: Digest> {
    kind: VectorKind,
    len: u32,
    root: VectorRoot<D>,
    inner: bmt::Tree<D>,
}

/// In-memory sparse closing overlay retained while interval proofs are constructed.
#[derive(Debug)]
pub(crate) struct PreparedUpdate<D: Digest> {
    kind: VectorKind,
    len: u32,
    positions: Vec<u32>,
    root: VectorRoot<D>,
    inner: bmt::Update<D>,
}

impl<D: Digest> PreparedUpdate<D> {
    pub(crate) const fn root(&self) -> VectorRoot<D> {
        self.root
    }
}

impl<D: Digest> Tree<D> {
    /// Returns the domain-separated, exact-length root digest.
    #[must_use]
    pub const fn root(&self) -> VectorRoot<D> {
        self.root
    }

    /// Opens one vector position.
    pub fn opening(&self, position: u32) -> Result<Opening<D>, Error> {
        check_positions(core::slice::from_ref(&position), self.len, false)?;
        Ok(Opening {
            position,
            proof: self.inner.proof(position)?,
        })
    }

    /// Opens strictly increasing, unique vector positions with one BMT multiproof.
    ///
    /// The empty position list is canonical only for an empty vector.
    pub fn multi_opening(&self, positions: &[u32]) -> Result<MultiOpening<D>, Error> {
        check_positions(positions, self.len, true)?;
        let proof = if positions.is_empty() {
            if self.len != 0 {
                return Err(Error::MalformedEmpty);
            }
            bmt::Proof::default()
        } else {
            self.inner.multi_proof(positions)?
        };
        Ok(MultiOpening {
            positions: positions.to_vec(),
            proof,
        })
    }

    /// Opens one contiguous range of vector positions.
    ///
    /// A zero-length range is canonical only for the empty vector at position zero.
    pub fn range_opening(&self, start: u32, count: u32) -> Result<RangeOpening<D>, Error> {
        if count == 0 {
            return if start == 0 && self.len == 0 {
                Ok(RangeOpening {
                    start,
                    proof: bmt::Proof::default(),
                })
            } else {
                Err(Error::MalformedEmpty)
            };
        }
        let end = start
            .checked_add(count)
            .filter(|end| *end <= self.len)
            .ok_or(Error::NonCanonicalPositions)?;
        Ok(RangeOpening {
            start,
            proof: self.inner.range_proof(start, end - 1)?,
        })
    }

    /// Builds a shared-frontier proof for the positions changed by a sparse update.
    ///
    /// An empty update is represented by an empty sibling list and may only verify when the two
    /// roots are identical.
    pub fn sparse_update(&self, positions: &[u32]) -> Result<SparseUpdate<D>, Error> {
        check_positions(positions, self.len, true)?;
        let proof = if positions.is_empty() {
            bmt::Proof {
                leaf_count: self.len,
                siblings: Vec::new(),
            }
        } else {
            self.inner.multi_proof(positions)?
        };
        Ok(SparseUpdate {
            positions: positions.to_vec(),
            proof,
        })
    }

    /// Builds paired proofs for an exhaustive partition of one sparse vector update.
    ///
    /// Construction hashes and visits only the changed paths plus the supplied boundaries. The
    /// returned closing root and every proof share one sparse BMT overlay.
    pub fn range_updates<H, B>(
        &self,
        positions: &[u32],
        closing_values: &[B],
        boundaries: &[u32],
        strategy: &impl Strategy,
    ) -> Result<(VectorRoot<D>, Vec<RangeUpdate<D>>), Error>
    where
        H: Hasher<Digest = D>,
        B: AsRef<[u8]> + Sync,
    {
        let update = self.prepare_update::<H, B>(positions, closing_values, strategy)?;
        let root = update.root();
        let ranges = self.range_updates_from_prepared(&update, boundaries, strategy)?;
        Ok((root, ranges))
    }

    pub(crate) fn prepare_update<H, B>(
        &self,
        positions: &[u32],
        closing_values: &[B],
        strategy: &impl Strategy,
    ) -> Result<PreparedUpdate<D>, Error>
    where
        H: Hasher<Digest = D>,
        B: AsRef<[u8]> + Sync,
    {
        check_positions(positions, self.len, true)?;
        if positions.len() != closing_values.len() {
            return Err(Error::OpeningLengthMismatch {
                positions: positions.len(),
                values: closing_values.len(),
            });
        }
        let pairs = strategy.try_map_collect_vec(
            positions.chunks(2).zip(closing_values.chunks(2)),
            |(positions, values)| -> Result<_, Error> {
                match (positions, values) {
                    ([first_position, second_position], [first, second]) => {
                        let (first, second) = leaf_digest_pair::<H>(
                            self.kind,
                            self.len,
                            *first_position,
                            first.as_ref(),
                            *second_position,
                            second.as_ref(),
                        )?;
                        Ok(((*first_position, first), Some((*second_position, second))))
                    }
                    ([position], [value]) => Ok((
                        (
                            *position,
                            leaf_digest::<H>(self.kind, self.len, *position, value.as_ref())?,
                        ),
                        None,
                    )),
                    _ => unreachable!("equally sized chunks contain one or two values"),
                }
            },
        )?;
        let mut changes = Vec::with_capacity(positions.len());
        for (first, second) in pairs {
            changes.push(first);
            if let Some(second) = second {
                changes.push(second);
            }
        }
        let inner = self.inner.update::<H>(&changes, strategy)?;
        let root = bind_root::<H>(self.kind, self.len, &inner.root());
        Ok(PreparedUpdate {
            kind: self.kind,
            len: self.len,
            positions: positions.to_vec(),
            root,
            inner,
        })
    }

    pub(crate) fn range_updates_from_prepared(
        &self,
        update: &PreparedUpdate<D>,
        boundaries: &[u32],
        strategy: &impl Strategy,
    ) -> Result<Vec<RangeUpdate<D>>, Error> {
        if update.kind != self.kind || update.len != self.len {
            return Err(Error::InvalidOpeningRoot);
        }
        let proofs = self
            .inner
            .range_update_proofs(&update.inner, boundaries, strategy)?;
        let ranges = boundaries
            .windows(2)
            .zip(proofs)
            .map(|(interval, proof)| {
                let first = update
                    .positions
                    .partition_point(|position| *position < interval[0]);
                let last = update
                    .positions
                    .partition_point(|position| *position < interval[1]);
                RangeUpdate {
                    start: interval[0],
                    end: interval[1],
                    positions: update.positions[first..last].to_vec(),
                    proof,
                }
            })
            .collect();
        Ok(ranges)
    }
}

/// Paired exact-update proof for one half-open interval of a typed vector.
///
/// The proof permits arbitrary changes outside `[start, end)` while proving every undisclosed
/// position inside it unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeUpdate<D: Digest> {
    /// First position in the proved interval.
    pub start: u32,
    /// Exclusive end of the proved interval.
    pub end: u32,
    /// Strictly increasing changed positions inside the interval.
    pub positions: Vec<u32>,
    /// Paired BMT frontier for the interval.
    pub proof: bmt::RangeUpdateProof<D>,
}

impl<D: Digest> RangeUpdate<D> {
    fn validate_shape(&self) -> Result<(), Error> {
        let len = self.proof.leaf_count;
        check_len(len)?;
        if self.start > self.end || self.end > len {
            return Err(Error::NonCanonicalPositions);
        }
        check_positions(&self.positions, len, true)?;
        if self
            .positions
            .first()
            .is_some_and(|position| *position < self.start)
            || self
                .positions
                .last()
                .is_some_and(|position| *position >= self.end)
        {
            return Err(Error::NonCanonicalPositions);
        }
        Ok(())
    }

    /// Verifies every disclosed change and the absence of hidden changes in this interval.
    pub fn verify<H, O, C>(
        &self,
        kind: VectorKind,
        opening_root: &VectorRoot<D>,
        closing_root: &VectorRoot<D>,
        opening_values: &[O],
        closing_values: &[C],
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        O: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        self.validate_shape()?;
        let len = self.proof.leaf_count;
        if self.positions.len() != opening_values.len() {
            return Err(Error::OpeningLengthMismatch {
                positions: self.positions.len(),
                values: opening_values.len(),
            });
        }
        if self.positions.len() != closing_values.len() {
            return Err(Error::OpeningLengthMismatch {
                positions: self.positions.len(),
                values: closing_values.len(),
            });
        }

        let mut opening = Vec::with_capacity(self.positions.len());
        let mut closing = Vec::with_capacity(self.positions.len());
        for ((&position, opening_value), closing_value) in self
            .positions
            .iter()
            .zip(opening_values)
            .zip(closing_values)
        {
            opening.push(leaf_digest::<H>(
                kind,
                len,
                position,
                opening_value.as_ref(),
            )?);
            closing.push(leaf_digest::<H>(
                kind,
                len,
                position,
                closing_value.as_ref(),
            )?);
        }
        let (opening_inner, closing_inner) =
            self.proof
                .roots::<H>(self.start..self.end, &self.positions, &opening, &closing)?;
        if bind_root::<H>(kind, len, &opening_inner) != *opening_root {
            return Err(Error::InvalidOpeningRoot);
        }
        if bind_root::<H>(kind, len, &closing_inner) != *closing_root {
            return Err(Error::HiddenChange);
        }
        Ok(())
    }
}

impl<D: Digest> Write for RangeUpdate<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.start.write(writer);
        self.end.write(writer);
        self.positions.write(writer);
        self.proof.write(writer);
    }
}

impl<D: Digest> EncodeSize for RangeUpdate<D> {
    fn encode_size(&self) -> usize {
        self.start.encode_size()
            + self.end.encode_size()
            + self.positions.encode_size()
            + self.proof.encode_size()
    }
}

impl<D: Digest> Read for RangeUpdate<D> {
    /// `(maximum changed positions, maximum shared hashes, maximum exterior pairs)`.
    type Cfg = (usize, usize, usize);

    fn read_cfg(
        reader: &mut impl Buf,
        (max_positions, max_shared, max_outside): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        let update = Self {
            start: u32::read(reader)?,
            end: u32::read(reader)?,
            positions: Vec::<u32>::read_range(reader, ..=*max_positions)?,
            proof: bmt::RangeUpdateProof::read_cfg(reader, &(*max_shared, *max_outside))?,
        };
        update.validate_shape().map_err(|_| {
            CodecError::Invalid("RangeUpdate", "range update shape is not canonical")
        })?;
        Ok(update)
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for RangeUpdate<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            start: u.arbitrary()?,
            end: u.arbitrary()?,
            positions: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// A bounded BMT proof for one contiguous range of encoded vector values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeOpening<D: Digest> {
    /// Position of the first opened value.
    pub start: u32,
    /// Minimal BMT frontier around the contiguous values.
    pub proof: bmt::Proof<D>,
}

impl<D: Digest> RangeOpening<D> {
    fn validate_shape(&self) -> Result<(), Error> {
        check_len(self.proof.leaf_count)?;
        if self.proof.leaf_count == 0 {
            if self.start != 0 || !self.proof.siblings.is_empty() {
                return Err(Error::MalformedEmpty);
            }
        } else if self.start >= self.proof.leaf_count {
            return Err(Error::NonCanonicalPositions);
        }
        Ok(())
    }

    /// Verifies contiguous encoded values against a domain-separated root.
    pub fn verify<H, B>(
        &self,
        kind: VectorKind,
        root: &VectorRoot<D>,
        encoded_values: &[B],
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        B: AsRef<[u8]>,
    {
        self.validate_shape()?;
        let len = self.proof.leaf_count;
        if encoded_values.is_empty() {
            return if len == 0 && self.start == 0 && *root == empty_root::<H>(kind) {
                Ok(())
            } else {
                Err(Error::MalformedEmpty)
            };
        }
        let count = u32::try_from(encoded_values.len())
            .map_err(|_| Error::TooManyValues(encoded_values.len() as u64))?;
        let end = self
            .start
            .checked_add(count)
            .filter(|end| *end <= len)
            .ok_or(Error::NonCanonicalPositions)?;
        let mut leaves = Vec::with_capacity(encoded_values.len());
        for (position, encoded) in (self.start..end).zip(encoded_values) {
            leaves.push((
                leaf_digest::<H>(kind, len, position, encoded.as_ref())?,
                position,
            ));
        }
        let inner = self
            .proof
            .root_from_multi_inclusion::<H>(&leaves, &Sequential)?;
        if bind_root::<H>(kind, len, &inner) == *root {
            Ok(())
        } else {
            Err(Error::InvalidOpening)
        }
    }

    pub(crate) fn read_bounded(
        reader: &mut impl Buf,
        max_values: usize,
        max_hashes: usize,
    ) -> Result<Self, CodecError> {
        let max_hashes = max_values.saturating_mul(bmt::MAX_LEVELS).min(max_hashes);
        let opening = Self {
            start: u32::read(reader)?,
            proof: bmt::Proof::read_bounded(reader, max_hashes)?,
        };
        opening.validate_shape().map_err(|_| {
            CodecError::Invalid("RangeOpening", "range proof shape is not canonical")
        })?;
        Ok(opening)
    }
}

impl<D: Digest> Write for RangeOpening<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.start.write(writer);
        self.proof.write(writer);
    }
}

impl<D: Digest> EncodeSize for RangeOpening<D> {
    fn encode_size(&self) -> usize {
        self.start.encode_size() + self.proof.encode_size()
    }
}

impl<D: Digest> Read for RangeOpening<D> {
    /// Maximum number of values disclosed by the contiguous range.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, maximum: &Self::Cfg) -> Result<Self, CodecError> {
        Self::read_bounded(reader, *maximum, usize::MAX)
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for RangeOpening<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            start: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// A bounded opening for one encoded vector value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opening<D: Digest> {
    /// Opened vector position.
    pub position: u32,
    /// BMT authentication path.
    pub proof: bmt::Proof<D>,
}

impl<D: Digest> Opening<D> {
    fn validate_shape(&self) -> Result<(), Error> {
        check_len(self.proof.leaf_count)?;
        check_positions(
            core::slice::from_ref(&self.position),
            self.proof.leaf_count,
            false,
        )
    }

    /// Reconstructs the domain-separated vector root authenticated by `encoded`.
    pub fn reconstruct<H: Hasher<Digest = D>>(
        &self,
        kind: VectorKind,
        encoded: &[u8],
    ) -> Result<VectorRoot<D>, Error> {
        let len = self.proof.leaf_count;
        check_len(len)?;
        check_positions(core::slice::from_ref(&self.position), len, false)?;
        let leaf = leaf_digest::<H>(kind, len, self.position, encoded)?;
        let inner = self
            .proof
            .root_from_multi_inclusion::<H>(&[(leaf, self.position)], &Sequential)?;
        Ok(bind_root::<H>(kind, len, &inner))
    }

    /// Verifies one already-encoded value against a typed root.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        kind: VectorKind,
        root: &VectorRoot<D>,
        encoded: &[u8],
    ) -> Result<(), Error> {
        if self.reconstruct::<H>(kind, encoded)? == *root {
            Ok(())
        } else {
            Err(Error::InvalidOpening)
        }
    }
}

impl<D: Digest> Write for Opening<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.position.write(writer);
        self.proof.write(writer);
    }
}

impl<D: Digest> Read for Opening<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let opening = Self {
            position: u32::read(reader)?,
            proof: bmt::Proof::read_cfg(reader, &1)?,
        };
        opening.validate_shape().map_err(|_| {
            CodecError::Invalid("Opening", "opening position or leaf count is invalid")
        })?;
        Ok(opening)
    }
}

impl<D: Digest> EncodeSize for Opening<D> {
    fn encode_size(&self) -> usize {
        self.position.encode_size() + self.proof.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for Opening<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            position: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// A bounded BMT multiproof paired with canonical vector positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiOpening<D: Digest> {
    /// Strictly increasing, unique opened positions.
    pub positions: Vec<u32>,
    /// Shared BMT authentication frontier.
    pub proof: bmt::Proof<D>,
}

impl<D: Digest> MultiOpening<D> {
    fn validate_shape(&self) -> Result<(), Error> {
        check_len(self.proof.leaf_count)?;
        check_positions(&self.positions, self.proof.leaf_count, true)?;
        if self.positions.is_empty()
            && (self.proof.leaf_count != 0 || !self.proof.siblings.is_empty())
        {
            return Err(Error::MalformedEmpty);
        }
        Ok(())
    }

    /// Verifies already-encoded values in the same order as [`Self::positions`].
    pub fn verify<H, B>(
        &self,
        kind: VectorKind,
        root: &VectorRoot<D>,
        encoded_values: &[B],
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        B: AsRef<[u8]>,
    {
        self.validate_shape()?;
        verify_multi_opening::<H, D, B>(kind, &self.positions, &self.proof, root, encoded_values)
    }

    /// Reads a multiproof without allocating more positions than its enclosing object permits.
    pub(crate) fn read_bounded(
        reader: &mut impl Buf,
        max_positions: usize,
    ) -> Result<Self, CodecError> {
        let positions =
            Vec::<u32>::read_range(reader, ..=max_positions.min(MAX_VECTOR_LENGTH as usize))?;
        let proof = bmt::Proof::read_cfg(reader, &positions.len())?;
        let opening = Self { positions, proof };
        opening.validate_shape().map_err(|_| {
            CodecError::Invalid("MultiOpening", "multiproof shape is not canonical")
        })?;
        Ok(opening)
    }
}

pub(crate) fn verify_multi_opening<H, D, B>(
    kind: VectorKind,
    positions: &[u32],
    proof: &bmt::Proof<D>,
    root: &VectorRoot<D>,
    encoded_values: &[B],
) -> Result<(), Error>
where
    H: Hasher<Digest = D>,
    D: Digest,
    B: AsRef<[u8]>,
{
    if positions.len() != encoded_values.len() {
        return Err(Error::OpeningLengthMismatch {
            positions: positions.len(),
            values: encoded_values.len(),
        });
    }
    let len = proof.leaf_count;
    let mut leaves = Vec::with_capacity(positions.len());
    for (&position, encoded) in positions.iter().zip(encoded_values) {
        leaves.push((
            leaf_digest::<H>(kind, len, position, encoded.as_ref())?,
            position,
        ));
    }
    let inner = proof.root_from_multi_inclusion::<H>(&leaves, &Sequential)?;
    if bind_root::<H>(kind, len, &inner) == *root {
        Ok(())
    } else {
        Err(Error::InvalidOpening)
    }
}

impl<D: Digest> Write for MultiOpening<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.positions.write(writer);
        self.proof.write(writer);
    }
}

impl<D: Digest> Read for MultiOpening<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Self::read_bounded(reader, MAX_VECTOR_LENGTH as usize)
    }
}

impl<D: Digest> EncodeSize for MultiOpening<D> {
    fn encode_size(&self) -> usize {
        self.positions.encode_size() + self.proof.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for MultiOpening<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            positions: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// One canonical BMT frontier shared by the opening and closing sides of a sparse update.
///
/// Every omitted subtree is represented by the same sibling digest on both sides. Consequently,
/// successful reconstruction proves that every undisclosed position is unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseUpdate<D: Digest> {
    /// Strictly increasing, unique changed positions.
    pub positions: Vec<u32>,
    /// Shared BMT authentication frontier.
    pub proof: bmt::Proof<D>,
}

impl<D: Digest> SparseUpdate<D> {
    fn validate_shape(&self) -> Result<(), Error> {
        let len = self.proof.leaf_count;
        check_len(len)?;
        check_positions(&self.positions, len, true)?;
        if self.positions.is_empty() && !self.proof.siblings.is_empty() {
            return Err(Error::MalformedEmpty);
        }
        Ok(())
    }

    /// Reconstructs the typed closing root from changed values and the cached opening frontier.
    ///
    /// `closing_values` must correspond one-for-one with [`Self::positions`]. This operation does
    /// not scan dormant leaves. It cannot determine whether a disclosed value changed because no
    /// opening values are supplied; [`Self::verify`] performs that exact-change check.
    pub fn reconstruct_closing<H, C>(
        &self,
        kind: VectorKind,
        closing_values: &[C],
    ) -> Result<VectorRoot<D>, Error>
    where
        H: Hasher<Digest = D>,
        C: AsRef<[u8]>,
    {
        self.validate_shape()?;
        let len = self.proof.leaf_count;
        if self.positions.len() != closing_values.len() {
            return Err(Error::OpeningLengthMismatch {
                positions: self.positions.len(),
                values: closing_values.len(),
            });
        }
        if self.positions.is_empty() {
            return if len == 0 {
                Ok(empty_root::<H>(kind))
            } else {
                Err(Error::MalformedEmpty)
            };
        }

        let mut closing_leaves = Vec::with_capacity(self.positions.len());
        for (&position, closing) in self.positions.iter().zip(closing_values) {
            closing_leaves.push((
                leaf_digest::<H>(kind, len, position, closing.as_ref())?,
                position,
            ));
        }
        let closing_inner = self
            .proof
            .root_from_multi_inclusion::<H>(&closing_leaves, &Sequential)?;
        Ok(bind_root::<H>(kind, len, &closing_inner))
    }

    /// Verifies the exact disclosed transition using one shared BMT proof.
    ///
    /// `opening_values` and `closing_values` must correspond one-for-one with
    /// [`Self::positions`]. Each disclosed value must actually change. An empty update is canonical
    /// only with no siblings and identical roots; an empty vector additionally requires its
    /// canonical domain-separated empty root.
    pub fn verify<H, O, C>(
        &self,
        kind: VectorKind,
        opening_root: &VectorRoot<D>,
        closing_root: &VectorRoot<D>,
        opening_values: &[O],
        closing_values: &[C],
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        O: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        self.validate_shape()?;
        let len = self.proof.leaf_count;
        if self.positions.len() != opening_values.len() {
            return Err(Error::OpeningLengthMismatch {
                positions: self.positions.len(),
                values: opening_values.len(),
            });
        }
        if self.positions.len() != closing_values.len() {
            return Err(Error::OpeningLengthMismatch {
                positions: self.positions.len(),
                values: closing_values.len(),
            });
        }

        if self.positions.is_empty() {
            if opening_root != closing_root {
                return Err(Error::HiddenChange);
            }
            if len == 0 && *opening_root != empty_root::<H>(kind) {
                return Err(Error::InvalidOpeningRoot);
            }
            return Ok(());
        }

        let mut opening_leaves = Vec::with_capacity(self.positions.len());
        for ((&position, opening), closing) in self
            .positions
            .iter()
            .zip(opening_values)
            .zip(closing_values)
        {
            if opening.as_ref() == closing.as_ref() {
                return Err(Error::UnchangedPosition(position));
            }
            opening_leaves.push((
                leaf_digest::<H>(kind, len, position, opening.as_ref())?,
                position,
            ));
        }

        let opening_inner = self
            .proof
            .root_from_multi_inclusion::<H>(&opening_leaves, &Sequential)?;
        if bind_root::<H>(kind, len, &opening_inner) != *opening_root {
            return Err(Error::InvalidOpeningRoot);
        }
        if self.reconstruct_closing::<H, _>(kind, closing_values)? != *closing_root {
            return Err(Error::HiddenChange);
        }
        Ok(())
    }
}

impl<D: Digest> Write for SparseUpdate<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.positions.write(writer);
        self.proof.write(writer);
    }
}

impl<D: Digest> Read for SparseUpdate<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let positions = Vec::<u32>::read_range(reader, ..=MAX_VECTOR_LENGTH as usize)?;
        let proof = bmt::Proof::read_cfg(reader, &positions.len())?;
        let update = Self { positions, proof };
        update.validate_shape().map_err(|_| {
            CodecError::Invalid("SparseUpdate", "sparse update shape is not canonical")
        })?;
        Ok(update)
    }
}

impl<D: Digest> EncodeSize for SparseUpdate<D> {
    fn encode_size(&self) -> usize {
        self.positions.encode_size() + self.proof.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for SparseUpdate<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            positions: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_parallel::{Rayon, Sequential};
    use std::num::NonZeroUsize;

    fn tree(kind: VectorKind, values: &[&[u8]]) -> Tree<Sha256Digest> {
        let mut builder = Builder::<Sha256>::new(kind, values.len() as u32).unwrap();
        for value in values {
            builder.add_encoded(value).unwrap();
        }
        builder.build(&Sequential).unwrap()
    }

    #[test]
    fn roots_bind_kind_length_and_value_order() {
        let values = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
        let state = tree(VectorKind::State, &values).root();
        let change = tree(VectorKind::Change, &values).root();
        let shorter = tree(VectorKind::State, &values[..2]).root();
        let reordered = tree(
            VectorKind::State,
            &[b"b".as_slice(), b"a".as_slice(), b"c".as_slice()],
        )
        .root();
        assert_ne!(state.digest, change.digest);
        assert_ne!(state.digest, shorter.digest);
        assert_ne!(state.digest, reordered.digest);
        assert_ne!(
            empty_root::<Sha256>(VectorKind::State).digest,
            empty_root::<Sha256>(VectorKind::Deposit).digest
        );
    }

    #[test]
    fn bulk_builder_is_strategy_independent_and_failure_atomic() {
        let values = (0..257_u64).collect::<Vec<_>>();
        let mut scalar = Builder::<Sha256>::new(VectorKind::Change, 257).unwrap();
        for value in &values {
            scalar.add_encoded(value.encode().as_ref()).unwrap();
        }
        let scalar = scalar.build(&Sequential).unwrap();

        let parallel = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();
        let mut bulk = Builder::<Sha256>::new(VectorKind::Change, 257).unwrap();
        bulk.add_values(&values, &parallel).unwrap();
        let bulk = bulk.build(&parallel).unwrap();
        assert_eq!(bulk.root(), scalar.root());
        assert_eq!(
            bulk.multi_opening(&[0, 128, 256]).unwrap(),
            scalar.multi_opening(&[0, 128, 256]).unwrap()
        );

        let mut bounded = Builder::<Sha256>::new(VectorKind::Change, 1).unwrap();
        assert!(bounded.add_values(&values[..2], &Sequential).is_err());
        bounded.add_values(&values[..1], &Sequential).unwrap();
        assert!(bounded.build(&Sequential).is_ok());
    }

    #[test]
    fn single_and_multi_openings_are_bounded_and_canonical() {
        let values = [
            b"zero".as_slice(),
            b"one".as_slice(),
            b"two".as_slice(),
            b"three".as_slice(),
            b"four".as_slice(),
        ];
        let tree = tree(VectorKind::Change, &values);
        let root = tree.root();
        let opening = tree.opening(4).unwrap();
        opening
            .verify::<Sha256>(VectorKind::Change, &root, values[4])
            .unwrap();
        assert!(
            opening
                .verify::<Sha256>(VectorKind::Change, &root, b"tampered")
                .is_err()
        );

        let multi = tree.multi_opening(&[0, 2, 4]).unwrap();
        multi
            .verify::<Sha256, _>(
                VectorKind::Change,
                &root,
                &[values[0], values[2], values[4]],
            )
            .unwrap();
        assert!(tree.multi_opening(&[2, 2]).is_err());
        assert!(tree.multi_opening(&[4, 2]).is_err());
        assert!(tree.multi_opening(&[5]).is_err());

        let encoded = multi.encode();
        assert_eq!(MultiOpening::decode(encoded).unwrap(), multi);
    }

    #[test]
    fn contiguous_range_opening_binds_position_length_and_values() {
        let values = [
            b"zero".as_slice(),
            b"one".as_slice(),
            b"two".as_slice(),
            b"three".as_slice(),
            b"four".as_slice(),
        ];
        let change_tree = tree(VectorKind::Change, &values);
        let root = change_tree.root();
        let opening = change_tree.range_opening(1, 3).unwrap();
        opening
            .verify::<Sha256, _>(VectorKind::Change, &root, &values[1..4])
            .unwrap();
        assert!(
            opening
                .verify::<Sha256, _>(VectorKind::Change, &root, &values[0..3])
                .is_err()
        );
        assert!(
            opening
                .verify::<Sha256, _>(VectorKind::Change, &root, &values[1..3])
                .is_err()
        );
        assert!(change_tree.range_opening(4, 2).is_err());
        assert!(change_tree.range_opening(1, 0).is_err());

        let encoded = opening.encode();
        assert_eq!(RangeOpening::decode_cfg(encoded, &3).unwrap(), opening);

        let empty = tree(VectorKind::Change, &[]);
        let opening = empty.range_opening(0, 0).unwrap();
        opening
            .verify::<Sha256, &[u8]>(VectorKind::Change, &empty.root(), &[])
            .unwrap();
    }

    #[test]
    fn paired_range_updates_prove_each_exhaustive_interval() {
        let opening_values = [
            b"a".as_slice(),
            b"b".as_slice(),
            b"c".as_slice(),
            b"d".as_slice(),
            b"e".as_slice(),
        ];
        let closing_values = [
            b"a".as_slice(),
            b"B".as_slice(),
            b"c".as_slice(),
            b"D".as_slice(),
            b"e".as_slice(),
        ];
        let opening_tree = tree(VectorKind::State, &opening_values);
        let closing_tree = tree(VectorKind::State, &closing_values);
        let (closing_root, ranges) = opening_tree
            .range_updates::<Sha256, _>(
                &[1, 3],
                &[closing_values[1], closing_values[3]],
                &[0, 2, 5],
                &Sequential,
            )
            .unwrap();
        let parallel = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();
        let (parallel_root, parallel_ranges) = opening_tree
            .range_updates::<Sha256, _>(
                &[1, 3],
                &[closing_values[1], closing_values[3]],
                &[0, 2, 5],
                &parallel,
            )
            .unwrap();
        assert_eq!(closing_root, closing_tree.root());
        assert_eq!(parallel_root, closing_root);
        assert_eq!(parallel_ranges, ranges);
        assert_eq!(ranges.len(), 2);
        ranges[0]
            .verify::<Sha256, _, _>(
                VectorKind::State,
                &opening_tree.root(),
                &closing_root,
                &[opening_values[1]],
                &[closing_values[1]],
            )
            .unwrap();
        ranges[1]
            .verify::<Sha256, _, _>(
                VectorKind::State,
                &opening_tree.root(),
                &closing_root,
                &[opening_values[3]],
                &[closing_values[3]],
            )
            .unwrap();

        let mut hidden = ranges[0].clone();
        hidden.positions.clear();
        assert!(
            hidden
                .verify::<Sha256, &[u8], &[u8]>(
                    VectorKind::State,
                    &opening_tree.root(),
                    &closing_root,
                    &[],
                    &[],
                )
                .is_err()
        );
    }

    #[test]
    fn sparse_update_proves_exact_shared_frontier() {
        let opening_values = [
            b"a".as_slice(),
            b"b".as_slice(),
            b"c".as_slice(),
            b"d".as_slice(),
            b"e".as_slice(),
        ];
        let closing_values = [
            b"A".as_slice(),
            b"b".as_slice(),
            b"c".as_slice(),
            b"D".as_slice(),
            b"e".as_slice(),
        ];
        let opening = tree(VectorKind::State, &opening_values);
        let closing = tree(VectorKind::State, &closing_values);
        let update = opening.sparse_update(&[0, 3]).unwrap();
        update
            .verify::<Sha256, _, _>(
                VectorKind::State,
                &opening.root(),
                &closing.root(),
                &[opening_values[0], opening_values[3]],
                &[closing_values[0], closing_values[3]],
            )
            .unwrap();

        assert!(matches!(
            update.verify::<Sha256, _, _>(
                VectorKind::State,
                &opening.root(),
                &closing.root(),
                &[opening_values[0], opening_values[3]],
                &[closing_values[0], b"wrong".as_slice()],
            ),
            Err(Error::HiddenChange)
        ));

        let hidden_values = [
            b"A".as_slice(),
            b"hidden".as_slice(),
            b"c".as_slice(),
            b"D".as_slice(),
            b"e".as_slice(),
        ];
        let hidden = tree(VectorKind::State, &hidden_values);
        assert!(matches!(
            update.verify::<Sha256, _, _>(
                VectorKind::State,
                &opening.root(),
                &hidden.root(),
                &[opening_values[0], opening_values[3]],
                &[hidden_values[0], hidden_values[3]],
            ),
            Err(Error::HiddenChange)
        ));
    }

    #[test]
    fn sparse_update_binds_kind_length_and_empty_shape() {
        let values = [b"a".as_slice()];
        let state = tree(VectorKind::State, &values);
        let update = state.sparse_update(&[]).unwrap();
        update
            .verify::<Sha256, &[u8], &[u8]>(
                VectorKind::State,
                &state.root(),
                &state.root(),
                &[],
                &[],
            )
            .unwrap();

        let change = tree(VectorKind::Change, &values);
        assert!(
            update
                .verify::<Sha256, &[u8], &[u8]>(
                    VectorKind::Change,
                    &state.root(),
                    &change.root(),
                    &[],
                    &[],
                )
                .is_err()
        );

        let empty = tree(VectorKind::State, &[]);
        let mut empty_update = empty.sparse_update(&[]).unwrap();
        empty_update.proof.siblings.push(Sha256::hash(&[b"extra"]));
        assert!(matches!(
            empty_update.verify::<Sha256, &[u8], &[u8]>(
                VectorKind::State,
                &empty.root(),
                &empty.root(),
                &[],
                &[],
            ),
            Err(Error::MalformedEmpty)
        ));
    }
}
