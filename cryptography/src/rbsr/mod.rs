//! Range-Based Set Reconciliation (RBSR) for efficient bi-directional set synchronization.
//!
//! This module implements the Negentropy protocol for comparing and reconciling
//! sets between two participants. RBSR uses a divide-and-conquer approach where
//! participants exchange fingerprints of ranges, recursively splitting non-matching
//! ranges until differences are identified.
//!
//! # Bi-directional Reconciliation
//!
//! RBSR is **bi-directional**: both participants independently discover items
//! they're missing. Each side runs their own reconciler and learns what to fetch
//! from the remote. The remote does the same and will request what they need.
//!
//! The protocol is symmetric; the only difference is who sends the first message.
//!
//! # Overview
//!
//! RBSR works by:
//! 1. Ordering items by hint (ordering key), then by ID
//! 2. Computing fingerprints over ranges of items
//! 3. Exchanging range fingerprints between participants
//! 4. Recursively splitting ranges where fingerprints differ
//! 5. Exchanging ID lists once ranges become small enough
//!
//! # Item Identity
//!
//! Items are identified by their **ID only**, not by (hint, ID). The hint
//! is used purely for ordering and partitioning the search space. This means:
//!
//! - Two items with the same ID are considered identical, even with different hints
//! - Hints do not need to be unique; multiple items can share the same hint
//! - Items are sorted by (hint, ID) for efficient range queries
//!
//! The hint can be any `u64` value: Unix timestamps, block heights, sequence numbers,
//! Lamport clocks, etc. This design is ideal for content-addressed data where the ID
//! is a hash of the content. If your use case requires (hint, ID) identity, include
//! the hint in your ID hash.
//!
//! # Properties
//!
//! - **Bi-directional**: Both sides independently discover what they're missing
//! - **Efficient**: Round-trips scale logarithmically with set size (log_B(N) / 2)
//! - **Flexible**: No rigid tree structure required; implementations can vary
//! - **Stateless**: No per-connection state required between messages
//! - **DoS Resistant**: Fingerprint computation is deterministic
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::rbsr::{Item, Reconciler, VecStorage};
//!
//! // Create storage for participant A (has items 1 and 2)
//! let mut storage_a = VecStorage::new();
//! storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
//! storage_a.insert(Item::from_bytes(1001, [0x02; 32]));
//!
//! // Create storage for participant B (has items 1 and 3)
//! let mut storage_b = VecStorage::new();
//! storage_b.insert(Item::from_bytes(1000, [0x01; 32]));
//! storage_b.insert(Item::from_bytes(1002, [0x03; 32]));
//!
//! // Participant A initiates reconciliation
//! let mut reconciler_a = Reconciler::new(&storage_a, 16);
//! let msg1 = reconciler_a.initiate();
//!
//! // Exchange messages, collecting missing IDs from each round
//! let mut reconciler_b = Reconciler::new(&storage_b, 16);
//! let (msg2, b_missing) = reconciler_b.reconcile(&msg1).unwrap();
//! let (msg3, a_missing) = reconciler_a.reconcile(&msg2).unwrap();
//! let (_, b_missing_2) = reconciler_b.reconcile(&msg3).unwrap();
//!
//! // A is missing [0x03], B is missing [0x02]
//! assert!(a_missing.contains(&[0x03; 32].into()));
//! assert!(b_missing.contains(&[0x02; 32].into()) || b_missing_2.contains(&[0x02; 32].into()));
//! ```
//!
//! # Acknowledgements
//!
//! This implementation is based on:
//! - <https://logperiodic.com/rbsr.html>: Range-Based Set Reconciliation overview
//! - <https://github.com/hoytech/negentropy>: Negentropy reference implementation
//! - <https://arxiv.org/abs/2212.13567>: Range-Based Set Reconciliation paper

use crate::blake3::Digest;
use crate::lthash::LtHash;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Error as CodecError, FixedSize, Read, ReadExt, Write};

/// Size of an item ID in bytes (32-byte digest).
pub const ID_SIZE: usize = Digest::SIZE;

/// Maximum hint value, used as "infinity" bound.
pub const MAX_HINT: u64 = u64::MAX;

/// Default branching factor for range splitting.
pub const DEFAULT_BRANCHING_FACTOR: usize = 16;

/// An item in the set, consisting of a hint (ordering key) and a 32-byte ID.
///
/// Items are ordered first by hint, then lexicographically by ID.
/// The hint is only used for ordering; item identity is determined solely by ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Item {
    /// Ordering hint (e.g., timestamp, block height, sequence number)
    pub hint: u64,
    /// Unique identifier, typically a cryptographic hash of the item content
    pub id: Digest,
}

impl Item {
    /// Create a new item with the given hint and ID.
    pub const fn new(hint: u64, id: Digest) -> Self {
        Self { hint, id }
    }

    /// Create a new item from a hint and raw bytes.
    pub const fn from_bytes(hint: u64, id: [u8; ID_SIZE]) -> Self {
        Self {
            hint,
            id: Digest(id),
        }
    }
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.hint.cmp(&other.hint) {
            core::cmp::Ordering::Equal => self.id.as_ref().cmp(other.id.as_ref()),
            ord => ord,
        }
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Write for Item {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.hint).write(buf);
        self.id.write(buf);
    }
}

impl Read for Item {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let hint = UInt::<u64>::read(buf)?.into();
        let id = Digest::read(buf)?;
        Ok(Self { hint, id })
    }
}

/// A bound representing the upper limit of a range.
///
/// Bounds consist of a hint and an ID prefix. The prefix can be truncated
/// to the minimum bytes needed for uniqueness, reducing message size.
/// An empty prefix represents zero (hint=0) or infinity (hint=MAX_HINT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// Hint component of the bound
    pub hint: u64,
    /// ID prefix (can be empty or truncated for efficiency)
    pub id_prefix: Vec<u8>,
}

impl Bound {
    /// Create a new bound with the given hint and full ID.
    pub fn new(hint: u64, id: Digest) -> Self {
        Self {
            hint,
            id_prefix: id.as_ref().to_vec(),
        }
    }

    /// Create a bound representing positive infinity.
    pub const fn infinity() -> Self {
        Self {
            hint: MAX_HINT,
            id_prefix: Vec::new(),
        }
    }

    /// Create a bound representing negative infinity (minimum).
    pub const fn zero() -> Self {
        Self {
            hint: 0,
            id_prefix: Vec::new(),
        }
    }

    /// Check if this bound represents infinity.
    pub const fn is_infinity(&self) -> bool {
        self.hint == MAX_HINT && self.id_prefix.is_empty()
    }

    /// Compare this bound against an item.
    /// Returns Ordering::Less if bound < item, etc.
    pub fn cmp_item(&self, item: &Item) -> core::cmp::Ordering {
        match self.hint.cmp(&item.hint) {
            core::cmp::Ordering::Equal => {
                // Compare prefix against item ID up to prefix length
                let prefix_len = self.id_prefix.len().min(ID_SIZE);
                if prefix_len == 0 {
                    // Empty prefix is less than any ID
                    core::cmp::Ordering::Less
                } else {
                    self.id_prefix[..prefix_len].cmp(&item.id.as_ref()[..prefix_len])
                }
            }
            ord => ord,
        }
    }

    /// Check if an item is less than this bound.
    pub fn item_below(&self, item: &Item) -> bool {
        self.cmp_item(item) == core::cmp::Ordering::Greater
    }
}

impl Write for Bound {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.hint).write(buf);
        (self.id_prefix.len() as u8).write(buf);
        buf.put_slice(&self.id_prefix);
    }
}

impl Read for Bound {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let hint = UInt::<u64>::read(buf)?.into();
        let prefix_len = u8::read(buf)? as usize;
        if prefix_len > ID_SIZE {
            return Err(CodecError::Invalid(
                "Bound",
                "id_prefix length exceeds ID_SIZE",
            ));
        }
        if buf.remaining() < prefix_len {
            return Err(CodecError::EndOfBuffer);
        }
        let mut id_prefix = vec![0u8; prefix_len];
        buf.copy_to_slice(&mut id_prefix);
        Ok(Self { hint, id_prefix })
    }
}

/// A fingerprint computed over a range of items.
///
/// Fingerprints use the full 32-byte [LtHash] checksum, providing ~200 bits of
/// security against collision attacks.
pub type Fingerprint = Digest;

/// Accumulator for computing fingerprints incrementally.
///
/// Uses [LtHash] for ~200 bits of security against collision attacks. LtHash is a
/// lattice-based homomorphic hash that is significantly more secure than simple
/// addition mod 2^256 (which can be broken in ~28 hours with sufficient resources).
pub type FingerprintAccumulator = LtHash;

/// Mode of a range in a reconciliation message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeMode {
    /// Skip this range (no processing needed).
    Skip,
    /// Fingerprint for comparison.
    Fingerprint(Fingerprint),
    /// List of item IDs in this range.
    IdList(Vec<Digest>),
}

impl RangeMode {
    const MODE_SKIP: u8 = 0;
    const MODE_FINGERPRINT: u8 = 1;
    const MODE_ID_LIST: u8 = 2;
}

impl Write for RangeMode {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Skip => {
                Self::MODE_SKIP.write(buf);
            }
            Self::Fingerprint(fp) => {
                Self::MODE_FINGERPRINT.write(buf);
                fp.write(buf);
            }
            Self::IdList(ids) => {
                Self::MODE_ID_LIST.write(buf);
                (ids.len() as u32).write(buf);
                for id in ids {
                    id.write(buf);
                }
            }
        }
    }
}

impl Read for RangeMode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let mode = u8::read(buf)?;
        match mode {
            Self::MODE_SKIP => Ok(Self::Skip),
            Self::MODE_FINGERPRINT => {
                let fp = Fingerprint::read(buf)?;
                Ok(Self::Fingerprint(fp))
            }
            Self::MODE_ID_LIST => {
                let count = u32::read(buf)? as usize;
                let mut ids = Vec::with_capacity(count);
                for _ in 0..count {
                    ids.push(Digest::read(buf)?);
                }
                Ok(Self::IdList(ids))
            }
            _ => Err(CodecError::InvalidEnum(mode)),
        }
    }
}

/// A range in a reconciliation message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    /// Upper bound of this range (lower bound is implicit from previous range)
    pub upper_bound: Bound,
    /// Mode and payload for this range
    pub mode: RangeMode,
}

impl Range {
    /// Create a new range with the given upper bound and mode.
    pub const fn new(upper_bound: Bound, mode: RangeMode) -> Self {
        Self { upper_bound, mode }
    }

    /// Create a skip range to infinity.
    pub const fn skip_to_infinity() -> Self {
        Self {
            upper_bound: Bound::infinity(),
            mode: RangeMode::Skip,
        }
    }
}

impl Write for Range {
    fn write(&self, buf: &mut impl BufMut) {
        self.upper_bound.write(buf);
        self.mode.write(buf);
    }
}

impl Read for Range {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let upper_bound = Bound::read(buf)?;
        let mode = RangeMode::read(buf)?;
        Ok(Self { upper_bound, mode })
    }
}

/// A reconciliation message containing ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Ranges in this message
    pub ranges: Vec<Range>,
}

impl Message {
    /// Create a new message with the given ranges.
    pub const fn new(ranges: Vec<Range>) -> Self {
        Self { ranges }
    }

    /// Check if this message represents completion (all ranges are Skip).
    ///
    /// The protocol is complete when all ranges have been resolved to Skip,
    /// meaning no further processing is needed.
    pub fn is_complete(&self) -> bool {
        if self.ranges.is_empty() {
            return false;
        }
        // Complete if all ranges are Skip and the last one reaches infinity
        self.ranges
            .iter()
            .all(|r| matches!(r.mode, RangeMode::Skip))
            && self
                .ranges
                .last()
                .is_some_and(|r| r.upper_bound.is_infinity())
    }
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.ranges.len() as u64).write(buf);
        for range in &self.ranges {
            range.write(buf);
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let count: u64 = UInt::read(buf)?.into();
        let mut ranges = Vec::with_capacity(count as usize);
        for _ in 0..count {
            ranges.push(Range::read(buf)?);
        }
        Ok(Self { ranges })
    }
}

/// Error type for reconciliation operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid message format
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),
    /// Codec error
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
}

/// Trait for item storage backends.
///
/// Implementations must maintain items in sorted order (by hint, then ID).
pub trait Storage {
    /// Get the number of items in storage.
    fn len(&self) -> usize;

    /// Check if storage is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get item at the given index (must be in sorted order).
    fn get(&self, index: usize) -> Option<&Item>;

    /// Find the index of the first item >= the given bound.
    fn lower_bound(&self, bound: &Bound) -> usize;

    /// Compute fingerprint over items in range [start_idx, end_idx).
    fn fingerprint(&self, start_idx: usize, end_idx: usize) -> Fingerprint {
        let mut acc = FingerprintAccumulator::new();
        for i in start_idx..end_idx {
            if let Some(item) = self.get(i) {
                acc.add(item.id.as_ref());
            }
        }
        acc.checksum()
    }

    /// Get IDs of items in range [start_idx, end_idx).
    fn ids_in_range(&self, start_idx: usize, end_idx: usize) -> Vec<Digest> {
        let mut ids = Vec::with_capacity(end_idx.saturating_sub(start_idx));
        for i in start_idx..end_idx {
            if let Some(item) = self.get(i) {
                ids.push(item.id);
            }
        }
        ids
    }
}

/// In-memory vector-based storage implementation.
#[derive(Debug, Clone, Default)]
pub struct VecStorage {
    items: Vec<Item>,
}

impl VecStorage {
    /// Create new empty storage.
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Create storage with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Insert an item, maintaining sorted order.
    pub fn insert(&mut self, item: Item) {
        let pos = self.items.partition_point(|i| i < &item);
        // Don't insert duplicates
        if pos < self.items.len() && self.items[pos] == item {
            return;
        }
        self.items.insert(pos, item);
    }

    /// Remove an item if it exists.
    pub fn remove(&mut self, item: &Item) -> bool {
        if let Ok(pos) = self.items.binary_search(item) {
            self.items.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if storage contains an item with the given ID.
    pub fn contains_id(&self, id: &Digest) -> bool {
        self.items.iter().any(|item| &item.id == id)
    }

    /// Get an iterator over all items.
    pub fn iter(&self) -> impl Iterator<Item = &Item> {
        self.items.iter()
    }

    /// Clear all items.
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

impl Storage for VecStorage {
    fn len(&self) -> usize {
        self.items.len()
    }

    fn get(&self, index: usize) -> Option<&Item> {
        self.items.get(index)
    }

    fn lower_bound(&self, bound: &Bound) -> usize {
        if bound.hint == 0 && bound.id_prefix.is_empty() {
            return 0;
        }
        self.items.partition_point(|item| bound.item_below(item))
    }
}

/// Reconciler for bi-directional set reconciliation.
///
/// Each participant discovers items they're missing from the remote.
/// Missing IDs are returned from each `reconcile()` call as they're discovered.
/// The protocol is symmetric; the only difference is who initiates.
///
/// Since reconciliation is bi-directional, the remote peer runs their own
/// reconciler and discovers what they're missing independently.
pub struct Reconciler<'a, S: Storage> {
    storage: &'a S,
    branching_factor: usize,
    /// Whether we are the initiator (affects how we respond to IdList)
    is_initiator: bool,
}

impl<'a, S: Storage> Reconciler<'a, S> {
    /// Create a new reconciler with the given storage and branching factor.
    pub fn new(storage: &'a S, branching_factor: usize) -> Self {
        Self {
            storage,
            branching_factor: branching_factor.max(2),
            is_initiator: false,
        }
    }

    /// Create a new reconciler with default branching factor.
    pub fn with_default_branching(storage: &'a S) -> Self {
        Self::new(storage, DEFAULT_BRANCHING_FACTOR)
    }

    /// Initiate reconciliation (client/initiator side).
    ///
    /// Returns the first message to send to the remote.
    pub fn initiate(&mut self) -> Message {
        self.is_initiator = true;
        // Send fingerprint for entire range
        let fp = self.storage.fingerprint(0, self.storage.len());
        Message::new(vec![Range::new(
            Bound::infinity(),
            RangeMode::Fingerprint(fp),
        )])
    }

    /// Process a received message and generate a response.
    ///
    /// Returns the response message and any missing IDs discovered in this round.
    pub fn reconcile(&mut self, msg: &Message) -> Result<(Message, Vec<Digest>), Error> {
        let mut response_ranges = Vec::new();
        let mut missing = Vec::new();
        let mut current_idx = 0;

        for range in &msg.ranges {
            let end_idx = self.storage.lower_bound(&range.upper_bound);

            match &range.mode {
                RangeMode::Skip => {
                    // Remote says skip, we skip too
                    response_ranges.push(Range::new(range.upper_bound.clone(), RangeMode::Skip));
                }
                RangeMode::Fingerprint(remote_fp) => {
                    let local_fp = self.storage.fingerprint(current_idx, end_idx);
                    let item_count = end_idx - current_idx;

                    if local_fp == *remote_fp {
                        // Fingerprints match, skip this range
                        response_ranges
                            .push(Range::new(range.upper_bound.clone(), RangeMode::Skip));
                    } else if item_count <= self.branching_factor {
                        // Small enough range, send ID list
                        let ids = self.storage.ids_in_range(current_idx, end_idx);
                        response_ranges.push(Range::new(
                            range.upper_bound.clone(),
                            RangeMode::IdList(ids),
                        ));
                    } else {
                        // Split into sub-ranges
                        self.split_range(
                            current_idx,
                            end_idx,
                            &range.upper_bound,
                            &mut response_ranges,
                        );
                    }
                }
                RangeMode::IdList(remote_ids) => {
                    // Compare ID lists to find what we're missing
                    let local_ids = self.storage.ids_in_range(current_idx, end_idx);

                    // Find IDs remote has that we don't
                    for remote_id in remote_ids {
                        if !local_ids.contains(remote_id) {
                            missing.push(*remote_id);
                        }
                    }

                    // Response depends on role:
                    // - Initiator receiving IdList: send our IdList so responder can compare
                    // - Responder receiving IdList: this completes the exchange, reply with Skip
                    if self.is_initiator {
                        response_ranges.push(Range::new(
                            range.upper_bound.clone(),
                            RangeMode::IdList(local_ids),
                        ));
                    } else {
                        response_ranges
                            .push(Range::new(range.upper_bound.clone(), RangeMode::Skip));
                    }
                }
            }

            current_idx = end_idx;
        }

        Ok((Message::new(response_ranges), missing))
    }

    /// Split a range into sub-ranges with fingerprints.
    fn split_range(
        &self,
        start_idx: usize,
        end_idx: usize,
        final_bound: &Bound,
        ranges: &mut Vec<Range>,
    ) {
        let count = end_idx - start_idx;
        let chunk_size = count.div_ceil(self.branching_factor);

        let mut current = start_idx;
        while current < end_idx {
            let chunk_end = (current + chunk_size).min(end_idx);
            let fp = self.storage.fingerprint(current, chunk_end);

            let bound = if chunk_end >= end_idx {
                // Last chunk uses the original bound
                final_bound.clone()
            } else if let Some(item) = self.storage.get(chunk_end) {
                // Use the item at chunk_end as the bound
                Bound::new(item.hint, item.id)
            } else {
                final_bound.clone()
            };

            ranges.push(Range::new(bound, RangeMode::Fingerprint(fp)));
            current = chunk_end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_item_ordering() {
        let a = Item::from_bytes(1000, [0x01; 32]);
        let b = Item::from_bytes(1000, [0x02; 32]);
        let c = Item::from_bytes(1001, [0x01; 32]);

        assert!(a < b); // Same hint, compare by ID
        assert!(b < c); // Different hint
        assert!(a < c);
    }

    #[test]
    fn test_item_codec() {
        let item = Item::from_bytes(12345, [0xAB; 32]);
        let mut buf = Vec::new();
        item.write(&mut buf);

        let decoded = Item::read(&mut &buf[..]).unwrap();
        assert_eq!(item, decoded);
    }

    #[test]
    fn test_bound_comparison() {
        let bound = Bound::new(1000, Digest([0x50; 32]));
        let item_below = Item::from_bytes(999, [0xFF; 32]);
        let item_at = Item::from_bytes(1000, [0x50; 32]);
        let item_above = Item::from_bytes(1000, [0x51; 32]);

        assert!(bound.item_below(&item_below));
        assert!(!bound.item_below(&item_at));
        assert!(!bound.item_below(&item_above));
    }

    #[test]
    fn test_fingerprint_accumulator() {
        let mut acc1 = FingerprintAccumulator::new();
        acc1.add(&[0x01; 32]);
        acc1.add(&[0x02; 32]);

        let mut acc2 = FingerprintAccumulator::new();
        acc2.add(&[0x02; 32]);
        acc2.add(&[0x01; 32]);

        // Order shouldn't matter (addition is commutative)
        assert_eq!(acc1.checksum(), acc2.checksum());
    }

    #[test]
    fn test_fingerprint_subtract() {
        let mut acc = FingerprintAccumulator::new();
        acc.add(&[0x01; 32]);
        acc.add(&[0x02; 32]);
        acc.add(&[0x03; 32]);
        acc.subtract(&[0x02; 32]);

        let mut acc2 = FingerprintAccumulator::new();
        acc2.add(&[0x01; 32]);
        acc2.add(&[0x03; 32]);

        assert_eq!(acc.checksum(), acc2.checksum());
    }

    #[test]
    fn test_fingerprint_combine() {
        let mut acc1 = FingerprintAccumulator::new();
        acc1.add(&[0x01; 32]);

        let mut acc2 = FingerprintAccumulator::new();
        acc2.add(&[0x02; 32]);

        acc1.combine(&acc2);

        let mut expected = FingerprintAccumulator::new();
        expected.add(&[0x01; 32]);
        expected.add(&[0x02; 32]);

        assert_eq!(acc1.checksum(), expected.checksum());
    }

    #[test]
    fn test_vec_storage_insert() {
        let mut storage = VecStorage::new();
        storage.insert(Item::from_bytes(1002, [0x03; 32]));
        storage.insert(Item::from_bytes(1000, [0x01; 32]));
        storage.insert(Item::from_bytes(1001, [0x02; 32]));

        // Should be sorted
        assert_eq!(storage.get(0).unwrap().hint, 1000);
        assert_eq!(storage.get(1).unwrap().hint, 1001);
        assert_eq!(storage.get(2).unwrap().hint, 1002);
    }

    #[test]
    fn test_vec_storage_no_duplicates() {
        let mut storage = VecStorage::new();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));
        storage.insert(Item::from_bytes(1000, [0x01; 32])); // Duplicate

        assert_eq!(storage.len(), 1);
    }

    #[test]
    fn test_vec_storage_lower_bound() {
        let mut storage = VecStorage::new();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));
        storage.insert(Item::from_bytes(1001, [0x02; 32]));
        storage.insert(Item::from_bytes(1002, [0x03; 32]));

        let bound = Bound::new(1001, Digest([0x02; 32]));
        let idx = storage.lower_bound(&bound);
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_identical_sets_reconciliation() {
        // Two identical sets should complete in one round
        let mut storage_a = VecStorage::new();
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_a.insert(Item::from_bytes(1001, [0x02; 32]));

        let mut storage_b = VecStorage::new();
        storage_b.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_b.insert(Item::from_bytes(1001, [0x02; 32]));

        let mut reconciler_a = Reconciler::new(&storage_a, 4);
        let msg1 = reconciler_a.initiate();

        let mut reconciler_b = Reconciler::new(&storage_b, 4);
        let (msg2, missing_b) = reconciler_b.reconcile(&msg1).unwrap();

        // Should be a skip response since fingerprints match
        assert!(msg2.ranges[0].upper_bound.is_infinity());
        assert!(matches!(msg2.ranges[0].mode, RangeMode::Skip));

        let (msg3, missing_a) = reconciler_a.reconcile(&msg2).unwrap();
        assert!(msg3.is_complete());

        // No missing items since sets are identical
        assert!(missing_a.is_empty());
        assert!(missing_b.is_empty());
    }

    #[test]
    fn test_different_sets_reconciliation() {
        // A has item that B doesn't, B has item that A doesn't
        let mut storage_a = VecStorage::new();
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_a.insert(Item::from_bytes(1001, [0x02; 32])); // Only A has this

        let mut storage_b = VecStorage::new();
        storage_b.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_b.insert(Item::from_bytes(1002, [0x03; 32])); // Only B has this

        let mut reconciler_a = Reconciler::new(&storage_a, 4);
        let msg1 = reconciler_a.initiate();

        let mut reconciler_b = Reconciler::new(&storage_b, 4);
        let (msg2, _) = reconciler_b.reconcile(&msg1).unwrap();

        // A receives B's IdList, compares, sends its own IdList
        let (msg3, missing_a) = reconciler_a.reconcile(&msg2).unwrap();

        // B receives A's IdList, compares, sends Skip (completing the exchange)
        let (msg4, missing_b) = reconciler_b.reconcile(&msg3).unwrap();
        assert!(msg4.is_complete());

        // A should know it's missing [0x03]
        assert!(missing_a.contains(&Digest([0x03; 32])));

        // B should know it's missing [0x02]
        assert!(missing_b.contains(&Digest([0x02; 32])));
    }

    #[test]
    fn test_empty_set_reconciliation() {
        let storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();
        storage_b.insert(Item::from_bytes(1000, [0x01; 32]));

        let mut reconciler_a = Reconciler::new(&storage_a, 4);
        let msg1 = reconciler_a.initiate();

        let mut reconciler_b = Reconciler::new(&storage_b, 4);
        let (msg2, _) = reconciler_b.reconcile(&msg1).unwrap();

        let (_, missing_a) = reconciler_a.reconcile(&msg2).unwrap();

        // A should know it's missing the item B has
        assert!(!missing_a.is_empty());
    }

    #[test]
    fn test_message_codec() {
        let msg = Message::new(vec![
            Range::new(
                Bound::new(1000, Digest([0x50; 32])),
                RangeMode::Fingerprint(Fingerprint::from([0xAB; 32])),
            ),
            Range::new(Bound::infinity(), RangeMode::Skip),
        ]);

        let mut buf = Vec::new();
        msg.write(&mut buf);

        let decoded = Message::read(&mut &buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_range_mode_codec() {
        // Test Skip
        let skip = RangeMode::Skip;
        let mut buf = Vec::new();
        skip.write(&mut buf);
        let decoded = RangeMode::read(&mut &buf[..]).unwrap();
        assert_eq!(skip, decoded);

        // Test Fingerprint
        let fp = RangeMode::Fingerprint(Fingerprint::from([0x12; 32]));
        buf.clear();
        fp.write(&mut buf);
        let decoded = RangeMode::read(&mut &buf[..]).unwrap();
        assert_eq!(fp, decoded);

        // Test IdList
        let ids = RangeMode::IdList(vec![Digest([0x01; 32]), Digest([0x02; 32])]);
        buf.clear();
        ids.write(&mut buf);
        let decoded = RangeMode::read(&mut &buf[..]).unwrap();
        assert_eq!(ids, decoded);
    }

    #[test]
    fn test_large_set_reconciliation() {
        // Test with larger sets
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Add 100 items to both, with 10 unique to each
        for i in 0u64..100 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            storage_a.insert(Item::from_bytes(i * 10, id));
            storage_b.insert(Item::from_bytes(i * 10, id));
        }

        // Add unique items to A
        for i in 100u64..110 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            storage_a.insert(Item::from_bytes(i * 10, id));
        }

        // Add unique items to B
        for i in 110u64..120 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            storage_b.insert(Item::from_bytes(i * 10, id));
        }

        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();
        let mut rounds = 0;
        let mut missing_a = Vec::new();
        let mut missing_b = Vec::new();
        const MAX_ROUNDS: usize = 50;

        while !msg.is_complete() && rounds < MAX_ROUNDS {
            let (next_msg, found) = reconciler_b.reconcile(&msg).unwrap();
            missing_b.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                break;
            }
            let (next_msg, found) = reconciler_a.reconcile(&msg).unwrap();
            missing_a.extend(found);
            msg = next_msg;
            rounds += 1;
        }

        // Should complete (logarithmic in set size)
        assert!(
            rounds < MAX_ROUNDS,
            "reconciliation did not complete in {} rounds",
            MAX_ROUNDS
        );

        // Check that differences were found
        // A should be missing the 10 items unique to B
        // B should be missing the 10 items unique to A
        assert!(missing_a.len() + missing_b.len() > 0);
    }

    #[test]
    fn test_fingerprint_determinism() {
        let mut storage = VecStorage::new();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));
        storage.insert(Item::from_bytes(1001, [0x02; 32]));

        let fp1 = storage.fingerprint(0, 2);
        let fp2 = storage.fingerprint(0, 2);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_bound_infinity() {
        let inf = Bound::infinity();
        assert!(inf.is_infinity());

        let not_inf = Bound::new(1000, Digest([0x01; 32]));
        assert!(!not_inf.is_infinity());
    }

    #[test]
    fn test_bound_codec() {
        // Test normal bound
        let bound = Bound::new(12345, Digest([0xAB; 32]));
        let mut buf = Vec::new();
        bound.write(&mut buf);
        let decoded = Bound::read(&mut &buf[..]).unwrap();
        assert_eq!(bound, decoded);

        // Test infinity bound
        let inf = Bound::infinity();
        buf.clear();
        inf.write(&mut buf);
        let decoded = Bound::read(&mut &buf[..]).unwrap();
        assert_eq!(inf, decoded);

        // Test zero bound
        let zero = Bound::zero();
        buf.clear();
        zero.write(&mut buf);
        let decoded = Bound::read(&mut &buf[..]).unwrap();
        assert_eq!(zero, decoded);
    }

    #[test]
    fn test_empty_fingerprint() {
        let storage = VecStorage::new();
        let fp = storage.fingerprint(0, 0);

        // Empty range should produce consistent fingerprint
        let fp2 = storage.fingerprint(0, 0);
        assert_eq!(fp, fp2);
    }

    #[test]
    fn test_vec_storage_remove() {
        let mut storage = VecStorage::new();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));
        storage.insert(Item::from_bytes(1001, [0x02; 32]));
        assert_eq!(storage.len(), 2);

        // Remove existing item
        let removed = storage.remove(&Item::from_bytes(1000, [0x01; 32]));
        assert!(removed);
        assert_eq!(storage.len(), 1);

        // Remove non-existent item
        let removed = storage.remove(&Item::from_bytes(1000, [0x01; 32]));
        assert!(!removed);
        assert_eq!(storage.len(), 1);
    }

    #[test]
    fn test_vec_storage_contains_id() {
        let mut storage = VecStorage::new();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));

        assert!(storage.contains_id(&Digest([0x01; 32])));
        assert!(!storage.contains_id(&Digest([0x02; 32])));
    }

    #[test]
    fn test_large_set_exact_differences() {
        // Test that all differences are found correctly
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Add 10 shared items (small enough to trigger IdList directly)
        for i in 0u64..10 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            storage_a.insert(Item::from_bytes(i * 10, id));
            storage_b.insert(Item::from_bytes(i * 10, id));
        }

        // Add 3 unique items to A
        let mut a_unique = Vec::new();
        for i in 10u64..13 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            storage_a.insert(Item::from_bytes(i * 10, id));
            a_unique.push(Digest(id));
        }

        // Add 3 unique items to B
        let mut b_unique = Vec::new();
        for i in 13u64..16 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            storage_b.insert(Item::from_bytes(i * 10, id));
            b_unique.push(Digest(id));
        }

        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();
        let mut missing_a = Vec::new();
        let mut missing_b = Vec::new();

        // Run reconciliation to completion (should be quick with small sets)
        for round in 0..10 {
            let (next_msg, found) = reconciler_b.reconcile(&msg).unwrap();
            missing_b.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                break;
            }
            let (next_msg, found) = reconciler_a.reconcile(&msg).unwrap();
            missing_a.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                // Final round for B
                let (_, found) = reconciler_b.reconcile(&msg).unwrap();
                missing_b.extend(found);
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // Verify A found all B's unique items (what A is missing)
        for id in &b_unique {
            assert!(missing_a.contains(id), "A should be missing {:?}", id);
        }

        // Verify B found all A's unique items (what B is missing)
        for id in &a_unique {
            assert!(missing_b.contains(id), "B should be missing {:?}", id);
        }
    }

    #[test]
    fn test_same_hint_multiple_items() {
        // Test that RBSR handles multiple items with the same hint correctly
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Add 5 items all with the same hint to both
        let shared_hint = 1000u64;
        for i in 0u8..5 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_a.insert(Item::from_bytes(shared_hint, id));
            storage_b.insert(Item::from_bytes(shared_hint, id));
        }

        // Add 2 more items with the SAME hint, unique to A
        let mut a_unique = Vec::new();
        for i in 5u8..7 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_a.insert(Item::from_bytes(shared_hint, id));
            a_unique.push(Digest(id));
        }

        // Add 2 more items with the SAME hint, unique to B
        let mut b_unique = Vec::new();
        for i in 7u8..9 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_b.insert(Item::from_bytes(shared_hint, id));
            b_unique.push(Digest(id));
        }

        // Verify storage is sorted correctly by ID within same hint
        assert_eq!(storage_a.len(), 7);
        assert_eq!(storage_b.len(), 7);
        for i in 0..storage_a.len() - 1 {
            let curr = storage_a.get(i).unwrap();
            let next = storage_a.get(i + 1).unwrap();
            assert_eq!(curr.hint, next.hint);
            assert!(curr.id < next.id, "items should be sorted by ID");
        }

        // Run reconciliation
        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();
        let mut missing_a = Vec::new();
        let mut missing_b = Vec::new();

        for round in 0..10 {
            let (next_msg, found) = reconciler_b.reconcile(&msg).unwrap();
            missing_b.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                break;
            }
            let (next_msg, found) = reconciler_a.reconcile(&msg).unwrap();
            missing_a.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                let (_, found) = reconciler_b.reconcile(&msg).unwrap();
                missing_b.extend(found);
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // Verify A found B's unique items (what A is missing)
        for id in &b_unique {
            assert!(missing_a.contains(id), "A should be missing {:?}", id);
        }

        // Verify B found A's unique items (what B is missing)
        for id in &a_unique {
            assert!(missing_b.contains(id), "B should be missing {:?}", id);
        }
    }

    #[test]
    fn test_same_ids_different_hints() {
        // IMPORTANT: Items are identified by ID only, NOT by (hint, id).
        // Hints are purely for ordering/partitioning the search space.
        // If both sides have the same ID (even with different hints),
        // they're considered to have the same item.
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Same IDs, but A uses hints 1000-1002, B uses hints 2000-2002
        let id1 = [0x01; 32];
        let id2 = [0x02; 32];
        let id3 = [0x03; 32];

        storage_a.insert(Item::from_bytes(1000, id1));
        storage_a.insert(Item::from_bytes(1001, id2));
        storage_a.insert(Item::from_bytes(1002, id3));

        storage_b.insert(Item::from_bytes(2000, id1));
        storage_b.insert(Item::from_bytes(2001, id2));
        storage_b.insert(Item::from_bytes(2002, id3));

        // Run reconciliation
        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();
        let mut missing_a = Vec::new();
        let mut missing_b = Vec::new();

        for round in 0..10 {
            let (next_msg, found) = reconciler_b.reconcile(&msg).unwrap();
            missing_b.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                break;
            }
            let (next_msg, found) = reconciler_a.reconcile(&msg).unwrap();
            missing_a.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                let (_, found) = reconciler_b.reconcile(&msg).unwrap();
                missing_b.extend(found);
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // Since items are identified by ID only, both sides have the same 3 items.
        // No differences should be detected!
        assert_eq!(missing_a.len(), 0, "same IDs = same items, no differences");
        assert_eq!(missing_b.len(), 0);
    }

    #[test]
    fn test_same_id_different_hint_with_unique_items() {
        // Even when items have different hints, if they share IDs they match.
        // This test shows mixed scenario: some IDs match, some don't.
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Shared ID (different hints - still considered same item)
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_b.insert(Item::from_bytes(2000, [0x01; 32])); // Same ID, different hint

        // Unique to A
        storage_a.insert(Item::from_bytes(1001, [0x02; 32]));

        // Unique to B
        storage_b.insert(Item::from_bytes(2001, [0x03; 32]));

        // Run reconciliation
        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();
        let mut missing_a = Vec::new();
        let mut missing_b = Vec::new();

        for round in 0..10 {
            let (next_msg, found) = reconciler_b.reconcile(&msg).unwrap();
            missing_b.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                break;
            }
            let (next_msg, found) = reconciler_a.reconcile(&msg).unwrap();
            missing_a.extend(found);
            msg = next_msg;
            if msg.is_complete() {
                let (_, found) = reconciler_b.reconcile(&msg).unwrap();
                missing_b.extend(found);
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // A should find it's missing [0x03] (unique to B)
        // B should find it's missing [0x02] (unique to A)
        // [0x01] matches despite different hints
        assert_eq!(missing_a.len(), 1);
        assert!(missing_a.contains(&Digest([0x03; 32])));
        assert_eq!(missing_b.len(), 1);
        assert!(missing_b.contains(&Digest([0x02; 32])));
    }
}
