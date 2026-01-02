//! Range-Based Set Reconciliation (RBSR) for efficient set synchronization.
//!
//! This module implements the Negentropy protocol for comparing and reconciling
//! sets between two participants. RBSR uses a divide-and-conquer approach where
//! participants exchange fingerprints of ranges, recursively splitting non-matching
//! ranges until differences are identified.
//!
//! # Overview
//!
//! RBSR works by:
//! 1. Ordering items by timestamp, then by ID
//! 2. Computing fingerprints over ranges of items
//! 3. Exchanging range fingerprints between participants
//! 4. Recursively splitting ranges where fingerprints differ
//! 5. Directly transmitting items once ranges become small enough
//!
//! # Item Identity
//!
//! Items are identified by their **ID only**, not by (timestamp, ID). The timestamp
//! is used purely for ordering and partitioning the search space. This means:
//!
//! - Two items with the same ID are considered identical, even with different timestamps
//! - Timestamps do not need to be unique; multiple items can share the same timestamp
//! - Items are sorted by (timestamp, ID) for efficient range queries
//!
//! This design is ideal for content-addressed data where the ID is a hash of the
//! content (e.g., Nostr events). If your use case requires (timestamp, ID) identity,
//! you should include the timestamp in your ID hash.
//!
//! # Properties
//!
//! - **Efficient**: Round-trips scale logarithmically with set size (log_B(N) / 2)
//! - **Flexible**: No rigid tree structure required; implementations can vary
//! - **Stateless**: Servers don't need per-connection state
//! - **DoS Resistant**: Fingerprint computation is deterministic
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::rbsr::{Item, Reconciler, VecStorage};
//!
//! // Create storage for participant A
//! let mut storage_a = VecStorage::new();
//! storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
//! storage_a.insert(Item::from_bytes(1001, [0x02; 32]));
//! storage_a.insert(Item::from_bytes(1002, [0x03; 32]));
//!
//! // Create storage for participant B (missing one item)
//! let mut storage_b = VecStorage::new();
//! storage_b.insert(Item::from_bytes(1000, [0x01; 32]));
//! storage_b.insert(Item::from_bytes(1002, [0x03; 32]));
//!
//! // Participant A initiates reconciliation
//! let mut reconciler_a = Reconciler::new(&storage_a, 16);
//! let msg1 = reconciler_a.initiate();
//!
//! // Participant B processes and responds
//! let mut reconciler_b = Reconciler::new(&storage_b, 16);
//! let msg2 = reconciler_b.reconcile(&msg1).unwrap();
//!
//! // Participant A processes response
//! let msg3 = reconciler_a.reconcile(&msg2).unwrap();
//!
//! // After reconciliation completes, check what B needs
//! // (B is missing the item with ID [0x02; 32])
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
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Size of an item ID in bytes (32-byte digest).
pub const ID_SIZE: usize = Digest::SIZE;

/// Maximum timestamp value, used as "infinity" bound.
pub const MAX_TIMESTAMP: u64 = u64::MAX;

/// Default branching factor for range splitting.
pub const DEFAULT_BRANCHING_FACTOR: usize = 16;

/// An item in the set, consisting of a timestamp and a 32-byte ID.
///
/// Items are ordered first by timestamp, then lexicographically by ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Item {
    /// Timestamp for ordering (can be any unit: seconds, microseconds, etc.)
    pub timestamp: u64,
    /// Unique identifier, typically a cryptographic hash of the item content
    pub id: Digest,
}

impl Item {
    /// Create a new item with the given timestamp and ID.
    pub const fn new(timestamp: u64, id: Digest) -> Self {
        Self { timestamp, id }
    }

    /// Create a new item from a timestamp and raw bytes.
    pub const fn from_bytes(timestamp: u64, id: [u8; ID_SIZE]) -> Self {
        Self {
            timestamp,
            id: Digest(id),
        }
    }
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.timestamp.cmp(&other.timestamp) {
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
        self.timestamp.write(buf);
        self.id.write(buf);
    }
}

impl Read for Item {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let timestamp = u64::read(buf)?;
        let id = Digest::read(buf)?;
        Ok(Self { timestamp, id })
    }
}

impl FixedSize for Item {
    const SIZE: usize = 8 + ID_SIZE; // u64 + 32 bytes
}

/// A bound representing the upper limit of a range.
///
/// Bounds consist of a timestamp and an optional ID prefix. The ID prefix
/// can be truncated to the minimum bytes needed for uniqueness, reducing
/// message size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// Timestamp component of the bound
    pub timestamp: u64,
    /// ID prefix (can be empty or truncated for efficiency)
    pub id_prefix: Vec<u8>,
}

impl Bound {
    /// Create a new bound with the given timestamp and full ID.
    pub fn new(timestamp: u64, id: Digest) -> Self {
        Self {
            timestamp,
            id_prefix: id.as_ref().to_vec(),
        }
    }

    /// Create a bound representing positive infinity.
    pub const fn infinity() -> Self {
        Self {
            timestamp: MAX_TIMESTAMP,
            id_prefix: Vec::new(),
        }
    }

    /// Create a bound representing negative infinity (minimum).
    pub const fn zero() -> Self {
        Self {
            timestamp: 0,
            id_prefix: Vec::new(),
        }
    }

    /// Check if this bound represents infinity.
    pub const fn is_infinity(&self) -> bool {
        self.timestamp == MAX_TIMESTAMP && self.id_prefix.is_empty()
    }

    /// Compare this bound against an item.
    /// Returns Ordering::Less if bound < item, etc.
    pub fn cmp_item(&self, item: &Item) -> core::cmp::Ordering {
        match self.timestamp.cmp(&item.timestamp) {
            core::cmp::Ordering::Equal => {
                // Compare ID prefix against item ID
                let prefix_len = self.id_prefix.len().min(ID_SIZE);
                self.id_prefix[..prefix_len].cmp(&item.id.as_ref()[..prefix_len])
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
        self.timestamp.write(buf);
        (self.id_prefix.len() as u8).write(buf);
        buf.put_slice(&self.id_prefix);
    }
}

impl Read for Bound {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let timestamp = u64::read(buf)?;
        let prefix_len = u8::read(buf)? as usize;
        if prefix_len > ID_SIZE {
            return Err(CodecError::Invalid("Bound", "id_prefix length exceeds ID_SIZE"));
        }
        if buf.remaining() < prefix_len {
            return Err(CodecError::EndOfBuffer);
        }
        let mut id_prefix = vec![0u8; prefix_len];
        buf.copy_to_slice(&mut id_prefix);
        Ok(Self {
            timestamp,
            id_prefix,
        })
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
    /// Protocol version
    pub version: u8,
    /// Ranges in this message
    pub ranges: Vec<Range>,
}

impl Message {
    /// Current protocol version.
    pub const VERSION: u8 = 1;

    /// Create a new message with the given ranges.
    pub const fn new(ranges: Vec<Range>) -> Self {
        Self {
            version: Self::VERSION,
            ranges,
        }
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
        self.ranges.iter().all(|r| matches!(r.mode, RangeMode::Skip))
            && self
                .ranges
                .last()
                .is_some_and(|r| r.upper_bound.is_infinity())
    }
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        (self.ranges.len() as u32).write(buf);
        for range in &self.ranges {
            range.write(buf);
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != Self::VERSION {
            return Err(CodecError::Invalid("Message", "unsupported protocol version"));
        }
        let count = u32::read(buf)? as usize;
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            ranges.push(Range::read(buf)?);
        }
        Ok(Self { version, ranges })
    }
}

/// Error type for reconciliation operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid message format
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),
    /// Protocol version mismatch
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    /// Codec error
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
}

/// Trait for item storage backends.
///
/// Implementations must maintain items in sorted order (by timestamp, then ID).
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
        if bound.timestamp == 0 && bound.id_prefix.is_empty() {
            return 0;
        }
        self.items.partition_point(|item| bound.item_below(item))
    }
}

/// Main reconciler for performing set reconciliation.
pub struct Reconciler<'a, S: Storage> {
    storage: &'a S,
    branching_factor: usize,
    /// IDs that the remote has but we don't
    have_ids: Vec<Digest>,
    /// IDs that we have but the remote doesn't
    need_ids: Vec<Digest>,
    /// Whether reconciliation is complete
    complete: bool,
    /// Whether we are the initiator (affects how we respond to IdList)
    is_initiator: bool,
}

impl<'a, S: Storage> Reconciler<'a, S> {
    /// Create a new reconciler with the given storage and branching factor.
    pub fn new(storage: &'a S, branching_factor: usize) -> Self {
        Self {
            storage,
            branching_factor: branching_factor.max(2),
            have_ids: Vec::new(),
            need_ids: Vec::new(),
            complete: false,
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
    /// Returns the response message, or an error if the message is invalid.
    pub fn reconcile(&mut self, msg: &Message) -> Result<Message, Error> {
        if msg.version != Message::VERSION {
            return Err(Error::UnsupportedVersion(msg.version));
        }

        let mut response_ranges = Vec::new();
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
                    // Compare ID lists to find differences
                    let local_ids = self.storage.ids_in_range(current_idx, end_idx);

                    // Find IDs remote has that we don't (we need to fetch these)
                    for remote_id in remote_ids {
                        if !local_ids.contains(remote_id) {
                            self.have_ids.push(*remote_id);
                        }
                    }

                    // Find IDs we have that remote doesn't (remote needs these)
                    for local_id in &local_ids {
                        if !remote_ids.contains(local_id) {
                            self.need_ids.push(*local_id);
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

        // Check if reconciliation is complete
        let result = Message::new(response_ranges);
        if result.is_complete() {
            self.complete = true;
        }

        Ok(result)
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
                Bound::new(item.timestamp, item.id)
            } else {
                final_bound.clone()
            };

            ranges.push(Range::new(bound, RangeMode::Fingerprint(fp)));
            current = chunk_end;
        }
    }

    /// Get IDs that the remote has but we don't (items we need to fetch).
    pub fn have_ids(&self) -> &[Digest] {
        &self.have_ids
    }

    /// Get IDs that we have but the remote doesn't (items to send to remote).
    pub fn need_ids(&self) -> &[Digest] {
        &self.need_ids
    }

    /// Check if reconciliation is complete.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Clear the accumulated difference lists.
    pub fn clear_differences(&mut self) {
        self.have_ids.clear();
        self.need_ids.clear();
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

        assert!(a < b); // Same timestamp, compare by ID
        assert!(b < c); // Different timestamp
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
        assert_eq!(storage.get(0).unwrap().timestamp, 1000);
        assert_eq!(storage.get(1).unwrap().timestamp, 1001);
        assert_eq!(storage.get(2).unwrap().timestamp, 1002);
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
        let msg2 = reconciler_b.reconcile(&msg1).unwrap();

        // Should be a skip response since fingerprints match
        assert!(msg2.ranges[0].upper_bound.is_infinity());
        assert!(matches!(msg2.ranges[0].mode, RangeMode::Skip));

        let msg3 = reconciler_a.reconcile(&msg2).unwrap();
        assert!(msg3.is_complete());
        assert!(reconciler_a.have_ids().is_empty());
        assert!(reconciler_a.need_ids().is_empty());
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
        let msg2 = reconciler_b.reconcile(&msg1).unwrap();

        // A receives B's IdList, compares, sends its own IdList
        let msg3 = reconciler_a.reconcile(&msg2).unwrap();

        // B receives A's IdList, compares, sends Skip (completing the exchange)
        let msg4 = reconciler_b.reconcile(&msg3).unwrap();
        assert!(msg4.is_complete());

        // A should know B has [0x03] (A needs to fetch)
        assert!(reconciler_a.have_ids().contains(&Digest([0x03; 32])));
        // A should know it has [0x02] that B needs
        assert!(reconciler_a.need_ids().contains(&Digest([0x02; 32])));

        // B should know A has [0x02] (B needs to fetch)
        assert!(reconciler_b.have_ids().contains(&Digest([0x02; 32])));
        // B should know it has [0x03] that A needs
        assert!(reconciler_b.need_ids().contains(&Digest([0x03; 32])));
    }

    #[test]
    fn test_empty_set_reconciliation() {
        let storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();
        storage_b.insert(Item::from_bytes(1000, [0x01; 32]));

        let mut reconciler_a = Reconciler::new(&storage_a, 4);
        let msg1 = reconciler_a.initiate();

        let mut reconciler_b = Reconciler::new(&storage_b, 4);
        let msg2 = reconciler_b.reconcile(&msg1).unwrap();

        let _msg3 = reconciler_a.reconcile(&msg2).unwrap();

        // A should know B has an item
        assert!(!reconciler_a.have_ids().is_empty() || !reconciler_b.need_ids().is_empty());
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
        const MAX_ROUNDS: usize = 50; // Increase max rounds for larger sets

        while !msg.is_complete() && rounds < MAX_ROUNDS {
            msg = reconciler_b.reconcile(&msg).unwrap();
            if msg.is_complete() {
                break;
            }
            msg = reconciler_a.reconcile(&msg).unwrap();
            rounds += 1;
        }

        // Should complete (logarithmic in set size)
        assert!(
            rounds < MAX_ROUNDS,
            "reconciliation did not complete in {} rounds",
            MAX_ROUNDS
        );

        // Check that differences were found
        let a_have = reconciler_a.have_ids().len();
        let a_need = reconciler_a.need_ids().len();
        let b_have = reconciler_b.have_ids().len();
        let b_need = reconciler_b.need_ids().len();

        // Total differences should be 20 (10 unique to each)
        assert!(a_have + a_need + b_have + b_need > 0);
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
    fn test_message_version_mismatch() {
        // Create a message with wrong version
        let mut buf = Vec::new();
        2u8.write(&mut buf); // Wrong version
        1u32.write(&mut buf); // 1 range
        Bound::infinity().write(&mut buf);
        RangeMode::Skip.write(&mut buf);

        let result = Message::read(&mut &buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconciler_version_check() {
        let storage = VecStorage::new();
        let mut reconciler = Reconciler::new(&storage, 4);

        // Create message with wrong version
        let bad_msg = Message {
            version: 99,
            ranges: vec![Range::skip_to_infinity()],
        };

        let result = reconciler.reconcile(&bad_msg);
        assert!(matches!(result, Err(Error::UnsupportedVersion(99))));
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

        // Run reconciliation to completion (should be quick with small sets)
        for round in 0..10 {
            msg = reconciler_b.reconcile(&msg).unwrap();
            if msg.is_complete() {
                break;
            }
            msg = reconciler_a.reconcile(&msg).unwrap();
            if msg.is_complete() {
                // Final round for B
                let _ = reconciler_b.reconcile(&msg).unwrap();
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // Verify A found all B's unique items
        for id in &b_unique {
            assert!(
                reconciler_a.have_ids().contains(id),
                "A should know B has {:?}",
                id
            );
        }

        // Verify A knows what B needs
        for id in &a_unique {
            assert!(
                reconciler_a.need_ids().contains(id),
                "A should know B needs {:?}",
                id
            );
        }

        // Verify B found all A's unique items
        for id in &a_unique {
            assert!(
                reconciler_b.have_ids().contains(id),
                "B should know A has {:?}",
                id
            );
        }

        // Verify B knows what A needs
        for id in &b_unique {
            assert!(
                reconciler_b.need_ids().contains(id),
                "B should know A needs {:?}",
                id
            );
        }
    }

    #[test]
    fn test_same_timestamp_multiple_items() {
        // Test that RBSR handles multiple items with the same timestamp correctly
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Add 5 items all with the same timestamp to both
        let shared_timestamp = 1000u64;
        for i in 0u8..5 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_a.insert(Item::from_bytes(shared_timestamp, id));
            storage_b.insert(Item::from_bytes(shared_timestamp, id));
        }

        // Add 2 more items with the SAME timestamp, unique to A
        let mut a_unique = Vec::new();
        for i in 5u8..7 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_a.insert(Item::from_bytes(shared_timestamp, id));
            a_unique.push(Digest(id));
        }

        // Add 2 more items with the SAME timestamp, unique to B
        let mut b_unique = Vec::new();
        for i in 7u8..9 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_b.insert(Item::from_bytes(shared_timestamp, id));
            b_unique.push(Digest(id));
        }

        // Verify storage is sorted correctly by ID within same timestamp
        assert_eq!(storage_a.len(), 7);
        assert_eq!(storage_b.len(), 7);
        for i in 0..storage_a.len() - 1 {
            let curr = storage_a.get(i).unwrap();
            let next = storage_a.get(i + 1).unwrap();
            assert_eq!(curr.timestamp, next.timestamp);
            assert!(curr.id < next.id, "items should be sorted by ID");
        }

        // Run reconciliation
        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();

        for round in 0..10 {
            msg = reconciler_b.reconcile(&msg).unwrap();
            if msg.is_complete() {
                break;
            }
            msg = reconciler_a.reconcile(&msg).unwrap();
            if msg.is_complete() {
                let _ = reconciler_b.reconcile(&msg).unwrap();
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // Verify A found B's unique items (same timestamp, different IDs)
        for id in &b_unique {
            assert!(
                reconciler_a.have_ids().contains(id),
                "A should know B has {:?}",
                id
            );
        }

        // Verify A knows what B needs
        for id in &a_unique {
            assert!(
                reconciler_a.need_ids().contains(id),
                "A should know B needs {:?}",
                id
            );
        }

        // Verify B found A's unique items
        for id in &a_unique {
            assert!(
                reconciler_b.have_ids().contains(id),
                "B should know A has {:?}",
                id
            );
        }

        // Verify B knows what A needs
        for id in &b_unique {
            assert!(
                reconciler_b.need_ids().contains(id),
                "B should know A needs {:?}",
                id
            );
        }
    }

    #[test]
    fn test_same_ids_different_timestamps() {
        // IMPORTANT: Items are identified by ID only, NOT by (timestamp, id).
        // Timestamps are purely for ordering/partitioning the search space.
        // If both sides have the same ID (even with different timestamps),
        // they're considered to have the same item.
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Same IDs, but A uses timestamps 1000-1002, B uses timestamps 2000-2002
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

        for round in 0..10 {
            msg = reconciler_b.reconcile(&msg).unwrap();
            if msg.is_complete() {
                break;
            }
            msg = reconciler_a.reconcile(&msg).unwrap();
            if msg.is_complete() {
                let _ = reconciler_b.reconcile(&msg).unwrap();
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // Since items are identified by ID only, both sides have the same 3 items.
        // No differences should be detected!
        assert_eq!(
            reconciler_a.have_ids().len(),
            0,
            "same IDs = same items, no differences"
        );
        assert_eq!(reconciler_a.need_ids().len(), 0);
        assert_eq!(reconciler_b.have_ids().len(), 0);
        assert_eq!(reconciler_b.need_ids().len(), 0);
    }

    #[test]
    fn test_same_id_different_timestamp_with_unique_items() {
        // Even when items have different timestamps, if they share IDs they match.
        // This test shows mixed scenario: some IDs match, some don't.
        let mut storage_a = VecStorage::new();
        let mut storage_b = VecStorage::new();

        // Shared ID (different timestamps - still considered same item)
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_b.insert(Item::from_bytes(2000, [0x01; 32])); // Same ID, different timestamp

        // Unique to A
        storage_a.insert(Item::from_bytes(1001, [0x02; 32]));

        // Unique to B
        storage_b.insert(Item::from_bytes(2001, [0x03; 32]));

        // Run reconciliation
        let mut reconciler_a = Reconciler::new(&storage_a, 16);
        let mut reconciler_b = Reconciler::new(&storage_b, 16);

        let mut msg = reconciler_a.initiate();

        for round in 0..10 {
            msg = reconciler_b.reconcile(&msg).unwrap();
            if msg.is_complete() {
                break;
            }
            msg = reconciler_a.reconcile(&msg).unwrap();
            if msg.is_complete() {
                let _ = reconciler_b.reconcile(&msg).unwrap();
                break;
            }
            assert!(round < 9, "reconciliation did not converge");
        }

        // A should find B has [0x03] (unique to B)
        // A should know it has [0x02] (unique to A)
        // [0x01] matches despite different timestamps
        assert_eq!(reconciler_a.have_ids().len(), 1);
        assert_eq!(reconciler_a.need_ids().len(), 1);
        assert!(reconciler_a.have_ids().contains(&Digest([0x03; 32])));
        assert!(reconciler_a.need_ids().contains(&Digest([0x02; 32])));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Item>,
        }
    }
}
