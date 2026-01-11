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
//! use commonware_cryptography::rbsr::{Item, Reconciler, MemStorage};
//!
//! // Create storage for participant A (has items 1 and 2)
//! let mut storage_a = MemStorage::default();
//! storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
//! storage_a.insert(Item::from_bytes(1001, [0x02; 32]));
//! storage_a.rebuild();
//!
//! // Create storage for participant B (has items 1 and 3)
//! let mut storage_b = MemStorage::default();
//! storage_b.insert(Item::from_bytes(1000, [0x01; 32]));
//! storage_b.insert(Item::from_bytes(1002, [0x03; 32]));
//! storage_b.rebuild();
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
use alloc::{collections::BTreeSet, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;
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
/// Bounds consist of a hint and an optional ID. When the ID is `None`,
/// the bound acts as a sentinel: at hint=0 it's less than everything,
/// at hint=MAX_HINT it's infinity (greater than everything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// Hint component of the bound
    pub hint: u64,
    /// Optional ID (None for sentinel bounds like infinity)
    pub id: Option<Digest>,
}

impl Bound {
    /// Create a new bound with the given hint and ID.
    pub fn new(hint: u64, id: Digest) -> Self {
        Self { hint, id: Some(id) }
    }

    /// Create a bound representing positive infinity.
    pub const fn infinity() -> Self {
        Self {
            hint: MAX_HINT,
            id: None,
        }
    }

    /// Check if this bound represents infinity.
    pub fn is_infinity(&self) -> bool {
        self.hint == MAX_HINT && self.id.is_none()
    }

    /// Compare this bound against an item.
    /// Returns Ordering::Less if bound < item, etc.
    pub fn cmp_item(&self, item: &Item) -> core::cmp::Ordering {
        match self.hint.cmp(&item.hint) {
            core::cmp::Ordering::Equal => match &self.id {
                None => core::cmp::Ordering::Less, // Sentinel is less than any ID
                Some(id) => id.cmp(&item.id),
            },
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
        match &self.id {
            Some(id) => {
                (ID_SIZE as u8).write(buf);
                id.write(buf);
            }
            None => {
                0u8.write(buf);
            }
        }
    }
}

impl Read for Bound {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let hint = UInt::<u64>::read(buf)?.into();
        let id_len = u8::read(buf)? as usize;
        let id = if id_len == 0 {
            None
        } else if id_len == ID_SIZE {
            Some(Digest::read(buf)?)
        } else {
            return Err(CodecError::Invalid("Bound", "id must be 0 or 32 bytes"));
        };
        Ok(Self { hint, id })
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

    /// Check if storage contains an item with the given ID.
    ///
    /// This searches the entire storage, not just a range, because items
    /// are identified by ID only (hints are just for ordering).
    fn contains_id(&self, id: &Digest) -> bool {
        for i in 0..self.len() {
            if let Some(item) = self.get(i) {
                if &item.id == id {
                    return true;
                }
            }
        }
        false
    }
}

/// Default checkpoint interval for [`MemStorage`].
pub const DEFAULT_CHECKPOINT_INTERVAL: usize = 1024;

/// In-memory storage with cached fingerprints for efficient reconciliation.
///
/// Uses checkpoints at regular intervals to enable O(K) fingerprint queries
/// where K is the checkpoint interval. Memory usage is O(n + n/K) for items
/// plus checkpoints.
///
/// For reconciling with multiple peers, fingerprints are computed once and
/// reused. The checkpoint-based approach allows deriving any range fingerprint
/// by combining cached checkpoints with partial computations.
///
/// # Example
///
/// ```ignore
/// let mut storage = MemStorage::default(); // default checkpoint interval
/// for item in items {
///     storage.insert(item);
/// }
/// storage.rebuild(); // Build checkpoint cache
///
/// // Now reconcile with multiple peers - fingerprints are cached
/// let mut reconciler_a = Reconciler::new(&storage, 16);
/// let mut reconciler_b = Reconciler::new(&storage, 16);
/// ```
#[derive(Debug, Clone)]
pub struct MemStorage {
    /// Items in sorted order (by hint, then ID)
    items: Vec<Item>,
    /// Set of all IDs for O(log n) membership checks
    id_set: BTreeSet<Digest>,
    /// Checkpoint interval (store LtHash every K items)
    checkpoint_interval: usize,
    /// Checkpoints: checkpoint[i] = LtHash of items[0..i*interval]
    checkpoints: Vec<LtHash>,
}

impl Default for MemStorage {
    fn default() -> Self {
        Self::new(DEFAULT_CHECKPOINT_INTERVAL)
    }
}

impl MemStorage {
    /// Create new empty storage with the given checkpoint interval.
    ///
    /// Smaller intervals use more memory but make fingerprint queries faster.
    /// Larger intervals save memory but require more computation per query.
    ///
    /// Recommended: 256-2048 depending on memory constraints.
    pub fn new(checkpoint_interval: usize) -> Self {
        Self {
            items: Vec::new(),
            id_set: BTreeSet::new(),
            checkpoint_interval: checkpoint_interval.max(1),
            checkpoints: vec![LtHash::new()], // checkpoint[0] = empty
        }
    }

    /// Create storage with the given capacity and checkpoint interval.
    pub fn with_capacity(capacity: usize, checkpoint_interval: usize) -> Self {
        let interval = checkpoint_interval.max(1);
        let num_checkpoints = capacity / interval + 2;
        Self {
            items: Vec::with_capacity(capacity),
            id_set: BTreeSet::new(),
            checkpoint_interval: interval,
            checkpoints: Vec::with_capacity(num_checkpoints),
        }
    }

    /// Insert an item. Call [`rebuild`](Self::rebuild) after batch inserts.
    pub fn insert(&mut self, item: Item) {
        if self.id_set.contains(&item.id) {
            return; // Duplicate ID
        }
        let pos = self.items.partition_point(|i| i < &item);
        self.items.insert(pos, item.clone());
        self.id_set.insert(item.id);
    }

    /// Remove an item. Call [`rebuild`](Self::rebuild) after batch removals.
    pub fn remove(&mut self, item: &Item) -> bool {
        if let Ok(pos) = self.items.binary_search(item) {
            self.id_set.remove(&self.items[pos].id);
            self.items.remove(pos);
            true
        } else {
            false
        }
    }

    /// Rebuild checkpoint cache after mutations.
    ///
    /// This is O(n) but only needs to be called once after batch mutations.
    /// Subsequent fingerprint queries benefit from the cached checkpoints.
    pub fn rebuild(&mut self) {
        self.checkpoints.clear();

        let mut acc = LtHash::new();
        self.checkpoints.push(acc.clone()); // checkpoint[0] = empty

        for (i, item) in self.items.iter().enumerate() {
            acc.add(item.id.as_ref());
            // Store checkpoint at interval boundaries
            if (i + 1) % self.checkpoint_interval == 0 {
                self.checkpoints.push(acc.clone());
            }
        }

        // Always store final checkpoint if not at boundary
        if self.items.len() % self.checkpoint_interval != 0 {
            self.checkpoints.push(acc);
        }
    }

    /// Get an iterator over all items.
    pub fn iter(&self) -> impl Iterator<Item = &Item> {
        self.items.iter()
    }

    /// Clear all items.
    pub fn clear(&mut self) {
        self.items.clear();
        self.id_set.clear();
        self.checkpoints.clear();
        self.checkpoints.push(LtHash::new());
    }

    /// Get the checkpoint interval.
    pub fn checkpoint_interval(&self) -> usize {
        self.checkpoint_interval
    }

    /// Get the number of checkpoints (for memory estimation).
    pub fn num_checkpoints(&self) -> usize {
        self.checkpoints.len()
    }

    /// Compute LtHash for a range, using checkpoints for efficiency.
    fn compute_range_hash(&self, start_idx: usize, end_idx: usize) -> LtHash {
        if start_idx >= end_idx || end_idx > self.items.len() {
            return LtHash::new();
        }

        let interval = self.checkpoint_interval;

        // Find checkpoint indices
        let start_checkpoint = start_idx / interval;
        let end_checkpoint = end_idx / interval;

        // Start from the checkpoint at or before start_idx
        let mut result = if end_checkpoint < self.checkpoints.len() {
            self.checkpoints[end_checkpoint].clone()
        } else if !self.checkpoints.is_empty() {
            self.checkpoints.last().unwrap().clone()
        } else {
            LtHash::new()
        };

        // Subtract the start checkpoint
        if start_checkpoint < self.checkpoints.len() {
            result.difference(&self.checkpoints[start_checkpoint]);
        }

        // Adjust for items between checkpoints
        let start_checkpoint_idx = start_checkpoint * interval;
        let end_checkpoint_idx = end_checkpoint * interval;

        // Subtract items from start_checkpoint_idx to start_idx
        for i in start_checkpoint_idx..start_idx.min(self.items.len()) {
            result.subtract(self.items[i].id.as_ref());
        }

        // Add items from end_checkpoint_idx to end_idx
        for i in end_checkpoint_idx..end_idx.min(self.items.len()) {
            result.add(self.items[i].id.as_ref());
        }

        result
    }
}

impl Storage for MemStorage {
    fn len(&self) -> usize {
        self.items.len()
    }

    fn get(&self, index: usize) -> Option<&Item> {
        self.items.get(index)
    }

    fn lower_bound(&self, bound: &Bound) -> usize {
        if bound.hint == 0 && bound.id.is_none() {
            return 0;
        }
        self.items.partition_point(|item| bound.item_below(item))
    }

    fn fingerprint(&self, start_idx: usize, end_idx: usize) -> Fingerprint {
        self.compute_range_hash(start_idx, end_idx).checksum()
    }

    fn contains_id(&self, id: &Digest) -> bool {
        self.id_set.contains(id)
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
                    // Remote says skip - merge with previous Skip if possible
                    Self::push_skip(&mut response_ranges, range.upper_bound.clone());
                }
                RangeMode::Fingerprint(remote_fp) => {
                    let local_fp = self.storage.fingerprint(current_idx, end_idx);
                    let item_count = end_idx - current_idx;

                    if local_fp == *remote_fp {
                        // Fingerprints match - merge with previous Skip if possible
                        Self::push_skip(&mut response_ranges, range.upper_bound.clone());
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
                    // Find IDs remote has that we don't (check entire storage,
                    // not just range - ID may exist with different hint)
                    for remote_id in remote_ids {
                        if !self.storage.contains_id(remote_id) {
                            missing.push(*remote_id);
                        }
                    }

                    // Response depends on role:
                    // - Initiator receiving IdList: send our IdList so responder can compare
                    // - Responder receiving IdList: this completes the exchange, reply with Skip
                    if self.is_initiator {
                        let local_ids = self.storage.ids_in_range(current_idx, end_idx);
                        response_ranges.push(Range::new(
                            range.upper_bound.clone(),
                            RangeMode::IdList(local_ids),
                        ));
                    } else {
                        Self::push_skip(&mut response_ranges, range.upper_bound.clone());
                    }
                }
            }

            current_idx = end_idx;
        }

        Ok((Message::new(response_ranges), missing))
    }

    /// Push a Skip range, merging with the previous range if it's also a Skip.
    fn push_skip(ranges: &mut Vec<Range>, bound: Bound) {
        if let Some(last) = ranges.last_mut() {
            if matches!(last.mode, RangeMode::Skip) {
                // Merge: just update the bound of the existing Skip
                last.upper_bound = bound;
                return;
            }
        }
        ranges.push(Range::new(bound, RangeMode::Skip));
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
        let mut storage = MemStorage::default();
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
        let mut storage = MemStorage::default();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));
        storage.insert(Item::from_bytes(1000, [0x01; 32])); // Duplicate

        assert_eq!(storage.len(), 1);
    }

    #[test]
    fn test_vec_storage_lower_bound() {
        let mut storage = MemStorage::default();
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
        let mut storage_a = MemStorage::default();
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_a.insert(Item::from_bytes(1001, [0x02; 32]));

        let mut storage_b = MemStorage::default();
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
        let mut storage_a = MemStorage::default();
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_a.insert(Item::from_bytes(1001, [0x02; 32])); // Only A has this

        let mut storage_b = MemStorage::default();
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
        let storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();
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
        let mut storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();

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
        let mut storage = MemStorage::default();
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
    }

    #[test]
    fn test_empty_fingerprint() {
        let storage = MemStorage::default();
        let fp = storage.fingerprint(0, 0);

        // Empty range should produce consistent fingerprint
        let fp2 = storage.fingerprint(0, 0);
        assert_eq!(fp, fp2);
    }

    #[test]
    fn test_vec_storage_remove() {
        let mut storage = MemStorage::default();
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
        let mut storage = MemStorage::default();
        storage.insert(Item::from_bytes(1000, [0x01; 32]));

        assert!(storage.contains_id(&Digest([0x01; 32])));
        assert!(!storage.contains_id(&Digest([0x02; 32])));
    }

    #[test]
    fn test_large_set_exact_differences() {
        // Test that all differences are found correctly
        let mut storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();

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
        let mut storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();

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
        let mut storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();

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
        let mut storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();

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

    #[test]
    fn test_skip_merging() {
        // Test that consecutive Skip ranges are merged to reduce bandwidth.
        // Create two identical large sets that will be split into many sub-ranges.
        let mut storage_a = MemStorage::default();
        let mut storage_b = MemStorage::default();

        // Add 100 items to both sets (identical)
        for i in 0..100u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            storage_a.insert(Item::from_bytes(i as u64 * 10, id));
            storage_b.insert(Item::from_bytes(i as u64 * 10, id));
        }

        // Use small branching factor to force many sub-ranges
        let mut reconciler_a = Reconciler::new(&storage_a, 4);
        let msg1 = reconciler_a.initiate();

        // First message should have 1 range (full fingerprint)
        assert_eq!(msg1.ranges.len(), 1);

        let mut reconciler_b = Reconciler::new(&storage_b, 4);
        let (msg2, _) = reconciler_b.reconcile(&msg1).unwrap();

        // Since fingerprints match, response should be a single merged Skip
        // (not many individual Skip ranges)
        assert_eq!(msg2.ranges.len(), 1);
        assert!(matches!(msg2.ranges[0].mode, RangeMode::Skip));
        assert!(msg2.ranges[0].upper_bound.is_infinity());
    }

    #[test]
    fn test_cached_storage_fingerprints() {
        // Verify MemStorage produces identical fingerprints to MemStorage
        let mut vec_storage = MemStorage::default();
        let mut cached_storage = MemStorage::new(16); // Small interval for testing

        // Add same items to both
        for i in 0..100u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            id[1] = i.wrapping_mul(7);
            let item = Item::from_bytes(i as u64 * 10, id);
            vec_storage.insert(item.clone());
            cached_storage.insert(item);
        }
        cached_storage.rebuild();

        // Verify fingerprints match for various ranges
        assert_eq!(
            vec_storage.fingerprint(0, 100),
            cached_storage.fingerprint(0, 100)
        );
        assert_eq!(
            vec_storage.fingerprint(0, 50),
            cached_storage.fingerprint(0, 50)
        );
        assert_eq!(
            vec_storage.fingerprint(25, 75),
            cached_storage.fingerprint(25, 75)
        );
        assert_eq!(
            vec_storage.fingerprint(99, 100),
            cached_storage.fingerprint(99, 100)
        );

        // Verify contains_id works
        let mut id = [0u8; 32];
        id[0] = 50;
        id[1] = 50u8.wrapping_mul(7);
        assert!(cached_storage.contains_id(&Digest(id)));

        let missing_id = Digest([0xFF; 32]);
        assert!(!cached_storage.contains_id(&missing_id));

        // Verify checkpoints are stored efficiently
        // With 100 items and interval=16, we should have ~7 checkpoints
        assert!(cached_storage.num_checkpoints() < 10);
    }

    #[test]
    fn test_cached_storage_reconciliation() {
        // Full reconciliation test with MemStorage
        let mut storage_a = MemStorage::new(16);
        let mut storage_b = MemStorage::new(16);

        // A has [0x01], B has [0x02] - simple disjoint sets
        storage_a.insert(Item::from_bytes(1000, [0x01; 32]));
        storage_b.insert(Item::from_bytes(1000, [0x02; 32]));
        storage_a.rebuild();
        storage_b.rebuild();

        // Verify fingerprints are different
        let fp_a = storage_a.fingerprint(0, 1);
        let fp_b = storage_b.fingerprint(0, 1);
        assert_ne!(fp_a, fp_b, "different items should have different fingerprints");

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

        // A is missing [0x02], B is missing [0x01]
        assert_eq!(missing_a.len(), 1);
        assert!(missing_a.contains(&Digest([0x02; 32])));
        assert_eq!(missing_b.len(), 1);
        assert!(missing_b.contains(&Digest([0x01; 32])));
    }

    #[test]
    fn test_multi_checkpoint_fingerprints() {
        // Test that fingerprint queries spanning multiple checkpoints are computed correctly.
        // Uses a small checkpoint interval to ensure queries cross checkpoint boundaries.
        let interval = 8;
        let num_items = 100;
        let mut storage = MemStorage::new(interval);

        // Create items with distinct IDs
        let mut items = Vec::new();
        for i in 0..num_items {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            let item = Item::from_bytes(i as u64 * 10, id);
            items.push(item.clone());
            storage.insert(item);
        }
        storage.rebuild();

        // Verify we have multiple checkpoints
        // With 100 items and interval=8, we should have ~13 checkpoints
        assert!(
            storage.num_checkpoints() >= 10,
            "expected multiple checkpoints, got {}",
            storage.num_checkpoints()
        );

        // Helper: compute fingerprint naively by iterating items
        let naive_fingerprint = |start: usize, end: usize| -> Fingerprint {
            let mut acc = FingerprintAccumulator::new();
            for item in items.iter().take(end).skip(start) {
                acc.add(item.id.as_ref());
            }
            acc.checksum()
        };

        // Test cases covering various checkpoint-spanning scenarios:
        let test_cases = [
            // (start, end, description)
            (0, num_items, "full range - spans all checkpoints"),
            (0, interval, "exactly one checkpoint worth"),
            (0, interval * 3, "exactly 3 checkpoints"),
            (1, interval - 1, "within first checkpoint, offset both ends"),
            (interval + 2, interval * 2 - 3, "within second checkpoint"),
            (5, interval + 5, "spans 2 checkpoints, unaligned"),
            (3, interval * 4 + 7, "spans 5 checkpoints, unaligned"),
            (interval, interval * 5, "spans 4 checkpoints, aligned start"),
            (7, interval * 6, "spans 6 checkpoints, aligned end"),
            (interval * 2, interval * 2 + 1, "single item at checkpoint boundary"),
            (0, 1, "single item at start"),
            (num_items - 1, num_items, "single item at end"),
            (num_items / 2, num_items / 2 + interval * 2, "middle range spanning 2+ checkpoints"),
        ];

        for (start, end, desc) in test_cases {
            let expected = naive_fingerprint(start, end);
            let actual = storage.fingerprint(start, end);
            assert_eq!(
                expected, actual,
                "fingerprint mismatch for range [{}..{}): {}",
                start, end, desc
            );
        }

        // Test edge cases
        assert_eq!(
            storage.fingerprint(0, 0),
            naive_fingerprint(0, 0),
            "empty range at start"
        );
        assert_eq!(
            storage.fingerprint(50, 50),
            naive_fingerprint(50, 50),
            "empty range in middle"
        );
    }

    #[test]
    fn test_cached_storage_memory_efficiency() {
        // Verify MemStorage uses less memory than full prefix sums
        let mut storage = MemStorage::new(1000);

        // Add 10,000 items
        for i in 0..10000u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            storage.insert(Item::from_bytes(i as u64, id));
        }
        storage.rebuild();

        // With 10,000 items and interval=1000, we should have ~11 checkpoints
        // (10 at boundaries + 1 final)
        // vs 10,001 prefix sums for full approach
        assert!(
            storage.num_checkpoints() <= 12,
            "expected ~11 checkpoints, got {}",
            storage.num_checkpoints()
        );

        // Fingerprints should still work correctly
        let fp1 = storage.fingerprint(0, 10000);
        let fp2 = storage.fingerprint(0, 5000);
        let fp3 = storage.fingerprint(5000, 10000);
        assert_ne!(fp1, fp2);
        assert_ne!(fp2, fp3);
    }
}
