//! Coordinator-free atomic publication over ordinary blobs.
//!
//! Atomic blobs narrow [`Storage`] to append, rewind, tag, and exact removal operations. New bytes
//! are written directly at their encoded offsets. Publication does not copy them. A published
//! rewind can shrink the backing, after which later appends reuse the discarded tail. Alternating
//! roots publish the visible length and integrity state without a coordinator record.
//!
//! # Backing layout
//!
//! [`BackingBlob`] exposes logical contents after a backend-owned container header. Creation is
//! delegated to [`Storage::open`], so this module neither encodes nor recovers that header. Atomic
//! identification begins at logical offset zero, where this module owns the following fixed prefix:
//!
//! ```text
//! logical offset     0              4096       6144       8192
//!                    +--------------+----------+----------+-------------------+
//! atomic contents    | identity     | root 0   | root 1   | encoded payload   |
//!                    | page (4 KiB) | even     | odd      |                   |
//!                    +--------------+----------+----------+-------------------+
//! ```
//!
//! Generation parity selects a root slot. Generation zero is a synthetic all-zero predecessor and
//! is never encoded. Writing generation `g` leaves the other slot's bytes untouched. A decided
//! shrink can later make the older root's payload extent out of bounds, so that root is not always
//! a valid fallback.
//!
//! The ordinary container has no persistent incarnation. The identity page supplies one so
//! recovery can distinguish an unlinked blob from a later same-name replacement:
//!
//! ```text
//! byte       0       7 8                 24   28                         4096
//!            +-------+-+------------------+----+----------------------------+
//! identity   | magic |G| incarnation      | crc| zero padding               |
//!            +-------+-+------------------+----+----------------------------+
//! width          7   1        16             4             4068
//! ```
//!
//! The magic is `CWUNOID`. The CRC32C covers the identity domain and bytes 0 through 23. Fresh
//! creation writes the complete page and synchronizes the backing once.
//!
//! A fresh identity is written only when the serialized open observed the name missing and created
//! its backing. A pre-existing name must contain a complete identity; an invalid or incomplete page
//! is rejected without mutation.
//!
//! # R15 root slots
//!
//! The first 132 bytes of each slot contain one root. Its magic is `CWUNO15`. Multi-byte integers
//! are big endian. The CRC32C covers the root domain and the preceding 128 bytes. It detects
//! malformed and torn state but is not authentication. The 20-byte binding is zero for roots
//! without a batch witness and is a truncated SHA-256 binding to the witness otherwise.
//!
//! ```text
//! byte    0      7 8      16     24     32  36  40  44       64       128 132
//!         +------+-+-------+------+------+---+---+---+---------+----------+---+
//! root    | magic|G| gen   | len  | tail |crc|fmt|wid| binding | tag      |crc|
//!         +------+-+-------+------+------+---+---+---+---------+----------+---+
//! width      7   1    8       8      8    4   4   4     20        64       4
//! ```
//!
//! `tail` and its CRC32C describe the only unfinished integrity unit. `fmt` is 0 for unbound, 1 for
//! variable, and 2 for chunked integrity. `wid` is nonzero only for chunked integrity. The
//! application owns all 64 tag bytes.
//!
//! A witness-bound slot uses the remaining bytes for a length frame, one local successor
//! link, and canonical zero padding:
//!
//! ```text
//! byte       0             132 136                         2048
//!            +-------------+---+---------------------------+
//! batch slot | root        |len| local link | zero padding |
//!            +-------------+---+---------------------------+
//! ```
//!
//! The fixed frame and variable link have this grammar:
//!
//! ```text
//! frame    [link length:4]
//!
//! link     [CWUNOL15:8][group id:16][removed:4]
//!          [incarnation:16][candidate template:132][payload descriptor:40]
//!          [next partition length + bytes][next name length + bytes][next incarnation:16]
//! ```
//!
//! The root binding covers this exact link under the truncated SHA-256 collision-resistance
//! assumption. All integer fields are big endian.
//!
//! Root spellings separate local authority from group evidence:
//!
//! - `BatchPrepared` is a candidate and requires complete ring evidence.
//! - `Finalized` is a locally selectable group result whose retained witness says whether it is
//!   present or removed.
//!
//! Locally selectable means recovery can choose the complete slot without following a peer. It
//! does not mean the issued bytes have crossed a durability operation. Live `Finalized` roots can
//! still carry durability debt.
//!
//! Each spelling has an exact suffix rule:
//!
//! ```text
//! BatchPrepared           exact framed witness and matching witness binding
//! Finalized                exact retained witness and matching witness binding
//! ```
//!
//! The guard encodes the root spelling:
//!
//! ```text
//! BatchPrepared = 1
//! Finalized     = 3 + ((generation / 2) mod 2)
//! ```
//!
//! Finalized guards alternate whenever one parity slot is reused. Before the final write is
//! issued, neither the previous same-slot root nor the prepared write contains the target guard.
//! Guard zero and generation zero are invalid. The generation is protected by the root checksum,
//! and generation parity selects the slot.
//!
//! # Direct publication
//!
//! A direct sync is encoded as a one-participant group whose successor is itself:
//!
//! ```text
//! write any new payload at encoded offsets
//!          |
//!          v
//! write complete BatchPrepared root + self witness
//!          |
//!          v
//! sync the backing blob                         durable decision
//!          |
//!          v
//! write Finalized root                          cleanup only
//! ```
//!
//! The candidate slot and any described payload suffix share one full-file durability operation.
//! The finalized spelling is not synchronized separately. If an earlier group left cleanup
//! debt on peer files, those files join this same concurrent durability layer.
//!
//! Large append epochs may finish detached payload preflushes before publication. These do not
//! publish a root. They establish an invisible durable prefix so the final publication still has
//! one bounded suffix to prove.
//!
//! # Multi-blob publication
//!
//! Canonical participant order forms a closed ring. Each local link binds its participant,
//! candidate, payload proof, and exact successor incarnation:
//!
//! ```text
//! A: [candidate A | next B] ---> B: [candidate B | next C]
//!           ^                                  |
//!           |                                  v
//!           +---------------- C: [candidate C | next A]
//!
//! write slot A    write slot B    write slot C
//! sync file A     sync file B     sync file C      one concurrent layer
//!          \____________ complete ring __________/
//!                           |
//!                           v
//!                    durable group decision
//! ```
//!
//! Every participant slot and every carried-debt barrier starts in that one concurrent set. There
//! are no fixed-size waves and no second final-root durability round. When at least one operation
//! participates, returning from [`AtomicStorage::start_apply`] with `Ok` proves the complete ring
//! is durable. Its completion handle waits for final-root writes, truncation, and in-memory
//! activation.
//!
//! # Recovery
//!
//! Once atomic identity initialization has completed, each issued write after the last successful
//! full-file durability cut may retain any subset of its addressed positions, including the empty
//! and complete subsets. An unretained position falls back to its earlier durable or retained
//! value. Recovery never assumes a prefix. A failed sync establishes no cut.
//! [`WriteOptions::SYNC`] covers only the bytes in its own write, not earlier writes. Resize and
//! unlink are ordered behind durable roots and have separate retry rules.
//!
//! Recovery reads the two fixed root slots first and follows only exact successor links from a
//! candidate found there.
//!
//! A group is accepted only when exact successor traversal closes at its starting participant,
//! locations are unique and in canonical cyclic order, incarnations are distinct, every candidate
//! transition is compatible, and every payload proof validates.
//! The outcome is therefore the complete predecessor vector or the complete candidate vector.
//!
//! ```text
//! local candidate
//!       |
//!       +-- complete closed ring + valid payload proofs --> finish whole group
//!       |
//!       `-- missing or invalid evidence -----------------> keep prior authority
//!
//! finish whole group
//!       |
//!       +-- finish every immediate unpaid witness predecessor
//!       +-- write missing locally selectable final spellings
//!       +-- barrier every readable participant
//!       `-- remove tombstoned names only after every final is durable
//! ```
//!
//! A rejected generation cannot be ignored because its bytes remain in a slot that will be reused.
//! Recovery first materializes a complete singleton `BatchPrepared` ring. Otherwise it durably
//! clears the rejected slot before returning mutable access, allowing the same generation to be
//! retried.
//!
//! # Bounded payload validation
//!
//! Each candidate describes only the suffix not covered by an earlier durability operation. The
//! descriptor binds its start and final logical endpoint inside the exact witness; its length is
//! derived from the candidate root. Its digest is SHA-256 over the payload domain followed by the
//! suffix bytes. The aggregate described suffix for a group is at most 64 MiB. Reopen therefore
//! reads fixed metadata plus a bounded payload suffix and never scans historical payload.
//!
//! # Integrity units
//!
//! Integrity-aware operations divide the encoded payload into application-selected units:
//!
//! ```text
//! completed units                         unfinished unit
//! +----------+--------+----------+--------+------------------+
//! | data     | CRC32C | data     | CRC32C | data             |
//! +----------+--------+----------+--------+------------------+
//!                                             ^
//!                                             root stores start + rolling CRC32C
//! ```
//!
//! Completed-unit footers are part of encoded offsets. The unfinished unit has no footer. Its root
//! metadata lets reopen validate or resume it without trusting caller-supplied checksum state.
//!
//! # Namespace ownership
//!
//! The backend owns its ordinary blob header and physical namespace. Atomic names are opt-in and
//! must not be opened through ordinary [`Storage`] while atomic handles exist. A new atomic blob
//! starts from R15's all-zero generation-zero predecessor. There is no compatibility path for
//! older experimental roots.
//!
//! Logical removal publishes a tombstone before physical unlink. Recovery makes every group final
//! independently durable before removing any member. The exclusive storage-lineage contract lets
//! recovery keep each verified name current through its durable removal.
//!
//! # Correctness invariants and assumptions
//!
//! - One storage value and its clones and wrappers form a storage lineage. Live operations share
//!   its exclusion lock; namespace recovery holds it exclusively. No independent storage instance,
//!   process, path alias, or ordinary handle mutates that lineage's names while atomic handles
//!   exist, and scans run only after every handle in their partition has been dropped.
//! - One handle operation, every overlapping batch, and every publication carrying the same prior
//!   group remain serialized until their I/O and cleanup have quiesced. Disjoint handles and debt
//!   groups may progress concurrently. Dropping an observer does not shorten ownership. Payload
//!   preflushes grant no authority and are drained before that handle can rewind or publish.
//! - Only a complete canonical root or bound ring grants payload authority. Bytes beyond the
//!   selected logical end have none. A published shrink reclaims them after the root is durable;
//!   recovery repeats a lost resize. Rewinding unpublished bytes first drains that handle's
//!   preflush, and a later append overwrites reused offsets before exposing them.
//! - A successful full-file sync is a truthful durability cut. Before the next cut, a crash may
//!   retain the old or issued value independently at every written byte. A failed sync establishes
//!   no cut, and range-sync covers only its own write.
//! - Fresh identifiers do not collide with retained token epochs, incarnations, or group
//!   identifiers, and the truncated SHA-256 witness binding is collision-resistant for reachable
//!   records. Correctness assumes no reachable torn or corrupt image has an accepted CRC32C
//!   collision; CRC32C is not authentication.

use crate::{
    ATOMIC_BLOB_TAG_LEN, AtomicBlob, AtomicStorage, BatchOperation, Blob as BackingBlob, Buf,
    Error, Handle, IntegrityAppend, IntegrityBoundary, IntegrityScheme, IntegritySnapshot,
    IntegrityToken, IntegrityUnit, IoBuf, IoBufs, IoBufsMut, Storage, WriteOptions,
    signal::{Signal, Signaler},
};
use commonware_cryptography::{Crc32, Hasher as _, Sha256};
use commonware_formatting::hex;
use commonware_utils::{
    channel::oneshot,
    sync::{
        AsyncMutex as Mutex, AsyncMutexGuard as MutexGuard, AsyncRwLock as RwLock,
        Mutex as BlockingMutex,
    },
    sys_rng,
};
use futures::future::join_all;
use rand::Rng as _;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
};

mod batch;

const ROOT_MAGIC: &[u8; 7] = b"CWUNO15";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_LOG_ROOT";
const PAYLOAD_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_BATCH_PAYLOAD";
const DIRECT_GROUP_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_DIRECT_GROUP";
const ROOT_GUARD_OFFSET: usize = 7;
const ROOT_INTEGRITY_START_OFFSET: usize = 24;
const ROOT_INTEGRITY_CHECKSUM_OFFSET: usize = 32;
const ROOT_INTEGRITY_SCHEME_OFFSET: usize = 36;
const ROOT_INTEGRITY_CHUNK_OFFSET: usize = 40;
const ROOT_BINDING_OFFSET: usize = 44;
const ROOT_PREFIX_LEN: usize = 64;
const ROOT_BINDING_LEN: usize = ROOT_PREFIX_LEN - ROOT_BINDING_OFFSET;
const ROOT_BODY_LEN: usize = ROOT_PREFIX_LEN + ATOMIC_BLOB_TAG_LEN;
const ROOT_CHECKSUM_LEN: usize = size_of::<u32>();
const ROOT_LEN: usize = ROOT_BODY_LEN + ROOT_CHECKSUM_LEN;
const ROOT_SLOT_LEN: u64 = 2 * 1024;
const ROOT_SLOT_SIZE: usize = ROOT_SLOT_LEN as usize;
pub(crate) const IDENTITY_PAGE_LEN: u64 = 4 * 1024;
const IDENTITY_MAGIC: &[u8; 7] = b"CWUNOID";
const IDENTITY_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_INCARNATION";
const IDENTITY_GUARD_OFFSET: usize = 7;
const IDENTITY_GUARD: u8 = 1;
const IDENTITY_LEN: usize = 28;
const INCARNATION_LEN: usize = 16;
const ROOT_OFFSETS: [u64; 2] = [IDENTITY_PAGE_LEN, IDENTITY_PAGE_LEN + ROOT_SLOT_LEN];
pub(crate) const DATA_OFFSET: u64 = IDENTITY_PAGE_LEN + 2 * ROOT_SLOT_LEN;
const MAX_UNSYNCED_PAYLOAD_LEN: u64 = 64 * 1024 * 1024;
const PAYLOAD_CHECKSUM_CHUNK_LEN: u64 = 1024 * 1024;
type RootSlot = [u8; ROOT_SLOT_SIZE];
type RootBinding = [u8; ROOT_BINDING_LEN];
type PayloadDigest = [u8; 32];
type ParticipantOperation<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;

fn validate_atomic_location(partition: &str, name: &[u8]) -> Result<(), Error> {
    batch::validate_location(partition, name).map_err(Into::into)
}

/// Storage-lineage-wide accounting for payload durability and live carried-group payments.
///
/// `total` is the sum reported by every live [`PayloadAccount`]. Registered rounds remain here
/// until their detached worker finishes, so namespace recovery can drain work whose original
/// observer was dropped. Weak carried-payment entries let recovery notify live group holders
/// without retaining their backing handles.
#[derive(Default)]
struct PayloadBudgetState {
    total: u128,
    next_round: u128,
    rounds: BTreeMap<u128, Signal>,
    carried_payments: BTreeMap<[u8; batch::GROUP_ID_LEN], Weak<CarriedPayment>>,
}

#[derive(Default)]
pub(crate) struct PayloadBudget {
    state: BlockingMutex<PayloadBudgetState>,
}

impl PayloadBudget {
    /// Register one detached preflush and return its lineage-unique identifier.
    fn register(&self, completion: Signal) -> u128 {
        let mut state = self.state.lock();
        let id = state.next_round;
        state.next_round = state
            .next_round
            .checked_add(1)
            .expect("atomic payload preflush round identifiers are not exhausted");
        assert!(state.rounds.insert(id, completion).is_none());
        id
    }

    /// Retire a successful preflush from lineage accounting.
    fn finish(&self, id: u128) {
        self.state.lock().rounds.remove(&id);
    }

    fn register_carried(
        self: &Arc<Self>,
        group_id: [u8; batch::GROUP_ID_LEN],
    ) -> Arc<CarriedPayment> {
        let payment = Arc::new(CarriedPayment {
            group_id,
            paid: AtomicBool::new(false),
            budget: Arc::downgrade(self),
        });
        let mut state = self.state.lock();
        assert!(
            state
                .carried_payments
                .get(&group_id)
                .and_then(Weak::upgrade)
                .is_none(),
            "atomic group identifiers are unique within one storage lineage"
        );
        state
            .carried_payments
            .insert(group_id, Arc::downgrade(&payment));
        payment
    }

    fn mark_carried_paid(&self, group_id: [u8; batch::GROUP_ID_LEN]) {
        let payment = {
            let mut state = self.state.lock();
            let payment = state
                .carried_payments
                .get(&group_id)
                .and_then(Weak::upgrade);
            if payment.is_none() {
                state.carried_payments.remove(&group_id);
            }
            payment
        };
        if let Some(payment) = payment {
            payment.paid.store(true, AtomicOrdering::Release);
        }
    }

    /// Wait for every registered round after the caller has excluded new lineage mutations.
    async fn drain(&self) -> Result<(), Error> {
        let rounds = self
            .state
            .lock()
            .rounds
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let results = join_all(rounds).await;
        if results.iter().any(Result::is_err) {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
}

/// One blob's contribution to the aggregate unsynchronized payload budget.
///
/// The account is shared by all handle clones. Dropping the last clone removes its contribution
/// even when the blob never publishes again.
struct PayloadAccount {
    budget: Arc<PayloadBudget>,
    amount: AtomicU64,
}

impl PayloadAccount {
    fn new(budget: Arc<PayloadBudget>) -> Arc<Self> {
        Arc::new(Self {
            budget,
            amount: AtomicU64::new(0),
        })
    }

    /// Replace this blob's contribution and return the new lineage aggregate.
    fn set(&self, amount: u64) -> u128 {
        let mut state = self.budget.state.lock();
        let previous = self.amount.swap(amount, AtomicOrdering::Relaxed);
        state.total = state
            .total
            .checked_sub(u128::from(previous))
            .expect("atomic payload accounting contains every live account")
            .checked_add(u128::from(amount))
            .expect("live atomic payload accounting fits u128");
        state.total
    }
}

impl Drop for PayloadAccount {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock();
        let amount = self.amount.load(AtomicOrdering::Relaxed);
        state.total = state
            .total
            .checked_sub(u128::from(amount))
            .expect("dropped atomic payload accounts remain in the aggregate");
    }
}

/// Coalesced preflush state for one blob.
///
/// Only one round runs at a time. Later requests raise that round's target rather than creating a
/// second concurrent durability operation for the same backing file. The sync gate also excludes
/// a peer publication paying carried cleanup debt for this backing.
#[derive(Default)]
struct PayloadPreflushState {
    current: Option<Arc<PayloadPreflushRound>>,
    failure: Option<Error>,
}

#[derive(Default)]
struct PayloadPreflush {
    state: BlockingMutex<PayloadPreflushState>,
    sync_gate: Arc<Mutex<()>>,
}

/// A detached full-file durability round whose target can advance while it runs.
struct PayloadPreflushRound {
    id: u128,
    requested: AtomicU64,
    completion: Signal,
}

/// Durable and transitional spellings encoded by the root guard.
///
/// Finalized roots are locally selectable after their full slot grammar validates. This is a
/// recovery classification, not proof that the installed bytes are durable. Finalized roots retain
/// their local witness. Batch-prepared roots require a complete witness ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootState {
    BatchPrepared,
    Finalized,
}

impl RootState {
    const fn guard(self, generation: u64) -> u8 {
        match self {
            Self::BatchPrepared => 1,
            Self::Finalized => {
                if (generation & 2) == 0 {
                    3
                } else {
                    4
                }
            }
        }
    }
}

fn checksum(parts: &[&[u8]]) -> u32 {
    let mut hasher = Crc32::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().1.as_u32()
}

fn update_payload_checksum(hasher: &mut Sha256, payload: &mut impl Buf) {
    while payload.remaining() != 0 {
        let chunk = payload.chunk();
        let len = chunk.len();
        hasher.update(chunk);
        payload.advance(len);
    }
}

/// Hash one bounded encoded payload suffix without materializing it as a contiguous allocation.
async fn payload_checksum_at<B: BackingBlob>(
    backing: &B,
    start: u64,
    len: u64,
) -> Result<PayloadDigest, Error> {
    let mut hasher = Sha256::default();
    hasher.update(PAYLOAD_DOMAIN);
    let mut offset = raw_len(start)?;
    let mut remaining = len;
    while remaining != 0 {
        let chunk_len = remaining.min(PAYLOAD_CHECKSUM_CHUNK_LEN) as usize;
        let mut payload = backing.read_at(offset, chunk_len).await?;
        update_payload_checksum(&mut hasher, &mut payload);
        offset = offset
            .checked_add(chunk_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        remaining -= chunk_len as u64;
    }
    Ok(hasher.finalize().1.as_ref().try_into().unwrap())
}

/// Derive the stable group identifier for a one-member publication.
///
/// The domain-separated input includes the path, incarnation, and generation. Correctness relies
/// on collisions in the 128-bit truncated SHA-256 result being infeasible.
fn direct_group_id(
    partition: &str,
    name: &[u8],
    incarnation: &[u8; INCARNATION_LEN],
    generation: u64,
) -> [u8; INCARNATION_LEN] {
    let partition_len = (partition.len() as u64).to_be_bytes();
    let name_len = (name.len() as u64).to_be_bytes();
    let generation = generation.to_be_bytes();
    let digest = Sha256::hash(&[
        DIRECT_GROUP_DOMAIN,
        &partition_len,
        partition.as_bytes(),
        &name_len,
        name,
        incarnation,
        &generation,
    ]);
    digest.as_ref()[..INCARNATION_LEN].try_into().unwrap()
}

/// Encode the complete canonical identity page for one namespace incarnation.
///
/// Fresh creation writes this complete page before its durability barrier.
fn encode_identity(identity: [u8; INCARNATION_LEN]) -> [u8; IDENTITY_PAGE_LEN as usize] {
    let mut page = [0u8; IDENTITY_PAGE_LEN as usize];
    page[..7].copy_from_slice(IDENTITY_MAGIC);
    page[IDENTITY_GUARD_OFFSET] = IDENTITY_GUARD;
    page[8..24].copy_from_slice(&identity);
    let crc = checksum(&[IDENTITY_DOMAIN, &page[..24]]);
    page[24..IDENTITY_LEN].copy_from_slice(&crc.to_be_bytes());
    page
}

/// Decode a complete canonical identity page.
pub(crate) fn decode_identity(
    page: &[u8; IDENTITY_PAGE_LEN as usize],
) -> Option<[u8; INCARNATION_LEN]> {
    if &page[..7] != IDENTITY_MAGIC
        || page[IDENTITY_GUARD_OFFSET] != IDENTITY_GUARD
        || page[IDENTITY_LEN..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let stored = u32::from_be_bytes(page[24..IDENTITY_LEN].try_into().unwrap());
    (stored == checksum(&[IDENTITY_DOMAIN, &page[..24]])).then(|| page[8..24].try_into().unwrap())
}

/// Encode a root with a zero witness binding.
///
/// A `BatchPrepared` result is only a template. `Candidate::bind` replaces its binding after the
/// exact local witness has been encoded.
fn encode_root_value(state: RootState, root: Root) -> [u8; ROOT_LEN] {
    encode_root_with_binding(state, root, [0; ROOT_BINDING_LEN])
}

/// Encode one complete root header with an explicit witness binding.
fn encode_root_with_binding(state: RootState, value: Root, binding: RootBinding) -> [u8; ROOT_LEN] {
    let mut root = [0u8; ROOT_LEN];
    root[..7].copy_from_slice(ROOT_MAGIC);
    root[ROOT_GUARD_OFFSET] = state.guard(value.generation);
    root[8..16].copy_from_slice(&value.generation.to_be_bytes());
    root[16..24].copy_from_slice(&value.logical_len.to_be_bytes());
    root[ROOT_INTEGRITY_START_OFFSET..ROOT_INTEGRITY_CHECKSUM_OFFSET]
        .copy_from_slice(&value.integrity_start.to_be_bytes());
    root[ROOT_INTEGRITY_CHECKSUM_OFFSET..ROOT_INTEGRITY_SCHEME_OFFSET]
        .copy_from_slice(&value.integrity_checksum.to_be_bytes());
    let (scheme, chunk) = match value.integrity_scheme {
        IntegrityScheme::Unbound => (0u32, 0u32),
        IntegrityScheme::Variable => (1, 0),
        IntegrityScheme::Chunked(size) => (2, size.get()),
    };
    root[ROOT_INTEGRITY_SCHEME_OFFSET..ROOT_INTEGRITY_CHUNK_OFFSET]
        .copy_from_slice(&scheme.to_be_bytes());
    root[ROOT_INTEGRITY_CHUNK_OFFSET..ROOT_BINDING_OFFSET].copy_from_slice(&chunk.to_be_bytes());
    root[ROOT_BINDING_OFFSET..ROOT_PREFIX_LEN].copy_from_slice(&binding);
    root[ROOT_PREFIX_LEN..ROOT_BODY_LEN].copy_from_slice(&value.tag);
    let checksum = checksum(&[ROOT_DOMAIN, &root[..ROOT_BODY_LEN]]);
    root[ROOT_BODY_LEN..].copy_from_slice(&checksum.to_be_bytes());
    root
}

fn root_binding(encoded: &[u8; ROOT_LEN]) -> RootBinding {
    encoded[ROOT_BINDING_OFFSET..ROOT_PREFIX_LEN]
        .try_into()
        .expect("the root binding has a fixed width")
}

/// Logical value carried by every root spelling.
///
/// The root does not store a separate payload map. `logical_len` selects one contiguous prefix,
/// while the integrity fields describe the only unfinished checksum unit in that prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Root {
    generation: u64,
    logical_len: u64,
    integrity_start: u64,
    integrity_checksum: u32,
    integrity_scheme: IntegrityScheme,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
}

#[cfg(test)]
impl Root {
    const fn unbound(generation: u64, logical_len: u64, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Self {
        Self {
            generation,
            logical_len,
            integrity_start: 0,
            integrity_checksum: 0,
            integrity_scheme: IntegrityScheme::Unbound,
            tag,
        }
    }
}

/// Decode the value fields without assigning local authority to their guard or checksum.
///
/// Transition repair uses this weaker parse only after independent evidence constrains every byte
/// to one of two canonical root spellings.
fn decode_root_fields(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    if &encoded[..7] != ROOT_MAGIC {
        return None;
    }
    let generation = u64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let scheme = u32::from_be_bytes(
        encoded[ROOT_INTEGRITY_SCHEME_OFFSET..ROOT_INTEGRITY_CHUNK_OFFSET]
            .try_into()
            .unwrap(),
    );
    let chunk = u32::from_be_bytes(
        encoded[ROOT_INTEGRITY_CHUNK_OFFSET..ROOT_BINDING_OFFSET]
            .try_into()
            .unwrap(),
    );
    let integrity_scheme = match (scheme, chunk) {
        (0, 0) => IntegrityScheme::Unbound,
        (1, 0) => IntegrityScheme::Variable,
        (2, chunk) => IntegrityScheme::Chunked(std::num::NonZeroU32::new(chunk)?),
        _ => return None,
    };
    (generation != 0).then(|| Root {
        generation,
        logical_len: u64::from_be_bytes(encoded[16..24].try_into().unwrap()),
        integrity_start: u64::from_be_bytes(
            encoded[ROOT_INTEGRITY_START_OFFSET..ROOT_INTEGRITY_CHECKSUM_OFFSET]
                .try_into()
                .unwrap(),
        ),
        integrity_checksum: u32::from_be_bytes(
            encoded[ROOT_INTEGRITY_CHECKSUM_OFFSET..ROOT_INTEGRITY_SCHEME_OFFSET]
                .try_into()
                .unwrap(),
        ),
        integrity_scheme,
        tag: encoded[ROOT_PREFIX_LEN..ROOT_BODY_LEN].try_into().unwrap(),
    })
}

/// Decode one exact spelling and validate its guard, binding rule, and CRC32C.
///
/// This does not validate slot parity, payload extent, integrity geometry, or the slot suffix.
fn decode_root(encoded: &[u8; ROOT_LEN], state: RootState) -> Option<Root> {
    let root = decode_root_fields(encoded)?;
    if encoded[ROOT_GUARD_OFFSET] != state.guard(root.generation) {
        return None;
    }
    let stored = u32::from_be_bytes(encoded[ROOT_BODY_LEN..].try_into().unwrap());
    if stored != checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]]) {
        return None;
    }
    Some(root)
}

/// Decode the first root spelling whose complete header grammar matches.
fn decode_any_root(encoded: &[u8; ROOT_LEN]) -> Option<(RootState, Root)> {
    [RootState::BatchPrepared, RootState::Finalized]
        .into_iter()
        .find_map(|state| decode_root(encoded, state).map(|root| (state, root)))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}

fn raw_len(logical_len: u64) -> Result<u64, Error> {
    DATA_OFFSET
        .checked_add(logical_len)
        .ok_or(Error::OffsetOverflow)
}

fn next_generation(generation: u64) -> Result<u64, Error> {
    generation.checked_add(1).map_or_else(
        || Err(invalid_data("atomic generation overflow").into()),
        Ok,
    )
}

/// Validate slot parity, checked payload extent, and canonical integrity geometry.
///
/// Guard, header CRC32C, witness binding, and suffix validation belong to the root and slot
/// decoders. The returned value is the raw backing extent selected by this root.
fn validate_root(root: Root, root_offset: u64, backing_len: u64) -> io::Result<u64> {
    if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
        return Err(invalid_data("atomic root generation is in the wrong slot"));
    }
    let end = DATA_OFFSET
        .checked_add(root.logical_len)
        .ok_or_else(|| invalid_data("atomic payload length overflows"))?;
    if end > backing_len {
        return Err(invalid_data("atomic root exceeds the backing blob"));
    }
    if root.integrity_start > root.logical_len {
        return Err(invalid_data(
            "atomic integrity tail starts beyond the payload",
        ));
    }
    let tail_len = root.logical_len - root.integrity_start;
    if tail_len == 0 && root.integrity_checksum != 0 {
        return Err(invalid_data("empty atomic integrity tail has a checksum"));
    }
    match root.integrity_scheme {
        IntegrityScheme::Unbound if root.integrity_start != 0 => {
            return Err(invalid_data(
                "unbound atomic integrity tail has a nonzero start",
            ));
        }
        IntegrityScheme::Chunked(size) => {
            let data_len = u64::from(size.get());
            let encoded_len = data_len
                .checked_add(size_of::<u32>() as u64)
                .ok_or_else(|| invalid_data("atomic integrity geometry overflows"))?;
            if !root.integrity_start.is_multiple_of(encoded_len) || tail_len >= data_len {
                return Err(invalid_data(
                    "atomic chunked integrity tail is noncanonical",
                ));
            }
        }
        IntegrityScheme::Unbound | IntegrityScheme::Variable => {}
    }
    Ok(end)
}

/// Classify a complete root slot before lineage or payload validation.
///
/// `Raw` includes corrupt roots and allowed torn transitions. Recovery interprets those bytes only
/// when a predecessor or bound witness supplies the missing authority.
#[derive(Clone, Copy, Debug)]
enum Slot {
    Zero,
    Root(RootState, Root),
    Finalized { root: Root, removed: bool },
    Raw,
}

impl Slot {
    const fn root(self) -> Option<Root> {
        match self {
            Self::Root(_, root) | Self::Finalized { root, .. } => Some(root),
            Self::Zero | Self::Raw => None,
        }
    }

    const fn independent(self) -> Option<(Root, bool)> {
        match self {
            Self::Finalized { root, removed } => Some((root, removed)),
            Self::Zero | Self::Root(_, _) | Self::Raw => None,
        }
    }
}

/// Decode a slot and enforce the suffix grammar for its root spelling.
fn decode_slot(
    encoded: &RootSlot,
    root_offset: u64,
    expected_incarnation: Option<&[u8; INCARNATION_LEN]>,
) -> Slot {
    if encoded.iter().all(|byte| *byte == 0) {
        Slot::Zero
    } else {
        let header: &[u8; ROOT_LEN] = encoded[..ROOT_LEN]
            .try_into()
            .expect("root slots contain a complete header");
        let Some((state, root)) = decode_any_root(header) else {
            return Slot::Raw;
        };
        let suffix_valid = match state {
            RootState::BatchPrepared => {
                let Some(link) = batch::link_at(encoded, "", &[], root_offset) else {
                    return Slot::Raw;
                };
                expected_incarnation
                    .is_none_or(|expected| link.participant.incarnation == *expected)
                    && header == &link.participant.candidate.prepared_root
            }
            RootState::Finalized => {
                let Some(link) = batch::link_at(encoded, "", &[], root_offset).filter(|link| {
                    expected_incarnation
                        .is_none_or(|expected| link.participant.incarnation == *expected)
                }) else {
                    return Slot::Raw;
                };
                let Some(final_root) = link.participant.candidate.final_root() else {
                    return Slot::Raw;
                };
                if header != &final_root {
                    return Slot::Raw;
                }
                return Slot::Finalized {
                    root,
                    removed: link.participant.removed,
                };
            }
        };
        if !suffix_valid {
            return Slot::Raw;
        }
        Slot::Root(state, root)
    }
}

/// Non-authoritative parity slot that must be durably cleared before reuse.
struct RejectionPlan {
    root_offset: u64,
}

const INTEGRITY_CHECKSUM_LEN: usize = size_of::<u32>();

fn validate_integrity(data: &[u8], expected: u32) -> io::Result<()> {
    let mut checksum = Crc32::default();
    checksum.update(data);
    if checksum.finalize().1.as_u32() == expected {
        Ok(())
    } else {
        Err(invalid_data("atomic integrity checksum mismatch"))
    }
}

/// Select the repair needed before the non-authoritative parity slot can be reused.
///
/// The newest valid locally selectable root is the authority. Its opposite slot must be zero, the
/// exact predecessor, or the next attempted generation. Clearing an attempted generation preserves
/// the authority's generation so the same next generation can be retried from a durable zero slot.
///
/// ```text
/// authority or slot condition                       result
/// ------------------------------------------------  -----------------------------------
/// removed Finalized h                              no local plan
/// exact canonical predecessor h - 1                no plan
/// durable zero slot                                no plan
/// BatchPrepared h + 1, Raw, older mosaic           clear the complete slot
/// bad gap or unresolved newer local authority      corruption
/// ```
fn rejection_plan_for(
    backing_len: u64,
    encoded: &[RootSlot; ROOT_OFFSETS.len()],
    expected_incarnation: Option<&[u8; INCARNATION_LEN]>,
) -> io::Result<Option<RejectionPlan>> {
    if backing_len < DATA_OFFSET {
        return Err(invalid_data("atomic blob is shorter than its root region"));
    }

    let slots: [Slot; ROOT_OFFSETS.len()] = std::array::from_fn(|index| {
        decode_slot(&encoded[index], ROOT_OFFSETS[index], expected_incarnation)
    });
    for (slot, offset) in slots.iter().zip(ROOT_OFFSETS) {
        if let Some(root) = slot.root()
            && ROOT_OFFSETS[(root.generation as usize) & 1] != offset
        {
            return Err(invalid_data("atomic root generation is in the wrong slot"));
        }
    }

    let mut authority: Option<(usize, bool, Root)> = None;
    let mut recovery_error = None;
    for (index, slot) in slots.iter().enumerate() {
        let Some((root, removed)) = slot.independent() else {
            continue;
        };
        match validate_root(root, ROOT_OFFSETS[index], backing_len) {
            Ok(_) => {}
            Err(error) => {
                recovery_error.get_or_insert(error);
                continue;
            }
        }
        if authority
            .as_ref()
            .is_none_or(|(_, _, selected)| root.generation > selected.generation)
        {
            authority = Some((index, removed, root));
        }
    }

    let (authority_index, authority_removed, authority) = match authority {
        Some(authority) => authority,
        None if matches!(slots[0], Slot::Zero) => (
            0,
            false,
            Root {
                generation: 0,
                logical_len: 0,
                integrity_start: 0,
                integrity_checksum: 0,
                integrity_scheme: IntegrityScheme::Unbound,
                tag: [0; ATOMIC_BLOB_TAG_LEN],
            },
        ),
        None => {
            return Err(recovery_error
                .unwrap_or_else(|| invalid_data("atomic blob has no recoverable root")));
        }
    };
    if authority_removed {
        return Ok(None);
    }
    let target_index = 1 - authority_index;
    let target = slots[target_index];
    if matches!(target, Slot::Zero) {
        return Ok(None);
    }
    if let Some((root, _)) = target.independent() {
        if root.generation < authority.generation {
            if validate_root(root, ROOT_OFFSETS[target_index], backing_len).is_ok()
                && root.generation.checked_add(1) == Some(authority.generation)
            {
                return Ok(None);
            }
            // A torn prepared-slot rewrite can turn the older slot into a checksum-valid
            // independent mosaic. The hybrid may have an unrelated generation, or retain the
            // predecessor generation while changing its value. Neither can supersede the newer
            // authority, but both must be consumed before this slot is reused.
        } else {
            return Err(invalid_data(format!(
                "atomic recovery left generation {} unresolved",
                root.generation
            )));
        }
    } else if let Some(root) = target.root()
        && authority.generation.checked_add(1) != Some(root.generation)
    {
        return Err(invalid_data(
            "atomic rejected candidate does not follow its predecessor",
        ));
    }

    authority
        .generation
        .checked_add(1)
        .ok_or_else(|| invalid_data("atomic generation overflow"))?;
    Ok(Some(RejectionPlan {
        root_offset: ROOT_OFFSETS[target_index],
    }))
}

/// Mutable view of one opened incarnation.
///
/// Three lengths separate visibility, publication, and earlier durability:
///
/// ```text
/// durable_len <= logical_len
/// committed.logical_len has no fixed ordering with durable_len or logical_len
/// logical_len is the encoded length visible through this handle
/// ```
///
/// Appends can move `logical_len` ahead of both baselines. Preflush can move `durable_len` past the
/// published end, while rewind can clamp it below that end. A pending rewind can also move
/// `logical_len` below the committed length. Dirtiness compares visible and published state, not
/// payload durability. Any admitted mutable I/O failure poisons the complete clone set until
/// reopen reconstructs this state.
#[derive(Clone, Debug)]
struct State {
    /// Fresh compare-token epoch shared by one opened handle and its clones.
    token_epoch: [u8; INCARNATION_LEN],
    /// Encoded payload length visible through this handle.
    logical_len: u64,
    /// Visible prefix covered by a completed full-file durability operation.
    durable_len: u64,
    /// Complete value selected by the current root.
    committed: Root,
    /// Start of the unfinished integrity unit in the visible payload.
    integrity_start: u64,
    /// Finalized checksum of the unfinished visible unit.
    integrity_checksum: u32,
    /// Integrity geometry bound to visible offsets.
    integrity_scheme: IntegrityScheme,
    /// Immediately visible application tag.
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
    /// In-memory compare-token component advanced by coherent mutations.
    revision: u64,
    /// Whether an admitted mutable operation ended without a known in-memory result.
    poisoned: bool,
    /// Whether a completed group selected logical absence for this incarnation.
    removed: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            token_epoch: [0; INCARNATION_LEN],
            logical_len: 0,
            durable_len: 0,
            committed: Root {
                generation: 0,
                logical_len: 0,
                integrity_start: 0,
                integrity_checksum: 0,
                integrity_scheme: IntegrityScheme::Unbound,
                tag: [0; ATOMIC_BLOB_TAG_LEN],
            },
            integrity_start: 0,
            integrity_checksum: 0,
            integrity_scheme: IntegrityScheme::Unbound,
            tag: [0; ATOMIC_BLOB_TAG_LEN],
            revision: 0,
            poisoned: false,
            removed: false,
        }
    }
}

impl State {
    /// Reconstruct visible state from the newest valid independent root.
    ///
    /// Group recovery and rejection consumption run before this selector. Batch-prepared roots and
    /// raw transitions are therefore ignored here. The returned length requests a
    /// repeated physical shrink when the selected logical end is shorter than the backing blob.
    fn recover_for(
        backing_len: u64,
        encoded: &[RootSlot; ROOT_OFFSETS.len()],
        expected_incarnation: Option<&[u8; INCARNATION_LEN]>,
        token_epoch: [u8; INCARNATION_LEN],
    ) -> io::Result<(Self, Option<u64>)> {
        let mut roots = Vec::new();
        let mut recovery_error = None;
        for (slot, offset) in encoded.iter().zip(ROOT_OFFSETS) {
            let Some((root, _)) = decode_slot(slot, offset, expected_incarnation).independent()
            else {
                continue;
            };
            match validate_root(root, offset, backing_len) {
                Ok(end) => roots.push((root, end)),
                Err(error) => {
                    recovery_error.get_or_insert(error);
                }
            }
        }
        roots.sort_by_key(|(root, _)| std::cmp::Reverse(root.generation));
        let (root, selected_len) = match roots.into_iter().next() {
            Some(selected) => selected,
            None if matches!(
                decode_slot(&encoded[0], ROOT_OFFSETS[0], expected_incarnation),
                Slot::Zero
            ) =>
            {
                (
                    Root {
                        generation: 0,
                        logical_len: 0,
                        integrity_start: 0,
                        integrity_checksum: 0,
                        integrity_scheme: IntegrityScheme::Unbound,
                        tag: [0; ATOMIC_BLOB_TAG_LEN],
                    },
                    DATA_OFFSET,
                )
            }
            None => {
                return Err(recovery_error
                    .unwrap_or_else(|| invalid_data("atomic blob has no recoverable root")));
            }
        };
        Ok((
            Self {
                token_epoch,
                logical_len: root.logical_len,
                durable_len: root.logical_len,
                committed: root,
                integrity_start: root.integrity_start,
                integrity_checksum: root.integrity_checksum,
                integrity_scheme: root.integrity_scheme,
                tag: root.tag,
                revision: 0,
                poisoned: false,
                removed: false,
            },
            (selected_len != backing_len).then_some(selected_len),
        ))
    }

    fn ensure_healthy(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned").into());
        }
        Ok(())
    }

    fn ensure_mutable(&self) -> Result<(), Error> {
        if self.removed {
            return Err(invalid_data("atomic blob incarnation was removed").into());
        }
        if self.committed.generation == u64::MAX {
            return Err(invalid_data("atomic generation exhausted").into());
        }
        Ok(())
    }

    fn set_tag(&mut self, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        if tag == self.tag {
            return Ok(());
        }
        self.ensure_mutable()?;
        self.tag = tag;
        self.advance_revision();
        Ok(())
    }

    fn integrity_tail(&self) -> Option<IntegrityUnit> {
        (self.integrity_start < self.logical_len).then_some(IntegrityUnit {
            offset: self.integrity_start,
            len: self.logical_len - self.integrity_start,
        })
    }

    const fn integrity_token(&self) -> IntegrityToken {
        IntegrityToken {
            epoch: self.token_epoch,
            revision: self.revision,
        }
    }

    fn expect_integrity_token(&self, expected: IntegrityToken) -> Result<(), Error> {
        if self.integrity_token() == expected {
            Ok(())
        } else {
            Err(invalid_input("atomic integrity state is stale"))
        }
    }

    const fn advance_revision(&mut self) {
        self.revision = self
            .revision
            .checked_add(1)
            .expect("atomic in-memory mutation revision exhausted");
    }

    /// Return whether visible state differs from its published baseline.
    fn is_dirty(&self) -> bool {
        self.logical_len != self.committed.logical_len
            || self.integrity_start != self.committed.integrity_start
            || self.integrity_checksum != self.committed.integrity_checksum
            || self.integrity_scheme != self.committed.integrity_scheme
            || self.tag != self.committed.tag
    }

    fn validate_integrity_tail(&self, data: &[u8]) -> Result<(), Error> {
        let Some(unit) = self.integrity_tail() else {
            return if data.is_empty() {
                Ok(())
            } else {
                Err(invalid_input(
                    "closed atomic integrity state has tail bytes",
                ))
            };
        };
        if usize::try_from(unit.len).ok() != Some(data.len()) {
            return Err(invalid_input("atomic integrity tail has an invalid length"));
        }
        validate_integrity(data, self.integrity_checksum).map_err(Into::into)
    }

    /// Preflight an integrity append and return its write plan when bytes must be written.
    ///
    /// The result interleaves caller bytes with protocol-owned CRC32C footers. Chunked mode can
    /// close several units in one append. Variable mode closes at most the caller-selected current
    /// unit. A returned [`PreparedAppend`] leaves state unchanged until `finish_append`. Empty
    /// scheme binding is the exception. It updates integrity metadata without backing I/O.
    ///
    /// ```text
    /// visible tail + caller bytes
    ///          |
    ///          +-- Continue --------> keep one unfinished unit
    ///          +-- Complete --------> append one footer and close it
    ///          `-- Chunked(width) --> append a footer at every full boundary
    /// ```
    fn prepare_integrity_append(
        &mut self,
        mut data: IoBufs,
        boundary: IntegrityBoundary,
    ) -> Result<Option<PreparedAppend>, Error> {
        if data.is_empty() && matches!(boundary, IntegrityBoundary::Continue) {
            return Ok(None);
        }
        if self.logical_len < self.committed.logical_len {
            return Err(invalid_input(
                "atomic append requires synchronizing the committed rewind first",
            ));
        }
        self.ensure_mutable()?;
        let requested_scheme = match boundary {
            IntegrityBoundary::Continue => None,
            IntegrityBoundary::Complete => Some(IntegrityScheme::Variable),
            IntegrityBoundary::Chunked(size) => Some(IntegrityScheme::Chunked(size)),
        };
        let integrity_scheme = match (self.integrity_scheme, requested_scheme) {
            (scheme, None) | (IntegrityScheme::Unbound, Some(scheme)) => scheme,
            (scheme, Some(requested)) if scheme == requested => scheme,
            _ => {
                return Err(invalid_input(
                    "atomic blob is already bound to a different integrity scheme",
                ));
            }
        };
        let logical_start = self.logical_len;
        let mut logical_cursor = logical_start;
        let mut integrity_start = self.integrity_start;
        let mut integrity_checksum = Crc32::resume(self.integrity_checksum);
        let mut result_offset = None;
        let mut parts = Vec::new();
        let mut footer_bytes = Vec::new();
        let chunk_size = match integrity_scheme {
            IntegrityScheme::Chunked(size) => Some(u64::from(size.get())),
            IntegrityScheme::Unbound | IntegrityScheme::Variable => None,
        };
        if let Some(chunk_size) = chunk_size
            && logical_cursor - integrity_start > chunk_size
        {
            return Err(invalid_input(
                "current atomic integrity unit exceeds the requested chunk size",
            ));
        }
        let closes_existing = matches!(boundary, IntegrityBoundary::Complete)
            && self.integrity_start != self.logical_len
            || chunk_size.is_some_and(|size| self.logical_len - self.integrity_start == size);
        if data.is_empty() && !closes_existing {
            if self.integrity_scheme != integrity_scheme {
                self.integrity_scheme = integrity_scheme;
                self.advance_revision();
            }
            return Ok(None);
        }

        let data_len = u64::try_from(data.len()).map_err(|_| Error::OffsetOverflow)?;
        let seal_count = if let Some(chunk_size) = chunk_size {
            let tail_len = logical_cursor - integrity_start;
            u64::try_from((u128::from(tail_len) + u128::from(data_len)) / u128::from(chunk_size))
                .map_err(|_| Error::OffsetOverflow)?
        } else if matches!(boundary, IntegrityBoundary::Complete) {
            1
        } else {
            0
        };
        let logical_end = logical_start
            .checked_add(data_len)
            .and_then(|end| {
                seal_count
                    .checked_mul(INTEGRITY_CHECKSUM_LEN as u64)
                    .and_then(|footer_len| end.checked_add(footer_len))
            })
            .ok_or(Error::OffsetOverflow)?;
        raw_len(logical_end)?;
        let mut packed = (seal_count > MAX_SCATTER_INTEGRITY_UNITS).then(PackedAppend::new);

        let seal = |parts: &mut Vec<(IoBufs, Option<usize>)>,
                    footer_bytes: &mut Vec<u8>,
                    packed: &mut Option<PackedAppend>,
                    integrity_start: &mut u64,
                    integrity_checksum: &mut Crc32,
                    logical_cursor: &mut u64|
         -> Result<(), Error> {
            debug_assert_ne!(*integrity_start, *logical_cursor);
            let footer = std::mem::take(integrity_checksum)
                .finalize()
                .1
                .as_u32()
                .to_be_bytes();
            if let Some(packed) = packed.as_mut() {
                packed.push(&footer);
            } else {
                let footer_offset = footer_bytes.len();
                footer_bytes.extend_from_slice(&footer);
                parts.push((IoBufs::default(), Some(footer_offset)));
            }
            *logical_cursor = logical_cursor
                .checked_add(INTEGRITY_CHECKSUM_LEN as u64)
                .ok_or(Error::OffsetOverflow)?;
            *integrity_start = *logical_cursor;
            Ok(())
        };

        if chunk_size.is_some_and(|size| logical_cursor - integrity_start == size) {
            seal(
                &mut parts,
                &mut footer_bytes,
                &mut packed,
                &mut integrity_start,
                &mut integrity_checksum,
                &mut logical_cursor,
            )?;
        }

        while !data.is_empty() {
            let available = chunk_size
                .map(|size| size - (logical_cursor - integrity_start))
                .unwrap_or(u64::MAX);
            let take = data
                .len()
                .min(usize::try_from(available).unwrap_or(usize::MAX));
            debug_assert_ne!(take, 0);
            let part = data.split_to(take);
            part.for_each_chunk(|chunk| {
                integrity_checksum.update(chunk);
            });
            result_offset.get_or_insert(logical_cursor);
            logical_cursor = logical_cursor
                .checked_add(take as u64)
                .ok_or(Error::OffsetOverflow)?;
            if let Some(packed) = packed.as_mut() {
                part.for_each_chunk(|chunk| packed.push(chunk));
            } else {
                parts.push((part, None));
            }
            if chunk_size.is_some_and(|size| logical_cursor - integrity_start == size) {
                seal(
                    &mut parts,
                    &mut footer_bytes,
                    &mut packed,
                    &mut integrity_start,
                    &mut integrity_checksum,
                    &mut logical_cursor,
                )?;
            }
        }
        if matches!(boundary, IntegrityBoundary::Complete) {
            seal(
                &mut parts,
                &mut footer_bytes,
                &mut packed,
                &mut integrity_start,
                &mut integrity_checksum,
                &mut logical_cursor,
            )?;
        }
        debug_assert_eq!(logical_cursor, logical_end);
        let encoded = packed.map_or_else(
            || {
                let footers = IoBuf::from(footer_bytes);
                let mut encoded = IoBufs::default();
                for (part, footer_offset) in parts {
                    encoded.append(part.coalesce());
                    if let Some(offset) = footer_offset {
                        encoded.append(footers.slice(offset..offset + INTEGRITY_CHECKSUM_LEN));
                    }
                }
                encoded
            },
            PackedAppend::finish,
        );
        let integrity_checksum = integrity_checksum.finalize().1.as_u32();
        Ok(Some(PreparedAppend {
            result_offset: result_offset.unwrap_or(logical_start),
            logical_start,
            logical_end: logical_cursor,
            encoded,
            integrity_start,
            integrity_checksum,
            integrity_scheme,
        }))
    }

    /// Install a successfully written append into the immediately visible state.
    ///
    /// Reusing an offset at or before the prior durable frontier conservatively moves the frontier
    /// back to the start of this write.
    fn finish_append(&mut self, prepared: PreparedAppend) {
        self.durable_len = if self.durable_len < prepared.logical_start {
            self.durable_len
        } else {
            prepared.logical_start
        };
        self.logical_len = prepared.logical_end;
        self.integrity_start = prepared.integrity_start;
        self.integrity_checksum = prepared.integrity_checksum;
        self.integrity_scheme = prepared.integrity_scheme;
        self.advance_revision();
    }

    const fn speculative_payload_len(&self) -> u64 {
        self.logical_len.saturating_sub(self.durable_len)
    }

    fn finish_payload_preflush(&mut self, target: u64) {
        assert!(target <= self.logical_len);
        self.durable_len = self.durable_len.max(target);
    }

    fn validate_rewind(&self, len: u64) -> Result<(), Error> {
        if len > self.logical_len {
            return Err(invalid_input("atomic rewind cannot extend a blob"));
        }
        if len == self.logical_len {
            return Ok(());
        }
        self.ensure_mutable()?;
        Ok(())
    }

    /// Build the read plan needed to prove a rewind target.
    ///
    /// An internally known unit boundary needs no read. Rewinding into a unit requires the complete
    /// current unit or one completed unit whose footer can be validated before rebuilding the
    /// retained prefix checksum.
    fn rewind_integrity_source(
        &self,
        len: u64,
        unit: Option<IntegrityUnit>,
    ) -> Result<Option<RewindIntegritySource>, Error> {
        self.validate_rewind(len)?;
        if len == self.logical_len || len == self.committed.logical_len {
            return Ok(None);
        }
        let current = self.integrity_tail();
        let unit = unit.or_else(|| {
            current.filter(|unit| {
                unit.offset < len
                    && unit
                        .offset
                        .checked_add(unit.len)
                        .is_some_and(|end| len <= end)
            })
        });
        let Some(unit) = unit else {
            let known_boundary = len == 0
                || current.is_some_and(|unit| len == unit.offset)
                || match self.integrity_scheme {
                    IntegrityScheme::Chunked(size) => {
                        let encoded_unit = u64::from(size.get())
                            .checked_add(INTEGRITY_CHECKSUM_LEN as u64)
                            .ok_or(Error::OffsetOverflow)?;
                        len.is_multiple_of(encoded_unit)
                    }
                    IntegrityScheme::Unbound | IntegrityScheme::Variable => false,
                };
            return if known_boundary {
                Ok(None)
            } else {
                Err(invalid_input(
                    "atomic rewind target is not a proven integrity-unit boundary",
                ))
            };
        };
        let is_current = current == Some(unit);
        if !is_current {
            self.integrity_scheme.validate_completed_unit(unit)?;
        }
        let data_end = unit
            .offset
            .checked_add(unit.len)
            .ok_or(Error::OffsetOverflow)?;
        if !is_current
            && matches!(self.integrity_scheme, IntegrityScheme::Chunked(_))
            && len == data_end
        {
            return Err(invalid_input(
                "atomic rewind cannot leave a full fixed-width integrity tail",
            ));
        }
        let encoded_end = if is_current {
            data_end
        } else {
            let encoded_end = data_end
                .checked_add(INTEGRITY_CHECKSUM_LEN as u64)
                .ok_or(Error::OffsetOverflow)?;
            if encoded_end > self.integrity_start {
                return Err(invalid_input(
                    "completed atomic integrity unit exceeds the completed payload prefix",
                ));
            }
            encoded_end
        };
        let retain_prefix = unit.offset < len && len <= data_end;
        let boundary = len == unit.offset || (!is_current && len == encoded_end);
        if !retain_prefix && !boundary {
            return Err(invalid_input(
                "atomic rewind integrity unit does not contain or border the new end",
            ));
        }
        if is_current && boundary {
            return Ok(None);
        }
        Ok(Some(RewindIntegritySource {
            unit,
            current: is_current,
            retain_prefix,
        }))
    }

    /// Apply a validated rewind and rebuild the unfinished integrity baseline.
    ///
    /// This changes logical authority only in memory. Publication selects the shorter root before
    /// any physical truncation is attempted.
    fn apply_rewind(
        &mut self,
        len: u64,
        source: Option<(IntegrityUnit, &[u8])>,
    ) -> Result<(), Error> {
        self.validate_rewind(len)?;
        if len == self.logical_len {
            return Ok(());
        }
        let integrity_scheme = if len == self.committed.logical_len {
            self.committed.integrity_scheme
        } else {
            self.integrity_scheme
        };
        let (integrity_start, integrity_checksum) = if len == self.committed.logical_len {
            (
                self.committed.integrity_start,
                self.committed.integrity_checksum,
            )
        } else if let Some((unit, data)) = source {
            if usize::try_from(unit.len).ok() != Some(data.len()) {
                return Err(invalid_input(
                    "atomic rewind integrity source has an invalid length",
                ));
            }
            let retained = usize::try_from(len - unit.offset).map_err(|_| Error::OffsetOverflow)?;
            let mut checksum = Crc32::default();
            checksum.update(&data[..retained]);
            (unit.offset, checksum.finalize().1.as_u32())
        } else {
            (len, 0)
        };
        self.logical_len = len;
        self.durable_len = self.durable_len.min(len);
        self.integrity_start = integrity_start;
        self.integrity_checksum = integrity_checksum;
        self.integrity_scheme = integrity_scheme;
        self.advance_revision();
        Ok(())
    }

    /// Snapshot the next root without changing visible or committed state.
    fn prepare_commit(&self) -> Result<Option<PreparedCommit>, Error> {
        if !self.is_dirty() {
            return Ok(None);
        }
        self.ensure_mutable()?;
        let generation = next_generation(self.committed.generation)?;
        let root_offset = ROOT_OFFSETS[(generation as usize) & 1];
        Ok(Some(PreparedCommit {
            generation,
            logical_len: self.logical_len,
            integrity_start: self.integrity_start,
            integrity_checksum: self.integrity_checksum,
            integrity_scheme: self.integrity_scheme,
            tag: self.tag,
            root_offset,
            truncate: self.logical_len < self.committed.logical_len,
        }))
    }

    /// Advance the in-memory published baseline after its durable decision and cleanup write.
    const fn finish_commit(&mut self, prepared: &PreparedCommit) {
        self.durable_len = prepared.logical_len;
        self.committed = Root {
            generation: prepared.generation,
            logical_len: prepared.logical_len,
            integrity_start: prepared.integrity_start,
            integrity_checksum: prepared.integrity_checksum,
            integrity_scheme: prepared.integrity_scheme,
            tag: prepared.tag,
        };
    }
}

/// Immutable root fields and cleanup requirements captured before direct publication starts.
struct PreparedCommit {
    generation: u64,
    logical_len: u64,
    integrity_start: u64,
    integrity_checksum: u32,
    integrity_scheme: IntegrityScheme,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
    root_offset: u64,
    truncate: bool,
}

/// Encoded append and the visible integrity state it establishes after a successful write.
struct PreparedAppend {
    result_offset: u64,
    logical_start: u64,
    logical_end: u64,
    encoded: IoBufs,
    integrity_start: u64,
    integrity_checksum: u32,
    integrity_scheme: IntegrityScheme,
}

const INTEGRITY_ENCODING_BLOCK_LEN: usize = 64 * 1024;
// Scatter encoding contributes one payload and one footer descriptor per completed unit.
const MAX_SCATTER_INTEGRITY_UNITS: u64 = 512;

/// Packs highly fragmented integrity encodings into bounded contiguous write chunks.
struct PackedAppend {
    encoded: IoBufs,
    block: Vec<u8>,
}

impl PackedAppend {
    fn new() -> Self {
        Self {
            encoded: IoBufs::default(),
            block: Vec::with_capacity(INTEGRITY_ENCODING_BLOCK_LEN),
        }
    }

    fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let available = INTEGRITY_ENCODING_BLOCK_LEN - self.block.len();
            if available == 0 {
                let block = std::mem::replace(
                    &mut self.block,
                    Vec::with_capacity(INTEGRITY_ENCODING_BLOCK_LEN),
                );
                self.encoded.append(IoBuf::from(block));
                continue;
            }
            let take = available.min(bytes.len());
            self.block.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
    }

    fn finish(mut self) -> IoBufs {
        if !self.block.is_empty() {
            self.encoded.append(IoBuf::from(self.block));
        }
        self.encoded
    }
}

/// Read plan for the integrity proof around a rewind target.
///
/// `current` selects the root-carried checksum with no footer. Otherwise the following footer must
/// be read. `retain_prefix` means data is also needed to rebuild the new rolling checksum.
#[derive(Clone, Copy)]
struct RewindIntegritySource {
    unit: IntegrityUnit,
    current: bool,
    retain_prefix: bool,
}

/// Poison-on-drop boundary for state-coupled mutable I/O.
///
/// Any exit while armed poisons shared state. Issued bytes or a decision may already be durable, so
/// reopen decides the outcome. Background observer drop does not drop the retained task. Detached
/// preflush failures poison explicitly. Validation and no-op paths remain unarmed. Successful
/// mutation paths disarm only after in-memory state reflects all I/O.
struct Operation<'a> {
    state: MutexGuard<'a, State>,
    armed: bool,
}

type CarriedSlot<B> = Arc<Mutex<Option<Arc<CarriedGroup<B>>>>>;

/// Participant file whose issued final root still needs a durability barrier.
struct CarriedMember<B> {
    partition: Arc<str>,
    name: Arc<[u8]>,
    incarnation: [u8; INCARNATION_LEN],
    backing: B,
    sync_gate: Arc<Mutex<()>>,
    slot: Weak<Mutex<Option<Arc<CarriedGroup<B>>>>>,
}

/// Process-local notification that recovery made one group's final roots independent.
struct CarriedPayment {
    group_id: [u8; batch::GROUP_ID_LEN],
    paid: AtomicBool,
    budget: Weak<PayloadBudget>,
}

impl CarriedPayment {
    fn is_paid(&self) -> bool {
        self.paid.load(AtomicOrdering::Acquire)
    }
}

impl Drop for CarriedPayment {
    fn drop(&mut self) {
        let Some(budget) = self.budget.upgrade() else {
            return;
        };
        let mut state = budget.state.lock();
        if state
            .carried_payments
            .get(&self.group_id)
            .is_some_and(|payment| std::ptr::eq(payment.as_ptr(), self))
        {
            state.carried_payments.remove(&self.group_id);
        }
    }
}

/// Live certificate and final-root durability debt for one decided group.
///
/// ```text
/// participant carried slots --Arc--> shared group --> participant backing handles
/// shared group ----------------Weak-----------------------> participant carried slots
/// ```
///
/// The bound ring is durable. Its identity and exact candidate fields certify the selected
/// predecessor while final roots remain unsynchronized. A later decision synchronizes every prior
/// member file before clearing pointer-matching slots. Weak back-references avoid a retention cycle
/// and let dropped participant handles disappear. If all handles disappear, the disk ring remains
/// recovery authority. This tracks final-root durability, not physical deletion.
struct CarriedGroup<B> {
    group_id: [u8; batch::GROUP_ID_LEN],
    members: Vec<CarriedMember<B>>,
    payment: Arc<CarriedPayment>,
    coordination: Mutex<()>,
}

/// Clear this group without disturbing a newer certificate already installed in a member slot.
async fn clear_carried_group<B>(group: &Arc<CarriedGroup<B>>) {
    for member in &group.members {
        let Some(slot) = member.slot.upgrade() else {
            continue;
        };
        let mut slot = slot.lock().await;
        if slot
            .as_ref()
            .is_some_and(|installed| Arc::ptr_eq(installed, group))
        {
            *slot = None;
        }
    }
}

async fn sync_carried_member<B: BackingBlob>(member: &CarriedMember<B>) -> Result<(), Error> {
    let _sync = member.sync_gate.lock().await;
    member.backing.sync().await
}

impl<'a> Operation<'a> {
    const fn new(state: MutexGuard<'a, State>) -> Self {
        Self {
            state,
            armed: false,
        }
    }

    const fn arm(&mut self) {
        self.armed = true;
    }

    fn finish(mut self) {
        self.armed = false;
    }
}

impl Deref for Operation<'_> {
    type Target = State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for Operation<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.poisoned = true;
        }
    }
}

/// Cloneable atomic view over one exact backing incarnation.
///
/// Clones share mutation state, payload accounting, preflush work, carried cleanup debt, and
/// operation ownership. The public ownership contract forbids independently opened handles, so
/// this type does not coordinate with them. The lineage exclusion lock separates live operations
/// from namespace recovery, while the operation mutex serializes conflicting clones and groups.
/// `driver` owns the cancellation policy for admitted work.
pub struct Blob<B> {
    backing: B,
    partition: Arc<str>,
    name: Arc<[u8]>,
    incarnation: [u8; INCARNATION_LEN],
    state: Arc<Mutex<State>>,
    payload: Arc<PayloadAccount>,
    preflush: Arc<PayloadPreflush>,
    carried: CarriedSlot<B>,
    driver: Driver,
    exclusion: Arc<RwLock<()>>,
    operation: Arc<Mutex<()>>,
}

/// Storage-lineage resources attached to each newly opened atomic blob.
pub(crate) struct AtomicResources {
    pub(crate) driver: Driver,
    pub(crate) exclusion: Arc<RwLock<()>>,
    pub(crate) namespace: Arc<Mutex<()>>,
    pub(crate) payload_budget: Arc<PayloadBudget>,
}

impl Clone for AtomicResources {
    fn clone(&self) -> Self {
        Self {
            driver: self.driver.clone(),
            exclusion: self.exclusion.clone(),
            namespace: self.namespace.clone(),
            payload_budget: self.payload_budget.clone(),
        }
    }
}

impl<B: Clone> Clone for Blob<B> {
    fn clone(&self) -> Self {
        Self {
            backing: self.backing.clone(),
            partition: self.partition.clone(),
            name: self.name.clone(),
            incarnation: self.incarnation,
            state: self.state.clone(),
            payload: self.payload.clone(),
            preflush: self.preflush.clone(),
            carried: self.carried.clone(),
            driver: self.driver.clone(),
            exclusion: self.exclusion.clone(),
            operation: self.operation.clone(),
        }
    }
}

impl<B: BackingBlob> Blob<B> {
    /// Normalize rejected local slot states before exposing a mutable handle.
    ///
    /// Namespace-aware recovery resolves every complete group before entering this function. The
    /// remaining local work consumes an incomplete candidate or repeats a lost truncate:
    ///
    /// ```text
    /// read both root slots
    ///          |
    ///          +-- rejected generation --> clear its slot --+
    ///          `-- stable frontier --------------------------+--> select root
    /// ```
    async fn open_named(
        backing: B,
        partition: &str,
        name: &[u8],
        backing_len: u64,
        incarnation: [u8; INCARNATION_LEN],
        token_epoch: [u8; INCARNATION_LEN],
        resources: AtomicResources,
    ) -> Result<(Self, u64), Error> {
        debug_assert!(backing_len >= DATA_OFFSET);

        let mut slots = Self::read_roots(&backing).await?;
        while let Some(plan) = rejection_plan_for(backing_len, &slots, Some(&incarnation))? {
            Self::clear_rejected_slot(&backing, &plan).await?;
            let index = ROOT_OFFSETS
                .iter()
                .position(|offset| *offset == plan.root_offset)
                .expect("rejection plans target a root slot");
            slots[index].fill(0);
        }
        let (state, truncate_to) =
            State::recover_for(backing_len, &slots, Some(&incarnation), token_epoch)?;
        if let Some(len) = truncate_to {
            // The selected root is already authority. Repeating a lost shrink before returning a
            // mutable handle prevents discarded physical offsets from being reused prematurely.
            backing.resize(len).await?;
        }
        let logical_len = state.logical_len;
        let AtomicResources {
            driver,
            exclusion,
            namespace: _,
            payload_budget,
        } = resources;
        Ok((
            Self {
                backing,
                partition: Arc::from(partition),
                name: Arc::from(name),
                incarnation,
                state: Arc::new(Mutex::new(state)),
                payload: PayloadAccount::new(payload_budget),
                preflush: Arc::new(PayloadPreflush::default()),
                carried: Arc::new(Mutex::new(None)),
                driver,
                exclusion,
                operation: Arc::new(Mutex::new(())),
            },
            logical_len,
        ))
    }

    /// Read the complete identity of an existing backing.
    async fn read_identity(backing: &B, backing_len: u64) -> Result<[u8; INCARNATION_LEN], Error> {
        if backing_len < IDENTITY_PAGE_LEN {
            return Err(invalid_data("ordinary blob cannot be opened as atomic").into());
        }
        let page = backing
            .read_at(0, IDENTITY_PAGE_LEN as usize)
            .await?
            .coalesce();
        let page = page
            .as_ref()
            .try_into()
            .expect("identity reads have a fixed length");
        decode_identity(page)
            .ok_or_else(|| invalid_data("ordinary blob cannot be opened as atomic").into())
    }

    /// Install an identity into a fresh ordinary backing.
    async fn initialize_identity(
        backing: &B,
        backing_len: u64,
        fresh_identity: impl FnOnce() -> [u8; INCARNATION_LEN] + Send,
    ) -> Result<[u8; INCARNATION_LEN], Error> {
        if backing_len != 0 {
            return Err(invalid_data("ordinary blob cannot be opened as atomic").into());
        }
        let incarnation = fresh_identity();
        let canonical = encode_identity(incarnation);
        backing.resize(DATA_OFFSET).await?;
        backing
            .write_at(0, canonical.to_vec(), WriteOptions::default())
            .await?;
        backing.sync().await?;
        Ok(incarnation)
    }

    /// Read the complete fixed recovery region for both alternating roots.
    async fn read_roots(backing: &B) -> Result<[RootSlot; ROOT_OFFSETS.len()], Error> {
        // Direct recovery is bounded: read both complete slots and never scan application payload.
        let mut slots = [[0u8; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
        for (slot, offset) in slots.iter_mut().zip(ROOT_OFFSETS) {
            let data = backing.read_at(offset, ROOT_SLOT_SIZE).await?.coalesce();
            slot.copy_from_slice(data.as_ref());
        }
        Ok(slots)
    }

    /// Durably erase every byte from a rejected non-authoritative slot before it can be reused.
    async fn clear_rejected_slot(backing: &B, plan: &RejectionPlan) -> Result<(), Error> {
        backing
            .write_at(
                plan.root_offset,
                vec![0; ROOT_SLOT_SIZE],
                WriteOptions::SYNC,
            )
            .await
    }

    async fn lock_state(&self) -> Result<MutexGuard<'_, State>, Error> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        Ok(state)
    }

    fn key(&self) -> (&str, &[u8]) {
        (&self.partition, &self.name)
    }

    fn same_handle(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// Drive one coalesced payload preflush until it reaches the latest requested target.
    ///
    /// A request that arrives during `sync` raises `requested`. The worker loops so completion
    /// covers every target admitted to this round before it retires lineage accounting. A
    /// successful barrier credits only the sampled target to `durable_len`, even if later writes
    /// also persisted. Requests raised during the barrier force another iteration. Preflush never
    /// changes generation, published state, or `dirty`.
    async fn run_payload_preflush(
        backing: B,
        state: Arc<Mutex<State>>,
        payload: Arc<PayloadAccount>,
        preflush: Arc<PayloadPreflush>,
        round: Arc<PayloadPreflushRound>,
        signaler: Signaler,
    ) {
        let _sync = preflush.sync_gate.lock().await;
        loop {
            let target = {
                let preflush_state = preflush.state.lock();
                let current = preflush_state
                    .current
                    .as_ref()
                    .expect("an admitted payload preflush remains current until completion");
                assert!(Arc::ptr_eq(current, &round));
                round.requested.load(AtomicOrdering::Relaxed)
            };
            if let Err(error) = backing.sync().await {
                state.lock().await.poisoned = true;
                payload.set(0);
                let mut preflush_state = preflush.state.lock();
                preflush_state.failure = Some(error);
                let current = preflush_state
                    .current
                    .take()
                    .expect("a failed payload preflush remains current");
                assert!(Arc::ptr_eq(&current, &round));
                drop(preflush_state);
                // A mutable storage failure consumes the lineage even when the last handle drops.
                // Retaining the closed completion makes every later namespace drain fail closed.
                return;
            }

            let mut blob_state = state.lock().await;
            blob_state.finish_payload_preflush(target);
            payload.set(blob_state.speculative_payload_len());
            drop(blob_state);

            let complete = {
                let mut preflush_state = preflush.state.lock();
                let current = preflush_state
                    .current
                    .as_ref()
                    .expect("a successful payload preflush remains current");
                assert!(Arc::ptr_eq(current, &round));
                if round.requested.load(AtomicOrdering::Relaxed) > target {
                    false
                } else {
                    preflush_state.current = None;
                    true
                }
            };
            if complete {
                payload.budget.finish(round.id);
                drop(signaler.signal(0));
                return;
            }
        }
    }

    /// Start or extend this blob's current detached payload durability round.
    async fn request_payload_preflush(&self, target: u64) -> Result<(), Error> {
        let (round, signaler) = {
            let mut preflush_state = self.preflush.state.lock();
            Self::take_payload_preflush_failure(&mut preflush_state)?;
            if let Some(round) = &preflush_state.current {
                round.requested.fetch_max(target, AtomicOrdering::Relaxed);
                return Ok(());
            }

            let (signaler, completion) = Signaler::new();
            let round = Arc::new(PayloadPreflushRound {
                id: self.payload.budget.register(completion.clone()),
                requested: AtomicU64::new(target),
                completion,
            });
            preflush_state.current = Some(round.clone());
            (round, signaler)
        };

        let backing = self.backing.clone();
        let state = self.state.clone();
        let payload = self.payload.clone();
        let preflush = self.preflush.clone();
        self.driver
            .drive_detached(async move {
                Self::run_payload_preflush(backing, state, payload, preflush, round, signaler)
                    .await;
            })
            .await;
        Self::take_payload_preflush_failure(&mut self.preflush.state.lock())
    }

    /// Wait for this blob's current preflush, then consume its recorded detached failure.
    async fn drain_payload_preflush(&self) -> Result<(), Error> {
        loop {
            let completion = {
                let mut state = self.preflush.state.lock();
                Self::take_payload_preflush_failure(&mut state)?;
                let Some(round) = &state.current else {
                    return Ok(());
                };
                round.completion.clone()
            };
            if completion.await.is_err() {
                let mut state = self.preflush.state.lock();
                Self::take_payload_preflush_failure(&mut state)?;
                return Err(Error::Closed);
            }
        }
    }

    fn take_payload_preflush_failure(state: &mut PayloadPreflushState) -> Result<(), Error> {
        state.failure.take().map_or(Ok(()), Err)
    }

    /// Serialize one append, write its final payload offsets, and then expose the new state.
    ///
    /// Validation and offset arithmetic complete before the operation is armed. Once backing I/O
    /// starts, cancellation or error poisons the handle because the visible write result is no
    /// longer known.
    async fn append_inner(
        &self,
        data: IoBufs,
        boundary: IntegrityBoundary,
        tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
        expected: Option<IntegrityToken>,
    ) -> Result<IntegrityAppend, Error> {
        let state = self.lock_state().await?;
        let mut operation = Operation::new(state);
        if let Some(expected) = expected {
            operation.expect_integrity_token(expected)?;
        }
        let fallback_offset = operation.logical_len;
        let prepared = operation.prepare_integrity_append(data, boundary)?;
        let result_offset = prepared
            .as_ref()
            .map_or(fallback_offset, |prepared| prepared.result_offset);
        let mut preflush_target = None;
        if let Some(mut prepared) = prepared {
            let backing_offset = raw_len(prepared.logical_start)?;
            let encoded = std::mem::take(&mut prepared.encoded);
            operation.arm();
            self.backing
                .write_at(backing_offset, encoded, WriteOptions::default())
                .await?;
            operation.finish_append(prepared);
            let aggregate = self.payload.set(operation.speculative_payload_len());
            if aggregate > u128::from(MAX_UNSYNCED_PAYLOAD_LEN) {
                let target = operation.logical_len;
                if matches!(&self.driver, Driver::Inline) {
                    let result = {
                        let _sync = self.preflush.sync_gate.lock().await;
                        self.backing.sync().await
                    };
                    if let Err(error) = result {
                        self.payload.set(0);
                        return Err(error);
                    }
                    operation.finish_payload_preflush(target);
                    self.payload.set(operation.speculative_payload_len());
                } else {
                    preflush_target = Some(target);
                }
            }
        }
        if let Some(tag) = tag {
            operation.set_tag(tag)?;
        }
        let token = operation.integrity_token();
        operation.finish();
        if let Some(target) = preflush_target {
            self.request_payload_preflush(target).await?;
        }
        Ok(IntegrityAppend {
            offset: result_offset,
            token,
        })
    }

    /// Validate and apply one logical rewind after all payload preflushes have quiesced.
    async fn rewind_inner(
        &self,
        expected: Option<IntegrityToken>,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        // Rewind may reclaim and reuse bytes covered by this handle's running full-file preflush.
        // Operation ownership prevents a new round from being admitted after this drain.
        self.drain_payload_preflush().await?;
        let mut state = self.lock_state().await?;
        if let Some(expected) = expected {
            state.expect_integrity_token(expected)?;
        }
        let source_data = self.validated_rewind_source(&state, len, unit).await?;
        state
            .apply_rewind(
                len,
                source_data
                    .as_ref()
                    .map(|(unit, data)| (*unit, data.as_slice())),
            )
            .expect("validated rewind sources are internally consistent");
        self.payload.set(state.speculative_payload_len());
        if let Some(tag) = tag {
            state.set_tag(tag)?;
        }
        Ok(state.integrity_token())
    }

    /// Read and verify the integrity source needed to rewind into a unit.
    async fn validated_rewind_source(
        &self,
        state: &State,
        len: u64,
        unit: Option<IntegrityUnit>,
    ) -> Result<Option<(IntegrityUnit, Vec<u8>)>, Error> {
        let Some(source) = state.rewind_integrity_source(len, unit)? else {
            return Ok(None);
        };
        let data_len = usize::try_from(source.unit.len).map_err(|_| Error::OffsetOverflow)?;
        let read_len = if source.current {
            data_len
        } else {
            data_len
                .checked_add(INTEGRITY_CHECKSUM_LEN)
                .ok_or(Error::OffsetOverflow)?
        };
        let offset = raw_len(source.unit.offset)?;
        let encoded = self.backing.read_at(offset, read_len).await?.coalesce();
        if source.current {
            state.validate_integrity_tail(encoded.as_ref())?;
        } else {
            let expected = u32::from_be_bytes(
                encoded.as_ref()[data_len..]
                    .try_into()
                    .expect("integrity checksum footers have a fixed length"),
            );
            validate_integrity(&encoded.as_ref()[..data_len], expected)?;
        }
        Ok(source
            .retain_prefix
            .then(|| (source.unit, encoded.as_ref()[..data_len].to_vec())))
    }

    /// Publish the current dirty state as a durable one-member decision.
    ///
    /// ```text
    /// build payload proof and self witness
    ///                 |
    ///                 v
    /// write candidate + sync this file and carried peers
    ///                 |
    ///                 v
    /// write final root + repeat truncate + activate state
    /// ```
    ///
    /// The concurrent barrier set is the publication's only durability layer. `Finalized` is
    /// ordinary cleanup. A later publication's barrier covers the same file, while recovery
    /// reconstructs the obligation from the durable self-link.
    async fn publish_locked(&self, state: MutexGuard<'_, State>) -> Result<(), Error> {
        let mut operation = Operation::new(state);
        let Some(prepared) = operation.prepare_commit()? else {
            operation.finish();
            return Ok(());
        };

        let root = Root {
            generation: prepared.generation,
            logical_len: prepared.logical_len,
            integrity_start: prepared.integrity_start,
            integrity_checksum: prepared.integrity_checksum,
            integrity_scheme: prepared.integrity_scheme,
            tag: prepared.tag,
        };
        let payload = if prepared.logical_len <= operation.durable_len {
            batch::PayloadDescriptor::empty(prepared.logical_len)
        } else {
            let len = prepared.logical_len - operation.durable_len;
            assert!(
                len <= MAX_UNSYNCED_PAYLOAD_LEN,
                "direct payload preflush bounds the recovery suffix"
            );
            batch::PayloadDescriptor {
                start: operation.durable_len,
                checksum: payload_checksum_at(&self.backing, operation.durable_len, len).await?,
            }
        };
        let group_id = direct_group_id(
            &self.partition,
            &self.name,
            &self.incarnation,
            prepared.generation,
        );
        let group = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: self.partition.to_string(),
                name: self.name.to_vec(),
                incarnation: self.incarnation,
                candidate: batch::Candidate::with_payload(root, payload)?,
                removed: false,
            }],
            group_id,
        )?;
        let participant = &group.participants[0];
        let final_root = participant
            .candidate
            .final_root()
            .expect("prepared direct candidates have a final root");
        let previous = self.carried.lock().await.clone();
        let _previous_guard = match &previous {
            Some(group) => Some(group.coordination.lock().await),
            None => None,
        };
        let previous_installed = match &previous {
            Some(group) => self
                .carried
                .lock()
                .await
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, group)),
            None => false,
        };
        let previous_requires_sync = previous_installed
            && previous
                .as_ref()
                .is_some_and(|group| !group.payment.is_paid());

        operation.arm();
        // The complete self-linked candidate and its payload obligation are the sole durable
        // decision. The finalized spelling is cleanup and deliberately has no second barrier.
        let mut preparations: Vec<ParticipantOperation<'_>> = vec![Box::pin(async {
            self.backing
                .write_at(
                    prepared.root_offset,
                    group.slots[0].to_vec(),
                    WriteOptions::default(),
                )
                .await?;
            self.backing.sync().await
        })];
        if let Some(previous) = &previous
            && previous_requires_sync
        {
            for member in &previous.members {
                if member.partition.as_ref() == self.partition.as_ref()
                    && member.name.as_ref() == self.name.as_ref()
                    && member.incarnation == self.incarnation
                {
                    continue;
                }
                preparations.push(Box::pin(sync_carried_member(member)));
            }
        }
        join_participant_io(preparations).await?;
        if let Some(previous) = &previous
            && previous_installed
        {
            clear_carried_group(previous).await;
        }
        self.backing
            .write_at(
                prepared.root_offset,
                final_root.to_vec(),
                WriteOptions::default(),
            )
            .await?;
        if prepared.truncate {
            // The selected root is authority before discarded offsets are reclaimed. If this
            // resize is lost, reopening repeats it before those offsets can be reused.
            self.backing.resize(raw_len(prepared.logical_len)?).await?;
        }
        operation.finish_commit(&prepared);
        self.payload.set(0);
        operation.finish();
        Ok(())
    }
}

/// Exact backing snapshot used while validating namespace and group recovery.
struct Existing<B> {
    backing: B,
    backing_len: u64,
    incarnation: [u8; INCARNATION_LEN],
    slots: [RootSlot; ROOT_OFFSETS.len()],
}

#[cfg(not(target_arch = "wasm32"))]
type DriverFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
#[cfg(not(target_arch = "wasm32"))]
const DRIVER_ADMISSION_CAPACITY: usize = 64;

#[cfg(not(target_arch = "wasm32"))]
/// Admission ownership shared by every clone in one filesystem storage lineage.
///
/// Foreground work can await a detached payload-preflush handoff while retaining its own permit.
/// Independent bounds let that handoff make progress while limiting all queued and running work.
pub(crate) struct BackgroundDriver {
    sender: OnceLock<tokio::sync::mpsc::UnboundedSender<DriverFuture>>,
    foreground: Arc<tokio::sync::Semaphore>,
    detached: Arc<tokio::sync::Semaphore>,
}

#[cfg(not(target_arch = "wasm32"))]
impl BackgroundDriver {
    fn new() -> Self {
        Self {
            sender: OnceLock::new(),
            foreground: Arc::new(tokio::sync::Semaphore::new(DRIVER_ADMISSION_CAPACITY)),
            detached: Arc::new(tokio::sync::Semaphore::new(DRIVER_ADMISSION_CAPACITY)),
        }
    }
}

/// Runtime ownership for admitted atomic work.
///
/// Backends whose physical I/O is cancellation-synchronous use the inline mode. Filesystem
/// backends use one lazily started worker per storage lineage so accepted work is independent of
/// the Tokio runtime polling its completion observer.
#[derive(Clone)]
pub(crate) enum Driver {
    #[cfg_attr(commonware_stability_BETA, allow(dead_code))]
    Inline,
    #[cfg(not(target_arch = "wasm32"))]
    Background(Arc<BackgroundDriver>),
}

/// Reserved foreground capacity that can synchronously accept one task.
///
/// Capacity is reserved before lineage ownership so every foreground path uses the same lock
/// order. Once lineage ownership is acquired, moving it into [`Self::drive`] has no cancellation
/// point before a background worker accepts the task.
enum ForegroundPermit {
    Inline,
    #[cfg(not(target_arch = "wasm32"))]
    Background {
        driver: Arc<BackgroundDriver>,
        admission: tokio::sync::OwnedSemaphorePermit,
    },
}

impl ForegroundPermit {
    fn drive<T, F>(self, task: F) -> Handle<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, Error>> + Send + 'static,
    {
        match self {
            Self::Inline => Handle::from_future(task),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Background { driver, admission } => {
                Driver::enqueue(Driver::Background(driver.clone()), &driver, task, admission)
            }
        }
    }
}

impl Driver {
    #[cfg_attr(commonware_stability_BETA, allow(dead_code))]
    pub(crate) const fn inline() -> Self {
        Self::Inline
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn background() -> Self {
        Self::Background(Arc::new(BackgroundDriver::new()))
    }

    /// Reserve foreground capacity before acquiring resources the driven task will own.
    async fn reserve(&self) -> Result<ForegroundPermit, Error> {
        match self {
            Self::Inline => Ok(ForegroundPermit::Inline),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Background(driver) => {
                let admission = driver
                    .foreground
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::Closed)?;
                Ok(ForegroundPermit::Background {
                    driver: driver.clone(),
                    admission,
                })
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn enqueue<T, F>(
        retention: Self,
        driver: &BackgroundDriver,
        task: F,
        admission: tokio::sync::OwnedSemaphorePermit,
    ) -> Handle<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, Error>> + Send + 'static,
    {
        let sender = driver.sender.get_or_init(start_driver);
        let (result_sender, result_receiver) = commonware_utils::channel::oneshot::channel();
        let task: DriverFuture = Box::pin(async move {
            let _retention = retention;
            let _admission = admission;
            let _ = result_sender.send(task.await);
        });
        if sender.send(task).is_err() {
            return Handle::ready(Err(Error::Closed));
        }
        Handle::from_receiver(result_receiver)
    }

    /// Run admitted work independently of a completion observer.
    ///
    /// Inline backends complete the future before returning. Background backends transfer it to
    /// their worker; if that worker has stopped, the caller completes the already-owned task.
    pub(crate) async fn drive_detached<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        match self {
            Self::Inline => task.await,
            #[cfg(not(target_arch = "wasm32"))]
            Self::Background(driver) => {
                let Ok(admission) = driver.detached.clone().acquire_owned().await else {
                    task.await;
                    return;
                };
                let sender = driver.sender.get_or_init(start_driver);
                let retention = self.clone();
                let task: DriverFuture = Box::pin(async move {
                    let _retention = retention;
                    let _admission = admission;
                    task.await;
                });
                if let Err(error) = sender.send(task) {
                    error.0.await;
                }
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn start_driver() -> tokio::sync::mpsc::UnboundedSender<DriverFuture> {
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<DriverFuture>();
    drop(crate::utils::thread::spawn(
        crate::utils::thread::system_thread_stack_size(),
        move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to create atomic storage runtime");
            runtime.block_on(async move {
                while let Some(task) = receiver.recv().await {
                    drop(tokio::spawn(task));
                }
            });
        },
    ));
    sender
}

/// Namespace operations that ordinary [`Storage`] deliberately does not promise.
///
/// The trait is crate-private so the public atomic interfaces are implemented only for runtimes
/// whose direct-entry open semantics are known under their public namespace
/// ownership contract. Protocol decoding and incarnation checks remain in this module; backends
/// only provide serialized namespace steps.
///
/// Every returned resource must belong to the same storage lineage and remain shared across its
/// clones and wrappers:
///
/// ```text
/// Storage lineage and clones
///   |-- AtomicResources -----------> opened Blob clones
///   `-- atomic_worker() -----------> owned namespace and publication tasks
/// ```
///
/// This coherence lets namespace recovery take exclusive ownership while live operations on
/// disjoint handles share the lineage. The budget accounts every live blob's speculative payload
/// contribution and retains detached rounds for exclusive recovery.
pub(crate) trait Backend: Storage {
    /// Owned backend used by detached atomic operations.
    ///
    /// This value may outlive the runtime polling its observer, so it must not retain resources
    /// whose destruction requires that runtime's execution context.
    type Worker: Backend<Blob = Self::Blob>;

    /// Create the owned backend used by a detached atomic operation.
    fn atomic_worker(&self) -> Self::Worker;

    /// Return the shared namespace, exclusion, payload accounting, and task driver for this
    /// lineage.
    ///
    /// Live operations hold shared exclusion through their I/O and cleanup. Namespace operations
    /// hold exclusive exclusion and drain detached payload preflushes before inspecting backings.
    fn atomic_resources(&self) -> AtomicResources;

    /// Generate a fresh identifier for an incarnation, opened token epoch, or multi-blob group.
    fn new_atomic_identifier(&self) -> [u8; INCARNATION_LEN] {
        let mut identifier = [0; INCARNATION_LEN];
        sys_rng().fill_bytes(&mut identifier);
        identifier
    }

    /// Open the current exact name without creating or repairing it.
    ///
    /// An incomplete ordinary container is reported as absent. A complete legacy container is
    /// rejected so its payload cannot be reinterpreted as atomic state.
    /// [`Storage::open`] owns any container-level recovery before atomic identity initialization.
    fn open_atomic_existing(
        &self,
        partition: &str,
        name: &[u8],
    ) -> impl std::future::Future<Output = Result<Option<(Self::Blob, u64)>, Error>> + Send;
}

/// Open an existing name only when its complete atomic identity is readable.
///
/// Missing, short, or torn identities return `None`. Recovery callers decide whether that image is
/// absent, ordinary, or corrupt; they never initialize it as a new atomic incarnation.
async fn open_existing<S: Backend>(
    storage: &S,
    partition: &str,
    name: &[u8],
) -> Result<Option<Existing<S::Blob>>, Error> {
    let Some((backing, backing_len)) = storage.open_atomic_existing(partition, name).await? else {
        return Ok(None);
    };
    if backing_len < DATA_OFFSET {
        return Ok(None);
    }
    let page = backing
        .read_at(0, IDENTITY_PAGE_LEN as usize)
        .await?
        .coalesce();
    let page: &[u8; IDENTITY_PAGE_LEN as usize] = page
        .as_ref()
        .try_into()
        .expect("identity reads have a fixed length");
    let Some(incarnation) = decode_identity(page) else {
        return Ok(None);
    };
    let slots = Blob::<S::Blob>::read_roots(&backing).await?;
    Ok(Some(Existing {
        backing,
        backing_len,
        incarnation,
        slots,
    }))
}

/// Durably remove a tombstoned name while exclusive lineage ownership is held.
///
/// Absence means cleanup already completed. Other failures leave the storage instance unusable and
/// must remain visible to the caller.
async fn remove_atomic_name<S: Storage>(
    storage: &S,
    partition: &str,
    name: &[u8],
) -> Result<(), Error> {
    match storage.remove(partition, Some(name)).await {
        Ok(()) | Err(Error::BlobMissing(_, _) | Error::PartitionMissing(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// One discovered ring participant together with the bytes needed to validate its local frontier.
#[derive(Clone)]
struct GroupMember<B> {
    link: batch::Link,
    backing: B,
    backing_len: u64,
    slots: [RootSlot; ROOT_OFFSETS.len()],
}

fn root_index(root_offset: u64) -> Option<usize> {
    ROOT_OFFSETS
        .iter()
        .position(|offset| *offset == root_offset)
}

/// Find the unique local witness for one group and incarnation.
fn matching_link<B>(
    existing: &Existing<B>,
    partition: &str,
    name: &[u8],
    group_id: &[u8; 16],
) -> Option<batch::Link> {
    let mut matches = existing
        .slots
        .iter()
        .zip(ROOT_OFFSETS)
        .filter_map(|(slot, offset)| {
            let link = batch::link_at(slot, partition, name, offset)?;
            (link.group_id == *group_id && link.participant.incarnation == existing.incarnation)
                .then_some(link)
        });
    let link = matches.next()?;
    matches.next().is_none().then_some(link)
}

/// Validate the predecessor evidence that keeps a candidate on the current recovery frontier.
///
/// `allow_successor` permits an older complete ring to remain usable behind one later incomplete
/// attempt. This is needed when that later attempt overwrote local predecessor bytes but never
/// formed its own durable decision.
///
/// ```text
/// local evidence                                      usable
/// candidate slot is newer                              no
/// exact Finalized root                                 yes
/// genesis candidate with a zero predecessor slot       yes
/// exact base-generation root                            yes
/// next BatchPrepared or raw predecessor                 only with fallback
/// anything else                                         no
/// ```
fn candidate_frontier_is_current(
    link: &batch::Link,
    slots: &[RootSlot; ROOT_OFFSETS.len()],
    allow_successor: bool,
) -> bool {
    let Some(root) = link.participant.candidate.root() else {
        return false;
    };
    let candidate_offset = link
        .participant
        .candidate
        .root_offset()
        .expect("decoded batch candidates have a root slot");
    let candidate_index =
        root_index(candidate_offset).expect("validated batch candidates target one root slot");
    if decode_slot(
        &slots[candidate_index],
        candidate_offset,
        Some(&link.participant.incarnation),
    )
    .root()
    .is_some_and(|installed| installed.generation > root.generation)
    {
        return false;
    }
    // An exact finalized root is locally selectable evidence for this participant. A later
    // publication may have consumed the opposite predecessor slot after its barrier also made
    // this final durable.
    // The older group must remain traversable. A peer whose concurrent debt barrier failed can use
    // this certificate to complete the same decision after a crash.
    if exact_final(link, slots) {
        return true;
    }

    let predecessor_index = 1 - candidate_index;
    let predecessor_slot = decode_slot(
        &slots[predecessor_index],
        ROOT_OFFSETS[predecessor_index],
        Some(&link.participant.incarnation),
    );
    let base_generation = link
        .participant
        .candidate
        .base_generation()
        .expect("decoded batch candidates have a predecessor generation");
    if base_generation == 0 && matches!(predecessor_slot, Slot::Zero) {
        return true;
    }
    match predecessor_slot {
        slot if slot.root().is_some_and(|predecessor| {
            predecessor.generation == base_generation
                && ROOT_OFFSETS[(predecessor.generation as usize) & 1]
                    == ROOT_OFFSETS[predecessor_index]
        }) =>
        {
            true
        }
        // A failed next publication may leave its complete candidate root while losing
        // both payload bytes and this group's ordinary final spelling. Newer candidates are
        // considered first; if they cannot decide, the still-complete prior ring remains the
        // fallback authority. Materializing it does not overwrite the newer candidate's slot.
        Slot::Root(RootState::BatchPrepared, successor)
            if allow_successor && root.generation.checked_add(1) == Some(successor.generation) =>
        {
            true
        }
        Slot::Raw if allow_successor => true,
        Slot::Zero | Slot::Root(_, _) | Slot::Finalized { .. } | Slot::Raw => false,
    }
}

/// Reject any root frontier that continues one incarnation after a tombstone.
///
/// Removal is terminal. A tombstone cannot be the predecessor of another candidate, and no
/// geometrically valid newer root can follow it. The incarnation remains linked for corruption
/// handling when either contradiction is present.
fn validate_terminal_frontier(
    link: &batch::Link,
    backing_len: u64,
    slots: &[RootSlot; ROOT_OFFSETS.len()],
) -> io::Result<()> {
    let candidate = link
        .participant
        .candidate
        .root()
        .expect("decoded batch links contain matching candidate roots");
    for (slot, offset) in slots.iter().zip(ROOT_OFFSETS) {
        let slot = decode_slot(slot, offset, Some(&link.participant.incarnation));
        let Some(root) = slot.root() else {
            continue;
        };
        if matches!(slot, Slot::Finalized { removed: true, .. })
            && root.generation < candidate.generation
        {
            return Err(invalid_data("atomic tombstone has a successor"));
        }
        if link.participant.removed
            && root.generation > candidate.generation
            && validate_root(root, offset, backing_len).is_ok()
        {
            return Err(invalid_data("atomic tombstone precedes a newer root"));
        }
    }
    Ok(())
}

/// Classify a candidate while optionally retaining a complete predecessor ring as fallback.
fn candidate_status(
    link: &batch::Link,
    backing_len: u64,
    slots: &[RootSlot; ROOT_OFFSETS.len()],
    allow_successor: bool,
) -> io::Result<Option<batch::CandidateStatus>> {
    let candidate = &link.participant.candidate;
    let root = candidate
        .root()
        .ok_or_else(|| invalid_data("batch candidate roots do not match"))?;
    validate_terminal_frontier(link, backing_len, slots)?;
    let payload_end = DATA_OFFSET
        .checked_add(root.logical_len)
        .ok_or_else(|| invalid_data("batch candidate payload length overflows"))?;
    let validation_len = if link.participant.removed {
        payload_end
    } else {
        if payload_end > backing_len {
            return Ok(None);
        }
        backing_len
    };
    if !candidate_frontier_is_current(link, slots, allow_successor) {
        return Ok(None);
    }
    let root_offset = candidate
        .root_offset()
        .expect("decoded batch candidates have a root slot");
    validate_root(root, root_offset, validation_len)?;
    let index = root_index(root_offset).expect("validated batch candidates target one root slot");
    let slot = &slots[index];
    let installed: &[u8; ROOT_LEN] = slot[..ROOT_LEN]
        .try_into()
        .expect("root slots contain a complete header");
    Ok(candidate.status(installed))
}

/// Verify the exact speculative suffix named by one participant's bound payload descriptor.
///
/// Removed participants and candidates whose complete payload is already durable have no suffix.
/// All other descriptors must end at the candidate root and fit inside the observed backing blob.
async fn candidate_payload_valid<B: BackingBlob>(member: &GroupMember<B>) -> Result<bool, Error> {
    let participant = &member.link.participant;
    let descriptor = participant.candidate.payload;
    let Some(root) = participant.candidate.root() else {
        return Ok(false);
    };
    let Some(len) = descriptor.len(root.logical_len) else {
        return Ok(false);
    };
    if participant.removed || len == 0 {
        return Ok(true);
    }
    let Some(backing_end) = DATA_OFFSET.checked_add(root.logical_len) else {
        return Ok(false);
    };
    if backing_end > member.backing_len {
        return Ok(false);
    }
    Ok(payload_checksum_at(&member.backing, descriptor.start, len).await? == descriptor.checksum)
}

/// Enforce the aggregate crash-time payload validation budget for one recovered group.
fn group_payload_within_recovery_bound<'a>(
    participants: impl IntoIterator<Item = &'a batch::Participant>,
) -> bool {
    participants
        .into_iter()
        .filter(|participant| !participant.removed)
        .try_fold(0u64, |total, participant| {
            total.checked_add(participant.candidate.payload_len()?)
        })
        .is_some_and(|total| total <= MAX_UNSYNCED_PAYLOAD_LEN)
}

/// Return whether this candidate's exact independent final spelling is installed.
fn exact_final(link: &batch::Link, slots: &[RootSlot; ROOT_OFFSETS.len()]) -> bool {
    let candidate = &link.participant.candidate;
    let Some(index) = candidate.root_offset().and_then(root_index) else {
        return false;
    };
    candidate
        .final_root()
        .is_some_and(|final_root| slots[index][..ROOT_LEN] == final_root)
}

/// Validate membership properties that are not implied by following successor links.
///
/// Successors must cover one canonical ordering of unique paths and incarnations. Sorting is
/// limited to borrowed links and does not change the returned traversal order.
fn canonical_ring(links: &[&batch::Link]) -> bool {
    if links.is_empty() {
        return false;
    }

    let mut canonical = links.to_vec();
    canonical.sort_by(|left, right| left.participant.key().cmp(&right.participant.key()));
    if canonical
        .windows(2)
        .any(|pair| pair[0].participant.key() == pair[1].participant.key())
    {
        return false;
    }
    let mut incarnations = canonical
        .iter()
        .map(|link| link.participant.incarnation)
        .collect::<Vec<_>>();
    incarnations.sort_unstable();
    if incarnations.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }

    canonical.iter().enumerate().all(|(index, link)| {
        let next = &canonical[(index + 1) % canonical.len()].participant;
        link.next.partition == next.partition
            && link.next.name == next.name
            && link.next.incarnation == next.incarnation
    })
}

/// Follow exact successor locations until the ring closes or evidence becomes incomplete.
///
/// Traversal opens only names embedded in validated links and allocates one member at a time. The
/// returned vector remains in successor order:
///
/// ```text
/// start k -> (k + 1) % n -> ... -> (k - 1) % n -> start k
/// ```
async fn traverse_group<S: Backend>(
    storage: &S,
    start: GroupMember<S::Blob>,
    allow_successor: bool,
) -> Result<Option<Vec<GroupMember<S::Blob>>>, Error> {
    if !candidate_frontier_is_current(&start.link, &start.slots, allow_successor) {
        return Ok(None);
    }
    let first_location = batch::Location {
        partition: start.link.participant.partition.clone(),
        name: start.link.participant.name.clone(),
        incarnation: start.link.participant.incarnation,
    };
    let group_id = start.link.group_id;
    let mut members = Vec::new();
    let mut locations = BTreeSet::new();
    let mut incarnations = BTreeSet::new();
    locations.insert((
        first_location.partition.clone(),
        first_location.name.clone(),
    ));
    incarnations.insert(first_location.incarnation);
    members.push(start);
    loop {
        let previous = members.last().expect("a group has a starting participant");
        if previous.link.next == first_location {
            break;
        }
        let location = previous.link.next.clone();
        if !locations.insert((location.partition.clone(), location.name.clone()))
            || !incarnations.insert(location.incarnation)
        {
            return Ok(None);
        }
        let Some(existing) = open_existing(storage, &location.partition, &location.name).await?
        else {
            return Ok(None);
        };
        if existing.incarnation != location.incarnation {
            return Ok(None);
        }
        let Some(link) = matching_link(&existing, &location.partition, &location.name, &group_id)
        else {
            return Ok(None);
        };
        if !candidate_frontier_is_current(&link, &existing.slots, allow_successor) {
            return Ok(None);
        }
        members.push(GroupMember {
            link,
            backing: existing.backing,
            backing_len: existing.backing_len,
            slots: existing.slots,
        });
    }

    let links = members
        .iter()
        .map(|member| &member.link)
        .collect::<Vec<_>>();
    Ok(canonical_ring(&links).then_some(members))
}

fn recovery_group_metadata_complete<B: BackingBlob>(
    members: &[GroupMember<B>],
    allow_successor: bool,
) -> io::Result<bool> {
    if !group_payload_within_recovery_bound(members.iter().map(|member| &member.link.participant)) {
        return Ok(false);
    }
    for member in members {
        if candidate_status(
            &member.link,
            member.backing_len,
            &member.slots,
            allow_successor,
        )?
        .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn recovery_group_complete<B: BackingBlob>(
    members: &[GroupMember<B>],
    allow_successor: bool,
) -> Result<bool, Error> {
    if !recovery_group_metadata_complete(members, allow_successor)? {
        return Ok(false);
    }
    for member in members {
        if !candidate_payload_valid(member).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn materialize_group_roots<B: BackingBlob>(members: &[GroupMember<B>]) -> Result<(), Error> {
    let mut finalizations = Vec::new();
    for member in members {
        if exact_final(&member.link, &member.slots) {
            continue;
        }
        let participant = &member.link.participant;
        let Some(final_root) = participant.candidate.final_root() else {
            return Err(invalid_data("batch candidate cannot be finalized").into());
        };
        finalizations.push(
            member.backing.write_at(
                participant
                    .candidate
                    .root_offset()
                    .expect("decoded batch candidates have a root slot"),
                final_root.to_vec(),
                WriteOptions::default(),
            ),
        );
    }
    join_participant_io(finalizations).await?;

    let barriers = members.iter().map(|member| member.backing.sync()).collect();
    join_participant_io(barriers).await
}

fn immediate_shorter_successor(
    older: &batch::Participant,
    older_root: Root,
    newer: &batch::Participant,
    backing_len: u64,
) -> bool {
    if newer.removed
        || newer.key() != older.key()
        || newer.incarnation != older.incarnation
        || newer.candidate.base_generation() != Some(older_root.generation)
    {
        return false;
    }
    let Some(newer_root) = newer.candidate.root() else {
        return false;
    };
    newer_root.logical_len < older_root.logical_len
        && DATA_OFFSET
            .checked_add(newer_root.logical_len)
            .is_some_and(|newer_end| newer_end <= backing_len)
}

fn predecessor_payload_is_obsolete<B: BackingBlob>(
    older: &GroupMember<B>,
    older_root: Root,
    accepted_members: &[GroupMember<B>],
) -> bool {
    let older_participant = &older.link.participant;
    if accepted_members.iter().any(|newer| {
        immediate_shorter_successor(
            older_participant,
            older_root,
            &newer.link.participant,
            older.backing_len,
        )
    }) {
        return true;
    }
    let Some(older_end) = DATA_OFFSET.checked_add(older_root.logical_len) else {
        return false;
    };
    older_end > older.backing_len
        && older.slots.iter().zip(ROOT_OFFSETS).any(|(slot, offset)| {
            let Some(newer) = batch::link_at(
                slot,
                &older_participant.partition,
                &older_participant.name,
                offset,
            ) else {
                return false;
            };
            immediate_shorter_successor(
                older_participant,
                older_root,
                &newer.participant,
                older.backing_len,
            )
        })
}

/// Return whether a later durable decision already paid a predecessor's cleanup debt.
///
/// A successor publication barrier synchronizes every carried predecessor member before its
/// decision can become authoritative. A shorter immediate successor therefore makes the older
/// payload obsolete even when a later speculative write regrows the discarded physical extent.
/// Predecessor roots must still have exact final spellings, and every non-obsolete extent and
/// frontier remains validated.
fn predecessor_debt_is_paid<B: BackingBlob>(
    predecessor: &[GroupMember<B>],
    accepted_members: &[GroupMember<B>],
) -> io::Result<bool> {
    if !predecessor
        .iter()
        .all(|member| exact_final(&member.link, &member.slots))
        || !group_payload_within_recovery_bound(
            predecessor.iter().map(|member| &member.link.participant),
        )
    {
        return Ok(false);
    }

    let any_obsolete = predecessor.iter().any(|older| {
        older
            .link
            .participant
            .candidate
            .root()
            .is_some_and(|older_root| {
                predecessor_payload_is_obsolete(older, older_root, accepted_members)
            })
    });
    if !any_obsolete {
        return Ok(false);
    }

    for older in predecessor {
        let Some(older_root) = older.link.participant.candidate.root() else {
            return Ok(false);
        };
        let Some(older_end) = DATA_OFFSET.checked_add(older_root.logical_len) else {
            return Ok(false);
        };
        let obsolete = predecessor_payload_is_obsolete(older, older_root, accepted_members);
        if older_end > older.backing_len && !obsolete {
            return Ok(false);
        }
        let validation_len = if obsolete {
            older_end
        } else {
            older.backing_len
        };
        if candidate_status(&older.link, validation_len, &older.slots, true)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn predecessor_groups<S: Backend>(
    storage: &S,
    members: &[GroupMember<S::Blob>],
) -> Result<Vec<Vec<GroupMember<S::Blob>>>, Error> {
    let mut groups = Vec::new();
    let mut group_ids = BTreeSet::new();
    let mut backings = members
        .iter()
        .map(|member| {
            let participant = &member.link.participant;
            (
                batch::Location {
                    partition: participant.partition.clone(),
                    name: participant.name.clone(),
                    incarnation: participant.incarnation,
                },
                member.backing.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for member in members {
        let participant = &member.link.participant;
        let predecessor_generation = participant
            .candidate
            .base_generation()
            .ok_or_else(|| invalid_data("batch predecessor candidate is invalid"))?;
        if predecessor_generation == 0 {
            continue;
        }
        let predecessor = member
            .slots
            .iter()
            .zip(ROOT_OFFSETS)
            .find_map(|(slot, offset)| {
                let link = batch::link_at(slot, &participant.partition, &participant.name, offset)?;
                let root = link.participant.candidate.root()?;
                (link.participant.incarnation == participant.incarnation
                    && root.generation == predecessor_generation)
                    .then_some(link)
            });
        let Some(link) = predecessor else {
            continue;
        };
        if !group_ids.insert(link.group_id) {
            continue;
        }
        let start = GroupMember {
            link,
            backing: member.backing.clone(),
            backing_len: member.backing_len,
            slots: member.slots,
        };
        let Some(mut predecessor) = traverse_group(storage, start, true).await? else {
            // Under exclusive lineage ownership, an unavailable predecessor edge can only be
            // cleanup performed after that predecessor's final roots became independent.
            continue;
        };
        if predecessor_debt_is_paid(&predecessor, members)? {
            continue;
        }
        // The accepted successor could only be issued after this immediate predecessor's payload
        // decision completed. Recovery still validates and materializes its metadata and cleanup
        // debt, but rehashing historical payload cannot distinguish a reachable crash outcome.
        if !recovery_group_metadata_complete(&predecessor, true)? {
            return Err(invalid_data("atomic group predecessor is incomplete").into());
        }
        // One path can occur in several predecessor rings. Use one live backing image so a later
        // full-file barrier cannot publish an independently opened stale snapshot.
        for member in &mut predecessor {
            let participant = &member.link.participant;
            let location = batch::Location {
                partition: participant.partition.clone(),
                name: participant.name.clone(),
                incarnation: participant.incarnation,
            };
            let backing = member.backing.clone();
            member.backing = backings.entry(location).or_insert(backing).clone();
        }
        groups.push(predecessor);
    }
    Ok(groups)
}

/// Transfer a proven group decision into independent final roots and namespace state.
///
/// Recovery first closes every immediate witness-bound predecessor, so accepting a successor
/// cannot strand a peer whose predecessor final is still only prepared. It then writes missing
/// independent final spellings and joins one durability operation on every participant. Every root
/// in the closure is durable before any tombstone is unlinked.
/// A successfully activated predecessor paid its carried ancestors in its decision barrier. If a
/// barrier fails, poisoning prevents another successor, so only the immediate predecessors can
/// remain unpaid.
///
/// This recovery barrier is the explicit payment of cleanup debt after reopen no longer has the
/// in-memory [`CarriedGroup`].
async fn finish_group<S: Backend>(
    storage: &S,
    members: &[GroupMember<S::Blob>],
) -> Result<(), Error> {
    let predecessors = predecessor_groups(storage, members).await?;
    for group in predecessors
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(members))
    {
        materialize_group_roots(group).await?;
    }

    for group in predecessors
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(members))
    {
        // A peer may already carry a later incomplete generation. Its own open resolves that
        // local frontier; an older group snapshot must never resize it.
        for member in group.iter().rev() {
            let participant = &member.link.participant;
            if participant.removed {
                remove_atomic_name(storage, &participant.partition, &participant.name).await?;
            }
        }
    }

    for group in predecessors
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(members))
    {
        let group_id = group
            .first()
            .expect("recovered groups are nonempty")
            .link
            .group_id;
        storage
            .atomic_resources()
            .payload_budget
            .mark_carried_paid(group_id);
    }
    Ok(())
}

/// Logical state selected for the name from which group recovery started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupRecovery {
    Present,
    Removed,
}

fn compare_link_generations_desc(left: &batch::Link, right: &batch::Link) -> std::cmp::Ordering {
    right
        .participant
        .candidate
        .base_generation()
        .cmp(&left.participant.candidate.base_generation())
}

/// Resolve the newest complete group reachable from one local backing snapshot.
///
/// Links are tried newest first. An incomplete newer attempt enables predecessor fallback for the
/// next older ring. A locally exact final remains authoritative when later cleanup has already
/// removed an edge after all participant finals became independent. A raw local slot enables
/// fallback before the first traversal because it may be a retained subset of a newer attempt.
async fn recover_groups<S: Backend>(
    storage: &S,
    partition: &str,
    name: &[u8],
    local: &Existing<S::Blob>,
    mut recovered: Option<&mut BTreeSet<[u8; batch::GROUP_ID_LEN]>>,
) -> Result<GroupRecovery, Error> {
    let mut links = local
        .slots
        .iter()
        .zip(ROOT_OFFSETS)
        .filter_map(|(slot, offset)| {
            let link = batch::link_at(slot, partition, name, offset)?;
            (link.participant.incarnation == local.incarnation).then_some(link)
        })
        .collect::<Vec<_>>();
    links.sort_by(compare_link_generations_desc);
    let mut allow_successor = local.slots.iter().zip(ROOT_OFFSETS).any(|(slot, offset)| {
        matches!(
            decode_slot(slot, offset, Some(&local.incarnation)),
            Slot::Raw
        )
    });
    for link in links {
        let local_outcome = if link.participant.removed {
            GroupRecovery::Removed
        } else {
            GroupRecovery::Present
        };
        let start = GroupMember {
            link,
            backing: local.backing.clone(),
            backing_len: local.backing_len,
            slots: local.slots,
        };
        let local_final = exact_final(&start.link, &start.slots);
        if local_final {
            let candidate = &start.link.participant.candidate;
            let root = candidate
                .root()
                .expect("decoded batch links contain matching candidate roots");
            let validation_len = if start.link.participant.removed {
                DATA_OFFSET
                    .checked_add(root.logical_len)
                    .ok_or_else(|| invalid_data("atomic payload length overflows"))?
            } else {
                start.backing_len
            };
            validate_root(
                root,
                candidate
                    .root_offset()
                    .expect("decoded batch candidates have a root slot"),
                validation_len,
            )?;
            validate_terminal_frontier(&start.link, start.backing_len, &start.slots)?;
            if recovered
                .as_deref()
                .is_some_and(|groups| groups.contains(&start.link.group_id))
            {
                return Ok(local_outcome);
            }
        }
        let retry_peer_successor =
            !allow_successor && candidate_frontier_is_current(&start.link, &start.slots, false);
        let mut traversal = traverse_group(storage, start.clone(), allow_successor).await?;
        let mut traversal_allow_successor = allow_successor;
        if traversal.is_none() && retry_peer_successor {
            // An intact local frontier remains usable when only a peer carries the next attempt.
            traversal = traverse_group(storage, start, true).await?;
            traversal_allow_successor = true;
        }
        if let Some(members) = traversal
            && recovery_group_complete(&members, traversal_allow_successor).await?
        {
            finish_group(storage, &members).await?;
            if let Some(recovered) = recovered.as_deref_mut() {
                let group_id = members
                    .first()
                    .expect("recovered groups are nonempty")
                    .link
                    .group_id;
                recovered.insert(group_id);
            }
            return Ok(local_outcome);
        }
        // An exact Finalized root and its retained witness are local authority for this
        // participant. Under exclusive namespace ownership, a missing successor can only be
        // cleanup after every participant's final root became independently durable.
        if local_final {
            return Ok(local_outcome);
        }
        allow_successor = true;
    }
    Ok(GroupRecovery::Present)
}

/// Requested mutation after duplicate handles have been canonicalized by path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchKind {
    Publish,
    Rewind(u64),
    Remove,
}

/// One canonical batch path and the exact handle authorized to mutate it.
struct BatchEntry<B> {
    blob: Blob<B>,
    kind: BatchKind,
}

/// Candidate root derived during read-only batch validation.
#[derive(Clone, Copy)]
struct BatchParticipantPlan {
    index: usize,
    root: Root,
    removed: bool,
}

/// Mutation guards held across the complete group decision and activation sequence.
///
/// Once armed, an error or canceled admitted operation poisons every selected state, including
/// clean selections. Selected handles cannot be reused after an indeterminate mutable-storage
/// outcome.
struct BatchMutation<'a> {
    states: Vec<MutexGuard<'a, State>>,
    armed: bool,
}

impl BatchMutation<'_> {
    const fn arm(&mut self) {
        self.armed = true;
    }

    fn finish(mut self) {
        self.armed = false;
    }
}

impl Drop for BatchMutation<'_> {
    fn drop(&mut self) {
        if self.armed {
            for state in &mut self.states {
                state.poisoned = true;
            }
        }
    }
}

/// Sort operations by canonical path and collapse only identical repeats of the same handle.
///
/// Distinct handles for one name are rejected even when they request the same mutation because
/// their in-memory visible states may differ.
fn canonicalize_batch<B: BackingBlob>(
    operations: Vec<BatchOperation<Blob<B>>>,
) -> Result<Vec<BatchEntry<B>>, Error> {
    let mut entries = BTreeMap::<(String, Vec<u8>), BatchEntry<B>>::new();
    for operation in operations {
        let (blob, kind) = match operation {
            BatchOperation::Publish(blob) => (blob, BatchKind::Publish),
            BatchOperation::Rewind { blob, len } => (blob, BatchKind::Rewind(len)),
            BatchOperation::Remove(blob) => (blob, BatchKind::Remove),
        };
        let key = (blob.partition.to_string(), blob.name.to_vec());
        match entries.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(BatchEntry { blob, kind });
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get().kind == kind && entry.get().blob.same_handle(&blob) => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(invalid_input(
                    "atomic batch contains conflicting or independently opened handles",
                ));
            }
        }
    }
    Ok(entries.into_values().collect())
}

/// Describe the exact non-durable suffix that recovery must hash for one candidate.
///
/// ```text
/// logical payload  [0 ........ durable_len) [durable_len ........ logical_len)
///                   already covered          SHA-256 descriptor suffix
/// descriptor       start = durable_len, len = logical_len - durable_len
/// backing bytes     DATA_OFFSET + start .. DATA_OFFSET + logical_len
/// ```
///
/// Removal and roots at or before `durable_len` use the canonical empty descriptor.
async fn candidate_payload_descriptor<B: BackingBlob>(
    blob: &Blob<B>,
    state: &State,
    logical_len: u64,
    removed: bool,
) -> Result<batch::PayloadDescriptor, Error> {
    if removed || logical_len <= state.durable_len {
        return Ok(batch::PayloadDescriptor::empty(logical_len));
    }
    let len = logical_len - state.durable_len;
    assert!(
        len <= MAX_UNSYNCED_PAYLOAD_LEN,
        "batch payload preflush bounds each recovery suffix"
    );
    Ok(batch::PayloadDescriptor {
        start: state.durable_len,
        checksum: payload_checksum_at(&blob.backing, state.durable_len, len).await?,
    })
}

/// Poll a complete participant I/O set to completion and report its first ordered error.
///
/// Draining every admitted future prevents a peer write from escaping group-wide exclusion after
/// another participant fails.
async fn join_participant_io<F>(operations: Vec<F>) -> Result<(), Error>
where
    F: Future<Output = Result<(), Error>> + Send,
{
    // Poll the complete participant set together. Even when one operation fails, join every
    // admitted peer before releasing group-wide exclusion.
    for result in join_all(operations).await {
        result?;
    }
    Ok(())
}

/// Return whether in-memory carried debt certifies the handle's selected predecessor.
///
/// A live group can have durable bound candidates while its independent final spellings remain
/// unsynchronized. The shared [`CarriedGroup`] is the authority that lets the next publication
/// accept that state without forcing recovery first.
async fn carried_predecessor_matches<B: BackingBlob>(
    blob: &Blob<B>,
    current: &Existing<B>,
    state: &State,
) -> bool {
    let Some(group) = blob.carried.lock().await.clone() else {
        return false;
    };
    debug_assert!(group.members.iter().any(|member| {
        member.slot.upgrade().is_some_and(|slot| {
            Arc::ptr_eq(&slot, &blob.carried)
                && member.partition.as_ref() == blob.partition.as_ref()
                && member.name.as_ref() == blob.name.as_ref()
                && member.incarnation == blob.incarnation
        })
    }));

    current
        .slots
        .iter()
        .zip(ROOT_OFFSETS)
        .filter_map(|(slot, offset)| {
            batch::link_at(slot, &blob.partition, &blob.name, offset).map(|link| (link, offset))
        })
        .any(|(link, offset)| {
            let root = link
                .participant
                .candidate
                .root()
                .expect("decoded batch links contain valid candidates");
            link.group_id == group.group_id
                && link.participant.incarnation == blob.incarnation
                && !link.participant.removed
                && validate_root(root, offset, current.backing_len).is_ok()
                && root == state.committed
        })
}

/// Return whether an exact durable self-link certifies the live singleton predecessor.
fn singleton_predecessor_matches<B: BackingBlob>(
    blob: &Blob<B>,
    current: &Existing<B>,
    state: &State,
) -> bool {
    current
        .slots
        .iter()
        .zip(ROOT_OFFSETS)
        .filter_map(|(slot, offset)| {
            batch::link_at(slot, &blob.partition, &blob.name, offset)
                .map(|link| (slot, link, offset))
        })
        .any(|(slot, link, offset)| {
            let candidate = &link.participant.candidate;
            let root = candidate
                .root()
                .expect("decoded batch links contain valid candidates");
            let installed: &[u8; ROOT_LEN] = slot[..ROOT_LEN]
                .try_into()
                .expect("root slots contain a complete header");
            installed == &candidate.prepared_root
                && link.participant.incarnation == blob.incarnation
                && !link.participant.removed
                && link.next.partition == blob.partition.as_ref()
                && link.next.name == blob.name.as_ref()
                && link.next.incarnation == blob.incarnation
                && validate_root(root, offset, current.backing_len).is_ok()
                && root == state.committed
        })
}

/// Validate, decide, and activate one coordinator-free multi-blob publication.
///
/// No candidate root is written until all operations, handles, incarnations, predecessor state,
/// witness sizes, rewind proofs, and payload bounds have been validated.
///
/// ```text
/// canonicalize operations
///          |
/// lock every participant and drain its payload preflush
///          |
/// reopen names and validate exact predecessor incarnations
///          |
/// preview mutations, hash bounded payload suffixes, encode and validate witnesses
///          |
/// write every candidate slot + sync every participant and carried-debt file
///          |                                                   one durability layer
///          v
/// signal durable decision
///          |
/// write final roots, resize, activate state, attach multi-member cleanup debt
/// ```
///
/// Errors before admission leave selected state unchanged. Errors after `mutation.arm()` poison
/// every selected state so callers must reopen and recover the old or complete new vector.
async fn apply_batch<S: Backend>(
    storage: &S,
    operations: Vec<BatchOperation<Blob<S::Blob>>>,
    decision: oneshot::Sender<()>,
) -> Result<(), Error> {
    let entries = canonicalize_batch(operations)?;
    if entries.is_empty() {
        let _ = decision.send(());
        return Ok(());
    }

    // Operation ownership closes the gap between an append's payload write and detached preflush
    // registration. Acquire every participant in canonical path order, then drain only those
    // participants before freezing their states.
    let mut _operation_guards = Vec::with_capacity(entries.len());
    for entry in &entries {
        _operation_guards.push(entry.blob.operation.clone().lock_owned().await);
    }
    for result in join_all(
        entries
            .iter()
            .map(|entry| entry.blob.drain_payload_preflush()),
    )
    .await
    {
        result?;
    }
    // Hold every participant mutation lock in canonical key order through validation, the decision
    // join, activation writes, and in-memory activation.
    let cores = entries
        .iter()
        .map(|entry| entry.blob.state.clone())
        .collect::<Vec<_>>();
    let mut states = Vec::with_capacity(cores.len());
    for core in &cores {
        let state = core.lock().await;
        state.ensure_healthy()?;
        states.push(state);
    }
    let mut mutation = BatchMutation {
        states,
        armed: false,
    };

    let mut participant_plans = Vec::new();
    let mut incarnations = BTreeSet::new();
    let mut rewind_sources = vec![None; entries.len()];
    for (index, entry) in entries.iter().enumerate() {
        let current = open_existing(storage, &entry.blob.partition, &entry.blob.name)
            .await?
            .ok_or_else(|| {
                Error::BlobMissing(entry.blob.partition.to_string(), hex(&entry.blob.name))
            })?;
        if current.incarnation != entry.blob.incarnation {
            return Err(Error::BlobMissing(
                entry.blob.partition.to_string(),
                hex(&entry.blob.name),
            ));
        }
        if !incarnations.insert(entry.blob.incarnation) {
            return Err(invalid_input(
                "atomic batch paths must name distinct blob incarnations",
            ));
        }
        let state = &mutation.states[index];
        let (durable, _) = State::recover_for(
            current.backing_len,
            &current.slots,
            Some(&current.incarnation),
            [0; INCARNATION_LEN],
        )?;
        let independent_predecessor = durable.committed == state.committed;
        let newer_bound_candidate = current
            .slots
            .iter()
            .zip(ROOT_OFFSETS)
            .filter_map(|(slot, offset)| {
                batch::link_at(slot, &entry.blob.partition, &entry.blob.name, offset)
                    .map(|link| (link, offset))
            })
            .any(|(link, _)| {
                link.participant.incarnation == current.incarnation
                    && link
                        .participant
                        .candidate
                        .root()
                        .is_some_and(|root| root.generation > state.committed.generation)
            });
        if (!independent_predecessor || newer_bound_candidate)
            && !singleton_predecessor_matches(&entry.blob, &current, state)
            && !carried_predecessor_matches(&entry.blob, &current, state).await
        {
            return Err(invalid_input(
                "atomic batch handle does not select the current durable predecessor",
            ));
        }
        let (candidate_state, participates) = match entry.kind {
            BatchKind::Publish => ((**state).clone(), state.is_dirty()),
            BatchKind::Rewind(len) => {
                let mut preview = (**state).clone();
                let source = entry.blob.validated_rewind_source(state, len, None).await?;
                preview
                    .apply_rewind(
                        len,
                        source.as_ref().map(|(unit, data)| (*unit, data.as_slice())),
                    )
                    .expect("validated rewind sources are internally consistent");
                rewind_sources[index] = source;
                let participates = preview.is_dirty();
                (preview, participates)
            }
            BatchKind::Remove => ((**state).clone(), true),
        };
        if !participates {
            continue;
        }
        let generation = next_generation(state.committed.generation)?;
        let root = Root {
            generation,
            logical_len: candidate_state.logical_len,
            integrity_start: candidate_state.integrity_start,
            integrity_checksum: candidate_state.integrity_checksum,
            integrity_scheme: candidate_state.integrity_scheme,
            tag: candidate_state.tag,
        };
        let removed = entry.kind == BatchKind::Remove;
        participant_plans.push(BatchParticipantPlan {
            index,
            root,
            removed,
        });
    }

    let group_id = (!participant_plans.is_empty()).then(|| storage.new_atomic_identifier());
    let mut participants = Vec::with_capacity(participant_plans.len());
    let mut participant_indices = Vec::with_capacity(participant_plans.len());
    for plan in &participant_plans {
        let entry = &entries[plan.index];
        let payload = candidate_payload_descriptor(
            &entry.blob,
            &mutation.states[plan.index],
            plan.root.logical_len,
            plan.removed,
        )
        .await?;
        participants.push(batch::Participant {
            partition: entry.blob.partition.to_string(),
            name: entry.blob.name.to_vec(),
            incarnation: entry.blob.incarnation,
            candidate: batch::Candidate::with_payload(plan.root, payload)?,
            removed: plan.removed,
        });
        participant_indices.push(plan.index);
    }
    debug_assert!(group_payload_within_recovery_bound(&participants));
    let prepared = (!participants.is_empty())
        .then(|| {
            batch::prepare_with_group_id(
                participants,
                group_id.expect("nonempty batches have an identifier"),
            )
        })
        .transpose()?;

    // A prior decision can make an explicit participant responsible for synchronizing peer files.
    // Serialize publications that share that hidden debt group, while leaving unrelated groups
    // independent. Locks are ordered by stable group identity.
    let mut previous_groups = Vec::new();
    let mut previous_group_ids = BTreeSet::new();
    for &index in &participant_indices {
        if let Some(group) = entries[index].blob.carried.lock().await.clone()
            && previous_group_ids.insert(group.group_id)
        {
            previous_groups.push(group);
        }
    }
    previous_groups.sort_by_key(|group| group.group_id);
    let mut _previous_group_guards = Vec::with_capacity(previous_groups.len());
    for group in &previous_groups {
        _previous_group_guards.push(group.coordination.lock().await);
    }
    let mut active_previous_group_ids = BTreeSet::new();
    for &index in &participant_indices {
        if let Some(group) = entries[index].blob.carried.lock().await.as_ref()
            && previous_group_ids.contains(&group.group_id)
        {
            active_previous_group_ids.insert(group.group_id);
        }
    }

    for (index, entry) in entries.iter().enumerate() {
        if let BatchKind::Rewind(len) = entry.kind {
            mutation.states[index]
                .apply_rewind(
                    len,
                    rewind_sources[index]
                        .as_ref()
                        .map(|(unit, data)| (*unit, data.as_slice())),
                )
                .expect("the previewed rewind remains internally consistent");
            entry
                .blob
                .payload
                .set(mutation.states[index].speculative_payload_len());
        }
    }
    let Some(prepared) = prepared else {
        mutation.finish();
        let _ = decision.send(());
        return Ok(());
    };
    debug_assert_eq!(prepared.participants.len(), participant_indices.len());
    for (&index, participant) in participant_indices.iter().zip(&prepared.participants) {
        debug_assert_eq!(entries[index].blob.key(), participant.key());
    }
    mutation.arm();

    // Every participant publishes its bound candidate slot and joins the same durability layer.
    // Await every operation even after an error so no canceled backing write can outlive the
    // group-wide exclusion held by this task.
    let participant_keys = prepared
        .participants
        .iter()
        .map(|participant| {
            (
                participant.partition.clone(),
                participant.name.clone(),
                participant.incarnation,
            )
        })
        .collect::<BTreeSet<_>>();
    let mut preparations: Vec<ParticipantOperation<'_>> = participant_indices
        .iter()
        .zip(&prepared.participants)
        .zip(&prepared.slots)
        .map(|((&index, participant), slot)| {
            let backing = &entries[index].blob.backing;
            Box::pin(async move {
                backing
                    .write_at(
                        participant
                            .candidate
                            .root_offset()
                            .expect("prepared candidates have a root slot"),
                        slot.to_vec(),
                        WriteOptions::default(),
                    )
                    .await?;
                backing.sync().await
            }) as ParticipantOperation<'_>
        })
        .collect();
    let mut debt_keys = BTreeSet::new();
    for group in &previous_groups {
        if !active_previous_group_ids.contains(&group.group_id) {
            continue;
        }
        if group.payment.is_paid() {
            continue;
        }
        for member in &group.members {
            let key = (
                member.partition.to_string(),
                member.name.to_vec(),
                member.incarnation,
            );
            if participant_keys.contains(&key) || !debt_keys.insert(key) {
                continue;
            }
            preparations.push(Box::pin(sync_carried_member(member)));
        }
    }
    join_participant_io(preparations).await?;
    for group in &previous_groups {
        if active_previous_group_ids.contains(&group.group_id) {
            clear_carried_group(group).await;
        }
    }
    // A complete bound ring and every candidate payload obligation are now durable. The remaining
    // work only transfers that decision into independent final-root spellings and activates state.
    let _ = decision.send(());

    // Final roots are cleanup spellings, not a second durability decision. Install all of them
    // concurrently without another barrier. A later publication folds them into its sole sync;
    // recovery materializes them before namespace cleanup when no later publication occurs.
    let finalizations = participant_indices
        .iter()
        .zip(&prepared.participants)
        .map(|(&index, participant)| {
            let backing = &entries[index].blob.backing;
            let final_root = participant
                .candidate
                .final_root()
                .expect("prepared groups contain valid candidates");
            async move {
                backing
                    .write_at(
                        participant
                            .candidate
                            .root_offset()
                            .expect("prepared candidates have a root slot"),
                        final_root.to_vec(),
                        WriteOptions::default(),
                    )
                    .await
            }
        })
        .collect();
    join_participant_io(finalizations).await?;

    for (&index, participant) in participant_indices.iter().zip(&prepared.participants) {
        let root = participant
            .candidate
            .root()
            .expect("prepared groups contain valid candidates");
        entries[index].blob.payload.set(0);
        if participant.removed {
            mutation.states[index].removed = true;
            continue;
        }
        let state = &mut mutation.states[index];
        if root.logical_len < state.committed.logical_len {
            entries[index]
                .blob
                .backing
                .resize(raw_len(root.logical_len)?)
                .await?;
        }
        state.logical_len = root.logical_len;
        state.durable_len = root.logical_len;
        state.integrity_start = root.integrity_start;
        state.integrity_checksum = root.integrity_checksum;
        state.integrity_scheme = root.integrity_scheme;
        state.tag = root.tag;
        state.committed = root;
    }

    if prepared.participants.len() > 1 {
        let group_id = group_id.expect("nonempty batches have an identifier");
        let carried = Arc::new(CarriedGroup {
            group_id,
            members: participant_indices
                .iter()
                .map(|&index| CarriedMember {
                    partition: entries[index].blob.partition.clone(),
                    name: entries[index].blob.name.clone(),
                    incarnation: entries[index].blob.incarnation,
                    backing: entries[index].blob.backing.clone(),
                    sync_gate: entries[index].blob.preflush.sync_gate.clone(),
                    slot: Arc::downgrade(&entries[index].blob.carried),
                })
                .collect(),
            payment: storage
                .atomic_resources()
                .payload_budget
                .register_carried(group_id),
            coordination: Mutex::new(()),
        });
        for &index in &participant_indices {
            *entries[index].blob.carried.lock().await = Some(carried.clone());
        }
    }

    mutation.finish();
    Ok(())
}

/// Map protocol parse failures to the path-aware corruption error used by public opens.
fn map_open_error(partition: &str, name: &[u8], error: Error) -> Error {
    match error {
        Error::Io(source)
            if matches!(
                source.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Error::BlobCorrupt(partition.into(), hex(name), source.to_string())
        }
        error => error,
    }
}

/// Recover one existing atomic name and return a mutable view when it remains logically present.
///
/// This path validates a complete identity, resolves a complete group, reclaims a tombstone,
/// consumes a rejected local generation, and repeats a lost truncate before returning.
async fn recover_existing_name<S: Backend>(
    storage: &S,
    resources: &AtomicResources,
    partition: &str,
    name: &[u8],
    recovered: Option<&mut BTreeSet<[u8; batch::GROUP_ID_LEN]>>,
) -> Result<Option<(Blob<S::Blob>, u64)>, Error> {
    let Some((backing, mut backing_len)) = storage.open_atomic_existing(partition, name).await?
    else {
        return Ok(None);
    };
    let incarnation = Blob::<S::Blob>::read_identity(&backing, backing_len)
        .await
        .map_err(|error| map_open_error(partition, name, error))?;
    if backing_len < DATA_OFFSET {
        backing.resize(DATA_OFFSET).await?;
        backing.sync().await?;
        backing_len = DATA_OFFSET;
    }
    let slots = Blob::<S::Blob>::read_roots(&backing).await?;
    let local = Existing {
        backing: backing.clone(),
        backing_len,
        incarnation,
        slots,
    };
    if recover_groups(storage, partition, name, &local, recovered)
        .await
        .map_err(|error| map_open_error(partition, name, error))?
        == GroupRecovery::Removed
    {
        remove_atomic_name(storage, partition, name).await?;
        return Ok(None);
    }

    let opened = Blob::open_named(
        backing,
        partition,
        name,
        backing_len,
        incarnation,
        storage.new_atomic_identifier(),
        resources.clone(),
    )
    .await
    .map_err(|error| map_open_error(partition, name, error))?;
    Ok(Some(opened))
}

/// Return as soon as a batch decision is durable while preserving its completion observer.
///
/// If the task exits before signaling a decision, its error is returned instead of a handle. Empty
/// and all-clean batches signal without creating a ring. For a participating batch:
///
/// ```text
/// shared lineage + participant/debt ownership -> candidate barrier -> signal decision
///                                                                       |
/// start_apply returns Handle <-------------------------------------------+
///          |
///          `-> final-root cleanup and activation -> Handle completes
/// ```
async fn await_batch_decision(
    mut completion: Handle<()>,
    decision: oneshot::Receiver<()>,
) -> Result<Handle<()>, Error> {
    commonware_macros::select! {
        decision = decision => match decision {
            Ok(()) => Ok(completion),
            Err(_) => match completion.await {
                Ok(()) => Err(Error::Closed),
                Err(error) => Err(error),
            },
        },
        result = &mut completion => {
            result?;
            Ok(Handle::ready(Ok(())))
        },
    }
}

/// Return a direct sync handle only after its publication task reaches the locked start point.
///
/// ```text
/// reserve capacity -> shared lineage -> admit task -> handle operation -> drain preflush -> lock State
///                                                                          |
///                                                           signal started |
///                                                                          v
/// start_sync returns Handle <-----------------------------------------------+
///          |
///          `-> candidate durability and cleanup -> Handle completes
/// ```
///
/// The state lock fixes the publication snapshot before the outer future returns. An inline driver
/// may complete the task before this handoff becomes observable.
async fn await_publication_start(
    mut completion: Handle<()>,
    started: oneshot::Receiver<()>,
) -> Handle<()> {
    commonware_macros::select! {
        started = started => match started {
            Ok(()) => completion,
            Err(_) => Handle::ready(completion.await),
        },
        result = &mut completion => Handle::ready(result),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
struct AdmissionPause {
    lineage: Weak<RwLock<()>>,
    entered: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
static ADMISSION_PAUSES: BlockingMutex<Vec<AdmissionPause>> = BlockingMutex::new(Vec::new());

#[cfg(all(test, not(target_arch = "wasm32")))]
async fn pause_admitted_operation_if_requested(lineage: &Arc<RwLock<()>>) {
    let target = Arc::downgrade(lineage);
    let pause = {
        let mut pauses = ADMISSION_PAUSES.lock();
        pauses
            .iter()
            .position(|pause| Weak::ptr_eq(&pause.lineage, &target))
            .map(|index| pauses.swap_remove(index))
    };
    let Some(pause) = pause else {
        return;
    };
    let _ = pause.entered.send(());
    let _ = pause.resume.await;
}

/// Shared namespace recovery pipeline for atomic open and scan operations.
///
/// ```text
/// hold exclusive lineage ownership and drain payload preflushes
///                                |
/// recover identity and complete the fixed prefix
///                    |
/// recover_groups, which may open and finish peers
///                    |
/// tombstone? open retries after durable unlink, scan omits the name
///                    |
/// open_named: repair or reject local roots and repeat a lost truncate
///                    |
/// return a handle or report a live scanned name
/// ```
///
/// Scan discards the temporary `open_named` handle after its repair and truncate side effects.
#[commonware_macros::stability(BETA)]
impl<S: Backend> AtomicStorage for S {
    type AtomicBlob = Blob<S::Blob>;

    fn open_atomic(
        &self,
        partition: &str,
        name: &[u8],
    ) -> impl std::future::Future<Output = Result<(Self::AtomicBlob, u64), Error>> + Send {
        Box::pin(async move {
            validate_atomic_location(partition, name)?;
            let resources = self.atomic_resources();
            let driver = resources.driver.clone();
            let worker = self.atomic_worker();
            let partition = partition.to_string();
            let name = name.to_vec();
            let permit = driver.reserve().await?;
            let guard = resources.exclusion.clone().write_owned().await;
            let task = async move {
                let _guard = guard;
                resources.payload_budget.drain().await?;
                if let Some(opened) =
                    recover_existing_name(&worker, &resources, &partition, &name, None).await?
                {
                    return Ok(opened);
                }

                let (backing, backing_len) = worker.open(&partition, &name).await?;
                let incarnation =
                    Blob::<S::Blob>::initialize_identity(&backing, backing_len, || {
                        worker.new_atomic_identifier()
                    })
                    .await
                    .map_err(|error| map_open_error(&partition, &name, error))?;
                Blob::open_named(
                    backing,
                    &partition,
                    &name,
                    DATA_OFFSET,
                    incarnation,
                    worker.new_atomic_identifier(),
                    resources.clone(),
                )
                .await
                .map_err(|error| map_open_error(&partition, &name, error))
            };
            permit.drive(task).await
        })
    }

    fn scan_atomic(
        &self,
        partition: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Vec<u8>>, Error>> + Send {
        Box::pin(async move {
            let resources = self.atomic_resources();
            let driver = resources.driver.clone();
            let worker = self.atomic_worker();
            let partition = partition.to_string();
            let permit = driver.reserve().await?;
            let guard = resources.exclusion.clone().write_owned().await;
            let task = async move {
                let _guard = guard;
                resources.payload_budget.drain().await?;
                let names = Storage::scan(&worker, &partition).await?;
                let mut live = Vec::with_capacity(names.len());
                let mut recovered = BTreeSet::new();
                for name in names {
                    if recover_existing_name(
                        &worker,
                        &resources,
                        &partition,
                        &name,
                        Some(&mut recovered),
                    )
                    .await?
                    .is_some()
                    {
                        live.push(name);
                    }
                }
                live.sort();
                Ok(live)
            };
            permit.drive(task).await
        })
    }

    fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> impl std::future::Future<Output = Result<Handle<()>, Error>> + Send {
        Box::pin(async move {
            let resources = self.atomic_resources();
            if operations.iter().any(|operation| {
                let blob = match operation {
                    BatchOperation::Publish(blob) | BatchOperation::Remove(blob) => blob,
                    BatchOperation::Rewind { blob, .. } => blob,
                };
                !Arc::ptr_eq(&resources.exclusion, &blob.exclusion)
            }) {
                return Err(invalid_input(
                    "atomic batch contains a handle from another storage lineage",
                ));
            }
            let driver = resources.driver.clone();
            let worker = self.atomic_worker();
            let (decision_sender, decision_receiver) = oneshot::channel();
            let permit = driver.reserve().await?;
            let guard = resources.exclusion.clone().read_owned().await;
            let task = async move {
                let _guard = guard;
                #[cfg(all(test, not(target_arch = "wasm32")))]
                pause_admitted_operation_if_requested(&resources.exclusion).await;
                apply_batch(&worker, operations, decision_sender).await
            };
            let completion = match permit {
                ForegroundPermit::Inline => Handle::ready(task.await),
                #[cfg(not(target_arch = "wasm32"))]
                permit @ ForegroundPermit::Background { .. } => permit.drive(task),
            };
            await_batch_decision(completion, decision_receiver).await
        })
    }
}

#[commonware_macros::stability(BETA)]
impl<B: BackingBlob> AtomicBlob for Blob<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        let state = self.lock_state().await?;
        // Rust's supported targets have at most 64-bit `usize`, so this conversion is infallible.
        let len_u64 = len as u64;
        let end = offset.checked_add(len_u64).ok_or(Error::OffsetOverflow)?;
        if end > state.logical_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read exceeds atomic blob length",
            )
            .into());
        }
        let backing_offset = DATA_OFFSET
            .checked_add(offset)
            .ok_or(Error::OffsetOverflow)?;
        self.backing.read_at(backing_offset, len).await
    }

    async fn tag(&self) -> Result<[u8; ATOMIC_BLOB_TAG_LEN], Error> {
        Ok(self.lock_state().await?.tag)
    }

    async fn set_tag(&self, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        self.lock_state().await?.set_tag(tag)
    }

    async fn integrity_scheme(&self) -> Result<IntegrityScheme, Error> {
        Ok(self.lock_state().await?.integrity_scheme)
    }

    async fn integrity_snapshot(&self) -> Result<IntegritySnapshot, Error> {
        let state = self.lock_state().await?;
        let encoded_len = state.logical_len;
        let scheme = state.integrity_scheme;
        let tag = state.tag;
        let token = state.integrity_token();
        let Some(unit) = state.integrity_tail() else {
            return Ok(IntegritySnapshot {
                encoded_len,
                scheme,
                tag,
                tail: None,
                token,
            });
        };
        let len = usize::try_from(unit.len).map_err(|_| Error::OffsetOverflow)?;
        let data = self
            .backing
            .read_at(raw_len(unit.offset)?, len)
            .await?
            .coalesce();
        state.validate_integrity_tail(data.as_ref())?;
        Ok(IntegritySnapshot {
            encoded_len,
            scheme,
            tag,
            tail: Some((unit, IoBufs::from(data.freeze()))),
            token,
        })
    }

    async fn compare_set_tag(
        &self,
        expected: IntegrityToken,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> Result<IntegrityToken, Error> {
        let mut state = self.lock_state().await?;
        state.expect_integrity_token(expected)?;
        state.set_tag(tag)?;
        Ok(state.integrity_token())
    }

    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let data = data.into();
        let permit = self.driver.reserve().await?;
        let lineage = exclusion.read_owned().await;
        permit
            .drive(Box::pin(async move {
                let _lineage = lineage;
                let _operation = operation.lock_owned().await;
                blob.append_inner(data, IntegrityBoundary::Continue, None, None)
                    .await
                    .map(|result| result.offset)
            }))
            .await
    }

    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let data = data.into();
        let permit = self.driver.reserve().await?;
        let lineage = exclusion.read_owned().await;
        permit
            .drive(Box::pin(async move {
                let _lineage = lineage;
                let _operation = operation.lock_owned().await;
                blob.append_inner(data, IntegrityBoundary::Continue, Some(tag), None)
                    .await
                    .map(|result| result.offset)
            }))
            .await
    }

    async fn append_integrity(
        &self,
        expected: IntegrityToken,
        data: impl Into<IoBufs> + Send,
        boundary: IntegrityBoundary,
        tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityAppend, Error> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let data = data.into();
        let permit = self.driver.reserve().await?;
        let lineage = exclusion.read_owned().await;
        permit
            .drive(Box::pin(async move {
                let _lineage = lineage;
                let _operation = operation.lock_owned().await;
                blob.append_inner(data, boundary, tag, Some(expected)).await
            }))
            .await
    }

    async fn read_integrity(&self, unit: IntegrityUnit) -> Result<IoBufs, Error> {
        let state = self.lock_state().await?;
        state.integrity_scheme.validate_completed_unit(unit)?;
        let data_len = usize::try_from(unit.len).map_err(|_| Error::OffsetOverflow)?;
        let encoded_len = data_len
            .checked_add(INTEGRITY_CHECKSUM_LEN)
            .ok_or(Error::OffsetOverflow)?;
        let encoded_end = unit
            .offset
            .checked_add(encoded_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if encoded_end > state.integrity_start {
            return Err(invalid_input(
                "integrity unit is not within the completed payload prefix",
            ));
        }
        let mut encoded = self
            .backing
            .read_at(raw_len(unit.offset)?, encoded_len)
            .await?
            .coalesce();
        let expected = u32::from_be_bytes(
            encoded.as_ref()[data_len..]
                .try_into()
                .expect("integrity checksum footers have a fixed length"),
        );
        validate_integrity(&encoded.as_ref()[..data_len], expected)?;
        encoded.truncate(data_len);
        Ok(IoBufs::from(encoded))
    }

    async fn rewind(&self, len: u64) -> Result<(), Error> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let permit = self.driver.reserve().await?;
        let lineage = exclusion.read_owned().await;
        permit
            .drive(Box::pin(async move {
                let _lineage = lineage;
                let _operation = operation.lock_owned().await;
                blob.rewind_inner(None, len, None, None).await.map(|_| ())
            }))
            .await
    }

    async fn rewind_tagged(&self, len: u64, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let permit = self.driver.reserve().await?;
        let lineage = exclusion.read_owned().await;
        permit
            .drive(Box::pin(async move {
                let _lineage = lineage;
                let _operation = operation.lock_owned().await;
                blob.rewind_inner(None, len, None, Some(tag))
                    .await
                    .map(|_| ())
            }))
            .await
    }

    async fn rewind_integrity(
        &self,
        expected: IntegrityToken,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let permit = self.driver.reserve().await?;
        let lineage = exclusion.read_owned().await;
        permit
            .drive(Box::pin(async move {
                let _lineage = lineage;
                let _operation = operation.lock_owned().await;
                blob.rewind_inner(Some(expected), len, unit, tag).await
            }))
            .await
    }

    async fn start_sync(&self) -> Handle<()> {
        let blob = self.clone();
        let exclusion = self.exclusion.clone();
        let operation = self.operation.clone();
        let (started_sender, started_receiver) = oneshot::channel();
        let permit = match self.driver.reserve().await {
            Ok(permit) => permit,
            Err(error) => return Handle::ready(Err(error)),
        };
        let lineage = exclusion.read_owned().await;
        let task = Box::pin(async move {
            let _lineage = lineage;
            let _operation = operation.lock_owned().await;
            blob.drain_payload_preflush().await?;
            let state = blob.lock_state().await?;
            let _ = started_sender.send(());
            blob.publish_locked(state).await
        });
        let completion = match permit {
            ForegroundPermit::Inline => Handle::ready(task.await),
            #[cfg(not(target_arch = "wasm32"))]
            permit @ ForegroundPermit::Background { .. } => permit.drive(task),
        };
        await_publication_start(completion, started_receiver).await
    }
}
