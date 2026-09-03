//! Settlement DA channel: dealing dissemination, vote return, and evidence
//! service.
//!
//! Distributed certification runs over one muxed-free p2p channel modeled on
//! the dkg dealing exchange: the operator sends each committee validator its
//! exact assigned proof slices with [`Message::Dealing`] (`Recipients::One`),
//! and the validator answers with [`Message::Vote`] on the same channel.
//! Dealings and votes are off-chain traffic, recoverable by resend: only the
//! finalized admission is durable protocol state.
//!
//! The validator side is the [`Sealer`]: it accepts dealings from any
//! configured operator's network identity, routes each dealing to the
//! deployment that operator runs, seals it with clearing `seal` against THAT
//! deployment's chain-registered close from its own applied state (never
//! against operator-supplied context material), persists the sealed dealing
//! durably, with the registered close context it sealed against, BEFORE
//! releasing its vote back to the sending operator, and retains it through
//! the close's challenge deadline. Each deployment's
//! sealed dealings live in their own archive (the partition folds the
//! deployment digest), so two deployments' closes never contend for one
//! deadline slot. Within one archive the record key is the batch id, which
//! is already deployment-unique by construction: the close header commits
//! the payment anchor, which folds the deployment digest.
//!
//! Dealings travel without their unchanged state: every proof slice covers
//! one span (a contiguous range of slices) and arrives as a [`DealtSlice`].
//! The operator encodes each slice's chunk once and sends every span as its
//! witness followed by the covered chunks
//! ([`Wire`](commonware_clearing::bajillion::retained::Wire)), so a slice
//! shared by many dealings is encoded once, and the validator hydrates the
//! decoded slice against the key interval it retains for that span at the
//! registered close's predecessor root, seeded from the deployment's genesis
//! accounts and advanced with every sealed close. The
//! intervals are retained one record per slice, so a later re-grouping of
//! slices this validator already holds into different spans needs no
//! re-sync. A slice it never held or already pruned (a validator that missed
//! a close, or one starting from an empty directory) is fetched from the
//! slice's other holders through their query servers with
//! [`EvidenceLookup::Interval`], one holder at a time from a deterministic
//! offset and bounded by the configured fetch timeout each (missing slices
//! are fetched concurrently), verified against the
//! registered close's predecessor root (certified by consensus, never taken
//! from the holder) and the slice bounds, retained, and only then hydrated
//! against. Evidence requests keep being served while a fetch is in flight.
//! A dealing whose interval no holder serves is skipped with a warning
//! naming the slice and every holder's decline. The advanced intervals are
//! made durable together with the sealed dealing before the vote leaves the
//! validator.
//!
//! The sealer also answers the query server's evidence requests through its
//! [`Mailbox`]: for every account in its assigned spans it serves the
//! openings a challenge, a chain withdrawal, or a claim needs, derived from
//! the retained sealed slice with [`SpanIndex`] and verified against the
//! sealed roots before they leave, plus the deployment's genesis state and
//! its retained slice intervals. Each retained interval is one authenticated
//! [`SliceRange`]: the slice's live leaves bracketed by the adjacent leaves
//! outside the slice (or the vector ends) under one range opening, so a
//! served interval proves both membership and completeness.

use crate::{
    chain::{
        query::{
            Evidence, EvidenceBody, EvidenceLookup, EvidenceRequest, EvidenceResponse,
            METHOD_EVIDENCE,
        },
        setup::ValidatorEntry,
        state::{Machine, Record, claim_roots_key, machine_key, status_key},
        types::Database,
        validator::{IO_BUFFER_SIZE, MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE},
    },
    protocol::{
        Deployment, Key, MAX_ACCOUNTS, MAX_DESTINATION_BYTES, MAX_SLICES, MAX_WITHDRAWALS,
        SLICE_BITS, short_digest, slice_codec,
    },
    rpc,
};
use anyhow::Context as _;
use bytes::{Buf, BufMut};
use commonware_actor::mailbox::{
    self, UnreliablePolicy, UnreliableReceiver as MailboxReceiver,
    UnreliableSender as MailboxSender,
};
use commonware_clearing::bajillion::{
    admission::{Vote, assigned_slice_spans, bls12381, seal, slice_holders},
    boundary::{DepositBatch, WithdrawalBatch},
    commitment::{self, Builder, RangeOpening, VectorKind, VectorRoot},
    retained::{DealtSlice, Interval},
    serve::{ServeError, SpanIndex},
    state::{AccountRow, AccountState, StateLeaf},
    transition::{
        Assignment, BatchId, CloseContext, Header, ProofSlice, RootBundle, StateCache, StateRange,
        TransitionError, account_slice,
    },
};
use commonware_codec::{
    DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _,
    Write,
};
use commonware_cryptography::{Hasher as _, Sha256, ed25519, sha256::Digest};
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Network, Spawner, buffer::paged::CacheRef, spawn_cell,
};
use commonware_storage::{
    Context as StorageContext,
    archive::{Archive as _, Identifier, prunable},
    translator::TwoCap,
};
use commonware_utils::{
    NZU64,
    channel::{fallible::OneshotExt as _, oneshot},
};
use futures::future::join_all;
use rand_core::CryptoRng;
use std::{collections::VecDeque, net::SocketAddr, ops::Range, pin::pin, time::Duration};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// One validator's dealing for the registered close: the close header and
/// roots with exactly that validator's assigned proof slices, one per
/// assigned span, each stripped of the unchanged state its retained
/// interval supplies. The operator sends each slice as the dealt wire
/// its dealing shares with every other dealing covering that slice, and
/// the validator decodes it as a [`DealtSlice`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Dealing<S = DealtSlice<Key, Digest>> {
    pub(crate) epoch: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) slices: Vec<S>,
}

impl<S: Write + EncodeSize> Write for Dealing<S> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.slices.write(buf);
    }
}

impl<S: Write + EncodeSize> EncodeSize for Dealing<S> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.slices.encode_size()
    }
}

impl Read for Dealing {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            slices: Vec::<DealtSlice<Key, Digest>>::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_SLICES), slice_codec()),
            )?,
        })
    }
}

/// One validator's attestation over a sealed close header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ballot {
    pub(crate) epoch: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) vote: Vote,
}

impl Write for Ballot {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.vote.write(buf);
    }
}

impl EncodeSize for Ballot {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.header.encode_size() + self.vote.encode_size()
    }
}

impl Read for Ballot {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Header::read(buf)?,
            vote: Vote::read(buf)?,
        })
    }
}

/// One settlement DA channel message, carrying a dealing's slices as `S`:
/// the shared dealt wire on the operator's sending side, the decoded
/// [`DealtSlice`] on the validator's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Message<S = DealtSlice<Key, Digest>> {
    Dealing(Dealing<S>),
    Vote(Ballot),
}

impl<S: Write + EncodeSize> Write for Message<S> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dealing(dealing) => {
                0_u8.write(buf);
                dealing.write(buf);
            }
            Self::Vote(ballot) => {
                1_u8.write(buf);
                ballot.write(buf);
            }
        }
    }
}

impl<S: Write + EncodeSize> EncodeSize for Message<S> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing(dealing) => dealing.encode_size(),
            Self::Vote(ballot) => ballot.encode_size(),
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Dealing(Dealing::read(buf)?)),
            1 => Ok(Self::Vote(Ballot::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One sealed dealing retained durably through its challenge deadline, with
/// the registered close context and boundary batches the span index serves
/// evidence from (the machine's registration slot is consumed at admission,
/// so they are not re-readable later).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    pub(crate) epoch: u64,
    /// Challenge deadline (an absolute block height) through which the
    /// dealing must stay retained.
    pub(crate) deadline: u64,
    /// The chain-registered close context the dealing sealed against, from
    /// this validator's own applied state.
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    /// The exact deposit boundary the registered close committed.
    pub(crate) deposits: DepositBatch<Key>,
    /// The exact withdrawal batch the registered close committed.
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) slices: Vec<ProofSlice<Key, Digest>>,
}

impl Write for Sealed {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.deadline.write(buf);
        self.context.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.slices.write(buf);
    }
}

impl EncodeSize for Sealed {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.deadline.encode_size()
            + self.context.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.slices.encode_size()
    }
}

impl Read for Sealed {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            deadline: u64::read(buf)?,
            context: CloseContext::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            deposits: DepositBatch::read_cfg(buf, &RangeCfg::new(0..=MAX_ACCOUNTS))?,
            withdrawals: WithdrawalBatch::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_WITHDRAWALS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            slices: Vec::<ProofSlice<Key, Digest>>::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_SLICES), slice_codec()),
            )?,
        })
    }
}

/// Durable store of sealed dealings: a prunable archive indexed by the
/// close's challenge deadline height and keyed by the close's batch id.
///
/// Height-based retention is exactly what prunable archives are for
/// (marshal's finalizations-by-height archive is the model), and every
/// record syncs incrementally instead of rewriting the whole store, which
/// matters at real dealing sizes.
///
/// The record contract at this store:
/// - a sealed dealing is put and synced here BEFORE its vote is sent (the
///   clearing admission contract: the vote attests to availability this
///   validator must be able to honor), and a failed sync stops the actor,
/// - retention is pruning: a record lives at its challenge deadline, and
///   sections strictly below the certified finalized height are released
///   (a deadline below that height means the window is closed), never on
///   wall clock,
/// - restart reloads the archive whole, so a validator killed between seal
///   and vote still holds its sealed dealing,
/// - one record per batch id, never overwritten: an identical
///   re-dissemination re-votes from the stored bytes, and because the
///   archive silently ignores a put at an occupied index, a DIFFERING
///   dealing for a stored deadline is refused loudly before any put.
pub(crate) type Store<E> = prunable::Archive<TwoCap, E, Digest, Sealed>;

/// Opens one deployment's durable dealing store under the `partition`
/// family: the partition folds the deployment digest, so every configured
/// deployment retains its sealed dealings in its own archive.
pub(crate) async fn store<E: StorageContext>(
    context: E,
    partition: &str,
    deployment: &Digest,
) -> Store<E> {
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let scoped = format!("{partition}-{}", short_digest(deployment));
    Store::init(
        context,
        prunable::Config {
            translator: TwoCap,
            key_partition: format!("{scoped}-key"),
            key_page_cache: page_cache,
            value_partition: format!("{scoped}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(1_024),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
    )
    .await
    .expect("failed to initialize the sealed dealing store")
}

/// One slice's live leaves at one state root, bracketed by the adjacent live
/// leaves outside the slice (or the vector ends) under one range opening.
///
/// The guards make the range complete as well as authentic: every leaf
/// between the guards is disclosed, so a verifier learns the slice's exact
/// live set at the root, not merely a subset of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SliceRange {
    /// The live leaf immediately before the slice's first member, or `None`
    /// at the start of the vector.
    pub(crate) predecessor: Option<StateLeaf<Key>>,
    /// The slice's live leaves, key-sorted.
    pub(crate) members: Vec<StateLeaf<Key>>,
    /// The live leaf immediately after the slice's last member, or `None` at
    /// the end of the vector.
    pub(crate) successor: Option<StateLeaf<Key>>,
    /// One range opening over the guards and members in vector order.
    pub(crate) opening: RangeOpening<Digest>,
}

/// Why a served [`SliceRange`] is not the slice's complete live set at the
/// root.
#[derive(Debug, Error)]
pub(crate) enum RangeError {
    /// A member or guard lies in the wrong slice, or the keys are not
    /// strictly ascending across guards and members.
    #[error("range leaves are not the slice's ordered live set")]
    Order,
    /// A guard is missing where leaves exist beyond the slice, or present
    /// at a vector end.
    #[error("range guards do not bracket the slice")]
    Guards,
    /// The opening does not reproduce the root over the disclosed leaves.
    #[error("range opening does not verify: {0}")]
    Opening(#[from] commitment::Error),
}

impl SliceRange {
    /// Verifies that this range is exactly `slice`'s live set at `root`:
    /// the members lie in the slice in ascending key order, each guard lies
    /// outside the slice on its side and exists exactly when the vector
    /// extends past the members on that side, and the opening reproduces
    /// the root over the disclosed leaves.
    pub(crate) fn verify(
        &self,
        root: &VectorRoot<Digest>,
        slice: u16,
        slice_bits: u8,
    ) -> Result<(), RangeError> {
        let slice_of = |leaf: &StateLeaf<Key>| {
            account_slice(&leaf.account, slice_bits).map_err(|_| RangeError::Order)
        };
        for member in &self.members {
            if slice_of(member)? != slice {
                return Err(RangeError::Order);
            }
        }
        if let Some(predecessor) = &self.predecessor
            && slice_of(predecessor)? >= slice
        {
            return Err(RangeError::Order);
        }
        if let Some(successor) = &self.successor
            && slice_of(successor)? <= slice
        {
            return Err(RangeError::Order);
        }
        let leaves = self
            .predecessor
            .iter()
            .chain(&self.members)
            .chain(self.successor.iter())
            .collect::<Vec<_>>();
        if leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(RangeError::Order);
        }

        // A guard is disclosed exactly when leaves exist on that side, so the
        // members provably occupy the positions between their neighbors.
        let len = self.opening.proof.leaf_count;
        let members = u32::try_from(self.members.len()).map_err(|_| RangeError::Guards)?;
        let start = self
            .opening
            .start
            .checked_add(u32::from(self.predecessor.is_some()))
            .ok_or(RangeError::Guards)?;
        let end = start.checked_add(members).ok_or(RangeError::Guards)?;
        if end > len
            || self.predecessor.is_some() != (start > 0)
            || self.successor.is_some() != (end < len)
        {
            return Err(RangeError::Guards);
        }
        let encoded = leaves.iter().map(|leaf| leaf.encode()).collect::<Vec<_>>();
        self.opening
            .verify::<Sha256, _>(VectorKind::State, root, &encoded)?;
        Ok(())
    }
}

impl Write for SliceRange {
    fn write(&self, buf: &mut impl BufMut) {
        self.predecessor.write(buf);
        self.members.write(buf);
        self.successor.write(buf);
        self.opening.write(buf);
    }
}

impl EncodeSize for SliceRange {
    fn encode_size(&self) -> usize {
        self.predecessor.encode_size()
            + self.members.encode_size()
            + self.successor.encode_size()
            + self.opening.encode_size()
    }
}

impl Read for SliceRange {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            predecessor: Option::<StateLeaf<Key>>::read(buf)?,
            members: Vec::<StateLeaf<Key>>::read_cfg(buf, &(RangeCfg::new(..=MAX_ACCOUNTS), ()))?,
            successor: Option::<StateLeaf<Key>>::read(buf)?,
            opening: RangeOpening::read_cfg(buf, &(MAX_ACCOUNTS + 2))?,
        })
    }
}

/// One slice's retained live leaves at one certified state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedInterval {
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) slice: u16,
    pub(crate) range: SliceRange,
}

impl Write for RetainedInterval {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.slice.write(buf);
        self.range.write(buf);
    }
}

impl EncodeSize for RetainedInterval {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.slice.encode_size() + self.range.encode_size()
    }
}

impl Read for RetainedInterval {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            root: VectorRoot::read(buf)?,
            slice: u16::read(buf)?,
            range: SliceRange::read(buf)?,
        })
    }
}

/// Durable store of retained slice intervals: a prunable archive sectioned
/// by the epoch whose dealing the interval hydrates and keyed by the digest
/// of the state root and slice.
///
/// Records stay per slice even though a dealt slice covers a span:
/// hydration concatenates the span's records in slice order, and the
/// advanced interval is split back into per-slice records, so the store is
/// independent of how the committee assignment groups slices into spans.
/// Sealing epoch `e` consumes the intervals at section `e` (the registered
/// close's predecessor root) and writes the advanced intervals at section
/// `e + 1` (its successor root), synced together with the sealed dealing
/// before the vote leaves this validator. Pruning keeps the consumed and
/// produced sections, so a retried close re-votes from the dealing store
/// while the next registration always finds its predecessor interval.
pub(crate) type IntervalStore<E> = prunable::Archive<TwoCap, E, Digest, RetainedInterval>;

/// The interval record key: one state root and slice.
fn interval_key(root: &VectorRoot<Digest>, slice: u16) -> Digest {
    Sha256::hash(&[root.digest.as_ref(), &slice.to_be_bytes()])
}

/// The interval record index: one section per epoch, one record per slice.
fn interval_index(epoch: u64, slice: u16) -> u64 {
    epoch
        .checked_mul(MAX_SLICES as u64)
        .and_then(|base| base.checked_add(u64::from(slice)))
        .expect("the interval index fits the epoch clock")
}

/// Merges one slice's unchanged leaves with its rows on one side of the
/// close: the span's predecessor live set (`successor` false) or its
/// successor live set (`successor` true), key-sorted.
///
/// A row contributes on a side exactly when its state there is active,
/// which is what [`Interval::advance`] applies and what the slice's state
/// ranges open.
pub(crate) fn live_set(
    unchanged: &[StateLeaf<Key>],
    rows: &[AccountRow<Key, Digest>],
    successor: bool,
) -> Vec<StateLeaf<Key>> {
    let side = |row: &AccountRow<Key, Digest>| -> AccountState {
        if successor {
            row.successor
        } else {
            row.predecessor
        }
    };
    let mut leaves = Vec::with_capacity(unchanged.len() + rows.len());
    let mut unchanged = unchanged.iter().peekable();
    for row in rows {
        while unchanged
            .peek()
            .is_some_and(|leaf| leaf.account < row.account)
        {
            leaves.push((*unchanged.next().expect("peeked")).clone());
        }
        let state = side(row);
        if state.active {
            leaves.push(StateLeaf {
                account: row.account.clone(),
                state,
            });
        }
    }
    leaves.extend(unchanged.cloned());
    leaves
}

/// Splits one span's guarded state range over `members` (its live leaves at
/// the range's root, key-sorted) into one [`SliceRange`] per slice of the
/// span, in slice order: each slice's members bracketed by its adjacent
/// leaves in the covered run (or the span's own guards, or the vector ends)
/// under an opening narrowed from the span's with [`RangeOpening::narrow`].
///
/// The span range must have verified against its root with exactly these
/// members: every member lies in the span (genesis splits the whole account
/// set over every slice, and advancing an interval never moves a leaf out
/// of its slice), and narrowing trusts the values it is given.
pub(crate) fn slice_ranges(
    range: &StateRange<Key, Digest>,
    members: &[StateLeaf<Key>],
    span: &Range<u16>,
    slice_bits: u8,
) -> Result<Vec<SliceRange>, commitment::Error> {
    let encoded = range
        .predecessor
        .iter()
        .chain(members)
        .chain(range.successor.iter())
        .map(|leaf| leaf.encode())
        .collect::<Vec<_>>();
    let position = |index: usize| -> Result<u32, commitment::Error> {
        u32::try_from(index)
            .ok()
            .and_then(|index| {
                range
                    .opening
                    .start
                    .checked_add(u32::from(range.predecessor.is_some()))?
                    .checked_add(index)
            })
            .ok_or(commitment::Error::NonCanonicalPositions)
    };

    // Members are key-sorted and slices partition the key space by prefix,
    // so each slice's members are one contiguous run in slice order.
    let mut cursor = 0;
    let mut ranges = Vec::with_capacity(span.len());
    for slice in span.clone() {
        let first = cursor;
        while members.get(cursor).is_some_and(|leaf| {
            account_slice(&leaf.account, slice_bits).expect("account keys partition") == slice
        }) {
            cursor += 1;
        }
        let run = first..cursor;
        let predecessor = run.start.checked_sub(1).map_or_else(
            || range.predecessor.clone(),
            |previous| Some(members[previous].clone()),
        );
        let successor = members
            .get(run.end)
            .map_or_else(|| range.successor.clone(), |next| Some(next.clone()));
        let start = position(run.start)?
            .checked_sub(u32::from(predecessor.is_some()))
            .ok_or(commitment::Error::NonCanonicalPositions)?;
        let count = u32::try_from(run.len())
            .ok()
            .and_then(|count| {
                count
                    .checked_add(u32::from(predecessor.is_some()))?
                    .checked_add(u32::from(successor.is_some()))
            })
            .ok_or(commitment::Error::NonCanonicalPositions)?;

        // An empty vector has nothing to narrow to: its bracket is the span's
        // own empty opening.
        let opening = if count == 0 {
            range.opening.clone()
        } else {
            range
                .opening
                .narrow::<Sha256, _>(VectorKind::State, &encoded, start, count)?
        };
        ranges.push(SliceRange {
            predecessor,
            members: members[run].to_vec(),
            successor,
            opening,
        });
    }
    assert!(
        cursor == members.len(),
        "retained leaf falls outside the span {span:?}"
    );
    Ok(ranges)
}

/// The deployment's genesis state: every configured account active at its
/// opening balance, committed exactly as the genesis machine commits it.
pub(crate) fn genesis_cache(deployment: &Deployment) -> StateCache<Key, Digest> {
    let mut leaves = deployment
        .accounts
        .iter()
        .map(|account| StateLeaf {
            account: account.key.clone(),
            state: AccountState {
                balance: account.balance,
                active: true,
                ..Default::default()
            },
        })
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    StateCache::new::<Sha256>(leaves).expect("the genesis deployment state is canonical")
}

/// The whole genesis state as one unguarded range at its root, the span
/// range every per-slice genesis interval narrows from.
pub(crate) fn genesis_range(genesis: &StateCache<Key, Digest>) -> StateRange<Key, Digest> {
    let len = u32::try_from(genesis.len()).expect("the genesis state fits the vector bound");
    let mut builder =
        Builder::<Sha256>::new(VectorKind::State, len).expect("the genesis length is canonical");
    builder
        .add_values(genesis.leaves(), &Sequential)
        .expect("the genesis leaves fit the declared length");
    let tree = builder.build(&Sequential).expect("the genesis tree builds");
    assert!(
        tree.root() == genesis.root(),
        "the genesis range tree diverges from the genesis cache"
    );
    StateRange {
        predecessor: None,
        successor: None,
        opening: tree
            .range_opening(0, len)
            .expect("the whole vector is a canonical range"),
    }
}

/// Opens one deployment's durable interval store under the `partition`
/// family and seeds the genesis intervals when the store is empty.
async fn intervals<E: StorageContext>(
    context: E,
    partition: &str,
    deployment: &Deployment,
    genesis: &StateCache<Key, Digest>,
) -> IntervalStore<E> {
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let scoped = format!("{partition}-{}", short_digest(deployment.digest()));
    let mut store = IntervalStore::init(
        context,
        prunable::Config {
            translator: TwoCap,
            key_partition: format!("{scoped}-key"),
            key_page_cache: page_cache,
            value_partition: format!("{scoped}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(MAX_SLICES as u64),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
    )
    .await
    .expect("failed to initialize the retained interval store");

    // A fresh store holds the deployment's genesis intervals: every slice of
    // the genesis account state, opened under the same root the genesis
    // machine committed. A store that already holds records was seeded on
    // an earlier start and has since advanced (or pruned) past genesis.
    if store.first_index().is_some() {
        return store;
    }
    let root = genesis.root();
    let span = 0..MAX_SLICES as u16;
    let ranges = slice_ranges(&genesis_range(genesis), genesis.leaves(), &span, SLICE_BITS)
        .expect("the genesis range narrows to every slice");
    for (slice, range) in span.zip(ranges) {
        range
            .verify(&root, slice, SLICE_BITS)
            .expect("the narrowed genesis range verifies at the genesis root");
        store = store
            .put_sync(
                interval_index(0, slice),
                interval_key(&root, slice),
                RetainedInterval { root, slice, range },
            )
            .await
            .expect("failed to seed the genesis interval");
    }
    store
}

/// The span's predecessor live set as the retained interval the span index
/// checks the slice against: the sealed slice's unchanged leaves merged with
/// its live predecessor rows, exactly what this validator hydrated against
/// when it sealed the slice.
fn predecessor_interval(slice: &ProofSlice<Key, Digest>) -> anyhow::Result<Interval<Key>> {
    Interval::new(live_set(&slice.unchanged, &slice.changes.rows, false))
        .context("sealed slice does not yield a canonical predecessor interval")
}

/// Answers one close-bound lookup from an indexed span: the served opening
/// under the sealed header and roots, `Absent` when the held slice has
/// nothing to open for it, or `NotHolder` when the account falls outside
/// the span.
///
/// Every other failure means the retained slice is inconsistent with itself,
/// which a validator's own sealed record cannot be: it is surfaced as an
/// error instead of an answer.
pub(crate) fn answer(
    index: &SpanIndex<'_, Key, Digest>,
    header: Header<Digest>,
    roots: RootBundle<Digest>,
    lookup: &EvidenceLookup,
) -> anyhow::Result<EvidenceResponse> {
    let body = match lookup {
        EvidenceLookup::PredecessorState { account, .. } => index
            .predecessor_opening::<Sha256>(account)
            .map(EvidenceBody::State),
        EvidenceLookup::SuccessorState { account, .. } => index
            .successor_opening::<Sha256>(account)
            .map(EvidenceBody::State),
        EvidenceLookup::Change { account, .. } => index
            .change_opening::<Sha256>(account)
            .map(EvidenceBody::Change),
        EvidenceLookup::CommittedEntry {
            payer, recipient, ..
        } => index
            .higher_entry_lookup::<Sha256>(payer, recipient)
            .map(EvidenceBody::CommittedEntry),
        EvidenceLookup::Account { account, .. } => index
            .account_lookup::<Sha256>(account)
            .map(EvidenceBody::Account),
        EvidenceLookup::WithdrawalOutput { account, .. } => index
            .withdrawal_claim::<Sha256>(account)
            .map(EvidenceBody::WithdrawalOutput),
        EvidenceLookup::Credits { recipient, .. } => {
            index
                .credits::<Sha256>(recipient)
                .map(|(entries, opening)| EvidenceBody::Credits {
                    entries: entries.to_vec(),
                    opening,
                })
        }
        EvidenceLookup::ExternalPayout { account, .. } => index
            .external_payout_claim::<Sha256>(account)
            .map(EvidenceBody::ExternalPayout),
        EvidenceLookup::GenesisState { .. } | EvidenceLookup::Interval { .. } => {
            anyhow::bail!("lookup is not close-bound")
        }
    };
    Ok(match body {
        Ok(body) => EvidenceResponse::Served(Evidence::Close {
            header,
            roots,
            body,
        }),
        Err(
            ServeError::Absent
            | ServeError::Unchanged
            | ServeError::NoWithdrawal
            | ServeError::NoPayout
            | ServeError::NoCredit,
        ) => EvidenceResponse::Absent,
        Err(ServeError::NotHeld { .. }) => EvidenceResponse::NotHolder {
            spans: vec![index.span().clone()],
        },
        Err(error) => return Err(error).context("retained slice cannot serve the lookup"),
    })
}

/// Why one holder did not supply a requested interval.
#[derive(Debug, Error)]
enum Decline {
    /// The holder did not answer within the configured fetch timeout.
    #[error("timed out")]
    Timeout,
    /// The connection or frame exchange failed.
    #[error("request failed: {0}")]
    Failed(String),
    /// The holder refused the request with an error response.
    #[error("request refused: {0}")]
    Refused(String),
    /// The holder answered with routing advice instead of the interval.
    #[error("holder answered {0:?}")]
    Advice(Box<EvidenceResponse>),
    /// The response is not a decodable interval.
    #[error("response is not an interval")]
    Garbage,
    /// The served range is not the slice's complete live set at the root.
    #[error("range does not verify: {0}")]
    Range(#[from] RangeError),
    /// The served members do not form a canonical retained interval.
    #[error("range is not a canonical interval: {0}")]
    Interval(#[from] TransitionError),
}

/// One holder's answer to an interval request, awaited for at most
/// `timeout` on the runtime clock and verified as `slice`'s complete live
/// set at `root` and as a canonical interval before it is returned. The
/// holder is adversarial: nothing it sends is trusted beyond what verifies
/// against the certified root.
async fn attempt<E: Clock + Network>(
    context: &E,
    holder: SocketAddr,
    request: &rpc::Request,
    root: &VectorRoot<Digest>,
    slice: u16,
    slice_bits: u8,
    timeout: Duration,
) -> Result<SliceRange, Decline> {
    let response = select! {
        response = rpc::call(context, holder, request) => response,
        _ = context.sleep(timeout) => return Err(Decline::Timeout),
    };
    let body = match response {
        Ok(rpc::Response::Success { body }) => body,
        Ok(rpc::Response::Error { error }) => {
            return Err(Decline::Refused(
                String::from_utf8_lossy(&error).into_owned(),
            ));
        }
        Err(error) => return Err(Decline::Failed(format!("{error:#}"))),
    };
    let range = match EvidenceResponse::decode(body) {
        Ok(EvidenceResponse::Served(Evidence::Interval(range))) => range,
        Ok(EvidenceResponse::Served(_)) | Err(_) => return Err(Decline::Garbage),
        Ok(advice) => return Err(Decline::Advice(Box::new(advice))),
    };
    range.verify(root, slice, slice_bits)?;
    Interval::new(range.members.clone())?;
    Ok(range)
}

/// Fetches `slice`'s retained interval at `root` from `holders` in the
/// given order, stopping at the first that serves a verifiable range. Each
/// attempt is bounded by `timeout`. Returns the range, or every holder's
/// decline when none serves.
async fn fetch_interval<E: Clock + Network>(
    context: &E,
    deployment: Digest,
    root: VectorRoot<Digest>,
    slice: u16,
    slice_bits: u8,
    holders: &[SocketAddr],
    timeout: Duration,
) -> Result<SliceRange, Vec<(SocketAddr, Decline)>> {
    let request = rpc::Request {
        method: METHOD_EVIDENCE,
        body: EvidenceRequest::new(deployment, EvidenceLookup::Interval { root, slice }).encode(),
    };
    let mut declines = Vec::with_capacity(holders.len());
    for &holder in holders {
        match attempt(context, holder, &request, &root, slice, slice_bits, timeout).await {
            Ok(range) => return Ok(range),
            Err(decline) => declines.push((holder, decline)),
        }
    }
    Err(declines)
}

/// Fetches every planned slice concurrently: `(slice, holders)` pairs with
/// the holders already in try order, so the whole fetch stalls for at most
/// one slice's rotation. Every slice is attempted even after another fails,
/// so a resent dealing has less left to fetch.
async fn fetch_intervals<E: Clock + Network>(
    context: &E,
    deployment: Digest,
    root: VectorRoot<Digest>,
    slice_bits: u8,
    plan: Vec<(u16, Vec<SocketAddr>)>,
    timeout: Duration,
) -> Vec<(u16, Result<SliceRange, Vec<(SocketAddr, Decline)>>)> {
    join_all(plan.into_iter().map(|(slice, holders)| async move {
        let outcome = fetch_interval(
            context, deployment, root, slice, slice_bits, &holders, timeout,
        )
        .await;
        (slice, outcome)
    }))
    .await
}

/// Sealer configuration.
pub(crate) struct Config<E>
where
    E: Spawner + StorageContext,
{
    /// The validator's dealt clearing committee signing scheme.
    pub(crate) scheme: bls12381::Scheme,
    /// The accepted dealers: each configured operator's network identity
    /// paired with the deployment it runs, in genesis order.
    pub(crate) operators: Vec<(ed25519::PublicKey, Deployment)>,
    /// The applied settlement database holding the registered closes.
    pub(crate) db: Database<E>,
    /// Storage partition family retaining sealed dealings.
    pub(crate) partition: String,
    /// Every committee validator's clearing key with the query address
    /// serving its retained intervals: the holders a missing interval is
    /// fetched from.
    pub(crate) validators: Vec<ValidatorEntry>,
    /// Longest one interval fetch waits on a holder before rotating to the
    /// next, on the runtime clock. Missing slices are fetched concurrently,
    /// so a dealing stalls for at most `(q - 1) * fetch_timeout` before it
    /// seals or is skipped.
    pub(crate) fetch_timeout: Duration,
}

/// One configured operator's sealing lane: its deployment and the durable
/// store retaining that deployment's sealed dealings.
struct Lane<E>
where
    E: StorageContext,
{
    peer: ed25519::PublicKey,
    deployment: Digest,
    /// Taken while one dealing is processed and always restored: archive
    /// operations consume and return the store.
    store: Option<Store<E>>,
    /// The retained slice intervals dealings hydrate against, taken and
    /// restored like the dealing store.
    intervals: Option<IntervalStore<E>>,
    /// The deployment's genesis state, served whole to every requester.
    genesis: StateCache<Key, Digest>,
}

/// Why a dealing addressed to the registered close is skipped before sealing.
enum Skip {
    /// No retained interval record for this slice at the predecessor root.
    Missing(u16),
    /// The dealt slice covering this span does not hydrate against the
    /// retained interval.
    Malformed(Range<u16>, CodecError),
}

/// One evidence request awaiting the sealer's answer.
///
/// The mailbox is fed by the public query server, so it is bounded with a
/// dropping policy: a request that finds the mailbox full is rejected, and
/// the query connection that carried it returns an error response instead of
/// queueing ahead of dealings without bound.
pub(crate) struct Serve {
    request: EvidenceRequest,
    response: oneshot::Sender<EvidenceResponse>,
}

impl UnreliablePolicy for Serve {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut VecDeque<Self>, _: Self) -> bool {
        false
    }
}

/// Async handle to the sealer's evidence service.
#[derive(Clone)]
pub(crate) struct Mailbox {
    sender: MailboxSender<Serve>,
}

impl Mailbox {
    /// Answers one evidence request from the sealer's retained dealings and
    /// intervals, or fails when the mailbox is full or the sealer stopped.
    pub(crate) async fn serve(&self, request: EvidenceRequest) -> anyhow::Result<EvidenceResponse> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .enqueue(Serve { request, response })
            .is_rejected()
        {
            anyhow::bail!("the sealer mailbox is full");
        }
        receiver.await.context("the sealer stopped")
    }
}

/// The validator's sealing actor on the settlement DA channel.
pub(crate) struct Sealer<E>
where
    E: Spawner + Metrics + Network + StorageContext + CryptoRng,
{
    context: ContextCell<E>,
    scheme: bls12381::Scheme,
    /// This validator's assigned spans under the chain's fixed committee
    /// and slice partition, the spans it serves evidence for.
    spans: Vec<Range<u16>>,
    operators: Vec<(ed25519::PublicKey, Deployment)>,
    /// The committee's evidence-serving identities, the holders a missing
    /// interval is fetched from.
    validators: Vec<ValidatorEntry>,
    fetch_timeout: Duration,
    db: Database<E>,
    partition: String,
    mailbox: MailboxReceiver<Serve>,
}

impl<E> Sealer<E>
where
    E: Spawner + Metrics + Network + StorageContext + CryptoRng,
{
    /// Creates the sealer and its evidence mailbox. Dropping the last clone
    /// of the mailbox closes it and stops the sealer, so the mailbox must
    /// outlive the sealer.
    pub(crate) fn new(context: E, config: Config<E>) -> (Self, Mailbox) {
        let me = config
            .scheme
            .me()
            .expect("the sealer requires a signing clearing scheme");
        assert!(
            !config.operators.is_empty(),
            "the sealer requires at least one configured operator"
        );
        let assignment =
            Assignment::new(config.scheme.committee().commitment::<Sha256>(), SLICE_BITS)
                .expect("the protocol slice partition is canonical");
        let spans = assigned_slice_spans::<Sha256, _>(config.scheme.committee(), &assignment, me)
            .expect("the sealer scheme is dealt from the chain's static committee");
        let (sender, mailbox) = mailbox::new_unreliable(context.child("mailbox"), MAILBOX_SIZE);
        (
            Self {
                context: ContextCell::new(context),
                scheme: config.scheme,
                spans,
                operators: config.operators,
                validators: config.validators,
                fetch_timeout: config.fetch_timeout,
                db: config.db,
                partition: config.partition,
                mailbox,
            },
            Mailbox { sender },
        )
    }

    /// Starts the sealer on the settlement DA channel.
    pub(crate) fn start<Se, Re>(mut self, chan: (Se, Re)) -> Handle<()>
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        spawn_cell!(self.context, self.run(chan))
    }

    async fn run<Se, Re>(mut self, (mut sender, mut receiver): (Se, Re))
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        let mut lanes = Vec::with_capacity(self.operators.len());
        for (index, (peer, deployment)) in self.operators.iter().enumerate() {
            // Context labels are 'static: one bounded allocation per
            // configured operator at actor start.
            let label: &'static str = format!("dealings_{index}").leak();
            let interval_label: &'static str = format!("intervals_{index}").leak();
            let genesis = genesis_cache(deployment);
            lanes.push(Lane {
                peer: peer.clone(),
                deployment: *deployment.digest(),
                store: Some(
                    store(
                        self.context.child(label),
                        &self.partition,
                        deployment.digest(),
                    )
                    .await,
                ),
                intervals: Some(
                    intervals(
                        self.context.child(interval_label),
                        &format!("{}-intervals", self.partition),
                        deployment,
                        &genesis,
                    )
                    .await,
                ),
                genesis,
            });
        }
        loop {
            // Dealings are rare and load-bearing, so the DA receiver is
            // polled ahead of the publicly fed evidence mailbox.
            select! {
                message = receiver.recv() => {
                    let Ok((peer, bytes)) = message else {
                        return;
                    };

                    // The configured operators are the only dealers, and the
                    // sender identity routes the dealing to the deployment that
                    // operator runs. Anything else on this channel is dropped
                    // without decoding past the bounds.
                    let Some(position) = lanes.iter().position(|lane| lane.peer == peer) else {
                        debug!(?peer, "dropping DA message from a non-operator peer");
                        continue;
                    };
                    let lane = &mut lanes[position];
                    let deployment = lane.deployment;
                    let mut store = lane
                        .store
                        .take()
                        .expect("the lane store is always restored");
                    let mut intervals = lane
                        .intervals
                        .take()
                        .expect("the lane interval store is always restored");
                    let Ok(Message::Dealing(mut dealing)) = Message::decode(bytes) else {
                        debug!("dropping undecodable or unexpected DA message");
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    };

                    // A replayed dealing for a batch this validator already
                    // sealed re-votes from the durable record (dissemination
                    // and votes are recoverable off-chain traffic), and never
                    // re-seals: the vote attested to exactly the retained bytes.
                    let batch = dealing.header.batch_id::<Sha256>().into_digest();
                    match store.get(Identifier::Key(&batch)).await {
                        Ok(Some(sealed)) => {
                            self.vote(&mut sender, &peer, sealed.epoch, sealed.header);
                            lane.store = Some(store);
                            lane.intervals = Some(intervals);
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            error!(?error, "sealer failed to read the dealing store");
                            return;
                        }
                    }

                    // The sending operator's deployment's chain-registered
                    // close from this validator's own applied state is the
                    // only sealing context: the dealing carries no context
                    // material to trust.
                    let (machine, height) = {
                        let guard = self.db.read().await;
                        let machine = match guard.get(&machine_key(&deployment)).await {
                            Ok(Some(Record::Machine(encoded))) => {
                                Machine::decode(encoded).expect("the persisted machine decodes")
                            }
                            Ok(_) => {
                                debug!("no settlement machine is applied yet");
                                lane.store = Some(store);
                                lane.intervals = Some(intervals);
                                continue;
                            }
                            Err(error) => {
                                error!(?error, "sealer failed to read applied state");
                                return;
                            }
                        };
                        let height = match guard.get(&status_key(&deployment)).await {
                            Ok(Some(Record::Status(status))) => status.height,
                            Ok(_) => 0,
                            Err(error) => {
                                error!(?error, "sealer failed to read applied status");
                                return;
                            }
                        };
                        (machine, height)
                    };
                    let Some(registered) = machine.registered() else {
                        debug!(
                            epoch = dealing.epoch,
                            "no registered close to seal against yet"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    };
                    if registered.context.payment().epoch() != dealing.epoch {
                        debug!(
                            epoch = dealing.epoch,
                            registered = registered.context.payment().epoch(),
                            "dealing is not for the registered epoch"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    }

                    // The header is one hash over the registered context and
                    // the dealt roots, a check seal repeats, so garbage is
                    // refused here before any per-slice hydration work.
                    if !dealing
                        .header
                        .verify::<Sha256, Key>(registered.context, &dealing.roots)
                    {
                        warn!(
                            epoch = dealing.epoch,
                            "dealing header does not commit the registered context and dealt roots"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    }

                    // The archive satisfies a put below its prune floor without
                    // storing, so a dealing whose challenge window already
                    // closed at the certified finalized height is refused
                    // instead of earning a vote its bytes could not back.
                    let deadline = registered.context.challenge_deadline();
                    if deadline < height {
                        debug!(
                            epoch = dealing.epoch,
                            deadline, height, "dealing challenge window already closed"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    }

                    // One close per challenge deadline: the archive silently
                    // ignores a put at an occupied index, so a differing
                    // dealing that would collide there is refused loudly before
                    // any seal work. An identical close was already answered
                    // from the store above.
                    match store.get(Identifier::Index(deadline)).await {
                        Ok(Some(_)) => {
                            warn!(
                                epoch = dealing.epoch,
                                deadline, "refusing a second close for a sealed challenge deadline"
                            );
                            lane.store = Some(store);
                            lane.intervals = Some(intervals);
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            error!(?error, "sealer failed to read the dealing store");
                            return;
                        }
                    }

                    // Seal enforces this validator's exact assignment over the
                    // hydrated slices. Comparing the dealt spans against it
                    // first spares a foreign dealing the hydration work.
                    let assigned = assigned_slice_spans::<Sha256, _>(
                        self.scheme.committee(),
                        registered.context.assignment(),
                        self.scheme.me().expect("signing scheme"),
                    )
                    .expect("the sealer scheme is dealt from the chain's static committee");
                    if dealing
                        .slices
                        .iter()
                        .map(|slice| slice.span())
                        .ne(assigned.iter())
                    {
                        warn!(
                            epoch = dealing.epoch,
                            "dealing does not match this validator's assignment"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    }

                    // One close per registered epoch in the interval store too:
                    // the advanced intervals land in the successor epoch's
                    // section keyed by the successor root, and the archive
                    // silently ignores a put at an occupied index. A crash
                    // between the interval sync and the dealing sync leaves
                    // that section filled by one close with no dealing stored,
                    // so a differing close for the same epoch is refused here
                    // instead of storing and voting a dealing whose intervals
                    // were dropped. An identical close re-puts idempotently.
                    let next = dealing
                        .epoch
                        .checked_add(1)
                        .expect("the epoch clock is bounded");
                    let mut occupied = None;
                    for slice in assigned.iter().flat_map(|span| span.clone()) {
                        match intervals
                            .get(Identifier::Index(interval_index(next, slice)))
                            .await
                        {
                            Ok(Some(record)) if record.root != dealing.roots.successor => {
                                occupied = Some(slice);
                                break;
                            }
                            Ok(_) => {}
                            Err(error) => {
                                error!(?error, "sealer failed to read the interval store");
                                return;
                            }
                        }
                    }
                    if let Some(slice) = occupied {
                        warn!(
                            epoch = dealing.epoch,
                            slice, "refusing a second close for a sealed interval section"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        continue;
                    }

                    // Every assigned slice's interval at the registered
                    // close's predecessor root must be retained before
                    // hydration. A slice this validator lacks (it never
                    // advanced past the predecessor close, or pruned the
                    // section) is fetched from the slice's other holders and
                    // verified against that root, which consensus certified,
                    // before it is retained. The lane stores stay restored
                    // and evidence keeps being served while the fetch is in
                    // flight, so a slow holder starves neither. A store read
                    // failure is fatal.
                    let predecessor_root = *registered.context.predecessor_root();
                    let mut missing = Vec::new();
                    for slice in assigned.iter().flat_map(|span| span.clone()) {
                        match intervals
                            .has(Identifier::Key(&interval_key(&predecessor_root, slice)))
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => missing.push(slice),
                            Err(error) => {
                                error!(?error, "sealer failed to read the interval store");
                                return;
                            }
                        }
                    }
                    if !missing.is_empty() {
                        let assignment = registered.context.assignment();
                        let plan = missing
                            .iter()
                            .map(|&slice| (slice, self.holders(assignment, slice)))
                            .collect::<Vec<_>>();
                        info!(
                            epoch = dealing.epoch,
                            ?missing,
                            "fetching missing retained intervals from their holders"
                        );
                        lane.store = Some(store);
                        lane.intervals = Some(intervals);
                        let Some(fetched) = self
                            .fetch_serving(
                                &mut lanes,
                                deployment,
                                predecessor_root,
                                assignment.slice_bits(),
                                plan,
                            )
                            .await
                        else {
                            return;
                        };
                        let lane = &mut lanes[position];
                        store = lane
                            .store
                            .take()
                            .expect("the lane store is always restored");
                        intervals = lane
                            .intervals
                            .take()
                            .expect("the lane interval store is always restored");
                        let mut failed = false;
                        for (slice, outcome) in fetched {
                            let range = match outcome {
                                Ok(range) => range,
                                Err(declines) => {
                                    warn!(
                                        epoch = dealing.epoch,
                                        slice,
                                        ?declines,
                                        "retained interval could not be fetched from its holders"
                                    );
                                    failed = true;
                                    continue;
                                }
                            };
                            let key = interval_key(&predecessor_root, slice);
                            intervals = match intervals
                                .put_sync(
                                    interval_index(dealing.epoch, slice),
                                    key,
                                    RetainedInterval {
                                        root: predecessor_root,
                                        slice,
                                        range,
                                    },
                                )
                                .await
                            {
                                Ok(intervals) => intervals,
                                Err(error) => {
                                    error!(?error, "fetched interval could not be made durable");
                                    return;
                                }
                            };

                            // The archive satisfies a put below its prune
                            // floor, or at an index another record occupies,
                            // without storing, so the record is confirmed
                            // present before hydration relies on it. Neither
                            // is retried: the floor never recedes and the
                            // occupant never leaves.
                            match intervals.has(Identifier::Key(&key)).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    warn!(
                                        epoch = dealing.epoch,
                                        slice,
                                        "fetched interval was not retained: its section is pruned or occupied"
                                    );
                                    failed = true;
                                }
                                Err(error) => {
                                    error!(?error, "sealer failed to read the interval store");
                                    return;
                                }
                            }
                        }
                        if failed {
                            lane.store = Some(store);
                            lane.intervals = Some(intervals);
                            continue;
                        }
                    }
                    let lane = &mut lanes[position];

                    // Hydrate each dealt slice against the retained interval
                    // covering its span at the registered close's predecessor
                    // root: the per-slice records concatenated in slice order,
                    // which is key order because slices partition the key
                    // space by prefix. Every record was confirmed present or
                    // fetched above, so a missing one here is a `Skip` that is
                    // answered once below and never fetched again. A store
                    // read failure is fatal.
                    let hydration = 'hydrate: {
                        let mut hydrated = Vec::with_capacity(dealing.slices.len());
                        let mut retained = Vec::with_capacity(dealing.slices.len());
                        for slice in std::mem::take(&mut dealing.slices) {
                            let span = slice.span().clone();
                            let mut leaves = Vec::new();
                            for index in span.clone() {
                                let key = interval_key(&predecessor_root, index);
                                match intervals.get(Identifier::Key(&key)).await {
                                    Ok(Some(record)) => leaves.extend(record.range.members),
                                    Ok(None) => break 'hydrate Err(Skip::Missing(index)),
                                    Err(error) => {
                                        error!(?error, "sealer failed to read the interval store");
                                        return;
                                    }
                                }
                            }
                            let interval = Interval::new(leaves)
                                .expect("durably retained intervals are canonical");
                            match slice.hydrate::<Sha256>(
                                &interval,
                                registered.context,
                                registered.deposits,
                                registered.withdrawals,
                            ) {
                                Ok(slice) => hydrated.push(slice),
                                Err(error) => break 'hydrate Err(Skip::Malformed(span, error)),
                            }
                            retained.push(interval);
                        }
                        Ok((hydrated, retained))
                    };
                    let (hydrated, mut retained) = match hydration {
                        Ok(hydrated) => hydrated,
                        Err(skip) => {
                            match skip {
                                Skip::Missing(slice) => warn!(
                                    epoch = dealing.epoch,
                                    slice,
                                    "retained interval is missing after the fetch"
                                ),
                                Skip::Malformed(span, error) => warn!(
                                    epoch = dealing.epoch,
                                    ?span,
                                    ?error,
                                    "dealt slice does not hydrate against the retained interval"
                                ),
                            }
                            lane.store = Some(store);
                            lane.intervals = Some(intervals);
                            continue;
                        }
                    };

                    // Clearing seal re-derives and enforces this validator's
                    // exact assignment, validates every hydrated slice against
                    // the registered context, verifies each slice's combined
                    // operator countersignature against the deployment's
                    // genesis-fixed acknowledgment key, and batch-verifies the
                    // payer signatures.
                    let sealed = match seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                        &self.scheme,
                        registered.context,
                        machine.operator_ack(),
                        registered.deposits,
                        registered.withdrawals,
                        &dealing.header,
                        &dealing.roots,
                        hydrated,
                        self.context.as_mut(),
                        &Sequential,
                    ) {
                        Ok((_, sealed)) => sealed,
                        Err(error) => {
                            warn!(?error, epoch = dealing.epoch, "dealing failed to seal");
                            lane.store = Some(store);
                            lane.intervals = Some(intervals);
                            continue;
                        }
                    };

                    // Advance and persist the retained intervals under the
                    // sealed close's successor root before anything else
                    // becomes durable: a crash after this point re-seals or
                    // re-votes from the stores, and an identical advanced
                    // record is idempotently ignored. Each advanced span is
                    // split back into one authenticated record per slice,
                    // narrowed from the sealed slice's successor range, empty
                    // for a slice with no live leaves exactly as genesis seeds
                    // it. Pruning keeps the consumed and produced epochs only.
                    let successor_root = dealing.roots.successor;
                    let slice_bits = registered.context.assignment().slice_bits();
                    for (interval, slice) in retained.iter_mut().zip(sealed.slices()) {
                        interval.advance(slice);
                        let ranges = slice_ranges(
                            &slice.successor,
                            interval.leaves(),
                            &slice.span,
                            slice_bits,
                        )
                        .expect("the sealed successor range narrows to every slice");
                        for (index, range) in slice.span.clone().zip(ranges) {
                            range
                                .verify(&successor_root, index, slice_bits)
                                .expect("the narrowed slice range verifies at the sealed root");
                            intervals = match intervals
                                .put_sync(
                                    interval_index(next, index),
                                    interval_key(&successor_root, index),
                                    RetainedInterval {
                                        root: successor_root,
                                        slice: index,
                                        range,
                                    },
                                )
                                .await
                            {
                                Ok(intervals) => intervals,
                                Err(error) => {
                                    error!(?error, "advanced interval could not be made durable");
                                    return;
                                }
                            };
                        }
                    }
                    intervals = match intervals.prune(interval_index(dealing.epoch, 0)).await {
                        Ok(intervals) => intervals,
                        Err(error) => {
                            error!(?error, "retained interval store could not prune");
                            return;
                        }
                    };

                    // Pruning is the retention rule: sections strictly below
                    // the certified finalized height (the applied status) are
                    // released, never on wall clock, because a deadline below
                    // that height means the challenge window is closed.
                    store = match store.prune(height).await {
                        Ok(store) => store,
                        Err(error) => {
                            error!(?error, "sealed dealing store could not prune");
                            return;
                        }
                    };

                    // Durable before vote: the sealed dealing is put at its
                    // challenge deadline and synced to disk before the
                    // attestation leaves this validator.
                    store = match store
                        .put_sync(
                            deadline,
                            batch,
                            Sealed {
                                epoch: dealing.epoch,
                                deadline,
                                context: registered.context.clone(),
                                header: *sealed.header(),
                                roots: *sealed.roots(),
                                deposits: registered.deposits.clone(),
                                withdrawals: registered.withdrawals.clone(),
                                slices: sealed.into_slices(),
                            },
                        )
                        .await
                    {
                        Ok(store) => store,
                        Err(error) => {
                            error!(?error, "sealed dealing could not be made durable");
                            return;
                        }
                    };
                    info!(epoch = dealing.epoch, "sealed dealing");
                    lane.store = Some(store);
                    lane.intervals = Some(intervals);
                    self.vote(&mut sender, &peer, dealing.epoch, dealing.header);
                },
                message = self.mailbox.recv() => {
                    let Some(Serve { request, response }) = message else {
                        info!("evidence mailbox closed; sealer stopping");
                        return;
                    };
                    match self.serve(&mut lanes, request).await {
                        Ok(answer) => {
                            response.send_lossy(answer);
                        }
                        Err(error) => {
                            error!(?error, "sealer failed to serve evidence");
                            return;
                        }
                    }
                },
            }
        }
    }

    /// The query addresses of `slice`'s other holders under `assignment`
    /// (at most `q - 1`), in ascending participant order rotated to this
    /// validator's own offset, so co-holders fetching one slice spread their
    /// requests. A participant genesis lists no address for is skipped.
    fn holders(&self, assignment: &Assignment<Digest>, slice: u16) -> Vec<SocketAddr> {
        let committee = self.scheme.committee();
        let me = self.scheme.me().expect("signing scheme");
        let mut holders = slice_holders::<Sha256, _>(committee, assignment, slice)
            .expect("the registered assignment is the committee's")
            .into_iter()
            .filter(|holder| *holder != me)
            .filter_map(|holder| {
                let key = committee.members().get(usize::from(holder))?;
                self.validators
                    .iter()
                    .find(|validator| validator.clearing == *key)
                    .map(|validator| validator.query)
            })
            .collect::<Vec<_>>();
        if !holders.is_empty() {
            let offset = (usize::from(me) + usize::from(slice)) % holders.len();
            holders.rotate_left(offset);
        }
        holders
    }

    /// Fetches the planned intervals from their holders while answering
    /// evidence requests, so a slow holder never starves the query servers
    /// waiting on this sealer. The caller restores the lane stores first, so
    /// serving reads them as usual, and the DA receiver waits (dealings are
    /// resent). Returns `None` when the mailbox closed or serving failed,
    /// which stops the actor.
    async fn fetch_serving(
        &mut self,
        lanes: &mut [Lane<E>],
        deployment: Digest,
        root: VectorRoot<Digest>,
        slice_bits: u8,
        plan: Vec<(u16, Vec<SocketAddr>)>,
    ) -> Option<Vec<(u16, Result<SliceRange, Vec<(SocketAddr, Decline)>>)>> {
        let mut fetch = pin!(fetch_intervals(
            self.context.as_present(),
            deployment,
            root,
            slice_bits,
            plan,
            self.fetch_timeout,
        ));
        loop {
            select! {
                fetched = &mut fetch => return Some(fetched),
                message = self.mailbox.recv() => {
                    let Some(Serve { request, response }) = message else {
                        info!("evidence mailbox closed; sealer stopping");
                        return None;
                    };
                    match self.serve(lanes, request).await {
                        Ok(answer) => {
                            response.send_lossy(answer);
                        }
                        Err(error) => {
                            error!(?error, "sealer failed to serve evidence");
                            return None;
                        }
                    }
                },
            }
        }
    }

    /// Answers one evidence request from the lane serving its deployment.
    ///
    /// Store reads take and restore the lane's stores within this call, and
    /// nothing here awaits another task, so serving never contends with the
    /// dealing path beyond its own turn of the actor loop. A store or state
    /// read failure is fatal, like every other storage failure in the actor.
    async fn serve(
        &self,
        lanes: &mut [Lane<E>],
        request: EvidenceRequest,
    ) -> anyhow::Result<EvidenceResponse> {
        let Some(lane) = lanes
            .iter_mut()
            .find(|lane| lane.deployment == request.deployment)
        else {
            return Ok(EvidenceResponse::Unknown);
        };
        match &request.lookup {
            EvidenceLookup::GenesisState { account } => Ok(lane
                .genesis
                .opening(account)
                .map_or(EvidenceResponse::Absent, |opening| {
                    EvidenceResponse::Served(Evidence::Genesis(opening))
                })),
            EvidenceLookup::Interval { root, slice } => {
                if !self.spans.iter().any(|span| span.contains(slice)) {
                    return Ok(EvidenceResponse::NotHolder {
                        spans: self.spans.clone(),
                    });
                }
                let intervals = lane
                    .intervals
                    .take()
                    .expect("the lane interval store is always restored");
                let record = intervals
                    .get(Identifier::Key(&interval_key(root, *slice)))
                    .await;
                lane.intervals = Some(intervals);
                Ok(match record.context("read the retained interval store")? {
                    Some(record) => EvidenceResponse::Served(Evidence::Interval(record.range)),
                    None => EvidenceResponse::Unsealed,
                })
            }
            lookup => {
                let batch = *lookup.batch().expect("close-bound lookups name a batch");
                let account = lookup
                    .account()
                    .expect("close-bound lookups name an account");
                let store = lane
                    .store
                    .take()
                    .expect("the lane store is always restored");
                let sealed = store.get(Identifier::Key(&batch)).await;
                lane.store = Some(store);
                let Some(sealed) = sealed.context("read the sealed dealing store")? else {
                    return self.released(&lane.deployment, &batch).await;
                };

                // A record whose challenge window closed at the applied
                // height is released advice, not evidence, whether or not
                // the dealing path has pruned its section yet.
                if sealed.deadline < self.height(&lane.deployment).await? {
                    return self.released(&lane.deployment, &batch).await;
                }
                let slice = account_slice(account, SLICE_BITS)
                    .expect("account keys are fixed-size and partition");
                let Some(slice) = sealed
                    .slices
                    .iter()
                    .find(|candidate| candidate.span.contains(&slice))
                else {
                    return Ok(EvidenceResponse::NotHolder {
                        spans: sealed
                            .slices
                            .iter()
                            .map(|slice| slice.span.clone())
                            .collect(),
                    });
                };
                let interval = predecessor_interval(slice)?;
                let index = SpanIndex::new::<Sha256>(
                    slice,
                    &interval,
                    &sealed.context,
                    &sealed.roots,
                    &sealed.withdrawals,
                )
                .context("index the retained slice")?;
                answer(&index, sealed.header, sealed.roots, lookup)
            }
        }
    }

    /// The applied status height of one deployment: the certified finalized
    /// height every retention decision is made against, zero before any
    /// status is applied.
    async fn height(&self, deployment: &Digest) -> anyhow::Result<u64> {
        let guard = self.db.read().await;
        Ok(
            match guard
                .get(&status_key(deployment))
                .await
                .context("read the applied status")?
            {
                Some(Record::Status(status)) => status.height,
                _ => 0,
            },
        )
    }

    /// Classifies a batch with no retained dealing: `Pruned` when the chain
    /// finalized it (its claim roots record exists, so the challenge window
    /// closed and the record was released), `Unsealed` otherwise.
    async fn released(
        &self,
        deployment: &Digest,
        batch: &Digest,
    ) -> anyhow::Result<EvidenceResponse> {
        let guard = self.db.read().await;
        let finalized = guard
            .get(&claim_roots_key(deployment, &BatchId::new(*batch)))
            .await
            .context("read the claim roots record")?
            .is_some();
        Ok(if finalized {
            EvidenceResponse::Pruned
        } else {
            EvidenceResponse::Unsealed
        })
    }

    /// Signs and returns one vote over a durably sealed header, addressed to
    /// the operator that disseminated the dealing.
    fn vote<Se>(
        &self,
        sender: &mut Se,
        operator: &ed25519::PublicKey,
        epoch: u64,
        header: Header<Digest>,
    ) where
        Se: Sender<PublicKey = ed25519::PublicKey>,
    {
        let vote = self
            .scheme
            .sign(&header)
            .expect("the sealer scheme was constructed as a signer");
        let message: Message = Message::Vote(Ballot {
            epoch,
            header,
            vote,
        });
        let sent = sender.send(Recipients::One(operator.clone()), message.encode(), true);
        if sent.is_empty() {
            debug!(epoch, "failed to send vote; the operator will resend");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{
            state::execute,
            tx::{AdmitRequest, RegisterEpochRequest, SettlementTx},
            types::Database,
        },
        protocol::{
            DepositEvent, INITIAL_BALANCE, PreparedEpoch, Protocol, clearing_private, committee,
            dealt_participant, deployment, deployments, identities,
        },
    };
    use bytes::Bytes;
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, DepositRecord, WithdrawalBatch},
        challenge::{AccountLookup, HigherEntryLookup},
        state::{AccountRow, Prefix, SettlementOutput},
        vector::OutVector,
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_p2p::simulated::{Config as NetConfig, Link, Network};
    use commonware_runtime::{
        Listener as _, Network as _, Runner as _, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
    };
    use commonware_storage::{
        journal::contiguous::variable::Config as VariableJournalConfig,
        merkle::full::Config as MerkleConfig, qmdb::current::VariableConfig,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, TestRng, probability, sync::Mutex};
    use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};

    /// The fetch timeout of every test sealer and direct fetch.
    const FETCH_TIMEOUT: Duration = Duration::from_millis(100);

    /// Opens a fresh settlement database with partitions under `prefix`.
    async fn open(
        context: deterministic::Context,
        prefix: &str,
    ) -> Database<deterministic::Context> {
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16));
        let config: VariableConfig<TwoCap, ((), ()), commonware_parallel::Sequential> =
            VariableConfig {
                merkle_config: MerkleConfig {
                    journal_partition: format!("{prefix}-mmr-journal"),
                    metadata_partition: format!("{prefix}-mmr-metadata"),
                    items_per_blob: NZU64!(64),
                    write_buffer: NZUsize!(2048),
                    strategy: Sequential,
                    page_cache: page_cache.clone(),
                },
                journal_config: VariableJournalConfig {
                    partition: format!("{prefix}-log-journal"),
                    items_per_section: NZU64!(64),
                    compression: None,
                    codec_config: ((), ()),
                    page_cache,
                    write_buffer: NZUsize!(2048),
                },
                grafted_metadata_partition: format!("{prefix}-grafted-metadata"),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
        <Database<deterministic::Context> as DatabaseSet<_>>::init(context, config).await
    }

    /// Executes one block against `db` under `configured` and applies it,
    /// with the height doubling as the timestamp.
    async fn apply_with(
        db: &Database<deterministic::Context>,
        height: u64,
        configured: &[crate::protocol::Deployment],
        txs: &[SettlementTx],
    ) {
        let batch = db.new_batches().await;
        let sealed = execute(
            batch,
            Height::new(height),
            height,
            &crate::protocol::Timing::DEFAULT,
            configured,
            txs,
        )
        .await
        .expect("block execution succeeds");
        db.apply(sealed).await;
    }

    /// Executes one block against `db` under the compiled default deployment
    /// and applies it.
    async fn apply(db: &Database<deterministic::Context>, height: u64, txs: &[SettlementTx]) {
        apply_with(db, height, &deployments(), txs).await;
    }

    /// The genesis account leaves, key-sorted.
    fn genesis_leaves() -> Vec<StateLeaf<Key>> {
        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        leaves
    }

    /// One epoch-0 close over genesis with a unit deposit, prepared for
    /// dissemination, and its chain transactions.
    fn fixture(
        protocol: &Protocol,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> (SettlementTx, SettlementTx, PreparedEpoch) {
        fixture_at(
            protocol,
            0,
            genesis_leaves(),
            b"da-fixture-deposit",
            admission_deadline,
            challenge_deadline,
        )
    }

    /// One close for `epoch` over `predecessor` leaves with a unit deposit
    /// to the first account, prepared for dissemination, and its chain
    /// transactions: the deposit and the boundary-only registration whose
    /// assigned deadlines the chain must reproduce at inclusion.
    fn fixture_at(
        protocol: &Protocol,
        epoch: u64,
        predecessor: Vec<StateLeaf<Key>>,
        deposit_label: &'static [u8],
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> (SettlementTx, SettlementTx, PreparedEpoch) {
        let account = predecessor[0].account.clone();
        let liability = predecessor
            .iter()
            .map(|leaf| leaf.state.balance)
            .sum::<u64>();
        let deposit = DepositEvent {
            id: Sha256::hash(&[deposit_label]),
            account: account.clone(),
            amount: 1,
        };
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
        let deposits_root = deposits.root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let signature = protocol.sign_chain_registration(
            epoch,
            liability,
            &deposits_root,
            &deposits_root,
            &withdrawals,
        );
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: protocol.deployment(),
            epoch,
            predecessor_liability: liability,
            deposits_root,
            staged_root: deposits_root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature,
        });

        let predecessor_state = predecessor[0].state;
        let successor_state = AccountState {
            balance: predecessor_state.balance + 1,
            ..predecessor_state
        };
        let row = AccountRow {
            account: account.clone(),
            predecessor: predecessor_state,
            successor: successor_state,
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix {
                deposit: 1,
                ..Prefix::default()
            },
        };
        let mut successor = predecessor.clone();
        successor[0].state = successor_state;
        let registration = protocol
            .registration_at(
                epoch,
                deposits,
                withdrawals,
                liability,
                admission_deadline,
                challenge_deadline,
            )
            .unwrap();
        let prepared = protocol
            .prepare(
                registration,
                vec![deposit.clone()],
                predecessor,
                vec![row],
                vec![OutVector::empty(epoch, account)],
                vec![None],
                Vec::new(),
                successor,
            )
            .unwrap();
        (
            SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                deployment: protocol.deployment(),
                event: deposit,
            }),
            register,
            prepared,
        )
    }

    /// One two-peer simulated network: the operator's DA channel endpoints
    /// and the validator's, with links per `to_validator`/`to_operator`.
    async fn network(
        context: &deterministic::Context,
        operator: &ed25519::PublicKey,
        validator: &ed25519::PublicKey,
        to_validator: bool,
        to_operator: bool,
    ) -> (
        (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) {
        let (net, oracle) = Network::new_with_peers(
            context.child("network"),
            NetConfig {
                max_size: 4 * 1024 * 1024,
                max_peers_per_set: NZUsize!(2),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            [operator.clone(), validator.clone()],
        )
        .await;
        net.start();
        let quota = commonware_runtime::Quota::per_second(commonware_utils::NZU32!(128));
        let operator_chan = oracle
            .control(operator.clone())
            .register(0, quota)
            .await
            .unwrap();
        let validator_chan = oracle
            .control(validator.clone())
            .register(0, quota)
            .await
            .unwrap();
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::from_millis(0),
            success_rate: probability!(1.0),
        };
        if to_validator {
            oracle
                .add_link(operator.clone(), validator.clone(), link.clone())
                .await
                .unwrap();
        }
        if to_operator {
            oracle
                .add_link(validator.clone(), operator.clone(), link)
                .await
                .unwrap();
        }
        (operator_chan, validator_chan)
    }

    /// A sealer for validator directory `index` over `db`, accepting
    /// dealings from the configured `operators` and fetching missing
    /// intervals from `validators`, with its evidence mailbox.
    fn sealer_with(
        context: &deterministic::Context,
        index: usize,
        operators: Vec<(ed25519::PublicKey, Deployment)>,
        db: Database<deterministic::Context>,
        partition: &str,
        validators: Vec<ValidatorEntry>,
    ) -> (Sealer<deterministic::Context>, Mailbox) {
        Sealer::new(
            context.child("sealer"),
            Config {
                scheme: bls12381::Scheme::signer(
                    committee().unwrap(),
                    clearing_private(index).unwrap(),
                )
                .unwrap(),
                operators,
                db,
                partition: partition.to_string(),
                validators,
                fetch_timeout: FETCH_TIMEOUT,
            },
        )
    }

    /// A sealer for validator directory `index` over `db`, accepting
    /// dealings from the configured `operators`, with no holders to fetch
    /// missing intervals from.
    fn sealer(
        context: &deterministic::Context,
        index: usize,
        operators: Vec<(ed25519::PublicKey, Deployment)>,
        db: Database<deterministic::Context>,
        partition: &str,
    ) -> (Sealer<deterministic::Context>, Mailbox) {
        sealer_with(context, index, operators, db, partition, Vec::new())
    }

    /// The operator's dealing over shared dealt wires is byte for byte the
    /// message the validator decodes: its slices are the hydrated slices
    /// stripped, and the decoded dealing re-encodes to the sent bytes.
    #[test]
    fn dealt_wire_encodes_the_decoded_dealing() {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let (_, _, prepared) = fixture(&protocol, 11, 12);
        let slices = protocol.slices(&prepared).unwrap();
        let dealings = protocol.dealings(&prepared, &slices).unwrap();
        let participant = dealt_participant(0).unwrap();
        let mine = dealings[usize::from(participant)].clone();
        let sent = Message::Dealing(Dealing {
            epoch: 0,
            header: prepared.close().header,
            roots: prepared.close().roots,
            slices: mine.clone(),
        });
        let bytes = sent.encode();
        assert_eq!(bytes.len(), sent.encode_size());
        let Ok(Message::Dealing(received)) = Message::decode(bytes.clone()) else {
            panic!("the dealt wire does not decode as a dealing");
        };
        let stripped = prepared
            .hydrate(mine)
            .unwrap()
            .into_iter()
            .map(|slice| DealtSlice::strip(slice, SLICE_BITS))
            .collect::<Vec<_>>();
        assert_eq!(received.slices, stripped);
        assert_eq!(Message::Dealing(received).encode(), bytes);
    }

    #[test]
    fn sealer_seals_persists_and_revotes() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-happy").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_000).public_key();
            let validator_key = PrivateKey::from_seed(9_001).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer_actor, _mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-happy",
            );
            sealer_actor.start(validator_chan);

            // The validator's exact dealing seals and earns a verified vote.
            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let mine = dealings[usize::from(participant)].clone();
            let hydrated = prepared.hydrate(mine.clone()).unwrap();
            let header = prepared.close().header;
            let roots = prepared.close().roots;
            let dealing = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: mine,
            });
            let sent = operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            assert_eq!(sent, vec![validator_key.clone()]);
            let (from, bytes) = operator_chan.1.recv().await.unwrap();
            assert_eq!(from, validator_key);
            let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                panic!("the sealer answered with a non-vote");
            };
            assert_eq!(ballot.epoch, 0);
            assert_eq!(ballot.header, header);
            assert_eq!(ballot.vote.signer, participant);
            let verifier = protocol.verifier();
            assert!(verifier.verify_vote(&header, &ballot.vote));

            // The sealed dealing is durably retained under the batch id, at
            // its challenge deadline.
            let store = store(context.child("probe"), "sealer-happy", &deployment()).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing is durable");
            assert_eq!(sealed.epoch, 0);
            assert_eq!(sealed.deadline, 12);
            assert_eq!(sealed.header, header);
            assert_eq!(sealed.roots, roots);
            assert_eq!(sealed.slices, hydrated);
            assert_eq!(store.first_index(), Some(12));

            // A replayed dealing re-votes from the durable record.
            let sent = operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            assert!(!sent.is_empty());
            let (_, bytes) = operator_chan.1.recv().await.unwrap();
            let Ok(Message::Vote(replayed)) = Message::decode(bytes) else {
                panic!("the sealer answered the replay with a non-vote");
            };
            assert_eq!(replayed.header, header);
            assert!(verifier.verify_vote(&header, &replayed.vote));
        });
    }

    #[test]
    fn sealer_refuses_tampered_dealings() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-tampered").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_100).public_key();
            let validator_key = PrivateKey::from_seed(9_101).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer_actor, _mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-tampered",
            );
            sealer_actor.start(validator_chan);

            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let header = prepared.close().header;
            let roots = prepared.close().roots;
            let mine = dealings[usize::from(participant)].clone();
            let hydrated = prepared.hydrate(mine.clone()).unwrap();

            // Another validator's assignment fails seal's exact-assignment
            // check, a corrupted slice (re-stripped from the hydrated form
            // with its coverage boundary moved) fails structural validation,
            // and a header over tampered roots fails the header check before
            // any slice is hydrated: none earns a vote or a durable record.
            let foreign = usize::from(participant) ^ 1;
            let wrong = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: dealings[foreign].clone(),
            });
            let mut corrupt_slices = hydrated.clone();
            let end = corrupt_slices[0]
                .coverage
                .boundaries
                .last_mut()
                .expect("a coverage range holds at least two boundaries");
            end.predecessor = end.predecessor.saturating_add(1);
            let corrupt = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: corrupt_slices
                    .into_iter()
                    .map(|slice| DealtSlice::strip(slice, SLICE_BITS))
                    .collect(),
            });
            let mut tampered = roots;
            tampered.successor = VectorRoot {
                digest: Sha256::hash(&[b"tampered-successor"]),
            };
            let garbage = Message::Dealing(Dealing {
                epoch: 0,
                header: Header::new::<Sha256, Key>(prepared.close_context(), &tampered),
                roots,
                slices: mine.clone(),
            });
            let good = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: mine,
            });
            for bytes in [
                wrong.encode(),
                corrupt.encode(),
                garbage.encode(),
                good.encode(),
            ] {
                let sent =
                    operator_chan
                        .0
                        .send(Recipients::One(validator_key.clone()), bytes, true);
                assert!(!sent.is_empty());
            }

            // The DA channel delivers in order, so the first (and only)
            // answer voting for the header proves the tampered dealings
            // produced nothing.
            let (_, bytes) = operator_chan.1.recv().await.unwrap();
            let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                panic!("the sealer answered with a non-vote");
            };
            assert_eq!(ballot.vote.signer, participant);
            assert!(protocol.verifier().verify_vote(&header, &ballot.vote));

            // Exactly one dealing was sealed and retained: indices are
            // unique per archive entry, and the only one is the close's
            // challenge deadline holding the untampered dealing.
            let store = store(context.child("probe"), "sealer-tampered", &deployment()).await;
            assert_eq!(store.first_index(), Some(12));
            assert_eq!(store.last_index(), Some(12));
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing is durable");
            assert_eq!(sealed.slices, hydrated);
        });
    }

    /// A crash between the interval sync and the dealing sync leaves the
    /// successor section filled by one close with no dealing stored. A
    /// differing close for the same registered epoch must then be refused
    /// before sealing: the archive would silently drop its intervals while
    /// its dealing was stored and voted.
    #[test]
    fn sealer_refuses_a_second_close_for_an_occupied_interval_section() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-occupied").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let mine = dealings[usize::from(participant)].clone();
            let header = prepared.close().header;
            let roots = prepared.close().roots;

            // Another close for epoch 0 already advanced this validator's
            // first assigned slice into section 1 under its own successor
            // root, exactly what a crash after the interval sync leaves.
            let slice = prepared.hydrate(mine.clone()).unwrap()[0].span.start;
            let foreign = VectorRoot {
                digest: Sha256::hash(&[b"foreign-successor"]),
            };
            let configured = deployments().remove(0);
            let genesis = genesis_cache(&configured);
            let seeded = intervals(
                context.child("seed"),
                "sealer-occupied-intervals",
                &configured,
                &genesis,
            )
            .await;
            let seeded = seeded
                .put_sync(
                    interval_index(1, slice),
                    interval_key(&foreign, slice),
                    RetainedInterval {
                        root: foreign,
                        slice,
                        range: SliceRange {
                            predecessor: None,
                            members: Vec::new(),
                            successor: None,
                            opening: RangeOpening {
                                start: 0,
                                proof: Default::default(),
                            },
                        },
                    },
                )
                .await
                .unwrap();
            drop(seeded);

            let operator_key = PrivateKey::from_seed(9_300).public_key();
            let validator_key = PrivateKey::from_seed(9_301).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer_actor, _mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), configured.clone())],
                db.clone(),
                "sealer-occupied",
            );
            sealer_actor.start(validator_chan);
            let dealing = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: mine,
            });
            let sent = operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            assert_eq!(sent, vec![validator_key.clone()]);
            context.sleep(Duration::from_secs(1)).await;

            // The otherwise valid dealing earned neither a durable record nor
            // the vote that follows it, and the occupied section is untouched.
            let store = store(context.child("probe"), "sealer-occupied", &deployment()).await;
            assert_eq!(store.first_index(), None);
            let batch = header.batch_id::<Sha256>().into_digest();
            assert_eq!(store.get(Identifier::Key(&batch)).await.unwrap(), None);
            let probe = intervals(
                context.child("interval_probe"),
                "sealer-occupied-intervals",
                &configured,
                &genesis,
            )
            .await;
            let record = probe
                .get(Identifier::Index(interval_index(1, slice)))
                .await
                .unwrap()
                .expect("the seeded interval is retained");
            assert_eq!(record.root, foreign);
            assert_eq!(
                probe
                    .get(Identifier::Key(&interval_key(&roots.successor, slice)))
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn sealed_dealing_is_durable_before_the_vote() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-durable").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_200).public_key();
            let validator_key = PrivateKey::from_seed(9_201).public_key();

            // No return link: the vote can never leave the validator, which
            // models a kill between seal and vote.
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, false).await;
            let (sealer_actor, _mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-durable",
            );
            let running = sealer_actor.start(validator_chan);

            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let mine = dealings[usize::from(participant)].clone();
            let hydrated = prepared.hydrate(mine.clone()).unwrap();
            let header = prepared.close().header;
            let dealing = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots: prepared.close().roots,
                slices: mine,
            });
            operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            context.sleep(Duration::from_secs(1)).await;
            running.abort();

            // The restarted validator still holds the sealed dealing even
            // though its vote never left, and re-votes on the resent dealing.
            let store = store(context.child("probe"), "sealer-durable", &deployment()).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing survived the crash before the vote");
            assert_eq!(sealed.slices, hydrated);
            drop(store);

            let relinked = context.child("relinked");
            let (mut operator_chan, validator_chan) =
                network(&relinked, &operator_key, &validator_key, true, true).await;
            let restarted = context.child("restarted");
            let (sealer_actor, _mailbox) = sealer(
                &restarted,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-durable",
            );
            sealer_actor.start(validator_chan);
            operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            let (_, bytes) = operator_chan.1.recv().await.unwrap();
            let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                panic!("the restarted sealer answered with a non-vote");
            };
            assert_eq!(ballot.header, header);
            assert!(protocol.verifier().verify_vote(&header, &ballot.vote));
        });
    }
    /// THE dealing-store cross-talk pin: two operators' closes share one
    /// challenge deadline, and the sealer seals both, retains each in its
    /// own deployment's archive, and votes back to each sender. Neither
    /// dealing collides with or displaces the other.
    #[test]
    fn dealing_stores_do_not_cross_talk() {
        deterministic::Runner::default().start(|context| async move {
            let alpha_protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let beta_protocol = Protocol::with_signer(
                NonZeroUsize::MIN,
                crate::protocol::operator_signer(1),
                crate::protocol::operator_ack_signer(1),
            )
            .unwrap();
            let alpha = alpha_protocol.deployment();
            let beta = beta_protocol.deployment();
            let configured = vec![
                crate::protocol::Deployment::new(
                    crate::protocol::operator_key(),
                    crate::protocol::operator_ack_key(0),
                    crate::protocol::accounts(),
                ),
                crate::protocol::Deployment::new(
                    crate::protocol::operator_signer(1).public_key(),
                    crate::protocol::operator_ack_key(1),
                    crate::protocol::accounts(),
                ),
            ];

            // Both deployments register in block 1 under the default policy,
            // so both closes carry the same assigned deadlines (11, 12).
            let (a_deposit, a_register, a_prepared) = fixture(&alpha_protocol, 11, 12);
            let (b_deposit, b_register, b_prepared) = fixture(&beta_protocol, 11, 12);
            let db = open(context.child("db"), "cross-talk").await;
            apply_with(
                &db,
                1,
                &configured,
                &[a_deposit, a_register, b_deposit, b_register],
            )
            .await;

            // One validator sealer configured for both operators, on a
            // three-peer simulated network.
            let alpha_key = PrivateKey::from_seed(9_400).public_key();
            let beta_key = PrivateKey::from_seed(9_401).public_key();
            let validator_key = PrivateKey::from_seed(9_402).public_key();
            let (net, oracle) = Network::new_with_peers(
                context.child("network"),
                NetConfig {
                    max_size: 4 * 1024 * 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                [alpha_key.clone(), beta_key.clone(), validator_key.clone()],
            )
            .await;
            net.start();
            let quota = commonware_runtime::Quota::per_second(commonware_utils::NZU32!(128));
            let mut alpha_chan = oracle
                .control(alpha_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let mut beta_chan = oracle
                .control(beta_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let validator_chan = oracle
                .control(validator_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            for operator in [&alpha_key, &beta_key] {
                oracle
                    .add_link(operator.clone(), validator_key.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(validator_key.clone(), operator.clone(), link.clone())
                    .await
                    .unwrap();
            }
            let (sealer_actor, _mailbox) = sealer(
                &context,
                0,
                vec![
                    (alpha_key.clone(), configured[0].clone()),
                    (beta_key.clone(), configured[1].clone()),
                ],
                db.clone(),
                "cross-talk",
            );
            sealer_actor.start(validator_chan);

            // Each operator disseminates its own dealing, and each vote
            // routes back to exactly the sender that earned it.
            let participant = dealt_participant(0).unwrap();
            let mut headers = Vec::new();
            for (protocol, prepared, chan) in [
                (&alpha_protocol, &a_prepared, &mut alpha_chan),
                (&beta_protocol, &b_prepared, &mut beta_chan),
            ] {
                let slices = protocol.slices(prepared).unwrap();
                let dealings = protocol.dealings(prepared, &slices).unwrap();
                let header = prepared.close().header;
                let message = Message::Dealing(Dealing {
                    epoch: 0,
                    header,
                    roots: prepared.close().roots,
                    slices: dealings[usize::from(participant)].clone(),
                });
                let sent = chan.0.send(
                    Recipients::One(validator_key.clone()),
                    message.encode(),
                    true,
                );
                assert_eq!(sent, vec![validator_key.clone()]);
                let (from, bytes) = chan.1.recv().await.unwrap();
                assert_eq!(from, validator_key);
                let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                    panic!("the sealer answered with a non-vote");
                };
                assert_eq!(ballot.header, header);
                assert!(protocol.verifier().verify_vote(&header, &ballot.vote));
                headers.push(header);
            }

            // The batch ids are deployment-unique and each archive holds
            // exactly its own deployment's dealing at the shared deadline.
            let alpha_batch = headers[0].batch_id::<Sha256>().into_digest();
            let beta_batch = headers[1].batch_id::<Sha256>().into_digest();
            assert_ne!(alpha_batch, beta_batch);
            let alpha_store = store(context.child("alpha_probe"), "cross-talk", &alpha).await;
            let beta_store = store(context.child("beta_probe"), "cross-talk", &beta).await;
            for (own, other, store, header) in [
                (&alpha_batch, &beta_batch, &alpha_store, &headers[0]),
                (&beta_batch, &alpha_batch, &beta_store, &headers[1]),
            ] {
                assert_eq!(store.first_index(), Some(12));
                assert_eq!(store.last_index(), Some(12));
                let sealed = store
                    .get(Identifier::Key(own))
                    .await
                    .unwrap()
                    .expect("the sealed dealing is durable in its own archive");
                assert_eq!(&sealed.header, header);
                assert_eq!(sealed.deadline, 12);
                assert_eq!(store.get(Identifier::Key(other)).await.unwrap(), None);
            }
        });
    }

    /// Disseminates validator directory 0's dealing for the epoch-0 close
    /// `prepared` over `operator_chan` and awaits its vote, returning the
    /// sealed header, roots, and the dealt proof slices as hydrated.
    async fn disseminate<Se, Re>(
        protocol: &Protocol,
        prepared: &PreparedEpoch,
        operator_chan: &mut (Se, Re),
        validator_key: &ed25519::PublicKey,
    ) -> (
        Header<Digest>,
        RootBundle<Digest>,
        Vec<ProofSlice<Key, Digest>>,
    )
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        disseminate_at(protocol, prepared, 0, operator_chan, validator_key).await
    }

    /// Disseminates validator directory 0's dealing for the `epoch` close
    /// `prepared` over `operator_chan` and awaits its vote, returning the
    /// sealed header, roots, and the dealt proof slices as hydrated.
    async fn disseminate_at<Se, Re>(
        protocol: &Protocol,
        prepared: &PreparedEpoch,
        epoch: u64,
        operator_chan: &mut (Se, Re),
        validator_key: &ed25519::PublicKey,
    ) -> (
        Header<Digest>,
        RootBundle<Digest>,
        Vec<ProofSlice<Key, Digest>>,
    )
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        let slices = protocol.slices(prepared).unwrap();
        let dealings = protocol.dealings(prepared, &slices).unwrap();
        let participant = dealt_participant(0).unwrap();
        let mine = dealings[usize::from(participant)].clone();
        let header = prepared.close().header;
        let roots = prepared.close().roots;
        let dealing = Message::Dealing(Dealing {
            epoch,
            header,
            roots,
            slices: mine.clone(),
        });
        let sent = operator_chan.0.send(
            Recipients::One(validator_key.clone()),
            dealing.encode(),
            true,
        );
        assert_eq!(sent, vec![validator_key.clone()]);
        let (_, bytes) = operator_chan.1.recv().await.unwrap();
        let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
            panic!("the sealer answered with a non-vote");
        };
        assert_eq!(ballot.header, header);
        (header, roots, prepared.hydrate(mine).unwrap())
    }

    /// Requests one piece of evidence for the default deployment.
    async fn evidence(mailbox: &Mailbox, lookup: EvidenceLookup) -> EvidenceResponse {
        mailbox
            .serve(EvidenceRequest::new(deployment(), lookup))
            .await
            .unwrap()
    }

    /// The fixture close's predecessor and successor live sets.
    fn live_sets(prepared: &PreparedEpoch) -> (Vec<StateLeaf<Key>>, Vec<StateLeaf<Key>>) {
        let close = prepared.close();
        (
            live_set(&close.unchanged, &close.rows, false),
            live_set(&close.unchanged, &close.rows, true),
        )
    }

    /// The served close-bound body, asserting the sealed header and roots
    /// ride with it.
    fn served(
        response: EvidenceResponse,
        header: &Header<Digest>,
        roots: &RootBundle<Digest>,
    ) -> EvidenceBody {
        let EvidenceResponse::Served(Evidence::Close {
            header: served_header,
            roots: served_roots,
            body,
        }) = response
        else {
            panic!("expected served close evidence, found {response:?}");
        };
        assert_eq!(&served_header, header);
        assert_eq!(&served_roots, roots);
        body
    }

    /// Every genesis slice range verifies at the genesis root and the ranges
    /// partition the genesis leaves in slice order.
    #[test]
    fn genesis_slice_ranges_verify_and_partition() {
        let genesis = genesis_cache(&deployments()[0]);
        let span = 0..MAX_SLICES as u16;
        let ranges = slice_ranges(
            &genesis_range(&genesis),
            genesis.leaves(),
            &span,
            SLICE_BITS,
        )
        .unwrap();
        assert_eq!(ranges.len(), MAX_SLICES);
        let mut members = Vec::new();
        for (slice, range) in span.zip(&ranges) {
            range.verify(&genesis.root(), slice, SLICE_BITS).unwrap();
            members.extend(range.members.iter().cloned());

            // A range with a guard moved into the slice, or a dropped guard,
            // no longer verifies.
            if let Some(guard) = &range.successor {
                let mut tampered = range.clone();
                tampered.members.push(guard.clone());
                tampered.successor = None;
                assert!(tampered.verify(&genesis.root(), slice, SLICE_BITS).is_err());
                let mut dropped = range.clone();
                dropped.successor = None;
                assert!(dropped.verify(&genesis.root(), slice, SLICE_BITS).is_err());
            }
        }
        assert_eq!(members, genesis.leaves());
    }

    #[test]
    fn sealer_serves_openings_for_every_account_in_its_spans() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-serves").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_500).public_key();
            let validator_key = PrivateKey::from_seed(9_501).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer, mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-serves",
            );
            let spans = sealer.spans.clone();
            sealer.start(validator_chan);
            let (header, roots, mine) =
                disseminate(&protocol, &prepared, &mut operator_chan, &validator_key).await;
            assert_eq!(
                mine.iter()
                    .map(|slice| slice.span.clone())
                    .collect::<Vec<_>>(),
                spans
            );
            let batch = header.batch_id::<Sha256>().into_digest();
            let predecessor_root = *prepared.close_context().predecessor_root();

            // The whole-close constructors every served state opening must
            // match byte for byte.
            let (predecessor, successor) = live_sets(&prepared);
            let predecessor_cache = StateCache::new::<Sha256>(predecessor.clone()).unwrap();
            let successor_cache = StateCache::new::<Sha256>(successor).unwrap();
            assert_eq!(predecessor_cache.root(), predecessor_root);
            assert_eq!(successor_cache.root(), roots.successor);
            let changed = prepared.close().rows[0].account.clone();

            let mut held = 0;
            for leaf in &predecessor {
                let account = leaf.account.clone();
                let slice = account_slice(&account, SLICE_BITS).unwrap();
                let lookups = [
                    EvidenceLookup::PredecessorState {
                        batch,
                        account: account.clone(),
                    },
                    EvidenceLookup::SuccessorState {
                        batch,
                        account: account.clone(),
                    },
                    EvidenceLookup::Account {
                        batch,
                        account: account.clone(),
                    },
                ];

                // Every close-bound lookup for a foreign slice names the
                // sealed spans so the requester can pick a holder.
                if !spans.iter().any(|span| span.contains(&slice)) {
                    for lookup in lookups {
                        assert_eq!(
                            evidence(&mailbox, lookup).await,
                            EvidenceResponse::NotHolder {
                                spans: spans.clone()
                            }
                        );
                    }
                    continue;
                }
                held += 1;
                let [predecessor_lookup, successor_lookup, account_lookup] = lookups;

                // State openings are the whole-tree openings, verified at
                // their roots.
                let EvidenceBody::State(opening) = served(
                    evidence(&mailbox, predecessor_lookup).await,
                    &header,
                    &roots,
                ) else {
                    panic!("predecessor state was not served as a state opening");
                };
                assert_eq!(opening, predecessor_cache.opening(&account).unwrap());
                opening
                    .proof
                    .verify::<Sha256>(
                        VectorKind::State,
                        &predecessor_root,
                        opening.leaf.encode().as_ref(),
                    )
                    .unwrap();
                let EvidenceBody::State(opening) =
                    served(evidence(&mailbox, successor_lookup).await, &header, &roots)
                else {
                    panic!("successor state was not served as a state opening");
                };
                assert_eq!(opening, successor_cache.opening(&account).unwrap());
                opening
                    .proof
                    .verify::<Sha256>(
                        VectorKind::State,
                        &roots.successor,
                        opening.leaf.encode().as_ref(),
                    )
                    .unwrap();

                // The higher-debit lookup resolves under the predecessor and
                // change roots: a change opening for the changed account, an
                // authenticated absence for every other.
                let EvidenceBody::Account(lookup) =
                    served(evidence(&mailbox, account_lookup).await, &header, &roots)
                else {
                    panic!("the account lookup was not served");
                };
                let (debit, change) = lookup
                    .resolve::<Sha256>(&predecessor_root, &roots.change, &account)
                    .unwrap();
                assert_eq!(debit, 0);
                assert_eq!(change.is_some(), account == changed);
                assert_eq!(
                    matches!(lookup, AccountLookup::Present(_)),
                    account == changed
                );

                // The change opening exists for the changed row alone, the
                // committed-entry lookup resolves for every payer, and the
                // fixture carries no withdrawal, payout, or credit.
                let change = evidence(
                    &mailbox,
                    EvidenceLookup::Change {
                        batch,
                        account: account.clone(),
                    },
                )
                .await;
                if account == changed {
                    let EvidenceBody::Change(opening) = served(change, &header, &roots) else {
                        panic!("the change opening was not served");
                    };
                    AccountLookup::Present(Box::new(opening))
                        .resolve::<Sha256>(&predecessor_root, &roots.change, &account)
                        .unwrap();
                } else {
                    assert_eq!(change, EvidenceResponse::Absent);
                }
                let recipient = if account == changed {
                    predecessor[1].account.clone()
                } else {
                    changed.clone()
                };
                let EvidenceBody::CommittedEntry(lookup) = served(
                    evidence(
                        &mailbox,
                        EvidenceLookup::CommittedEntry {
                            batch,
                            payer: account.clone(),
                            recipient: recipient.clone(),
                        },
                    )
                    .await,
                    &header,
                    &roots,
                ) else {
                    panic!("the committed entry lookup was not served");
                };
                assert_eq!(
                    matches!(lookup, HigherEntryLookup::Present { .. }),
                    account == changed
                );
                lookup
                    .resolve::<Sha256>(&roots.change, &account, &recipient)
                    .unwrap();
                for lookup in [
                    EvidenceLookup::WithdrawalOutput {
                        batch,
                        account: account.clone(),
                    },
                    EvidenceLookup::ExternalPayout {
                        batch,
                        account: account.clone(),
                    },
                    EvidenceLookup::Credits {
                        batch,
                        recipient: account.clone(),
                    },
                ] {
                    assert_eq!(evidence(&mailbox, lookup).await, EvidenceResponse::Absent);
                }
            }
            assert!(
                held > 0,
                "the fixture places accounts in the sealer's spans"
            );

            // Genesis state is served whole, for held and foreign slices alike.
            let genesis = genesis_cache(&deployments()[0]);
            for leaf in &predecessor {
                let EvidenceResponse::Served(Evidence::Genesis(opening)) = evidence(
                    &mailbox,
                    EvidenceLookup::GenesisState {
                        account: leaf.account.clone(),
                    },
                )
                .await
                else {
                    panic!("genesis state was not served");
                };
                assert_eq!(opening, genesis.opening(&leaf.account).unwrap());
            }
        });
    }

    /// Routing advice: a foreign slice names this validator's spans, an
    /// unknown batch or interval root is unsealed, and a foreign deployment
    /// is unknown.
    #[test]
    fn sealer_answers_routing_advice() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-advice").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_600).public_key();
            let validator_key = PrivateKey::from_seed(9_601).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer, mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-advice",
            );
            let spans = sealer.spans.clone();
            sealer.start(validator_chan);
            let (header, roots, _) =
                disseminate(&protocol, &prepared, &mut operator_chan, &validator_key).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let account = identities()[0].key.clone();

            // The quorum window leaves exactly one slice outside this
            // validator's spans, and an interval request for it is routed.
            let foreign = (0..MAX_SLICES as u16)
                .find(|slice| !spans.iter().any(|span| span.contains(slice)))
                .expect("a four-validator quorum of three leaves one slice unheld");
            assert_eq!(
                evidence(
                    &mailbox,
                    EvidenceLookup::Interval {
                        root: roots.successor,
                        slice: foreign,
                    },
                )
                .await,
                EvidenceResponse::NotHolder {
                    spans: spans.clone()
                }
            );

            // A batch this validator never sealed, and an interval root it
            // never reached, are unsealed rather than errors.
            assert_eq!(
                evidence(
                    &mailbox,
                    EvidenceLookup::PredecessorState {
                        batch: Sha256::hash(&[b"unknown-batch"]),
                        account: account.clone(),
                    },
                )
                .await,
                EvidenceResponse::Unsealed
            );
            let held = spans[0].start;
            assert_eq!(
                evidence(
                    &mailbox,
                    EvidenceLookup::Interval {
                        root: VectorRoot {
                            digest: Sha256::hash(&[b"unknown-root"]),
                        },
                        slice: held,
                    },
                )
                .await,
                EvidenceResponse::Unsealed
            );

            // A deployment this validator does not serve is unknown, even for
            // a batch it sealed under another deployment.
            assert_eq!(
                mailbox
                    .serve(EvidenceRequest::new(
                        Sha256::hash(&[b"foreign-deployment"]),
                        EvidenceLookup::PredecessorState { batch, account },
                    ))
                    .await
                    .unwrap(),
                EvidenceResponse::Unknown
            );
        });
    }

    /// Every retained interval is served as a range that verifies at its
    /// root and discloses exactly the slice's live set.
    #[test]
    fn sealer_serves_verifiable_intervals() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-intervals").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_700).public_key();
            let validator_key = PrivateKey::from_seed(9_701).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer, mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-intervals",
            );
            let spans = sealer.spans.clone();
            sealer.start(validator_chan);
            let (_, roots, _) =
                disseminate(&protocol, &prepared, &mut operator_chan, &validator_key).await;
            let predecessor_root = *prepared.close_context().predecessor_root();
            let (predecessor, successor) = live_sets(&prepared);

            // The consumed (genesis) and produced (successor) intervals are
            // both retained, one verifiable range per held slice.
            for (root, leaves) in [
                (predecessor_root, &predecessor),
                (roots.successor, &successor),
            ] {
                for slice in spans.iter().flat_map(|span| span.clone()) {
                    let EvidenceResponse::Served(Evidence::Interval(range)) =
                        evidence(&mailbox, EvidenceLookup::Interval { root, slice }).await
                    else {
                        panic!("the retained interval was not served");
                    };
                    range.verify(&root, slice, SLICE_BITS).unwrap();
                    let expected = leaves
                        .iter()
                        .filter(|leaf| account_slice(&leaf.account, SLICE_BITS).unwrap() == slice)
                        .cloned()
                        .collect::<Vec<_>>();
                    assert_eq!(range.members, expected);
                    if let Some(guard) = &range.predecessor {
                        assert!(account_slice(&guard.account, SLICE_BITS).unwrap() < slice);
                    }
                    if let Some(guard) = &range.successor {
                        assert!(account_slice(&guard.account, SLICE_BITS).unwrap() > slice);
                    }

                    // The range is bound to its root: it does not verify at
                    // the other one.
                    let other = if root == predecessor_root {
                        roots.successor
                    } else {
                        predecessor_root
                    };
                    assert!(range.verify(&other, slice, SLICE_BITS).is_err());
                }
            }
        });
    }

    /// A restarted sealer serves from its durable records: the sealed
    /// dealing and intervals reload from the archives, and the close context
    /// is recovered from the still-registered close in applied state.
    #[test]
    fn served_evidence_survives_restart() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-restart").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_800).public_key();
            let validator_key = PrivateKey::from_seed(9_801).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            let (sealer_actor, mailbox) = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-restart",
            );
            let spans = sealer_actor.spans.clone();
            let running = sealer_actor.start(validator_chan);
            let (header, roots, _) =
                disseminate(&protocol, &prepared, &mut operator_chan, &validator_key).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let predecessor_root = *prepared.close_context().predecessor_root();
            let (predecessor, _) = live_sets(&prepared);
            let held = predecessor
                .iter()
                .find(|leaf| {
                    let slice = account_slice(&leaf.account, SLICE_BITS).unwrap();
                    spans.iter().any(|span| span.contains(&slice))
                })
                .expect("the fixture places an account in the sealer's spans")
                .account
                .clone();
            let lookup = EvidenceLookup::PredecessorState {
                batch,
                account: held.clone(),
            };
            let before = evidence(&mailbox, lookup.clone()).await;
            let EvidenceBody::State(expected) = served(before, &header, &roots) else {
                panic!("predecessor state was not served before the restart");
            };

            // The close is admitted before the restart, so the chain no
            // longer names its registration: the restarted sealer serves it
            // from the persisted record alone, through the challenge window
            // in which challenge and claim evidence is needed.
            let result = protocol.complete(prepared, &mut TestRng::new(7)).unwrap();
            apply(&db, 2, &[SettlementTx::Admit(AdmitRequest::from(&result))]).await;
            let Some(Record::Machine(encoded)) = db
                .read()
                .await
                .get(&machine_key(&deployment()))
                .await
                .unwrap()
            else {
                panic!("the settlement machine is applied");
            };
            assert!(Machine::decode(encoded).unwrap().registered().is_none());
            running.abort();
            drop(mailbox);

            // The restarted sealer answers the same lookups from the durable
            // records, byte for byte.
            let relinked = context.child("relinked");
            let (_, validator_chan) =
                network(&relinked, &operator_key, &validator_key, true, true).await;
            let restarted = context.child("restarted");
            let (sealer_actor, mailbox) = sealer(
                &restarted,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                db.clone(),
                "sealer-restart",
            );
            sealer_actor.start(validator_chan);
            let EvidenceBody::State(after) =
                served(evidence(&mailbox, lookup).await, &header, &roots)
            else {
                panic!("predecessor state was not served after the restart");
            };
            assert_eq!(after, expected);
            after
                .proof
                .verify::<Sha256>(
                    VectorKind::State,
                    &predecessor_root,
                    after.leaf.encode().as_ref(),
                )
                .unwrap();
            let slice = account_slice(&held, SLICE_BITS).unwrap();
            let EvidenceResponse::Served(Evidence::Interval(range)) = evidence(
                &mailbox,
                EvidenceLookup::Interval {
                    root: roots.successor,
                    slice,
                },
            )
            .await
            else {
                panic!("the retained interval was not served after the restart");
            };
            range.verify(&roots.successor, slice, SLICE_BITS).unwrap();
        });
    }

    /// The query address of committee participant `index` in the fetch tests.
    fn peer_address(index: usize) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 7_000 + index as u16))
    }

    /// One successful evidence response.
    fn respond(response: &EvidenceResponse) -> rpc::Response {
        rpc::Response::Success {
            body: response.encode(),
        }
    }

    /// Serves scripted evidence at `address` on the runtime network: every
    /// request on every connection is decoded and answered by `handler`, or
    /// left unanswered when it returns `None`.
    fn peer<F>(context: &deterministic::Context, address: SocketAddr, handler: F)
    where
        F: Fn(EvidenceRequest) -> Option<rpc::Response> + Send + Sync + 'static,
    {
        context.child("peer").spawn(move |context| async move {
            let mut listener = context.bind(address).await.expect("the peer binds");
            let handler = Arc::new(handler);
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    return;
                };
                let handler = handler.clone();
                context.child("connection").spawn(move |_| async move {
                    let Ok(request) = rpc::recv_request(&mut stream).await else {
                        return;
                    };
                    assert_eq!(request.method, METHOD_EVIDENCE);
                    let request = EvidenceRequest::decode(request.body)
                        .expect("the sealer sends a well-formed evidence request");
                    match handler(request) {
                        Some(response) => {
                            let _ = rpc::send_response(&mut sink, &response).await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                });
            }
        });
    }

    /// The status singleton of the default deployment.
    async fn status(db: &Database<deterministic::Context>) -> crate::chain::state::StatusRecord {
        match db
            .read()
            .await
            .get(&status_key(&deployment()))
            .await
            .unwrap()
        {
            Some(Record::Status(status)) => status,
            record => panic!("expected the status record, found {record:?}"),
        }
    }

    /// Two registered epochs on one chain: epoch 0 sealed by validator 0's
    /// sealer `a`, which then retains epoch 1's predecessor intervals,
    /// admitted and finalized on the chain, and epoch 1 registered over its
    /// successor state with the deadlines the chain assigns at inclusion.
    struct TwoEpochs {
        protocol: Protocol,
        db: Database<deterministic::Context>,
        /// The epoch-1 close awaiting dissemination.
        prepared: PreparedEpoch,
        /// Epoch 1's predecessor root: epoch 0's successor root.
        root: VectorRoot<Digest>,
        /// Validator 0's assigned spans.
        spans: Vec<Range<u16>>,
        /// Epoch 1's predecessor interval of every slice validator 0 holds,
        /// as sealer `a` serves it.
        ranges: BTreeMap<u16, SliceRange>,
        /// Sealer `a`'s evidence mailbox, held so it keeps running.
        _mailbox: Mailbox,
    }

    async fn two_epochs(context: &deterministic::Context, prefix: &str) -> TwoEpochs {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
        let db = open(context.child("db"), prefix).await;
        apply(&db, 1, &[deposit_tx, register_tx]).await;

        // Sealer `a` seals epoch 0 and advances its intervals under the
        // successor root.
        let operator_key = PrivateKey::from_seed(9_900).public_key();
        let validator_key = PrivateKey::from_seed(9_901).public_key();
        let (mut operator_chan, validator_chan) = network(
            &context.child("a"),
            &operator_key,
            &validator_key,
            true,
            true,
        )
        .await;
        let (sealer_a, mailbox) = sealer(
            context,
            0,
            vec![(operator_key.clone(), deployments().remove(0))],
            db.clone(),
            &format!("{prefix}-a"),
        );
        let spans = sealer_a.spans.clone();
        sealer_a.start(validator_chan);
        let (_, roots, _) =
            disseminate(&protocol, &prepared, &mut operator_chan, &validator_key).await;
        let (_, successor) = live_sets(&prepared);

        // Epoch 0 is admitted at height 2 and finalizes once its challenge
        // window (through height 12) elapses.
        let result = protocol.complete(prepared, &mut TestRng::new(7)).unwrap();
        assert_eq!(result.finalized.successor_root, roots.successor);
        apply(&db, 2, &[SettlementTx::Admit(AdmitRequest::from(&result))]).await;
        for height in 3..=13 {
            apply(&db, height, &[]).await;
        }
        assert_eq!(status(&db).await.last_finalized, Some(0));

        // Epoch 1 registers at height 14 over epoch 0's successor state, so
        // its assigned deadlines are heights 24 and 25.
        let (deposit_tx, register_tx, prepared) =
            fixture_at(&protocol, 1, successor, b"da-fixture-deposit-1", 24, 25);
        apply(&db, 14, &[deposit_tx, register_tx]).await;
        let root = roots.successor;
        assert_eq!(*prepared.close_context().predecessor_root(), root);

        let mut ranges = BTreeMap::new();
        for slice in spans.iter().flat_map(|span| span.clone()) {
            let EvidenceResponse::Served(Evidence::Interval(range)) =
                evidence(&mailbox, EvidenceLookup::Interval { root, slice }).await
            else {
                panic!("sealer a does not serve epoch 1's predecessor interval");
            };
            ranges.insert(slice, range);
        }
        TwoEpochs {
            protocol,
            db,
            prepared,
            root,
            spans,
            ranges,
            _mailbox: mailbox,
        }
    }

    /// The genesis validator list of the fetch tests: committee participant
    /// `index` served at [`peer_address`].
    fn peer_entries() -> Vec<ValidatorEntry> {
        committee()
            .unwrap()
            .members()
            .iter()
            .enumerate()
            .map(|(index, key)| ValidatorEntry {
                clearing: *key,
                query: peer_address(index),
            })
            .collect()
    }

    /// The slices of `spans` that participant `index` co-holds with
    /// validator 0.
    fn co_held(spans: &[Range<u16>], index: usize) -> Vec<u16> {
        let committee = committee().unwrap();
        let assignment = Assignment::new(committee.commitment::<Sha256>(), SLICE_BITS).unwrap();
        spans
            .iter()
            .flat_map(|span| span.clone())
            .filter(|&slice| {
                slice_holders::<Sha256, _>(&committee, &assignment, slice)
                    .unwrap()
                    .iter()
                    .any(|holder| usize::from(*holder) == index)
            })
            .collect()
    }

    /// A sealer that never advanced past the predecessor close fetches every
    /// missing interval from the slice's other holders over the wire,
    /// verifies it against the registered predecessor root, retains it byte
    /// for byte as the holders do, and seals and votes on the dealing. Each
    /// slice costs exactly one request when its first holder serves.
    #[test]
    fn sealer_fetches_missing_intervals_from_holders() {
        deterministic::Runner::default().start(|context| async move {
            let chain = Box::pin(two_epochs(&context, "fetch")).await;
            let me = usize::from(dealt_participant(0).unwrap());

            // Every other committee member serves epoch 1's predecessor
            // intervals from what sealer `a` retained, recording the slices
            // it was asked for.
            let asked: Arc<Mutex<Vec<u16>>> = Arc::default();
            for index in 0..committee().unwrap().members().len() {
                if index == me {
                    continue;
                }
                let ranges = chain.ranges.clone();
                let root = chain.root;
                let asked = asked.clone();
                peer(&context, peer_address(index), move |request| {
                    assert_eq!(request.deployment, deployment());
                    let EvidenceLookup::Interval {
                        root: requested,
                        slice,
                    } = request.lookup
                    else {
                        panic!("the sealer asked for non-interval evidence");
                    };
                    assert_eq!(requested, root);
                    asked.lock().push(slice);
                    Some(respond(&EvidenceResponse::Served(Evidence::Interval(
                        ranges[&slice].clone(),
                    ))))
                });
            }

            // Sealer `b` starts from a fresh directory holding only the
            // genesis intervals, and its epoch-1 dealing earns a vote.
            let operator_key = PrivateKey::from_seed(9_910).public_key();
            let validator_key = PrivateKey::from_seed(9_911).public_key();
            let (mut operator_chan, validator_chan) = network(
                &context.child("b"),
                &operator_key,
                &validator_key,
                true,
                true,
            )
            .await;
            let (sealer_b, mailbox_b) = sealer_with(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                chain.db.clone(),
                "fetch-b",
                peer_entries(),
            );
            sealer_b.start(validator_chan);
            let (header, _, mine) = disseminate_at(
                &chain.protocol,
                &chain.prepared,
                1,
                &mut operator_chan,
                &validator_key,
            )
            .await;

            // One request per missing slice, each answered by its first
            // holder.
            let mut asked = asked.lock().clone();
            asked.sort_unstable();
            let expected = chain
                .spans
                .iter()
                .flat_map(|span| span.clone())
                .collect::<Vec<_>>();
            assert_eq!(asked, expected);

            // The fetched records equal the holders' byte for byte, both as
            // served and as retained, and the sealed dealing is durable.
            let configured = deployments().remove(0);
            let probe = intervals(
                context.child("interval_probe"),
                "fetch-b-intervals",
                &configured,
                &genesis_cache(&configured),
            )
            .await;
            for (slice, range) in &chain.ranges {
                let EvidenceResponse::Served(Evidence::Interval(fetched)) = evidence(
                    &mailbox_b,
                    EvidenceLookup::Interval {
                        root: chain.root,
                        slice: *slice,
                    },
                )
                .await
                else {
                    panic!("sealer b does not serve the fetched interval");
                };
                assert_eq!(fetched.encode(), range.encode());
                let record = probe
                    .get(Identifier::Key(&interval_key(&chain.root, *slice)))
                    .await
                    .unwrap()
                    .expect("the fetched interval is durable");
                assert_eq!(
                    record.encode(),
                    RetainedInterval {
                        root: chain.root,
                        slice: *slice,
                        range: range.clone(),
                    }
                    .encode()
                );
            }
            let store = store(context.child("store_probe"), "fetch-b", &deployment()).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing is durable");
            assert_eq!(sealed.epoch, 1);
            assert_eq!(sealed.slices, mine);
        });
    }

    /// When no holder serves a missing interval the dealing is skipped: every
    /// reachable co-holder is asked once per slice, nothing is retained, and
    /// no vote leaves the sealer.
    #[test]
    fn sealer_skips_a_dealing_no_holder_serves() {
        deterministic::Runner::default().start(|context| async move {
            let chain = Box::pin(two_epochs(&context, "declined")).await;
            let me = usize::from(dealt_participant(0).unwrap());

            // The first other member is unreachable, the rest answer with
            // routing advice.
            let asked: Arc<Mutex<BTreeMap<usize, Vec<u16>>>> = Arc::default();
            let others = (0..committee().unwrap().members().len())
                .filter(|index| *index != me)
                .collect::<Vec<_>>();
            for &index in &others[1..] {
                let asked = asked.clone();
                peer(&context, peer_address(index), move |request| {
                    let EvidenceLookup::Interval { slice, .. } = request.lookup else {
                        panic!("the sealer asked for non-interval evidence");
                    };
                    asked.lock().entry(index).or_default().push(slice);
                    Some(respond(&EvidenceResponse::Unsealed))
                });
            }

            let operator_key = PrivateKey::from_seed(9_920).public_key();
            let validator_key = PrivateKey::from_seed(9_921).public_key();
            let (mut operator_chan, validator_chan) = network(
                &context.child("b"),
                &operator_key,
                &validator_key,
                true,
                true,
            )
            .await;
            let (sealer_b, _mailbox_b) = sealer_with(
                &context,
                0,
                vec![(operator_key.clone(), deployments().remove(0))],
                chain.db.clone(),
                "declined-b",
                peer_entries(),
            );
            sealer_b.start(validator_chan);
            let slices = chain.protocol.slices(&chain.prepared).unwrap();
            let dealings = chain.protocol.dealings(&chain.prepared, &slices).unwrap();
            let header = chain.prepared.close().header;
            let dealing = Message::Dealing(Dealing {
                epoch: 1,
                header,
                roots: chain.prepared.close().roots,
                slices: dealings[me].clone(),
            });
            let sent = operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            assert_eq!(sent, vec![validator_key.clone()]);
            select! {
                _ = operator_chan.1.recv() => panic!("the sealer voted without the intervals"),
                _ = context.sleep(Duration::from_secs(30)) => {},
            }

            // Every reachable co-holder was asked exactly once for each slice
            // it co-holds.
            let asked = asked.lock().clone();
            for &index in &others[1..] {
                let mut slices = asked.get(&index).cloned().unwrap_or_default();
                slices.sort_unstable();
                assert_eq!(slices, co_held(&chain.spans, index));
            }

            // Neither the intervals nor the dealing became durable.
            let configured = deployments().remove(0);
            let probe = intervals(
                context.child("interval_probe"),
                "declined-b-intervals",
                &configured,
                &genesis_cache(&configured),
            )
            .await;
            for slice in chain.spans.iter().flat_map(|span| span.clone()) {
                assert_eq!(
                    probe
                        .get(Identifier::Key(&interval_key(&chain.root, slice)))
                        .await
                        .unwrap(),
                    None
                );
            }
            let store = store(context.child("store_probe"), "declined-b", &deployment()).await;
            assert_eq!(store.first_index(), None);
            let batch = header.batch_id::<Sha256>().into_digest();
            assert_eq!(store.get(Identifier::Key(&batch)).await.unwrap(), None);
        });
    }

    /// Every way a holder can fail to supply an interval is declined and the
    /// next holder is tried: a guard moved into the slice, a dropped member
    /// (tampered completeness), a range at another root, routing advice, an
    /// error response, garbage, an unreachable address, and a silent holder.
    /// The first verifiable range ends the fetch, and the holders after it
    /// are never asked.
    #[test]
    fn fetch_declines_every_tampered_or_unhelpful_holder() {
        deterministic::Runner::default().start(|context| async move {
            let configured = deployments().remove(0);
            let genesis = genesis_cache(&configured);
            let root = genesis.root();
            let span = 0..MAX_SLICES as u16;
            let ranges = slice_ranges(
                &genesis_range(&genesis),
                genesis.leaves(),
                &span,
                SLICE_BITS,
            )
            .unwrap();

            // A slice with members and a successor guard, so both tampering
            // kinds are expressible, and the same slice at another root.
            let (slice, range) = span
                .clone()
                .zip(ranges.iter())
                .find(|(_, range)| !range.members.is_empty() && range.successor.is_some())
                .expect("genesis fills a guarded slice");
            let range = range.clone();
            let mut altered = genesis.leaves().to_vec();
            altered[0].state.balance += 1;
            let altered = StateCache::new::<Sha256>(altered).unwrap();
            let foreign = slice_ranges(
                &genesis_range(&altered),
                altered.leaves(),
                &span,
                SLICE_BITS,
            )
            .unwrap()
            .swap_remove(usize::from(slice));
            let mut moved = range.clone();
            moved
                .members
                .push(moved.successor.take().expect("the slice has a guard"));
            let mut dropped = range.clone();
            dropped.members.pop();
            let interval = |range: &SliceRange| {
                respond(&EvidenceResponse::Served(Evidence::Interval(range.clone())))
            };

            // Holder scripts in try order: seven declining holders, then the
            // correct one, then one that must never be asked. Index 6 is
            // never bound.
            let scripts = [
                Some(interval(&moved)),
                Some(interval(&dropped)),
                Some(interval(&foreign)),
                Some(respond(&EvidenceResponse::Unsealed)),
                Some(rpc::error_response("evidence is not served".into())),
                Some(rpc::Response::Success {
                    body: Bytes::from_static(&[0xff]),
                }),
            ];
            for (index, script) in scripts.into_iter().enumerate() {
                peer(&context, peer_address(index), move |_| script.clone());
            }
            peer(&context, peer_address(7), |_| None);
            {
                let range = range.clone();
                peer(&context, peer_address(8), move |_| Some(interval(&range)));
            }
            let spare: Arc<Mutex<usize>> = Arc::default();
            {
                let spare = spare.clone();
                peer(&context, peer_address(9), move |_| {
                    *spare.lock() += 1;
                    Some(respond(&EvidenceResponse::Unsealed))
                });
            }
            let holders = (0..10).map(peer_address).collect::<Vec<_>>();

            // The peers bind once the runtime polls them.
            context.sleep(Duration::from_millis(1)).await;

            // The correct range is accepted unchanged after eight declines.
            let fetched = fetch_interval(
                &context,
                *configured.digest(),
                root,
                slice,
                SLICE_BITS,
                &holders,
                FETCH_TIMEOUT,
            )
            .await
            .expect("the last holder serves the slice");
            assert_eq!(fetched, range);
            assert_eq!(*spare.lock(), 0);

            // Without it, every holder's decline is reported in try order.
            let declines = fetch_interval(
                &context,
                *configured.digest(),
                root,
                slice,
                SLICE_BITS,
                &holders[..8],
                FETCH_TIMEOUT,
            )
            .await
            .expect_err("no holder serves the slice");
            assert_eq!(
                declines
                    .iter()
                    .map(|(holder, _)| *holder)
                    .collect::<Vec<_>>(),
                holders[..8]
            );
            let declines = declines
                .into_iter()
                .map(|(_, decline)| decline)
                .collect::<Vec<_>>();
            assert!(matches!(declines[0], Decline::Range(RangeError::Order)));
            assert!(matches!(
                declines[1],
                Decline::Range(RangeError::Opening(_))
            ));
            assert!(matches!(
                declines[2],
                Decline::Range(RangeError::Opening(_))
            ));
            assert!(matches!(
                &declines[3],
                Decline::Advice(advice) if **advice == EvidenceResponse::Unsealed
            ));
            assert!(matches!(declines[4], Decline::Refused(_)));
            assert!(matches!(declines[5], Decline::Garbage));
            assert!(matches!(declines[6], Decline::Failed(_)));
            assert!(matches!(declines[7], Decline::Timeout));
        });
    }

    /// The holders of a slice exclude the fetching validator, keep ascending
    /// participant order, rotate to the validator's own offset, and skip a
    /// participant genesis lists no address for.
    #[test]
    fn holders_exclude_self_and_rotate() {
        deterministic::Runner::default().start(|context| async move {
            let db = open(context.child("db"), "holders").await;
            let operator_key = PrivateKey::from_seed(9_930).public_key();
            let (sealer, _mailbox) = sealer_with(
                &context,
                0,
                vec![(operator_key, deployments().remove(0))],
                db,
                "holders",
                peer_entries(),
            );
            let committee = committee().unwrap();
            let assignment = Assignment::new(committee.commitment::<Sha256>(), SLICE_BITS).unwrap();
            let me = dealt_participant(0).unwrap();
            for slice in sealer.spans.iter().flat_map(|span| span.clone()) {
                let others = slice_holders::<Sha256, _>(&committee, &assignment, slice)
                    .unwrap()
                    .into_iter()
                    .filter(|holder| *holder != me)
                    .map(|holder| peer_address(usize::from(holder)))
                    .collect::<Vec<_>>();
                assert_eq!(others.len(), committee.quorum() - 1);
                let mut expected = others.clone();
                expected.rotate_left((usize::from(me) + usize::from(slice)) % others.len());
                assert_eq!(sealer.holders(&assignment, slice), expected);
            }

            // A slice this validator does not hold still names its holders,
            // and an address-less participant is skipped.
            let foreign = (0..MAX_SLICES as u16)
                .find(|slice| !sealer.spans.iter().any(|span| span.contains(slice)))
                .expect("a four-validator quorum of three leaves one slice unheld");
            assert_eq!(
                sealer.holders(&assignment, foreign).len(),
                committee.quorum()
            );
            let db = open(context.child("partial_db"), "holders-partial").await;
            let (partial, _mailbox) = sealer_with(
                &context,
                0,
                vec![(
                    PrivateKey::from_seed(9_931).public_key(),
                    deployments().remove(0),
                )],
                db,
                "holders-partial",
                peer_entries().into_iter().take(1).collect(),
            );
            let listed = partial.holders(&assignment, foreign);
            assert!(listed.len() <= 1);
        });
    }
}
