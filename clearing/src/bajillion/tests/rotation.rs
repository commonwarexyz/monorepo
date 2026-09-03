//! Committee rotation without the settlement chain.
//!
//! The incoming committee's validators fetch the retained intervals they lack from the
//! outgoing committee's holders over a codec-framed request and response exchange, verify
//! every answer under the successor root the outgoing certificate committed, and seal the
//! next epoch's dealing themselves. `committee_rotation_hands_over_intervals_between_groups`
//! is the code that shows a committee change is possible with dealing alone. The two
//! `committee_rotation_*_slices_*` tests show the repair when the committee size, and with it
//! the slice count, changes: a verified coarser slice is narrowed to the finer slices it
//! covers, and two verified adjacent slices are merged into the slice they halve.

use super::*;
use crate::bajillion::{
    admission::{
        AdmissionError, Committee, SealedDealing, assigned_slice_spans, bls12381, seal,
        slice_holders,
    },
    commitment::VectorRoot,
    retained::decode_dealt_slice_bounded,
    serve::{SliceInterval, merge_intervals, narrow_interval, slice_interval, verified_interval},
    transition::{MAX_SLICE_BITS, OperatorVariant, StateRange},
};
use alloc::collections::{BTreeMap, BTreeSet};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Decode, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_utils::Participant;
use core::{cmp::Ordering, num::NonZeroU64, ops::Range};
use thiserror::Error;

/// Eight slices, so each validator of a four-member committee holds six.
const SLICE_BITS: u8 = 3;
/// Key seeds of the outgoing committee's validators.
const OUTGOING: [u64; 4] = [1_001, 1_002, 1_003, 1_004];
/// Key seeds of the two validators that join the incoming committee.
const JOINING: [u64; 2] = [1_005, 1_006];
/// Outgoing positions that leave the committee.
const LEAVING: [Participant; 2] = [Participant::new(0), Participant::new(2)];
/// The outgoing holder that answers one member short. Position 0 is asked first for six of
/// the eight slices, so its answers are the ones the incoming committee must catch.
const BYZANTINE: Participant = Participant::new(0);
/// Key seeds of the seven-member committee the four `OUTGOING` validators grow into.
const GROWN: [u64; 7] = [1_001, 1_002, 1_003, 1_004, 1_005, 1_006, 1_007];
/// Key seeds of the four-member committee `GROWN` shrinks to: three continuing, one joining.
const SHRUNK: [u64; 4] = [1_002, 1_004, 1_006, 1_008];

fn validator(seed: u64) -> BlsPrivate {
    BlsPrivate::new(Scalar::from(seed))
}

/// Builds a committee from validator keys with one signing scheme per member, in participant
/// order.
fn committee(keys: &[BlsPrivate]) -> (Committee, Vec<bls12381::Scheme>) {
    let committee = Committee::new(keys.iter().map(compute_public::<MinSig>).collect()).unwrap();
    let mut schemes = keys
        .iter()
        .map(|key| bls12381::Scheme::signer(committee.clone(), key.clone()).unwrap())
        .collect::<Vec<_>>();
    schemes.sort_by_key(|scheme| scheme.me().unwrap());
    (committee, schemes)
}

/// Accounts from seeds, key-sorted.
fn accounts(seeds: impl Iterator<Item = u64>) -> Vec<(VerifyingKey, SigningKey)> {
    let mut accounts = seeds
        .map(|seed| {
            let private = SigningKey::from_seed(seed);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    accounts
}

/// One close's activity, by index into a key table.
struct Activity {
    /// Payers and the accounts each pays one unit.
    sends: Vec<(usize, Vec<usize>)>,
    /// Deposited accounts and amounts.
    deposits: Vec<(usize, u64)>,
    /// Withdrawing accounts and actions.
    withdrawals: Vec<(usize, WithdrawalAction)>,
}

/// Prepares one close at `epoch` under `assignment` from the live `leaves`, applying
/// `activity` over `keys`, the key-sorted table of every account that may appear.
fn close_under(
    epoch: u64,
    assignment: Assignment<ShaDigest>,
    keys: &[(VerifyingKey, SigningKey)],
    leaves: Vec<StateLeaf<VerifyingKey>>,
    activity: &Activity,
) -> Fixture {
    assert!(keys.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let operator_bls_private = BlsPrivate::new(Scalar::from(OPERATOR_SEED));
    let operator_bls = compute_public::<OperatorVariant>(&operator_bls_private);
    let deployment = Sha256::hash(&[b"close-test-deployment"]);
    let cache = StateCache::new::<Sha256>(leaves).unwrap();
    let deposits = DepositBatch::new(
        activity
            .deposits
            .iter()
            .map(|(account, amount)| DepositRecord::new(keys[*account].0.clone(), *amount).unwrap())
            .collect(),
    )
    .unwrap();
    let withdrawals = WithdrawalBatch::new(
        activity
            .withdrawals
            .iter()
            .map(|(account, action)| {
                SignedWithdrawal::sign(
                    deployment,
                    cache.root().digest,
                    Bytes::from_static(b"destination"),
                    *action,
                    99,
                    &keys[*account].1,
                )
            })
            .collect(),
    )
    .unwrap();
    let context = EpochContext::new::<Sha256>(
        deployment,
        epoch,
        operator.public_key(),
        &deposits,
        &withdrawals,
        cache.liability(),
        98,
        99,
        CloseLimits::protocol_maximum(),
        assignment,
    )
    .and_then(|context| context.bind::<Sha256>(&cache, &deposits, &withdrawals))
    .unwrap();

    let mut vectors = BTreeMap::new();
    let mut incoming: BTreeMap<VerifyingKey, Vec<TransposeEntry<VerifyingKey>>> = BTreeMap::new();
    for (payer, recipients) in &activity.sends {
        let payer = &keys[*payer].0;
        let mut entries = recipients
            .iter()
            .map(|recipient| OutEntry {
                recipient: keys[*recipient].0.clone(),
                cumulative: 1,
                count: 1,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        for entry in &entries {
            assert_ne!(entry.recipient, *payer, "no self payments");
            incoming
                .entry(entry.recipient.clone())
                .or_default()
                .push(TransposeEntry {
                    recipient: entry.recipient.clone(),
                    payer: payer.clone(),
                    cumulative: entry.cumulative,
                    count: entry.count,
                });
        }
        vectors.insert(
            payer.clone(),
            OutVector::new(epoch, payer.clone(), entries).unwrap(),
        );
    }

    let mut transpose = Vec::new();
    let mut rows = Vec::new();
    let mut out_vectors = Vec::new();
    let mut acks = Vec::new();
    let mut operator_signatures = Vec::new();
    let mut prefix = Prefix::default();
    for (public, private) in keys {
        let predecessor = cache
            .leaves()
            .binary_search_by(|leaf| leaf.account.cmp(public))
            .map(|position| cache.leaves()[position].state)
            .unwrap_or_default();
        let vector = vectors.remove(public);
        let mut group = incoming.remove(public).unwrap_or_default();
        group.sort_unstable_by(|left, right| left.payer.cmp(&right.payer));
        let deposit = deposits.amount_for(public);
        let withdrawal = withdrawals.request_for(public).is_some();
        if vector.is_none() && group.is_empty() && deposit == 0 && !withdrawal {
            continue;
        }
        let credit = group.iter().map(|entry| entry.cumulative).sum::<u64>();
        let receipts = group.iter().map(|entry| entry.count).sum::<u64>();
        let vector = vector.unwrap_or_else(|| OutVector::empty(epoch, public.clone()));
        let (successor, output) = derive_successor(
            public,
            &predecessor,
            &deposits,
            &withdrawals,
            &vector,
            credit,
            receipts,
        )
        .unwrap();
        let outgoing = if vector.entries().is_empty() {
            operator_signatures.push(None);
            None
        } else {
            let body = VectorSendBody::new(
                context.payment(),
                public.clone(),
                0,
                successor.cumulative_debit,
                vector.root::<Sha256, ShaDigest>().unwrap(),
            );
            let ack = VectorAck::sign_by_authorities(body, private, &operator);
            operator_signatures.push(Some(bls_ack(&operator_bls_private, ack.body())));
            let send = SendAuthorization::from_raw_unchecked(
                ack.body().clone(),
                ack.payer_signature().clone(),
            );
            acks.push(ack);
            Some(send)
        };
        let mut row = AccountRow {
            account: public.clone(),
            predecessor,
            successor,
            outgoing,
            output,
            prefix: Prefix::default(),
        };
        let delta =
            validate_row::<Sha256, _, _>(&context, &deposits, &withdrawals, &row, &vector, &group)
                .unwrap();
        prefix = prefix.checked_extend(delta).unwrap();
        row.prefix = prefix;
        rows.push(row);
        out_vectors.push(vector);
        transpose.extend(group);
    }
    let out_partials = out_vectors
        .iter()
        .map(OutVector::accumulator)
        .collect::<Vec<_>>();
    let prepared = prepare_close_with_strategy::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        rows,
        out_vectors,
        &out_partials,
        &operator_signatures,
        transpose,
        &Sequential,
    )
    .unwrap();
    Fixture {
        cache,
        context,
        deposits,
        withdrawals,
        prepared,
        accounts: keys.to_vec(),
        acks,
        operator,
        operator_bls_private,
        operator_bls,
    }
}

/// Epoch `e`'s close under `assignment`: 24 live accounts and four fresh ones, ten senders,
/// deposits creating three accounts, closes deleting three, one partial withdrawal, and one
/// payout to a fresh account that never becomes live. Returns the key-sorted table of every
/// account with the close.
fn epoch_close(assignment: Assignment<ShaDigest>) -> (Vec<(VerifyingKey, SigningKey)>, Fixture) {
    let live = accounts((0..24).map(|index| ACCOUNT_SEED_START + index));
    let fresh = accounts((0..4).map(|index| ACCOUNT_SEED_START + 1_000 + index));
    let keys = accounts(
        (0..24)
            .chain(1_000..1_004)
            .map(|index| ACCOUNT_SEED_START + index),
    );
    let at = |public: &VerifyingKey| keys.binary_search_by(|(key, _)| key.cmp(public)).unwrap();
    let recipients = live[..6]
        .iter()
        .chain([&fresh[2], &fresh[3]])
        .map(|(public, _)| at(public))
        .collect::<Vec<_>>();
    let opening = AccountState {
        balance: OPENING_BALANCE,
        active: true,
        ..AccountState::default()
    };
    let first = close_under(
        EPOCH,
        assignment,
        &keys,
        live.iter()
            .map(|(public, _)| StateLeaf {
                account: public.clone(),
                state: opening,
            })
            .collect(),
        &Activity {
            sends: (0..10)
                .map(|payer| {
                    let paid = (1..=2)
                        .map(|offset| recipients[(payer + offset) % recipients.len()])
                        .collect();
                    (at(&live[payer].0), paid)
                })
                .collect(),
            deposits: vec![
                (at(&fresh[0].0), 50),
                (at(&fresh[1].0), 70),
                (at(&fresh[2].0), 20),
                (at(&live[16].0), 10),
            ],
            withdrawals: vec![
                (at(&live[12].0), WithdrawalAction::Close),
                (at(&live[13].0), WithdrawalAction::Close),
                (at(&live[5].0), WithdrawalAction::Close),
                (
                    at(&live[15].0),
                    WithdrawalAction::Amount(NonZeroU64::new(30).unwrap()),
                ),
            ],
        },
    );
    let close_e = first.prepared.close();
    let created = close_e
        .rows
        .iter()
        .filter(|row| !row.predecessor.active && row.successor.active)
        .count();
    let deleted = close_e
        .rows
        .iter()
        .filter(|row| row.predecessor.active && !row.successor.active)
        .count();
    assert_eq!((created, deleted), (3, 3));
    assert!(!close_e.unchanged.is_empty());
    (keys, first)
}

/// The next epoch's close at `epoch` under `assignment` from the live `successor` state:
/// eight of the first ten live accounts each pay the next two, with no deposits or
/// withdrawals.
fn next_close(
    epoch: u64,
    assignment: Assignment<ShaDigest>,
    keys: &[(VerifyingKey, SigningKey)],
    successor: Vec<StateLeaf<VerifyingKey>>,
) -> Fixture {
    let at = |public: &VerifyingKey| keys.binary_search_by(|(key, _)| key.cmp(public)).unwrap();
    let live_after = successor
        .iter()
        .map(|leaf| at(&leaf.account))
        .collect::<Vec<_>>();
    close_under(
        epoch,
        assignment,
        keys,
        successor,
        &Activity {
            sends: (0..8)
                .map(|payer| {
                    let paid = vec![live_after[(payer + 1) % 10], live_after[(payer + 2) % 10]];
                    (live_after[payer], paid)
                })
                .collect(),
            deposits: Vec::new(),
            withdrawals: Vec::new(),
        },
    )
}

/// The whole successor state of a close, key-sorted.
fn successor_leaves(fixture: &Fixture) -> Vec<StateLeaf<VerifyingKey>> {
    successor_intervals(fixture)
        .iter()
        .flat_map(|interval| interval.leaves().iter().cloned())
        .collect()
}

/// The whole successor state of a close as its vector tree, for byte-for-byte comparison.
fn successor_tree(
    fixture: &Fixture,
) -> (Vec<StateLeaf<VerifyingKey>>, commitment::Tree<ShaDigest>) {
    let leaves = successor_leaves(fixture);
    let mut builder =
        commitment::Builder::<Sha256>::new(VectorKind::State, leaves.len() as u32).unwrap();
    builder.add_values(&leaves, &Sequential).unwrap();
    let tree = builder.build(&Sequential).unwrap();
    assert_eq!(tree.root(), fixture.prepared.close().roots.successor);
    (leaves, tree)
}

/// What the whole successor tree opens for `span`: its members bracketed by the neighbors
/// that exist.
fn whole_span(
    leaves: &[StateLeaf<VerifyingKey>],
    tree: &commitment::Tree<ShaDigest>,
    span: &Range<u16>,
    slice_bits: u8,
) -> SliceInterval<VerifyingKey, ShaDigest> {
    let slice_of =
        |leaf: &StateLeaf<VerifyingKey>| account_slice(&leaf.account, slice_bits).unwrap();
    let start = leaves.partition_point(|leaf| slice_of(leaf) < span.start);
    let end = leaves.partition_point(|leaf| slice_of(leaf) < span.end);
    let predecessor = start
        .checked_sub(1)
        .map(|previous| leaves[previous].clone());
    let successor = leaves.get(end).cloned();
    let first = start - usize::from(predecessor.is_some());
    let count = end - first + usize::from(successor.is_some());
    SliceInterval {
        members: leaves[start..end].to_vec(),
        range: StateRange {
            predecessor,
            successor,
            opening: tree.range_opening(first as u32, count as u32).unwrap(),
        },
    }
}

#[test]
fn slice_interval_matches_whole_tree_openings() {
    // A dense close with created and deleted accounts, then a sparse one with empty slices.
    for (fixture, sparse) in [
        (churn_fixture(), false),
        (fixture_with(EPOCH, 6, 3, 3, 2, None), true),
    ] {
        let slice_bits = fixture.context.assignment().slice_bits();
        let slice_count = 1_u16 << slice_bits;
        let (leaves, tree) = successor_tree(&fixture);
        let expected = successor_intervals(&fixture);
        assert_eq!(
            sparse,
            expected.iter().any(|interval| interval.leaves().is_empty())
        );
        let root = &fixture.prepared.close().roots.successor;
        let split = slice_count / 2 + 1;
        let whole = 0..slice_count;
        let shapes = [
            single_spans(slice_bits),
            vec![split..slice_count, 0..split],
            vec![whole],
        ];
        for spans in &shapes {
            let slices = fixture
                .prepared
                .assemble_slices(&fixture.cache, spans, &Sequential)
                .unwrap();
            for slice in &slices {
                for index in slice.span.clone() {
                    // The holder's answer is the whole tree's bracket for the slice, and the
                    // receiver reconstructs exactly the interval the holder advanced.
                    let served = slice_interval::<Sha256, _, _>(slice, index, slice_bits).unwrap();
                    assert_eq!(
                        served,
                        whole_span(&leaves, &tree, &(index..index + 1), slice_bits)
                    );
                    let verified =
                        verified_interval::<Sha256, _, _>(&served, root, index, slice_bits)
                            .unwrap();
                    assert_eq!(verified, expected[usize::from(index)]);
                }
                if let Some(outside) = (0..slice_count).find(|index| !slice.span.contains(index)) {
                    assert!(matches!(
                        slice_interval::<Sha256, _, _>(slice, outside, slice_bits),
                        Err(ServeError::NotHeld { slice }) if slice == outside
                    ));
                }
            }
        }
    }
}

#[test]
fn verified_interval_rejects_tampered_dropped_foreign_and_wrong_root() {
    let fixture = churn_fixture();
    let slice_bits = fixture.context.assignment().slice_bits();
    let close = fixture.prepared.close();
    let root = &close.roots.successor;
    let (leaves, tree) = successor_tree(&fixture);
    let slice_of =
        |leaf: &StateLeaf<VerifyingKey>| account_slice(&leaf.account, slice_bits).unwrap();
    let verify = |interval: &SliceInterval<VerifyingKey, ShaDigest>, root, index, bits| {
        verified_interval::<Sha256, _, _>(interval, root, index, bits)
    };

    // A populated slice with a neighbor on each side.
    let index = slice_of(&leaves[leaves.len() / 2]);
    let honest = whole_span(&leaves, &tree, &(index..index + 1), slice_bits);
    let (Some(before), Some(after)) = (&honest.range.predecessor, &honest.range.successor) else {
        panic!("fixture slice is not interior");
    };
    assert!(!honest.members.is_empty());
    verify(&honest, root, index, slice_bits).unwrap();

    // A tampered member and a dropped member both miss the root.
    let mut tampered = honest.clone();
    tampered.members[0].state.balance += 1;
    assert!(matches!(
        verify(&tampered, root, index, slice_bits),
        Err(ServeError::Commitment(_))
    ));
    let mut dropped = honest.clone();
    dropped.members.pop();
    assert!(matches!(
        verify(&dropped, root, index, slice_bits),
        Err(ServeError::Commitment(_))
    ));

    // A valid opening over this slice and its higher neighbor is not either slice's live set,
    // and an honest interval is not the neighbor's.
    let neighbor = slice_of(after);
    let foreign = whole_span(&leaves, &tree, &(index..neighbor + 1), slice_bits);
    assert!(matches!(
        verify(&foreign, root, index, slice_bits),
        Err(ServeError::Range)
    ));
    assert!(matches!(
        verify(&foreign, root, neighbor, slice_bits),
        Err(ServeError::Range)
    ));
    assert!(matches!(
        verify(&honest, root, neighbor, slice_bits),
        Err(ServeError::Range)
    ));

    // A valid empty bracket between two leaves below the slice does not prove it empty: both
    // neighbors must straddle the slice.
    let position = leaves
        .iter()
        .position(|leaf| leaf == before)
        .expect("neighbor is a leaf");
    assert!(position >= 1, "fixture slice has two lower leaves");
    let trap = SliceInterval {
        members: Vec::new(),
        range: StateRange {
            predecessor: Some(leaves[position - 1].clone()),
            successor: Some(before.clone()),
            opening: tree.range_opening((position - 1) as u32, 2).unwrap(),
        },
    };
    assert!(matches!(
        verify(&trap, root, index, slice_bits),
        Err(ServeError::Range)
    ));

    // A root the opening cannot reproduce, and a slice outside the partition.
    assert!(matches!(
        verify(&honest, &close.roots.change, index, slice_bits),
        Err(ServeError::Commitment(_))
    ));
    assert!(matches!(
        verify(
            &honest,
            fixture.context.predecessor_root(),
            index,
            slice_bits
        ),
        Err(ServeError::Commitment(_))
    ));
    assert!(matches!(
        verify(&honest, root, 1 << slice_bits, slice_bits),
        Err(ServeError::Transition(CloseError::SliceIndex))
    ));
    assert!(matches!(
        verify(&honest, root, index, 9),
        Err(ServeError::Transition(CloseError::SliceBits))
    ));
}

#[test]
fn narrowed_and_merged_intervals_match_whole_state_and_broken_seams_are_rejected() {
    // A dense close, then a sparse one with empty slices, both under three bits and re-sliced
    // to two bits and back.
    for fixture in [churn_fixture(), fixture_with(EPOCH, 6, 3, 3, 2, None)] {
        let fine_bits = fixture.context.assignment().slice_bits();
        let coarse_bits = fine_bits - 1;
        let (leaves, tree) = successor_tree(&fixture);
        let fine = intervals_of(&leaves, fine_bits);
        let coarse = intervals_of(&leaves, coarse_bits);
        let mut populated = 0;
        for (index, expected) in coarse.iter().enumerate() {
            let slice = index as u16;
            let lower = slice << 1;
            let merge = |first: &SliceInterval<VerifyingKey, ShaDigest>,
                         second: &SliceInterval<VerifyingKey, ShaDigest>| {
                merge_intervals(first, second, slice, coarse_bits)
            };

            // Narrowing the coarse slice yields each half's whole-state interval, and merging
            // the halves as the whole tree serves them yields the coarse slice back.
            for half in [lower, lower + 1] {
                assert_eq!(
                    narrow_interval(expected, half, fine_bits).unwrap(),
                    fine[usize::from(half)]
                );
            }
            let first = whole_span(&leaves, &tree, &(lower..lower + 1), fine_bits);
            let second = whole_span(&leaves, &tree, &(lower + 1..lower + 2), fine_bits);
            assert_eq!(merge(&first, &second).unwrap(), *expected);
            if first.members.is_empty() && second.members.is_empty() {
                continue;
            }
            populated += 1;

            // Swapped halves carry the wrong prefixes.
            assert!(matches!(merge(&second, &first), Err(ServeError::Range)));

            // A member dropped on either side of the seam, or a guard that no longer names
            // the other half's first leaf, breaks the seam.
            if let Some((_, rest)) = first.members.split_last() {
                let mut dropped = first.clone();
                dropped.members = rest.to_vec();
                assert!(matches!(merge(&dropped, &second), Err(ServeError::Range)));
            }
            if !second.members.is_empty() {
                let mut dropped = second.clone();
                dropped.members.remove(0);
                assert!(matches!(merge(&first, &dropped), Err(ServeError::Range)));
                let mut unguarded = first.clone();
                unguarded.range.successor = None;
                assert!(matches!(merge(&unguarded, &second), Err(ServeError::Range)));
            }

            // A populated slice other than the adjacent half is not the pair's other half.
            let other = (0..1_u16 << fine_bits)
                .filter(|other| !(lower..lower + 2).contains(other))
                .find(|other| !fine[usize::from(*other)].leaves().is_empty());
            if let Some(other) = other {
                let foreign = whole_span(&leaves, &tree, &(other..other + 1), fine_bits);
                assert!(matches!(merge(&first, &foreign), Err(ServeError::Range)));
                assert!(matches!(merge(&foreign, &second), Err(ServeError::Range)));
            }
        }
        assert!(populated > 0);

        // Slices outside the partition.
        assert!(matches!(
            narrow_interval(&coarse[0], 0, MAX_SLICE_BITS + 1),
            Err(ServeError::Transition(CloseError::SliceBits))
        ));
        assert!(matches!(
            narrow_interval(&coarse[0], 1 << fine_bits, fine_bits),
            Err(ServeError::Transition(CloseError::SliceIndex))
        ));
        let first = whole_span(&leaves, &tree, &(0..1), fine_bits);
        let second = whole_span(&leaves, &tree, &(1..2), fine_bits);
        assert!(matches!(
            merge_intervals(&first, &second, 0, MAX_SLICE_BITS),
            Err(ServeError::Transition(CloseError::SliceBits))
        ));
        assert!(matches!(
            merge_intervals(&first, &second, 1 << coarse_bits, coarse_bits),
            Err(ServeError::Transition(CloseError::SliceIndex))
        ));
    }
}

/// What an incoming validator asks an outgoing holder.
#[derive(Debug, Eq, PartialEq)]
enum Request {
    /// The live leaves of `slice` at the successor root `root` the holder certified.
    Interval {
        root: VectorRoot<ShaDigest>,
        slice: u16,
    },
}

impl Write for Request {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Interval { root, slice } => {
                0_u8.write(writer);
                root.write(writer);
                slice.write(writer);
            }
        }
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        match self {
            Self::Interval { root, slice } => u8::SIZE + root.encode_size() + slice.encode_size(),
        }
    }
}

impl Read for Request {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Interval {
                root: VectorRoot::read(reader)?,
                slice: u16::read(reader)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// What an outgoing holder answers.
#[derive(Debug, Eq, PartialEq)]
enum Response {
    /// The slice's exact live set under the requested root.
    Interval(Box<SliceInterval<VerifyingKey, ShaDigest>>),
    /// The holder does not serve the slice.
    NotHolder,
    /// The holder certified no close with that successor root.
    Unknown,
}

impl Write for Response {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Interval(interval) => {
                0_u8.write(writer);
                interval.members.write(writer);
                interval.range.predecessor.write(writer);
                interval.range.successor.write(writer);
                interval.range.opening.write(writer);
            }
            Self::NotHolder => 1_u8.write(writer),
            Self::Unknown => 2_u8.write(writer),
        }
    }
}

impl EncodeSize for Response {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Interval(interval) => {
                    interval.members.encode_size()
                        + interval.range.predecessor.encode_size()
                        + interval.range.successor.encode_size()
                        + interval.range.opening.encode_size()
                }
                Self::NotHolder | Self::Unknown => 0,
            }
    }
}

impl Read for Response {
    /// Most members one slice may hold and most proof hashes one opening may carry.
    type Cfg = (usize, usize);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (max_members, max_hashes) = *cfg;
        match u8::read(reader)? {
            0 => {
                let members = Vec::<StateLeaf<VerifyingKey>>::read_cfg(
                    reader,
                    &(RangeCfg::new(..=max_members), ()),
                )?;
                let range = StateRange::read_bounded(reader, members.len(), max_hashes)?;
                Ok(Self::Interval(Box::new(SliceInterval { members, range })))
            }
            1 => Ok(Self::NotHolder),
            2 => Ok(Self::Unknown),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// How a Byzantine holder answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    /// Every populated slice one member short.
    Short,
    /// With the interval of another slice it holds.
    Foreign,
}

/// An outgoing validator after sealing epoch `e`: the dealing it certified and the per-slice
/// intervals it advanced, which it serves to the incoming committee.
struct Holder {
    sealed: SealedDealing<VerifyingKey, ShaDigest>,
    /// Slice bits of the assignment it sealed under.
    slice_bits: u8,
    intervals: BTreeMap<u16, Interval<VerifyingKey>>,
    /// How it answers wrongly, when it does.
    fault: Option<Fault>,
    /// Slices this holder no longer serves.
    pruned: BTreeSet<u16>,
}

impl Holder {
    /// Seals the close of `fixture` as validator `scheme` and advances the predecessor
    /// intervals of its spans.
    fn seal(
        scheme: &bls12381::Scheme,
        fixture: &Fixture,
        predecessor: &[Interval<VerifyingKey>],
        seed: u64,
    ) -> (bls12381::Vote, Self) {
        let close = fixture.prepared.close();
        let slice_bits = fixture.context.assignment().slice_bits();
        let spans = assigned_slice_spans::<Sha256, _>(
            scheme.committee(),
            fixture.context.assignment(),
            scheme.me().unwrap(),
        )
        .unwrap();
        let slices = fixture
            .prepared
            .assemble_slices(&fixture.cache, &spans, &Sequential)
            .unwrap();
        let (vote, sealed) = seal::<Sha256, _, _, AckBatchVerifier, _>(
            scheme,
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            slices,
            &mut TestRng::new(seed),
            &Sequential,
        )
        .unwrap();
        let mut intervals = BTreeMap::new();
        for slice in sealed.slices() {
            let mut interval = span_interval(predecessor, &slice.span);
            interval.advance(slice);
            intervals.extend(split(&interval, &slice.span, slice_bits));
        }
        (
            vote,
            Self {
                sealed,
                slice_bits,
                intervals,
                fault: None,
                pruned: BTreeSet::new(),
            },
        )
    }

    /// Answers one request.
    fn answer(&self, request: &Request) -> Response {
        let Request::Interval { root, slice } = request;
        if *root != self.sealed.roots().successor {
            return Response::Unknown;
        }
        if self.pruned.contains(slice) {
            return Response::NotHolder;
        }
        let Some(proof) = self.sealed.serve(*slice) else {
            return Response::NotHolder;
        };
        let mut interval = slice_interval::<Sha256, _, _>(proof, *slice, self.slice_bits).unwrap();
        match self.fault {
            Some(Fault::Short) if !interval.members.is_empty() => {
                interval.members.remove(0);
            }
            Some(Fault::Foreign) => {
                let other = self
                    .sealed
                    .slices()
                    .iter()
                    .flat_map(|held| held.span.clone())
                    .find(|held| held != slice)
                    .expect("holder has another slice");
                let proof = self.sealed.serve(other).expect("holder serves its slices");
                interval = slice_interval::<Sha256, _, _>(proof, other, self.slice_bits).unwrap();
            }
            _ => {}
        }
        Response::Interval(Box::new(interval))
    }
}

/// Splits one advanced span interval into per-slice intervals under `slice_bits`.
fn split(
    interval: &Interval<VerifyingKey>,
    span: &Range<u16>,
    slice_bits: u8,
) -> BTreeMap<u16, Interval<VerifyingKey>> {
    let mut buckets: BTreeMap<u16, Vec<StateLeaf<VerifyingKey>>> =
        span.clone().map(|slice| (slice, Vec::new())).collect();
    for leaf in interval.leaves() {
        let slice = account_slice(&leaf.account, slice_bits).unwrap();
        buckets
            .get_mut(&slice)
            .expect("advanced leaf left its span")
            .push(leaf.clone());
    }
    buckets
        .into_iter()
        .map(|(slice, leaves)| (slice, Interval::new(leaves).unwrap()))
        .collect()
}

/// Concatenates the retained per-slice intervals of `span`, or names the first slice missing.
fn joined(
    intervals: &BTreeMap<u16, Interval<VerifyingKey>>,
    span: &Range<u16>,
) -> Result<Interval<VerifyingKey>, u16> {
    let mut leaves = Vec::new();
    for slice in span.clone() {
        leaves.extend(intervals.get(&slice).ok_or(slice)?.leaves().iter().cloned());
    }
    Ok(Interval::new(leaves).unwrap())
}

/// Carries one request to a holder and its answer back, both as bytes.
fn exchange(
    holder: &Holder,
    request: &Request,
    max_members: usize,
) -> Result<Response, CodecError> {
    let request = Request::decode(request.encode())?;
    let response = holder.answer(&request);
    let encoded = response.encode();
    assert_eq!(encoded.len(), response.encode_size());

    // The receiver bounds the opening's hashes by the bytes it accepted.
    let decoded = Response::decode_cfg(
        encoded.clone(),
        &(max_members, encoded.len() / ShaDigest::SIZE),
    )?;
    assert_eq!(decoded, response, "wire must round-trip exactly");
    Ok(decoded)
}

/// What one incoming validator saw from the outgoing holders, by holder and outgoing slice.
#[derive(Debug, Default)]
struct Log {
    /// Answers that verified.
    served: Vec<(Participant, u16)>,
    /// Answers that failed verification.
    rejected: Vec<(Participant, u16, ServeError)>,
    /// Holders that declined a slice or answered unusably.
    declined: Vec<(Participant, u16)>,
}

impl Log {
    /// Appends what another fetch saw.
    fn extend(&mut self, other: Self) {
        self.served.extend(other.served);
        self.rejected.extend(other.rejected);
        self.declined.extend(other.declined);
    }
}

/// Asks the outgoing holders of `slice` in holder order and returns the first answer that
/// verifies under `root` with the interval it proves, logging every answer.
fn fetch_slice(
    holders: &[Holder],
    outgoing: &Committee,
    assignment: &Assignment<ShaDigest>,
    root: &VectorRoot<ShaDigest>,
    slice: u16,
    max_members: usize,
    log: &mut Log,
) -> Option<(
    SliceInterval<VerifyingKey, ShaDigest>,
    Interval<VerifyingKey>,
)> {
    let request = Request::Interval { root: *root, slice };
    for holder in slice_holders::<Sha256, _>(outgoing, assignment, slice).unwrap() {
        let Ok(response) = exchange(&holders[usize::from(holder)], &request, max_members) else {
            log.declined.push((holder, slice));
            continue;
        };
        match response {
            Response::Interval(interval) => {
                match verified_interval::<Sha256, _, _>(
                    &interval,
                    root,
                    slice,
                    assignment.slice_bits(),
                ) {
                    Ok(verified) => {
                        log.served.push((holder, slice));
                        return Some((*interval, verified));
                    }
                    Err(error) => log.rejected.push((holder, slice, error)),
                }
            }
            Response::NotHolder | Response::Unknown => log.declined.push((holder, slice)),
        }
    }
    None
}

/// Why an incoming validator did not seal.
#[derive(Debug, Error)]
enum HandoffError {
    /// No outgoing holder served the slice, so its span cannot be hydrated.
    #[error("no holder served slice {0}")]
    Unserved(u16),
    /// The dealt span did not decode or hydrate against the retained intervals.
    #[error("dealt span did not hydrate: {0}")]
    Hydrate(CodecError),
    /// The hydrated dealing did not seal.
    #[error("dealing did not seal: {0}")]
    Seal(AdmissionError),
}

/// An incoming validator: its signer under the incoming committee, the spans it must retain
/// there, and the per-slice intervals it kept from the outgoing committee or fetched.
struct Joiner {
    scheme: bls12381::Scheme,
    spans: Vec<Range<u16>>,
    /// Slice bits of the incoming assignment.
    slice_bits: u8,
    intervals: BTreeMap<u16, Interval<VerifyingKey>>,
}

impl Joiner {
    /// An incoming validator under `assignment` retaining `retained`, the per-slice intervals
    /// it validated under `retained_bits`, re-sliced to the incoming partition: each is
    /// narrowed to the two slices it covers when the partition doubles, and two retained
    /// halves join into the slice they halve when it halves.
    fn new(
        scheme: bls12381::Scheme,
        assignment: &Assignment<ShaDigest>,
        retained: BTreeMap<u16, Interval<VerifyingKey>>,
        retained_bits: u8,
    ) -> Self {
        let spans =
            assigned_slice_spans::<Sha256, _>(scheme.committee(), assignment, scheme.me().unwrap())
                .unwrap();
        let slice_bits = assignment.slice_bits();
        assert!(
            slice_bits.abs_diff(retained_bits) <= 1,
            "the slice count changes by one bit per rotation"
        );
        let intervals = match slice_bits.cmp(&retained_bits) {
            Ordering::Equal => retained,
            Ordering::Greater => retained
                .iter()
                .flat_map(|(coarse, interval)| {
                    [coarse << 1, (coarse << 1) + 1]
                        .map(|fine| (fine, narrow_interval(interval, fine, slice_bits).unwrap()))
                })
                .collect(),

            // Both halves are this validator's own validated live sets, so their union is
            // the merged slice's.
            Ordering::Less => retained
                .iter()
                .filter(|(lower, _)| *lower % 2 == 0)
                .filter_map(|(lower, first)| {
                    let second = retained.get(&(lower + 1))?;
                    let leaves = first
                        .leaves()
                        .iter()
                        .chain(second.leaves())
                        .cloned()
                        .collect();
                    Some((lower >> 1, Interval::new(leaves).unwrap()))
                })
                .collect(),
        };
        Self {
            scheme,
            spans,
            slice_bits,
            intervals,
        }
    }

    fn me(&self) -> Participant {
        self.scheme.me().unwrap()
    }

    /// The slices of this validator's spans it does not retain yet.
    fn lacking(&self) -> Vec<u16> {
        self.spans
            .iter()
            .flat_map(Clone::clone)
            .filter(|slice| !self.intervals.contains_key(slice))
            .collect()
    }

    /// Fetches every lacking slice from the outgoing holders in holder order, keeping the
    /// first answer that verifies under `root`, and repairs across a slice count change: when
    /// the outgoing partition is one bit coarser, the outgoing slice covering a lacking slice
    /// is fetched once and narrowed to both slices it covers, and when it is one bit finer, a
    /// lacking slice's two halves are fetched from their own holders and merged.
    fn fetch(
        &mut self,
        holders: &[Holder],
        outgoing: &Committee,
        assignment: &Assignment<ShaDigest>,
        root: &VectorRoot<ShaDigest>,
        max_members: usize,
    ) -> Log {
        let mut log = Log::default();
        let fetch = |slice, log: &mut Log| {
            fetch_slice(holders, outgoing, assignment, root, slice, max_members, log)
        };
        for slice in self.lacking() {
            if self.intervals.contains_key(&slice) {
                // Narrowing the outgoing slice covering it filled this one already.
                continue;
            }
            match self.slice_bits.cmp(&assignment.slice_bits()) {
                Ordering::Equal => {
                    if let Some((_, interval)) = fetch(slice, &mut log) {
                        self.intervals.insert(slice, interval);
                    }
                }
                Ordering::Greater => {
                    let coarse = slice >> 1;
                    if let Some((_, interval)) = fetch(coarse, &mut log) {
                        for fine in [coarse << 1, (coarse << 1) + 1] {
                            let narrowed = narrow_interval(&interval, fine, self.slice_bits);
                            self.intervals.insert(fine, narrowed.unwrap());
                        }
                    }
                }
                Ordering::Less => {
                    let lower = slice << 1;
                    let Some((first, _)) = fetch(lower, &mut log) else {
                        continue;
                    };
                    let Some((second, _)) = fetch(lower + 1, &mut log) else {
                        continue;
                    };

                    // Both halves verified under `root`, so their seam is proven consistent.
                    let merged = merge_intervals(&first, &second, slice, self.slice_bits)
                        .expect("verified halves meet at their seam");
                    self.intervals.insert(slice, merged);
                }
            }
        }
        log
    }

    /// Hydrates the dealt spans of `fixture` against the retained intervals, seals them, and
    /// advances the intervals.
    fn seal(
        &mut self,
        fixture: &Fixture,
        dealt: &[Bytes],
        seed: u64,
    ) -> Result<bls12381::Vote, HandoffError> {
        let context = &fixture.context;
        let close = fixture.prepared.close();
        let mut intervals = Vec::with_capacity(dealt.len());
        let mut dealing = Vec::with_capacity(dealt.len());
        for (span, encoded) in self.spans.iter().zip(dealt) {
            let interval = joined(&self.intervals, span).map_err(HandoffError::Unserved)?;
            let slice = decode_dealt_slice_bounded::<VerifyingKey, ShaDigest>(
                encoded,
                *context.limits(),
                encoded.len(),
            )
            .and_then(|dealt| {
                dealt.hydrate::<Sha256>(&interval, context, &fixture.deposits, &fixture.withdrawals)
            })
            .map_err(HandoffError::Hydrate)?;
            intervals.push(interval);
            dealing.push(slice);
        }
        let (vote, sealed) = seal::<Sha256, _, _, AckBatchVerifier, _>(
            &self.scheme,
            context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            dealing,
            &mut TestRng::new(seed),
            &Sequential,
        )
        .map_err(HandoffError::Seal)?;
        for (mut interval, slice) in intervals.into_iter().zip(sealed.slices()) {
            interval.advance(slice);
            self.intervals
                .extend(split(&interval, &slice.span, self.slice_bits));
        }
        Ok(vote)
    }
}

/// Every outgoing validator seals its own dealing of `fixture` and advances its intervals to
/// the successor state. Returns the holders and the exact certificate over the header from
/// the first quorum of votes.
fn seal_outgoing(
    schemes: &[bls12381::Scheme],
    fixture: &Fixture,
) -> (Vec<Holder>, bls12381::Certificate) {
    let predecessor = intervals_of(
        fixture.cache.leaves(),
        fixture.context.assignment().slice_bits(),
    );
    let expected = successor_intervals(fixture);
    let mut votes = Vec::new();
    let mut holders = Vec::new();
    for (seed, scheme) in schemes.iter().enumerate() {
        let (vote, holder) = Holder::seal(scheme, fixture, &predecessor, seed as u64);
        for (slice, interval) in &holder.intervals {
            assert_eq!(interval, &expected[usize::from(*slice)]);
        }
        votes.push(vote);
        holders.push(holder);
    }
    let quorum = schemes[0].committee().quorum();
    let certificate = schemes[0]
        .assemble_exact(votes.into_iter().take(quorum))
        .unwrap();
    (holders, certificate)
}

/// Every incoming validator is dealt its spans of `next` in dealt form, and every validator
/// holding its intervals hydrates, seals with its own key, and advances. Returns the votes
/// and the validators that did not seal, with why.
fn seal_incoming(
    joiners: &mut [Joiner],
    next: &Fixture,
) -> (Vec<bls12381::Vote>, Vec<(Participant, HandoffError)>) {
    let expected_next = successor_intervals(next);
    let mut votes = Vec::new();
    let mut failed = Vec::new();
    for (seed, joiner) in joiners.iter_mut().enumerate() {
        let dealings = next
            .prepared
            .deal(&next.cache, &joiner.spans, &Sequential)
            .unwrap();
        let dealt = joiner
            .spans
            .iter()
            .map(|span| dealings.encode_span(span).encode())
            .collect::<Vec<_>>();
        match joiner.seal(next, &dealt, 100 + seed as u64) {
            Ok(vote) => {
                for span in &joiner.spans {
                    for slice in span.clone() {
                        assert_eq!(joiner.intervals[&slice], expected_next[usize::from(slice)]);
                    }
                }
                votes.push(vote);
            }
            Err(error) => failed.push((joiner.me(), error)),
        }
    }
    (votes, failed)
}

/// The settlement chain is not involved: committee A certifies epoch `e`, committee B's
/// validators obtain the intervals they lack from A's holders over the wire, verify them
/// against the successor root A certified, and seal and certify epoch `e + 1` under B's own
/// assignment. One departing A holder answers one member short and is caught. One slice no
/// holder still serves leaves one B validator unable to hydrate, and B certifies with the
/// remaining quorum.
#[test]
fn committee_rotation_hands_over_intervals_between_groups() {
    // Committee A (outgoing) and committee B (incoming): two of A's four validators leave and
    // two join, so B's canonical order, commitment, and ring-window assignment all differ.
    let outgoing_keys = OUTGOING.map(validator);
    let (committee_a, schemes_a) = committee(&outgoing_keys);
    let mut incoming_keys = outgoing_keys
        .iter()
        .filter(|key| {
            let position = committee_a
                .index_of(&compute_public::<MinSig>(key))
                .unwrap();
            !LEAVING.contains(&position)
        })
        .cloned()
        .collect::<Vec<_>>();
    incoming_keys.extend(JOINING.map(validator));
    let (committee_b, schemes_b) = committee(&incoming_keys);
    assert_ne!(
        committee_a.commitment::<Sha256>(),
        committee_b.commitment::<Sha256>()
    );
    let assignment_a = Assignment::new(committee_a.commitment::<Sha256>(), SLICE_BITS).unwrap();
    let assignment_b = Assignment::new(committee_b.commitment::<Sha256>(), SLICE_BITS).unwrap();
    let slice_count = assignment_a.slice_count();
    let quorum = committee_a.quorum();
    assert_eq!((committee_a.members().len(), quorum), (4, 3));
    assert!(LEAVING.contains(&BYZANTINE));

    // Epoch e under A, sealed by every A validator, whose intervals advance to the successor
    // state. A's exact certificate over header_e is what B will check.
    let (keys, first) = epoch_close(assignment_a);
    let expected_e = successor_intervals(&first);
    let (mut holders, certificate_a) = seal_outgoing(&schemes_a, &first);
    let verifier_a = bls12381::Scheme::verifier(committee_a.clone());

    // What A publishes: header, roots, and certificate. B trusts the successor root only
    // after the certificate verifies against committee A and the roots against the header.
    let header_e = *holders[0].sealed.header();
    let roots_e = *holders[0].sealed.roots();
    assert!(verifier_a.verify_exact(&header_e, &certificate_a));
    assert!(header_e.verify::<Sha256, VerifyingKey>(&first.context, &roots_e));
    let root = roots_e.successor;

    // B's validators: continuing members keep the intervals they hold, new members hold none.
    let mut joiners = schemes_b
        .iter()
        .map(|scheme| {
            let key = &committee_b.members()[usize::from(scheme.me().unwrap())];
            let retained = committee_a
                .index_of(key)
                .map(|held| holders[usize::from(held)].intervals.clone())
                .unwrap_or_default();
            Joiner::new(scheme.clone(), &assignment_b, retained, SLICE_BITS)
        })
        .collect::<Vec<_>>();
    let dealing = usize::from(slice_count) * quorum / committee_b.members().len();
    assert_eq!(
        joiners
            .iter()
            .filter(|joiner| joiner.intervals.is_empty())
            .map(|joiner| joiner.lacking().len())
            .collect::<Vec<_>>(),
        vec![dealing; 2]
    );

    // One slice that exactly one B validator must fetch is no longer served by any A holder,
    // and A's departing position 0 answers one member short.
    let (pruned, unlucky) = (0..slice_count)
        .find_map(|slice| {
            let lacking = joiners
                .iter()
                .filter(|joiner| joiner.lacking().contains(&slice))
                .map(Joiner::me)
                .collect::<Vec<_>>();
            (lacking.len() == 1).then(|| (slice, lacking[0]))
        })
        .expect("a slice exactly one incoming validator lacks");
    for holder in &mut holders {
        holder.pruned.insert(pruned);
    }
    holders[usize::from(BYZANTINE)].fault = Some(Fault::Short);
    let max_members = usize::try_from(first.context.limits().max_states()).unwrap();

    // A root A never certified is unknown to its holders.
    assert!(matches!(
        exchange(
            &holders[1],
            &Request::Interval {
                root: *first.context.predecessor_root(),
                slice: 0,
            },
            max_members,
        ),
        Ok(Response::Unknown)
    ));

    // Handoff: every B validator asks A's holders of each slice it lacks, in holder order,
    // across the wire, and keeps the first answer that verifies under the certified root.
    let mut rejected = 0;
    let mut served = 0;
    for joiner in &mut joiners {
        let lacking = joiner.lacking();
        let log = joiner.fetch(&holders, &committee_a, &assignment_a, &root, max_members);
        for (holder, slice) in &log.served {
            let fetched = &joiner.intervals[slice];
            assert_eq!(fetched, &holders[usize::from(*holder)].intervals[slice]);
            assert_eq!(fetched, &expected_e[usize::from(*slice)]);
        }

        // A dropped member is caught by the bracket rule when it was the vector's last leaf
        // and by the opening otherwise.
        for (holder, slice, error) in &log.rejected {
            assert_eq!(*holder, BYZANTINE, "slice {slice}: {error}");
            assert!(
                matches!(error, ServeError::Range | ServeError::Commitment(_)),
                "{error}"
            );
        }
        if joiner.me() == unlucky {
            assert_eq!(joiner.lacking(), vec![pruned]);
            assert_eq!(log.served.len() + 1, lacking.len());
            assert_eq!(
                log.declined
                    .iter()
                    .filter(|(_, slice)| *slice == pruned)
                    .count(),
                quorum
            );
        } else {
            assert!(joiner.lacking().is_empty());
            assert_eq!(log.served.len(), lacking.len());
        }
        rejected += log.rejected.len();
        served += log.served.len();
    }
    assert!(rejected > 0, "the Byzantine holder was never asked first");
    assert!(served > rejected);

    // Epoch e + 1 under B from the successor state of epoch e. The operator deals each B
    // validator its spans in dealt form, and every validator holding its intervals hydrates,
    // seals with its own key, and advances.
    let second = next_close(EPOCH + 1, assignment_b, &keys, successor_leaves(&first));
    assert_eq!(*second.context.predecessor_root(), root);
    let close_next = second.prepared.close();
    let (votes, failed) = seal_incoming(&mut joiners, &second);

    // The validator nobody served cannot hydrate its span and does not seal. The other three
    // are exactly B's quorum, so B certifies epoch e + 1 without A.
    assert!(
        matches!(
            failed.as_slice(),
            [(validator, HandoffError::Unserved(slice))] if *validator == unlucky && *slice == pruned
        ),
        "{failed:?}"
    );
    assert_eq!(votes.len(), quorum);
    let certificate_b = schemes_b[0].assemble_exact(votes).unwrap();
    let verifier_b = bls12381::Scheme::verifier(committee_b);
    assert!(verifier_b.verify_exact(&close_next.header, &certificate_b));
    assert!(!verifier_a.verify_exact(&close_next.header, &certificate_b));
}

/// Rotates from the `outgoing` validators, who seal epoch `e` under `outgoing_bits`, to the
/// `incoming` validators, who seal epoch `e + 1` under `incoming_bits`, across a slice count
/// change: every incoming validator repairs the intervals it lacks from the outgoing holders'
/// verified answers, narrowing when the partition doubles and merging when it halves. The
/// holders in `faults` answer wrongly. Returns how many slices the incoming validators lacked
/// after re-slicing what they retained, and everything they saw from the holders.
fn resize(
    outgoing: &[u64],
    outgoing_bits: u8,
    incoming: &[u64],
    incoming_bits: u8,
    faults: &[(Participant, Fault)],
) -> (usize, Log) {
    let outgoing_keys = outgoing.iter().copied().map(validator).collect::<Vec<_>>();
    let incoming_keys = incoming.iter().copied().map(validator).collect::<Vec<_>>();
    let (committee_out, schemes_out) = committee(&outgoing_keys);
    let (committee_in, schemes_in) = committee(&incoming_keys);
    assert_ne!(
        committee_out.commitment::<Sha256>(),
        committee_in.commitment::<Sha256>()
    );
    let assignment_out =
        Assignment::new(committee_out.commitment::<Sha256>(), outgoing_bits).unwrap();
    let assignment_in =
        Assignment::new(committee_in.commitment::<Sha256>(), incoming_bits).unwrap();

    // The slice count is the smallest power of two at or above the committee size, so it
    // changes with the size.
    for (committee, assignment) in [
        (&committee_out, &assignment_out),
        (&committee_in, &assignment_in),
    ] {
        assert_eq!(
            usize::from(assignment.slice_count()),
            committee.members().len().next_power_of_two()
        );
    }
    assert_eq!(outgoing_bits.abs_diff(incoming_bits), 1);

    // Epoch e under the outgoing committee, sealed and certified by its validators. The
    // incoming committee trusts the successor root only after the certificate verifies
    // against the outgoing committee and the roots against the header.
    let (keys, first) = epoch_close(assignment_out);
    let (mut holders, certificate_out) = seal_outgoing(&schemes_out, &first);
    let verifier_out = bls12381::Scheme::verifier(committee_out.clone());
    let header_e = *holders[0].sealed.header();
    let roots_e = *holders[0].sealed.roots();
    assert!(verifier_out.verify_exact(&header_e, &certificate_out));
    assert!(header_e.verify::<Sha256, VerifyingKey>(&first.context, &roots_e));
    let root = roots_e.successor;
    for (holder, fault) in faults {
        holders[usize::from(*holder)].fault = Some(*fault);
    }

    // The incoming validators: continuing members re-slice what they retain to the incoming
    // partition, which already matches the whole successor state, and newcomers hold none.
    let successor = successor_leaves(&first);
    let expected_in = intervals_of(&successor, incoming_bits);
    let mut joiners = schemes_in
        .iter()
        .map(|scheme| {
            let key = &committee_in.members()[usize::from(scheme.me().unwrap())];
            let retained = committee_out
                .index_of(key)
                .map(|held| holders[usize::from(held)].intervals.clone())
                .unwrap_or_default();
            Joiner::new(scheme.clone(), &assignment_in, retained, outgoing_bits)
        })
        .collect::<Vec<_>>();
    for joiner in &joiners {
        for (slice, interval) in &joiner.intervals {
            assert_eq!(interval, &expected_in[usize::from(*slice)]);
        }
    }
    let lacking = joiners
        .iter()
        .map(|joiner| joiner.lacking().len())
        .sum::<usize>();
    assert!(lacking > 0);

    // Repair over the wire: every answer is verified under the certified root as the outgoing
    // slice it was asked for before it is narrowed or merged, so a wrong answer is rejected
    // before any repair uses it, and every repaired interval is the whole state's.
    let max_members = usize::try_from(first.context.limits().max_states()).unwrap();
    let mut log = Log::default();
    for joiner in &mut joiners {
        let seen = joiner.fetch(
            &holders,
            &committee_out,
            &assignment_out,
            &root,
            max_members,
        );
        assert!(joiner.lacking().is_empty());
        for (slice, interval) in &joiner.intervals {
            assert_eq!(interval, &expected_in[usize::from(*slice)]);
        }
        for (holder, slice, error) in &seen.rejected {
            assert!(
                faults.iter().any(|(faulty, _)| faulty == holder),
                "slice {slice}: {error}"
            );
            assert!(
                matches!(error, ServeError::Range | ServeError::Commitment(_)),
                "{error}"
            );
        }
        assert!(seen.declined.is_empty());
        log.extend(seen);
    }
    for (faulty, _) in faults {
        assert!(
            log.rejected.iter().any(|(holder, _, _)| holder == faulty),
            "{faulty:?} was never caught"
        );
    }

    // Epoch e + 1 under the incoming committee: every validator hydrates its dealt spans
    // against the repaired intervals and seals, and the exact certificate is the incoming
    // committee's alone.
    let second = next_close(EPOCH + 1, assignment_in, &keys, successor);
    assert_eq!(*second.context.predecessor_root(), root);
    let (votes, failed) = seal_incoming(&mut joiners, &second);
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(votes.len(), committee_in.members().len());
    let certificate_in = schemes_in[0]
        .assemble_exact(votes.into_iter().take(committee_in.quorum()))
        .unwrap();
    let verifier_in = bls12381::Scheme::verifier(committee_in);
    let header_next = &second.prepared.close().header;
    assert!(verifier_in.verify_exact(header_next, &certificate_in));
    assert!(!verifier_out.verify_exact(header_next, &certificate_in));
    (lacking, log)
}

/// Four validators over four slices grow into seven over eight, so every incoming slice is
/// half of one outgoing slice. An incoming validator lacking slice `b` fetches outgoing slice
/// `b / 2`, verifies it complete under the certified root, and narrows it to both halves, so
/// fewer answers than lacking slices are needed. The outgoing position 0 answers short and is
/// caught before anything is narrowed.
#[test]
fn committee_rotation_splits_slices_when_the_committee_grows() {
    let (lacking, log) = resize(&OUTGOING, 2, &GROWN, 3, &[(BYZANTINE, Fault::Short)]);
    assert!(log.served.len() < lacking);
}

/// Seven validators over eight slices shrink into four over four, so every incoming slice is
/// the union of two adjacent outgoing slices, each with its own holders. An incoming validator
/// lacking slice `c` fetches outgoing slices `2c` and `2c + 1`, verifies each, checks their
/// seam, and joins them, so every lacking slice takes two answers. The outgoing position 0
/// answers short and position 1 answers with another slice it holds, and both are caught
/// before anything is merged.
#[test]
fn committee_rotation_merges_slices_when_the_committee_shrinks() {
    let (lacking, log) = resize(
        &GROWN,
        3,
        &SHRUNK,
        2,
        &[
            (Participant::new(0), Fault::Short),
            (Participant::new(1), Fault::Foreign),
        ],
    );
    assert_eq!(log.served.len(), 2 * lacking);
}
