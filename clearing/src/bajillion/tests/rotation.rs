//! Committee rotation without the settlement chain.
//!
//! The incoming committee's validators fetch the retained intervals they lack from the
//! outgoing committee's holders over a codec-framed request and response exchange, verify
//! every answer under the successor root the outgoing certificate committed, and seal the
//! next epoch's dealing themselves. `committee_rotation_hands_over_intervals_between_groups`
//! is the code that shows a committee change is possible with dealing alone.

use super::*;
use crate::bajillion::{
    admission::{
        AdmissionError, Committee, SealedDealing, assigned_slice_spans, bls12381, seal,
        slice_holders,
    },
    commitment::VectorRoot,
    retained::decode_dealt_slice_bounded,
    serve::{SliceInterval, slice_interval, verified_interval},
    transition::{OperatorVariant, StateRange},
};
use alloc::collections::{BTreeMap, BTreeSet};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Decode, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_utils::Participant;
use core::{num::NonZeroU64, ops::Range};
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

/// The whole successor state of a close as its vector tree, for byte-for-byte comparison.
fn successor_tree(
    fixture: &Fixture,
) -> (Vec<StateLeaf<VerifyingKey>>, commitment::Tree<ShaDigest>) {
    let leaves = successor_intervals(fixture)
        .iter()
        .flat_map(|interval| interval.leaves().iter().cloned())
        .collect::<Vec<_>>();
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

/// An outgoing validator after sealing epoch `e`: the dealing it certified and the per-slice
/// intervals it advanced, which it serves to the incoming committee.
struct Holder {
    sealed: SealedDealing<VerifyingKey, ShaDigest>,
    intervals: BTreeMap<u16, Interval<VerifyingKey>>,
    /// Answers every populated slice one member short.
    byzantine: bool,
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
            intervals.extend(split(&interval, &slice.span));
        }
        (
            vote,
            Self {
                sealed,
                intervals,
                byzantine: false,
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
        let mut interval = slice_interval::<Sha256, _, _>(proof, *slice, SLICE_BITS).unwrap();
        if self.byzantine && !interval.members.is_empty() {
            interval.members.remove(0);
        }
        Response::Interval(Box::new(interval))
    }
}

/// Splits one advanced span interval into per-slice intervals.
fn split(
    interval: &Interval<VerifyingKey>,
    span: &Range<u16>,
) -> BTreeMap<u16, Interval<VerifyingKey>> {
    let mut buckets: BTreeMap<u16, Vec<StateLeaf<VerifyingKey>>> =
        span.clone().map(|slice| (slice, Vec::new())).collect();
    for leaf in interval.leaves() {
        let slice = account_slice(&leaf.account, SLICE_BITS).unwrap();
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

/// What one incoming validator saw from the outgoing holders.
#[derive(Debug, Default)]
struct Log {
    /// Answers that verified, by holder and slice.
    served: Vec<(Participant, u16)>,
    /// Answers that failed verification, by holder and slice.
    rejected: Vec<(Participant, u16, ServeError)>,
    /// Holders that declined a slice or answered unusably.
    declined: Vec<(Participant, u16)>,
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
    intervals: BTreeMap<u16, Interval<VerifyingKey>>,
}

impl Joiner {
    fn new(
        scheme: bls12381::Scheme,
        assignment: &Assignment<ShaDigest>,
        retained: BTreeMap<u16, Interval<VerifyingKey>>,
    ) -> Self {
        let spans =
            assigned_slice_spans::<Sha256, _>(scheme.committee(), assignment, scheme.me().unwrap())
                .unwrap();
        Self {
            scheme,
            spans,
            intervals: retained,
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
    /// first answer that verifies under `root`.
    fn fetch(
        &mut self,
        holders: &[Holder],
        outgoing: &Committee,
        assignment: &Assignment<ShaDigest>,
        root: &VectorRoot<ShaDigest>,
        max_members: usize,
    ) -> Log {
        let mut log = Log::default();
        for slice in self.lacking() {
            let request = Request::Interval { root: *root, slice };
            for holder in slice_holders::<Sha256, _>(outgoing, assignment, slice).unwrap() {
                let Ok(response) = exchange(&holders[usize::from(holder)], &request, max_members)
                else {
                    log.declined.push((holder, slice));
                    continue;
                };
                match response {
                    Response::Interval(interval) => {
                        match verified_interval::<Sha256, _, _>(&interval, root, slice, SLICE_BITS)
                        {
                            Ok(verified) => {
                                self.intervals.insert(slice, verified);
                                log.served.push((holder, slice));
                                break;
                            }
                            Err(error) => log.rejected.push((holder, slice, error)),
                        }
                    }
                    Response::NotHolder | Response::Unknown => log.declined.push((holder, slice)),
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
            self.intervals.extend(split(&interval, &slice.span));
        }
        Ok(vote)
    }
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

    // Epoch e under A: 24 live accounts and four fresh ones, ten senders, deposits creating
    // three accounts, closes deleting three, one partial withdrawal, and one payout to a
    // fresh account that never becomes live.
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
        assignment_a,
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

    // Every A validator seals its own dealing and advances its intervals to the successor
    // state. A's exact certificate over header_e is what B will check.
    let predecessor = intervals_of(first.cache.leaves(), SLICE_BITS);
    let expected_e = successor_intervals(&first);
    let mut votes = Vec::new();
    let mut holders = Vec::new();
    for (seed, scheme) in schemes_a.iter().enumerate() {
        let (vote, holder) = Holder::seal(scheme, &first, &predecessor, seed as u64);
        for (slice, interval) in &holder.intervals {
            assert_eq!(interval, &expected_e[usize::from(*slice)]);
        }
        votes.push(vote);
        holders.push(holder);
    }
    let verifier_a = bls12381::Scheme::verifier(committee_a.clone());
    let certificate_a = schemes_a[0]
        .assemble_exact(votes.into_iter().take(quorum))
        .unwrap();

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
            Joiner::new(scheme.clone(), &assignment_b, retained)
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
    holders[usize::from(BYZANTINE)].byzantine = true;
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
    let successor = expected_e
        .iter()
        .flat_map(|interval| interval.leaves().iter().cloned())
        .collect::<Vec<_>>();
    let live_after = successor
        .iter()
        .map(|leaf| at(&leaf.account))
        .collect::<Vec<_>>();
    let second = close_under(
        EPOCH + 1,
        assignment_b,
        &keys,
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
    );
    assert_eq!(*second.context.predecessor_root(), root);
    let close_next = second.prepared.close();
    let expected_next = successor_intervals(&second);
    let mut votes = Vec::new();
    let mut failed = Vec::new();
    for (seed, joiner) in joiners.iter_mut().enumerate() {
        let dealings = second
            .prepared
            .deal(&second.cache, &joiner.spans, &Sequential)
            .unwrap();
        let dealt = joiner
            .spans
            .iter()
            .map(|span| dealings.encode_span(span).encode())
            .collect::<Vec<_>>();
        match joiner.seal(&second, &dealt, 100 + seed as u64) {
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
