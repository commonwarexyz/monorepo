use crate::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{
        AccountLookup, AckWitness, Challenge, ChallengeError, ChallengeKind, ChangeOpening,
        EntryWitness, StateLookup, Verdict, account_lookup, adjudicate, higher_entry_lookup,
    },
    commitment::{self, VectorKind},
    payment::{
        AckError, EntryReceipt, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck,
        VectorSendBody,
    },
    posted::derive_successor,
    retained::Interval,
    serve::{ServeError, SpanIndex},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, ChallengeIndex, ChangeParts, Close, CloseContext, CloseLimits, EpochContext,
        PreparedClose, ProofSlice, RootBundle, StateCache, TransitionError as CloseError,
        account_slice, prepare_close_with_strategy, validate_close_with_strategy, validate_row,
        validate_slice,
    },
    vector::{OutEntry, OutVector, TransposeEntry},
};
use commonware_codec::{DecodeExt, Encode, EncodeSize};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private as BlsPrivate, Scalar},
        ops::{compute_public, sign_message},
    },
    sha256::Digest as ShaDigest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as AckBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
mod rotation;

const EPOCH: u64 = 7;
const OPENING_BALANCE: u64 = 1_000_000;
const OPERATOR_SEED: u64 = 1;
const ACCOUNT_SEED_START: u64 = 10_000;

struct Fixture {
    cache: StateCache<VerifyingKey, ShaDigest>,
    context: CloseContext<VerifyingKey, ShaDigest>,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: WithdrawalBatch<VerifyingKey, ShaDigest>,
    prepared: PreparedClose<VerifyingKey, ShaDigest>,
    accounts: Vec<(VerifyingKey, SigningKey)>,
    acks: Vec<VectorAck<VerifyingKey, ShaDigest>>,
    operator: SigningKey,
    operator_bls_private: BlsPrivate,
    operator_bls: crate::bajillion::transition::OperatorKey,
}

fn bls_ack(
    private: &BlsPrivate,
    body: &VectorSendBody<VerifyingKey, ShaDigest>,
) -> crate::bajillion::transition::OperatorSignature {
    sign_message::<crate::bajillion::transition::OperatorVariant>(
        private,
        VECTOR_ACK_AGGREGATE_NAMESPACE,
        commonware_codec::Encode::encode(body).as_ref(),
    )
}

fn partials(
    out_vectors: &[OutVector<VerifyingKey>],
) -> Vec<commonware_cryptography::lthash::LtHash> {
    out_vectors.iter().map(OutVector::accumulator).collect()
}

fn operator_signatures(
    fixture: &Fixture,
) -> Vec<Option<crate::bajillion::transition::OperatorSignature>> {
    fixture
        .acks
        .iter()
        .map(|ack| Some(bls_ack(&fixture.operator_bls_private, ack.body())))
        .collect()
}

/// Builds a close where every account sends one unit to each of `out_degree` of the first
/// `credited` accounts.
fn fixture(live: usize, credited: usize, out_degree: usize) -> Fixture {
    fixture_with(EPOCH, live, live, credited, out_degree, None)
}

/// Builds a close at `epoch` over `live` accounts where the first `senders` (in key order)
/// each send one unit to `out_degree` of the first `credited` accounts. Accounts that
/// neither send nor receive stay unchanged. `opening` carries prior states forward (absent
/// accounts open at the default balance), which chains fixtures across epochs.
fn fixture_with(
    epoch: u64,
    live: usize,
    senders: usize,
    credited: usize,
    out_degree: usize,
    opening: Option<&alloc::collections::BTreeMap<VerifyingKey, AccountState>>,
) -> Fixture {
    assert!(senders <= live && credited <= senders && out_degree <= credited);
    fixture_from(
        epoch,
        live,
        &(0..senders).collect::<Vec<_>>(),
        credited,
        out_degree,
        opening,
    )
}

/// Builds a close over `live` accounts where every `stride`th account in key order sends
/// one unit to `out_degree` of the first `credited` accounts, so the changed rows are
/// scattered across the key space and some slices hold only unchanged leaves.
fn sparse_fixture(live: usize, stride: usize, credited: usize, out_degree: usize) -> Fixture {
    fixture_from(
        EPOCH,
        live,
        &(0..live).step_by(stride).collect::<Vec<_>>(),
        credited,
        out_degree,
        None,
    )
}

/// Builds a close at `epoch` over `live` accounts where the accounts at `senders` (indices
/// in key order) each send one unit to `out_degree` of the first `credited` accounts.
fn fixture_from(
    epoch: u64,
    live: usize,
    senders: &[usize],
    credited: usize,
    out_degree: usize,
    opening: Option<&alloc::collections::BTreeMap<VerifyingKey, AccountState>>,
) -> Fixture {
    assert!(
        senders.iter().all(|index| *index < live) && credited <= live && out_degree <= credited
    );
    let mut accounts = (0..live)
        .map(|index| {
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index as u64);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let operator_bls_private = BlsPrivate::new(Scalar::from(OPERATOR_SEED));
    let operator_bls =
        compute_public::<crate::bajillion::transition::OperatorVariant>(&operator_bls_private);

    let state_of = |public: &VerifyingKey| -> AccountState {
        opening
            .and_then(|states| states.get(public).copied())
            .unwrap_or(AccountState {
                balance: OPENING_BALANCE,
                active: true,
                ..AccountState::default()
            })
    };
    let leaves = accounts
        .iter()
        .map(|(public, _)| StateLeaf {
            account: public.clone(),
            state: state_of(public),
        })
        .collect::<Vec<_>>();
    let cache = StateCache::new::<Sha256>(leaves).unwrap();
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let assignment = Assignment::new(Sha256::hash(&[b"close-test-committee"]), 3).unwrap();
    let context = EpochContext::new::<Sha256>(
        Sha256::hash(&[b"close-test-deployment"]),
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

    // Edge (i -> (i + j) % credited) for j in 0..out_degree, one unit each, from the
    // `senders` accounts. Rows cover exactly the senders and the credited recipients.
    let mut incoming = vec![Vec::new(); live];
    let mut vectors_by_account = vec![None; live];
    for index in senders.iter().copied() {
        let (public, private) = &accounts[index];
        let mut entries = (0..out_degree)
            .map(|j| OutEntry {
                recipient: accounts[(index + j) % credited].0.clone(),
                cumulative: 1,
                count: 1,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        for entry in &entries {
            let recipient = accounts
                .binary_search_by(|(public, _)| public.cmp(&entry.recipient))
                .unwrap();
            incoming[recipient].push(TransposeEntry {
                recipient: entry.recipient.clone(),
                payer: public.clone(),
                cumulative: entry.cumulative,
                count: entry.count,
            });
        }
        let vector = OutVector::new(epoch, public.clone(), entries).unwrap();
        vectors_by_account[index] = Some((vector, private));
    }

    let mut transpose = Vec::new();
    let mut rows = Vec::with_capacity(live);
    let mut out_vectors = Vec::with_capacity(live);
    let mut acks = Vec::with_capacity(senders.len());
    let mut operator_signatures = Vec::with_capacity(live);
    let mut prefix = Prefix::default();
    for (index, (public, _)) in accounts.iter().enumerate() {
        let sends = vectors_by_account[index].is_some();
        if !sends && incoming[index].is_empty() {
            continue;
        }
        let mut group = incoming[index].clone();
        group.sort_unstable_by(|left, right| left.payer.cmp(&right.payer));
        let credit = group.iter().map(|entry| entry.cumulative).sum::<u64>();
        let receipts = group.iter().map(|entry| entry.count).sum::<u64>();
        let debit = if sends { out_degree as u64 } else { 0 };
        let predecessor = state_of(public);
        let successor = AccountState {
            balance: predecessor.balance - debit + credit,
            cumulative_debit: predecessor.cumulative_debit + debit,
            cumulative_credit: predecessor.cumulative_credit + credit,
            receipt_count: predecessor.receipt_count + receipts,
            active: true,
        };
        let (vector, outgoing) = match vectors_by_account[index].take() {
            Some((vector, private)) => {
                let send_root = vector.root::<Sha256, ShaDigest>().unwrap();
                let body = VectorSendBody::new(
                    context.payment(),
                    public.clone(),
                    0,
                    successor.cumulative_debit,
                    send_root,
                );
                let ack = VectorAck::sign_by_authorities(body, private, &operator);
                let send = SendAuthorization::from_raw_unchecked(
                    ack.body().clone(),
                    ack.payer_signature().clone(),
                );
                operator_signatures.push(Some(bls_ack(&operator_bls_private, ack.body())));
                acks.push(ack);
                (vector, Some(send))
            }
            None => {
                operator_signatures.push(None);
                (
                    OutVector::new(epoch, public.clone(), Vec::new()).unwrap(),
                    None,
                )
            }
        };
        prefix = prefix
            .checked_extend(Prefix {
                debit,
                credit,
                out_count: if sends { out_degree as u64 } else { 0 },
                in_count: group.len() as u64,
                ..Prefix::default()
            })
            .unwrap();
        rows.push(AccountRow {
            account: public.clone(),
            predecessor,
            successor,
            outgoing,
            output: SettlementOutput::None,
            prefix,
        });
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
        accounts,
        acks,
        operator,
        operator_bls_private,
        operator_bls,
    }
}

#[test]
fn close_validates_and_deals() {
    let fixture = fixture(24, 8, 2);
    fixture
        .prepared
        .validate::<Sha256, AckBatchVerifier, _>(
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &mut TestRng::new(0),
            &Sequential,
        )
        .unwrap();

    let close = fixture.prepared.close();
    validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        close,
        &mut TestRng::new(1),
        &Sequential,
    )
    .unwrap();

    let slice_count = fixture.context.assignment().slice_count();
    let mut spans = (0..slice_count)
        .map(|slice| slice..slice + 1)
        .collect::<Vec<_>>();
    spans.push(0..slice_count);
    let slices = fixture
        .prepared
        .assemble_slices(&fixture.cache, &spans, &Sequential)
        .unwrap();
    assert_eq!(slices.len(), spans.len());
    for slice in &slices {
        validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            slice,
            &mut TestRng::new(7),
        )
        .unwrap();
    }

    let terminal = fixture.prepared.terminal_proof().unwrap();
    let totals = terminal
        .verify::<Sha256, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
        )
        .unwrap();
    assert_eq!(totals.debit, totals.credit);
    assert_eq!(totals.debit, 24 * 2);
}

#[test]
fn misrouted_transpose_edges_are_rejected() {
    // Out-degree one over as many recipients as payers, so every recipient has exactly one
    // in-edge and swapping two entries' payers preserves every row equation.
    let fixture = fixture(8, 8, 1);
    let close = fixture.prepared.close();
    let mut transpose = close.rebuild_transpose().unwrap();
    let payers = (transpose[0].payer.clone(), transpose[1].payer.clone());
    assert_ne!(transpose[0].recipient, transpose[1].recipient);
    transpose[0].payer = payers.1;
    transpose[1].payer = payers.0;

    let out_partials = partials(&close.out_vectors);
    let signatures = operator_signatures(&fixture);
    let result = prepare_close_with_strategy::<Sha256, _, _>(
        &fixture.cache,
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        close.rows.clone(),
        close.out_vectors.clone(),
        &out_partials,
        &signatures,
        transpose,
        &Sequential,
    )
    .unwrap()
    .validate::<Sha256, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &mut TestRng::new(3),
        &Sequential,
    );
    assert!(matches!(result, Err(CloseError::MultisetMismatch)));
}

#[test]
fn understated_transpose_entries_are_rejected() {
    let fixture = fixture(8, 4, 2);
    let close = fixture.prepared.close();
    let mut transpose = close.rebuild_transpose().unwrap();
    transpose[0].cumulative += 1;

    let out_partials = partials(&close.out_vectors);
    let signatures = operator_signatures(&fixture);
    let result = prepare_close_with_strategy::<Sha256, _, _>(
        &fixture.cache,
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        close.rows.clone(),
        close.out_vectors.clone(),
        &out_partials,
        &signatures,
        transpose,
        &Sequential,
    )
    .unwrap()
    .validate::<Sha256, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &mut TestRng::new(4),
        &Sequential,
    );
    assert!(matches!(result, Err(CloseError::CreditTotals)));
}

#[test]
fn tampered_operator_aggregates_are_rejected() {
    // Aggregates are self-authenticating rather than header-bound: swapping two slices'
    // aggregates keeps the header valid and must still fail verification.
    let fixture = fixture(24, 8, 2);
    let close = fixture.prepared.close();
    let mut doctored = close.clone();
    let sending = doctored
        .operator_aggregates
        .iter()
        .enumerate()
        .filter_map(|(index, aggregate)| aggregate.is_some().then_some(index))
        .take(2)
        .collect::<Vec<_>>();
    assert!(sending.len() == 2, "fixture spans multiple sending slices");
    doctored.operator_aggregates.swap(sending[0], sending[1]);
    let result = validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &doctored,
        &mut TestRng::new(31),
        &Sequential,
    );
    assert!(matches!(
        result,
        Err(CloseError::Ack(AckError::InvalidOperatorSignature))
    ));

    // Dropping a sending slice's aggregate trips the Some/None alignment arm.
    let mut dropped = close.clone();
    dropped.operator_aggregates[sending[0]] = None;
    let result = validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &dropped,
        &mut TestRng::new(32),
        &Sequential,
    );
    assert!(matches!(
        result,
        Err(CloseError::Ack(AckError::InvalidOperatorSignature))
    ));
}

#[test]
fn transpose_len_is_header_bound_and_checked() {
    // A doctored count under a rebuilt header fails the rebuilt-length pin, and under the
    // original header fails header verification outright.
    let fixture = fixture(8, 4, 1);
    let close = fixture.prepared.close();
    let mut doctored = close.clone();
    doctored.roots.transpose_len += 1;
    doctored.header = crate::bajillion::transition::Header::new::<Sha256, VerifyingKey>(
        &fixture.context,
        &doctored.roots,
    );
    let result = validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &doctored,
        &mut TestRng::new(33),
        &Sequential,
    );
    assert!(matches!(result, Err(CloseError::TransposeRoot)));

    let mut unbound = close.clone();
    unbound.roots.transpose_len += 1;
    let result = validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &unbound,
        &mut TestRng::new(34),
        &Sequential,
    );
    assert!(matches!(result, Err(CloseError::HeaderRoot)));
}

#[test]
fn corrupted_sender_partials_fail_validation() {
    // A sender partial that disagrees with its vector poisons the out-side boundary
    // checksums, so the terminal equality fails against the honestly folded transpose.
    let fixture = fixture(8, 4, 2);
    let close = fixture.prepared.close();
    let mut out_partials = partials(&close.out_vectors);
    out_partials[0].add(b"stray");

    let signatures = operator_signatures(&fixture);
    let result = prepare_close_with_strategy::<Sha256, _, _>(
        &fixture.cache,
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        close.rows.clone(),
        close.out_vectors.clone(),
        &out_partials,
        &signatures,
        close.rebuild_transpose().unwrap(),
        &Sequential,
    )
    .unwrap()
    .validate::<Sha256, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &mut TestRng::new(11),
        &Sequential,
    );
    assert!(matches!(result, Err(CloseError::MultisetMismatch)));
}

#[test]
fn challenges_adjudicate() {
    let fixture = fixture(16, 8, 2);
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();

    // The operator privately acknowledged one more unit on an existing edge.
    let payer_position = 3_usize;
    let (payer_public, payer_private) = &fixture.accounts[payer_position];
    let committed = &close.out_vectors[payer_position];
    let mut entries = committed.entries().to_vec();
    entries[0].cumulative += 1;
    entries[0].count += 1;
    let retained_recipient = entries[0].recipient.clone();
    let retained = OutVector::new(EPOCH, payer_public.clone(), entries).unwrap();
    let retained_root = retained.root::<Sha256, ShaDigest>().unwrap();
    let retained_body = VectorSendBody::new(
        fixture.context.payment(),
        payer_public.clone(),
        1,
        close.rows[payer_position].successor.cumulative_debit + 1,
        retained_root,
    );
    let retained_ack =
        VectorAck::sign_by_authorities(retained_body, payer_private, &fixture.operator);
    let crate::bajillion::vector::OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = retained
        .lookup::<Sha256, ShaDigest>(&retained_recipient)
        .unwrap()
    else {
        panic!("retained entry is present");
    };
    let entry_witness = EntryWitness {
        ack: AckWitness::from_ack(&retained_ack),
        recipient: retained_recipient.clone(),
        cumulative,
        count,
        opening,
    };
    let sender = higher_entry_lookup::<Sha256, _, _>(
        &index,
        payer_public,
        Some(committed),
        &retained_recipient,
    )
    .unwrap();
    let challenge = Challenge::HigherAckEntry {
        entry: Box::new(entry_witness),
        sender: Box::new(sender),
    };
    let encoded = challenge.encode();
    assert_eq!(
        Challenge::<VerifyingKey, ShaDigest>::decode(encoded).unwrap(),
        challenge
    );
    assert_eq!(
        adjudicate::<Sha256, _, _>(&fixture.context, &close.header, &close.roots, &challenge)
            .unwrap(),
        Verdict::Proven(ChallengeKind::HigherAckEntry)
    );

    // The same retained acknowledgment also contradicts the public terminal debit.
    let payer = account_lookup::<Sha256, _, _>(&index, &fixture.cache, payer_public).unwrap();
    let debit_challenge = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&retained_ack)),
        payer: Box::new(payer.clone()),
    };
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &debit_challenge
        )
        .unwrap(),
        Verdict::Proven(ChallengeKind::HigherAckDebit)
    );

    // The committed acknowledgment matches the close exactly.
    let committed_ack = fixture.acks[payer_position].clone();
    let clean = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&committed_ack)),
        payer: Box::new(payer),
    };
    assert_eq!(
        adjudicate::<Sha256, _, _>(&fixture.context, &close.header, &close.roots, &clean).unwrap(),
        Verdict::NoContradiction
    );

    // The committed entry matches the public terminal entry exactly.
    let committed_entry = committed.entries()[0].clone();
    let crate::bajillion::vector::OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = committed
        .lookup::<Sha256, ShaDigest>(&committed_entry.recipient)
        .unwrap()
    else {
        panic!("committed entry is present");
    };
    let clean_entry = Challenge::HigherAckEntry {
        entry: Box::new(EntryWitness {
            ack: AckWitness::from_ack(&committed_ack),
            recipient: committed_entry.recipient.clone(),
            cumulative,
            count,
            opening,
        }),
        sender: Box::new(
            higher_entry_lookup::<Sha256, _, _>(
                &index,
                payer_public,
                Some(committed),
                &committed_entry.recipient,
            )
            .unwrap(),
        ),
    };
    assert_eq!(
        adjudicate::<Sha256, _, _>(&fixture.context, &close.header, &close.roots, &clean_entry)
            .unwrap(),
        Verdict::NoContradiction
    );

    // Two operator countersignatures at one sequence number with different roots.
    let fork = Challenge::AckFork {
        left: Box::new(AckWitness::from_ack(&committed_ack)),
        right: Box::new(AckWitness::from_ack(&{
            let body = VectorSendBody::new(
                fixture.context.payment(),
                payer_public.clone(),
                0,
                close.rows[payer_position].successor.cumulative_debit + 5,
                retained_root,
            );
            VectorAck::sign_by_authorities(body, payer_private, &fixture.operator)
        })),
    };
    assert_eq!(
        adjudicate::<Sha256, _, _>(&fixture.context, &close.header, &close.roots, &fork).unwrap(),
        Verdict::Proven(ChallengeKind::AckFork)
    );
}

#[test]
fn foreign_context_acks_are_rejected() {
    let fixture = fixture(8, 4, 1);
    let close = fixture.prepared.close();
    let position = 2_usize;
    let (payer_public, payer_private) = fixture
        .accounts
        .iter()
        .find(|(public, _)| *public == close.rows[position].account)
        .cloned()
        .unwrap();

    // Re-sign the identical endpoint under a foreign anchor.
    let committed = fixture.acks[position].body();
    let foreign = VectorSendBody::from_raw_unchecked(
        Sha256::hash(&[b"close-foreign-anchor"]),
        EPOCH,
        payer_public,
        committed.seq(),
        committed.cumulative_debit(),
        committed.send_root(),
    );
    let mut rows = close.rows.clone();
    let mut signatures = operator_signatures(&fixture);
    signatures[position] = Some(bls_ack(&fixture.operator_bls_private, &foreign));
    rows[position].outgoing = Some(SendAuthorization::sign(foreign, &payer_private));

    let out_partials = partials(&close.out_vectors);
    let result = prepare_close_with_strategy::<Sha256, _, _>(
        &fixture.cache,
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        rows,
        close.out_vectors.clone(),
        &out_partials,
        &signatures,
        close.rebuild_transpose().unwrap(),
        &Sequential,
    )
    .unwrap()
    .validate::<Sha256, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &mut TestRng::new(5),
        &Sequential,
    );
    assert!(matches!(
        result,
        Err(CloseError::Ack(AckError::WrongContext))
    ));
}

#[test]
fn ack_debit_arms_convict_same_seq_forks_and_later_batches() {
    let fixture = fixture(16, 8, 2);
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
    let position = 3_usize;
    let (payer_public, payer_private) = fixture
        .accounts
        .iter()
        .find(|(public, _)| *public == close.rows[position].account)
        .cloned()
        .unwrap();
    let committed = &fixture.acks[position];
    let lookup = account_lookup::<Sha256, _, _>(&index, &fixture.cache, &payer_public).unwrap();

    // A different body countersigned at the COMMITTED sequence is equivocation against the
    // certified terminal: with the operator's acceptance aggregated per slice, no individual
    // countersignature of the committed body is extractable, so this conviction rides on the
    // certificate plus the retained acknowledgment.
    let mut entries = close.out_vectors[position].entries().to_vec();
    let moved = entries.remove(0).cumulative;
    entries[0].cumulative += moved;
    let rearranged = OutVector::new(EPOCH, payer_public.clone(), entries).unwrap();
    let same_seq = VectorAck::sign_by_authorities(
        VectorSendBody::new(
            fixture.context.payment(),
            payer_public.clone(),
            committed.body().seq(),
            committed.body().cumulative_debit(),
            rearranged.root::<Sha256, ShaDigest>().unwrap(),
        ),
        &payer_private,
        &fixture.operator,
    );
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &Challenge::HigherAckDebit {
                ack: Box::new(AckWitness::from_ack(&same_seq)),
                payer: Box::new(lookup.clone()),
            }
        )
        .unwrap(),
        Verdict::Proven(ChallengeKind::HigherAckDebit)
    );

    // A retained retry of the committed endpoint itself never convicts.
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &Challenge::HigherAckDebit {
                ack: Box::new(AckWitness::from_ack(committed)),
                payer: Box::new(lookup.clone()),
            }
        )
        .unwrap(),
        Verdict::NoContradiction
    );

    // The identical rearrangement countersigned as a strictly later batch convicts: the
    // operator acknowledged a successor endpoint the close does not carry.
    let later_seq = VectorAck::sign_by_authorities(
        VectorSendBody::new(
            fixture.context.payment(),
            payer_public,
            committed.body().seq() + 1,
            committed.body().cumulative_debit(),
            rearranged.root::<Sha256, ShaDigest>().unwrap(),
        ),
        &payer_private,
        &fixture.operator,
    );
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &Challenge::HigherAckDebit {
                ack: Box::new(AckWitness::from_ack(&later_seq)),
                payer: Box::new(lookup),
            }
        )
        .unwrap(),
        Verdict::Proven(ChallengeKind::HigherAckDebit)
    );
}

#[test]
fn ack_debit_arms_decline_earlier_retries_and_credit_only_rows() {
    // Recommit one sender's terminal at sequence one so an earlier sequence exists.
    let fixture = fixture(16, 8, 2);
    let close = fixture.prepared.close();
    let position = 3_usize;
    let (payer_public, payer_private) = fixture
        .accounts
        .iter()
        .find(|(public, _)| *public == close.rows[position].account)
        .cloned()
        .unwrap();
    let committed = fixture.acks[position].body();
    let terminal = VectorSendBody::new(
        fixture.context.payment(),
        payer_public.clone(),
        1,
        committed.cumulative_debit(),
        committed.send_root(),
    );
    let mut rows = close.rows.clone();
    let mut signatures = operator_signatures(&fixture);
    signatures[position] = Some(bls_ack(&fixture.operator_bls_private, &terminal));
    rows[position].outgoing = Some(SendAuthorization::sign(terminal, &payer_private));
    let out_partials = partials(&close.out_vectors);
    let prepared = prepare_close_with_strategy::<Sha256, _, _>(
        &fixture.cache,
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        rows,
        close.out_vectors.clone(),
        &out_partials,
        &signatures,
        close.rebuild_transpose().unwrap(),
        &Sequential,
    )
    .unwrap();
    prepared
        .validate::<Sha256, AckBatchVerifier, _>(
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &mut TestRng::new(47),
            &Sequential,
        )
        .unwrap();
    let close = prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
    let lookup = account_lookup::<Sha256, _, _>(&index, &fixture.cache, &payer_public).unwrap();

    // A retained earlier batch under a different root never convicts, whether it carries the
    // terminal debit or less: the committed later batch supersedes it.
    let mut entries = close.out_vectors[position].entries().to_vec();
    let moved = entries.remove(0).cumulative;
    entries[0].cumulative += moved;
    let rearranged = OutVector::new(EPOCH, payer_public.clone(), entries)
        .unwrap()
        .root::<Sha256, ShaDigest>()
        .unwrap();
    for debit in [
        committed.cumulative_debit(),
        committed.cumulative_debit() - 1,
    ] {
        let earlier = VectorAck::sign_by_authorities(
            VectorSendBody::new(
                fixture.context.payment(),
                payer_public.clone(),
                0,
                debit,
                rearranged,
            ),
            &payer_private,
            &fixture.operator,
        );
        assert_eq!(
            adjudicate::<Sha256, _, _>(
                &fixture.context,
                &close.header,
                &close.roots,
                &Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(&earlier)),
                    payer: Box::new(lookup.clone()),
                }
            )
            .unwrap(),
            Verdict::NoContradiction,
            "debit {debit}"
        );
    }

    // A credit-only row commits no outgoing endpoint, so an acknowledgment at its predecessor
    // debit is a zero-advance retry at any sequence number, not a contradiction.
    let fixture = churn_fixture();
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
    let row = close
        .rows
        .iter()
        .find(|row| {
            row.outgoing.is_none()
                && row.successor.cumulative_credit > row.predecessor.cumulative_credit
        })
        .expect("the churn fixture credits an account that never sends");
    let (account, private) = fixture
        .accounts
        .iter()
        .find(|(public, _)| *public == row.account)
        .cloned()
        .unwrap();
    let lookup = account_lookup::<Sha256, _, _>(&index, &fixture.cache, &account).unwrap();
    let root = OutVector::empty(EPOCH, account.clone())
        .root::<Sha256, ShaDigest>()
        .unwrap();
    for seq in [0, 1, 7] {
        let retry = VectorAck::sign_by_authorities(
            VectorSendBody::new(
                fixture.context.payment(),
                account.clone(),
                seq,
                row.predecessor.cumulative_debit,
                root,
            ),
            &private,
            &fixture.operator,
        );
        assert_eq!(
            adjudicate::<Sha256, _, _>(
                &fixture.context,
                &close.header,
                &close.roots,
                &Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(&retry)),
                    payer: Box::new(lookup.clone()),
                }
            )
            .unwrap(),
            Verdict::NoContradiction,
            "seq {seq}"
        );
    }
}

#[test]
fn absent_payer_arms_convict_from_zero() {
    let fixture = fixture(8, 4, 1);
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();

    // A payer outside the close entirely: any positive countersigned endpoint contradicts the
    // zero the absent arms resolve to.
    let phantom = SigningKey::from_seed(999_999);
    let recipient = fixture.accounts[0].0.clone();
    let vector = OutVector::new(
        EPOCH,
        phantom.public_key(),
        vec![OutEntry {
            recipient: recipient.clone(),
            cumulative: 5,
            count: 1,
        }],
    )
    .unwrap();
    let ack = VectorAck::sign_by_authorities(
        VectorSendBody::new(
            fixture.context.payment(),
            phantom.public_key(),
            0,
            5,
            vector.root::<Sha256, ShaDigest>().unwrap(),
        ),
        &phantom,
        &fixture.operator,
    );

    let payer =
        account_lookup::<Sha256, _, _>(&index, &fixture.cache, &phantom.public_key()).unwrap();
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &Challenge::HigherAckDebit {
                ack: Box::new(AckWitness::from_ack(&ack)),
                payer: Box::new(payer),
            }
        )
        .unwrap(),
        Verdict::Proven(ChallengeKind::HigherAckDebit)
    );

    let crate::bajillion::vector::OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = vector.lookup::<Sha256, ShaDigest>(&recipient).unwrap()
    else {
        panic!("phantom entry is present");
    };
    let sender =
        higher_entry_lookup::<Sha256, _, _>(&index, &phantom.public_key(), None, &recipient)
            .unwrap();
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &Challenge::HigherAckEntry {
                entry: Box::new(EntryWitness {
                    ack: AckWitness::from_ack(&ack),
                    recipient,
                    cumulative,
                    count,
                    opening,
                }),
                sender: Box::new(sender),
            }
        )
        .unwrap(),
        Verdict::Proven(ChallengeKind::HigherAckEntry)
    );
}

#[test]
fn infeasible_retained_entries_are_rejected() {
    let fixture = fixture(8, 4, 1);
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
    let position = 2_usize;
    let payer_public = close.rows[position].account.clone();
    let committed = &close.out_vectors[position];
    let entry = committed.entries()[0].clone();
    let crate::bajillion::vector::OutTipLookup::Present { opening, .. } = committed
        .lookup::<Sha256, ShaDigest>(&entry.recipient)
        .unwrap()
    else {
        panic!("committed entry is present");
    };
    let sender = higher_entry_lookup::<Sha256, _, _>(
        &index,
        &payer_public,
        Some(committed),
        &entry.recipient,
    )
    .unwrap();
    let result = adjudicate::<Sha256, _, _>(
        &fixture.context,
        &close.header,
        &close.roots,
        &Challenge::HigherAckEntry {
            entry: Box::new(EntryWitness {
                ack: AckWitness::from_ack(&fixture.acks[position]),
                recipient: entry.recipient,
                cumulative: 1,
                count: 2,
                opening,
            }),
            sender: Box::new(sender),
        },
    );
    assert!(matches!(
        result,
        Err(ChallengeError::Ack(AckError::InfeasibleEntry))
    ));
}

#[test]
fn forged_entry_openings_are_rejected() {
    let fixture = fixture(8, 4, 1);
    let close = fixture.prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
    let position = 2_usize;
    let (payer_public, payer_private) = fixture
        .accounts
        .iter()
        .find(|(public, _)| *public == close.rows[position].account)
        .cloned()
        .unwrap();
    let committed = &close.out_vectors[position];
    let recipient = committed.entries()[0].recipient.clone();
    let sender =
        higher_entry_lookup::<Sha256, _, _>(&index, &payer_public, Some(committed), &recipient)
            .unwrap();

    // A two-unit edge acknowledged off the close, so a bumped count stays feasible and
    // reaches the opening check.
    let mut entries = committed.entries().to_vec();
    entries[0].cumulative = 2;
    let doubled = OutVector::new(EPOCH, payer_public.clone(), entries).unwrap();
    let doubled_ack = VectorAck::sign_by_authorities(
        VectorSendBody::new(
            fixture.context.payment(),
            payer_public,
            1,
            close.rows[position].successor.cumulative_debit + 1,
            doubled.root::<Sha256, ShaDigest>().unwrap(),
        ),
        &payer_private,
        &fixture.operator,
    );

    // A genuine acknowledgment and its genuine opening never authenticate a claimed value the
    // opening does not commit, on the receipt and the challenge alike.
    let reject = |ack: &VectorAck<VerifyingKey, ShaDigest>,
                  vector: &OutVector<VerifyingKey>,
                  cumulative: u64,
                  count: u64| {
        let crate::bajillion::vector::OutTipLookup::Present { opening, .. } =
            vector.lookup::<Sha256, ShaDigest>(&recipient).unwrap()
        else {
            panic!("edge entry is present");
        };
        let receipt = EntryReceipt {
            ack: ack.clone(),
            recipient: recipient.clone(),
            cumulative,
            count,
            opening: opening.clone(),
        };
        assert!(matches!(
            receipt.verify::<Sha256>(fixture.context.payment()),
            Err(AckError::InvalidEntryOpening)
        ));
        let result = adjudicate::<Sha256, _, _>(
            &fixture.context,
            &close.header,
            &close.roots,
            &Challenge::HigherAckEntry {
                entry: Box::new(EntryWitness {
                    ack: AckWitness::from_ack(ack),
                    recipient: recipient.clone(),
                    cumulative,
                    count,
                    opening,
                }),
                sender: Box::new(sender.clone()),
            },
        );
        assert!(matches!(
            result,
            Err(ChallengeError::Ack(AckError::InvalidEntryOpening))
        ));
    };

    // The committed edge is (1, 1): claim one more unit.
    reject(&fixture.acks[position], committed, 2, 1);

    // The doubled edge is (2, 1): claim one more unit, then one more payment.
    reject(&doubled_ack, &doubled, 3, 1);
    reject(&doubled_ack, &doubled, 2, 2);
}

/// Builds a replica from a fixture's opening state vector.
fn replica_of(fixture: &Fixture) -> crate::bajillion::posted::Replica<VerifyingKey> {
    crate::bajillion::posted::Replica::genesis(fixture.cache.leaves()).unwrap()
}

/// Encodes, decodes, and validates one close as a posted corpus against `replica`, asserting
/// exact sizing and parity with the in-memory close, then rolls the replica forward.
fn posted_round_trip(
    fixture: &Fixture,
    replica: &mut crate::bajillion::posted::Replica<VerifyingKey>,
) -> Vec<u8> {
    let close = fixture.prepared.close();
    let indices = crate::bajillion::posted::resolve_indices(close).unwrap();
    let mut buf = Vec::new();
    crate::bajillion::posted::write(close, &indices, replica, &mut buf);
    assert_eq!(
        buf.len(),
        crate::bajillion::posted::encoded_size(close, replica).unwrap()
    );
    let decoded = crate::bajillion::posted::read::<Sha256, _, _>(
        &mut &buf[..],
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        replica,
        1 << 20,
        1 << 20,
    )
    .unwrap();
    assert_eq!(&decoded, close);
    validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &decoded,
        &mut TestRng::new(11),
        &Sequential,
    )
    .unwrap();
    replica.apply(&decoded);
    buf
}

#[test]
fn posted_corpus_round_trips_and_streams_across_closes() {
    // Epoch one: 20 accounts, 12 senders, 8 credited, 5 idle accounts stay unchanged. The
    // wire posts no unchanged vector, no predecessor states, and no keys for live
    // accounts, and must still decode to the exact in-memory close.
    let first = fixture_with(EPOCH, 20, 12, 8, 2, None);
    let mut replica = replica_of(&first);
    let posted_live = replica.live();
    posted_round_trip(&first, &mut replica);
    let close = first.prepared.close();
    assert_eq!(replica.live(), posted_live, "no account went inactive");

    // Epoch two: build the next close on the carried states (different senders), and post
    // it against the rolled-forward replica. Predecessors now differ from the opening
    // balance, so this passes only if the replica tracked epoch one exactly.
    let carried: alloc::collections::BTreeMap<_, _> = first
        .cache
        .leaves()
        .iter()
        .map(|leaf| (leaf.account.clone(), leaf.state))
        .chain(
            close
                .rows
                .iter()
                .map(|row| (row.account.clone(), row.successor)),
        )
        .collect();
    let second = fixture_with(EPOCH + 1, 20, 9, 6, 3, Some(&carried));
    posted_round_trip(&second, &mut replica);
}

#[test]
fn posted_corpus_rejects_divergent_replicas_and_tampering() {
    let fixture = fixture_with(EPOCH, 20, 12, 8, 2, None);
    let close = fixture.prepared.close();
    let replica = replica_of(&fixture);
    let indices = crate::bajillion::posted::resolve_indices(close).unwrap();
    let mut buf = Vec::new();
    crate::bajillion::posted::write(close, &indices, &replica, &mut buf);

    // A replica that already applied the close (or any divergent state) cannot decode a
    // valid close: derived material lands on different roots or fails derivation outright.
    let mut advanced = replica.clone();
    advanced.apply(close);
    let stale = crate::bajillion::posted::read::<Sha256, _, _>(
        &mut &buf[..],
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
        &advanced,
        1 << 20,
        1 << 20,
    );
    if let Ok(decoded) = stale {
        assert!(
            validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
                &fixture.context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                &decoded,
                &mut TestRng::new(12),
                &Sequential,
            )
            .is_err(),
            "stale replica must not decode a valid close"
        );
    }

    // Bit flips are rejected at decode or by full validation of the decoded close.
    for position in [0_usize, buf.len() / 2, buf.len() - 1] {
        let mut tampered = buf.clone();
        tampered[position] ^= 0x01;
        let rejected = match crate::bajillion::posted::read::<Sha256, _, _>(
            &mut &tampered[..],
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &replica,
            1 << 20,
            1 << 20,
        ) {
            Err(_) => true,
            Ok(decoded) => {
                decoded != *close
                    || validate_close_with_strategy::<Sha256, _, _, AckBatchVerifier, _>(
                        &fixture.context,
                        &fixture.operator_bls,
                        &fixture.deposits,
                        &fixture.withdrawals,
                        &decoded,
                        &mut TestRng::new(13),
                        &Sequential,
                    )
                    .is_err()
            }
        };
        assert!(rejected, "tampered byte {position} must not survive");
    }

    // Trailing bytes are rejected outright.
    let mut trailing = buf.clone();
    trailing.push(0);
    assert!(
        crate::bajillion::posted::read::<Sha256, _, _>(
            &mut &trailing[..],
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &replica,
            1 << 20,
            1 << 20,
        )
        .is_err()
    );
}

/// Builds one retained interval per slice from a key-sorted live-state vector.
fn intervals_of(
    leaves: &[StateLeaf<VerifyingKey>],
    slice_bits: u8,
) -> Vec<crate::bajillion::retained::Interval<VerifyingKey>> {
    let count = 1_usize << slice_bits;
    let mut buckets: Vec<Vec<StateLeaf<VerifyingKey>>> = vec![Vec::new(); count];
    for leaf in leaves {
        let slice = crate::bajillion::transition::account_slice(&leaf.account, slice_bits).unwrap()
            as usize;
        buckets[slice].push(leaf.clone());
    }
    buckets
        .into_iter()
        .map(|leaves| crate::bajillion::retained::Interval::new(leaves).unwrap())
        .collect()
}

/// Concatenates the per-slice intervals of one span into the interval its dealt slice
/// hydrates against, as a retaining assignee does.
fn span_interval(
    intervals: &[crate::bajillion::retained::Interval<VerifyingKey>],
    span: &core::ops::Range<u16>,
) -> crate::bajillion::retained::Interval<VerifyingKey> {
    let leaves = intervals[usize::from(span.start)..usize::from(span.end)]
        .iter()
        .flat_map(|interval| interval.leaves().iter().cloned())
        .collect();
    crate::bajillion::retained::Interval::new(leaves).unwrap()
}

/// Splits one advanced span interval back into its per-slice intervals.
fn split_interval(
    intervals: &mut [crate::bajillion::retained::Interval<VerifyingKey>],
    span: &core::ops::Range<u16>,
    advanced: &crate::bajillion::retained::Interval<VerifyingKey>,
    slice_bits: u8,
) {
    let mut buckets: Vec<Vec<StateLeaf<VerifyingKey>>> =
        vec![Vec::new(); usize::from(span.end - span.start)];
    for leaf in advanced.leaves() {
        let slice = crate::bajillion::transition::account_slice(&leaf.account, slice_bits).unwrap();
        assert!(span.contains(&slice), "advanced leaf left its span");
        buckets[usize::from(slice - span.start)].push(leaf.clone());
    }
    for (offset, leaves) in buckets.into_iter().enumerate() {
        intervals[usize::from(span.start) + offset] =
            crate::bajillion::retained::Interval::new(leaves).unwrap();
    }
}

/// Deals, strips, hydrates, validates, and advances every requested span of a close
/// against retained per-slice intervals, asserting that the operator's dealt wire is the
/// stripped slice's wire and that hydration reproduces the full slice, and returning
/// (dealt bytes, full bytes).
fn dealt_round_trip(
    fixture: &Fixture,
    intervals: &mut [crate::bajillion::retained::Interval<VerifyingKey>],
    spans: &[core::ops::Range<u16>],
) -> (usize, usize) {
    let close = fixture.prepared.close();
    let slice_bits = fixture.context.assignment().slice_bits();
    let slices = fixture
        .prepared
        .assemble_slices(&fixture.cache, spans, &Sequential)
        .unwrap();
    let dealings = fixture
        .prepared
        .deal(&fixture.cache, spans, &Sequential)
        .unwrap();
    let mut dealt_bytes = 0;
    let mut full_bytes = 0;
    for slice in slices {
        let span = slice.span.clone();
        full_bytes += slice.encoded_size();
        assert_eq!(slice.encode().len(), slice.encoded_size());
        let expected = slice.clone();
        let dealt = crate::bajillion::retained::DealtSlice::strip(slice, slice_bits);
        assert_eq!(dealt.span(), &span);
        dealt_bytes += dealt.encode_size();

        // The operator's wire is the witness segment followed by one chunk per covered
        // slice, and it is byte for byte the stripped slice's encoding.
        let encoded = dealt.encode();
        assert_eq!(encoded.len(), dealt.encode_size());
        let wire = dealings.encode_span(&span);
        assert_eq!(
            wire.segments().len(),
            usize::from(span.end - span.start) + 1
        );
        assert_eq!(wire.encode_size(), encoded.len());
        assert_eq!(dealings.span_size(&span), encoded.len());
        assert_eq!(
            wire.encode(),
            encoded,
            "dealt wire must match the stripped slice"
        );

        // The dealt wire round-trips under the adversarial decode bounds before hydration.
        let decoded = crate::bajillion::retained::decode_dealt_slice_bounded::<
            VerifyingKey,
            ShaDigest,
        >(encoded.as_ref(), *fixture.context.limits(), encoded.len())
        .unwrap();
        assert_eq!(decoded, dealt, "dealt slice wire must round-trip exactly");
        let mut interval = span_interval(intervals, &span);
        let hydrated = decoded
            .hydrate::<Sha256>(
                &interval,
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
            )
            .unwrap();
        assert_eq!(
            hydrated, expected,
            "hydration must reproduce the dealt slice"
        );
        validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            &hydrated,
            &mut TestRng::new(17),
        )
        .unwrap();
        interval.advance(&hydrated);
        split_interval(intervals, &span, &interval, slice_bits);
    }
    (dealt_bytes, full_bytes)
}

/// Every slice as its own span.
fn single_spans(slice_bits: u8) -> Vec<core::ops::Range<u16>> {
    (0..1_u16 << slice_bits)
        .map(|slice| slice..slice + 1)
        .collect()
}

#[test]
fn dealt_slices_hydrate_validate_and_stream() {
    // Epoch one: 20 accounts, 12 senders, 5 idle. Retained intervals come from the
    // predecessor state, the dealt slices carry no unchanged leaves, and hydration must
    // reproduce the full slice byte for byte, one span per slice.
    let first = fixture_with(EPOCH, 20, 12, 8, 2, None);
    let slice_bits = first.context.assignment().slice_bits();
    let slice_count = 1_u16 << slice_bits;
    let whole = 0..slice_count;
    let mut intervals = intervals_of(first.cache.leaves(), slice_bits);
    let stale = intervals.clone();
    let (dealt, full) = dealt_round_trip(&first, &mut intervals, &single_spans(slice_bits));
    assert!(
        dealt < full,
        "dealt slices must be smaller: {dealt} vs {full}"
    );

    // Advanced intervals must equal the successor state, sliced.
    let close = first.prepared.close();
    let carried: alloc::collections::BTreeMap<_, _> = first
        .cache
        .leaves()
        .iter()
        .map(|leaf| (leaf.account.clone(), leaf.state))
        .chain(
            close
                .rows
                .iter()
                .map(|row| (row.account.clone(), row.successor)),
        )
        .collect();
    let successor = intervals_of(
        &carried
            .iter()
            .filter(|(_, state)| state.active)
            .map(|(account, state)| StateLeaf {
                account: account.clone(),
                state: *state,
            })
            .collect::<Vec<_>>(),
        slice_bits,
    );
    assert_eq!(intervals, successor);

    // Epoch two on the carried states, with different senders, dealt as two multi-slice
    // spans (a wrapped dealing): hydration succeeds only if every interval advanced exactly,
    // and the span witness must come out smaller than the per-slice one.
    let second = fixture_with(EPOCH + 1, 20, 9, 6, 3, Some(&carried));
    let split = slice_count / 2 + 1;
    let spans = [split..slice_count, 0..split];
    let mut advanced = intervals.clone();
    let (span_dealt, _) = dealt_round_trip(&second, &mut advanced, &spans);
    let mut per_slice = intervals.clone();
    let (single_dealt, _) = dealt_round_trip(&second, &mut per_slice, &single_spans(slice_bits));
    assert!(
        span_dealt < single_dealt,
        "spans must amortize the witness: {span_dealt} vs {single_dealt}"
    );
    assert_eq!(advanced, per_slice);
    let mut whole_span = intervals.clone();
    let (whole_dealt, _) =
        dealt_round_trip(&second, &mut whole_span, core::slice::from_ref(&whole));
    assert!(whole_dealt < span_dealt, "{whole_dealt} vs {span_dealt}");
    assert_eq!(whole_span, per_slice);

    // A stale interval (epoch one's predecessor state) hydrates epoch two's whole-close span
    // into material that misses the certified roots.
    let second_slices = second
        .prepared
        .assemble_slices(&second.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap();
    let second_close = second.prepared.close();
    let mut rejected = false;
    for slice in second_slices {
        let span = slice.span.clone();
        let expected = slice.clone();
        let dealt = crate::bajillion::retained::DealtSlice::strip(slice, slice_bits);
        match dealt.hydrate::<Sha256>(
            &span_interval(&stale, &span),
            &second.context,
            &second.deposits,
            &second.withdrawals,
        ) {
            Err(_) => rejected = true,
            Ok(hydrated) => {
                if hydrated != expected
                    && validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
                        &second.context,
                        &second.operator_bls,
                        &second.deposits,
                        &second.withdrawals,
                        &second_close.header,
                        &second_close.roots,
                        &hydrated,
                        &mut TestRng::new(19),
                    )
                    .is_err()
                {
                    rejected = true;
                }
            }
        }
    }
    assert!(rejected, "stale intervals must not validate");
}

/// A span's holders check every covered boundary, not only the two at its ends: an operator
/// that commits a wrong internal boundary consistently (coverage root and header rebuilt over
/// it) is rejected by the span's validation, at the internal check rather than the opening.
#[test]
fn run_rejects_consistently_committed_wrong_internal_boundary() {
    let base = fixture_with(EPOCH, 20, 12, 8, 2, None);
    let slice_count = base.context.assignment().slice_count();
    let whole = 0..slice_count;
    let boundaries = base
        .prepared
        .assemble_slices(&base.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap()
        .remove(0)
        .coverage
        .boundaries;
    let rows = boundaries.last().unwrap().change;

    // An internal boundary with rows and edges on both sides, so every corrupted field is
    // load-bearing and its two accumulator checksums differ.
    let index = (1..usize::from(slice_count))
        .find(|index| {
            let boundary = &boundaries[*index];
            boundary.change > 0
                && boundary.change < rows
                && boundary.prefix.out_count > 0
                && boundary.out_check != boundary.in_check
        })
        .expect("the fixture has a load-bearing internal boundary");

    type Corrupt = fn(&mut crate::bajillion::transition::SliceBoundary);
    type Expected = fn(&CloseError) -> bool;
    let cases: [(&str, Corrupt, Expected); 4] = [
        (
            "predecessor position",
            |boundary| boundary.predecessor += 1,
            |error| matches!(error, CloseError::SliceCoverage),
        ),
        (
            "change position",
            |boundary| boundary.change -= 1,
            |error| matches!(error, CloseError::SliceCoverage),
        ),
        (
            "prefix",
            |boundary| boundary.prefix.debit += 1,
            |error| matches!(error, CloseError::Prefix),
        ),
        (
            "checksums",
            |boundary| core::mem::swap(&mut boundary.out_check, &mut boundary.in_check),
            |error| matches!(error, CloseError::Prefix),
        ),
    ];
    for (name, corrupt, expected) in cases {
        let mut fixture = fixture_with(EPOCH, 20, 12, 8, 2, None);
        fixture
            .prepared
            .corrupt_boundary::<Sha256>(&fixture.context, index, corrupt);
        let close = fixture.prepared.close();
        let slice = fixture
            .prepared
            .assemble_slices(&fixture.cache, core::slice::from_ref(&whole), &Sequential)
            .unwrap()
            .remove(0);
        let error = validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            &slice,
            &mut TestRng::new(23),
        )
        .expect_err(name);
        assert!(expected(&error), "{name}: {error:?}");
    }

    // The per-slice aggregates are pinned to their own slices: swapping two present
    // aggregates inside an otherwise valid span fails the operator countersignature check.
    let mut slice = base
        .prepared
        .assemble_slices(&base.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap()
        .remove(0);
    let present = slice
        .operator_aggregates
        .iter()
        .enumerate()
        .filter_map(|(index, aggregate)| aggregate.as_ref().map(|_| index))
        .collect::<Vec<_>>();
    assert!(present.len() >= 2, "the fixture sends from several slices");
    slice.operator_aggregates.swap(present[0], present[1]);
    let close = base.prepared.close();
    assert!(matches!(
        validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
            &base.context,
            &base.operator_bls,
            &base.deposits,
            &base.withdrawals,
            &close.header,
            &close.roots,
            &slice,
            &mut TestRng::new(29),
        ),
        Err(CloseError::Ack(AckError::InvalidOperatorSignature))
    ));
}

/// A close with created, deleted, and paid-out accounts: deposits open fresh accounts, full
/// withdrawals close live ones (including a credited one), an amount withdrawal leaves one
/// live, a deposit lands on an idle account, and a fresh recipient without a deposit is
/// paid out. Successor positions therefore shift against predecessor positions inside every
/// span, and hydration must resolve full-key rows next to rank gaps.
fn churn_fixture() -> Fixture {
    const LIVE: usize = 24;
    const SENDERS: usize = 10;
    const OUT_DEGREE: usize = 2;
    let epoch = EPOCH;
    let mut live = (0..LIVE)
        .map(|index| {
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + index as u64);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    live.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let fresh = (0..4_u64)
        .map(|index| {
            let private = SigningKey::from_seed(ACCOUNT_SEED_START + 1_000 + index);
            (private.public_key(), private)
        })
        .collect::<Vec<_>>();
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let operator_bls_private = BlsPrivate::new(Scalar::from(OPERATOR_SEED));
    let operator_bls =
        compute_public::<crate::bajillion::transition::OperatorVariant>(&operator_bls_private);
    let opening = AccountState {
        balance: OPENING_BALANCE,
        active: true,
        ..AccountState::default()
    };
    let cache = StateCache::new::<Sha256>(
        live.iter()
            .map(|(public, _)| StateLeaf {
                account: public.clone(),
                state: opening,
            })
            .collect(),
    )
    .unwrap();
    let deployment = Sha256::hash(&[b"close-test-deployment"]);

    // Deposits: three fresh accounts and one idle live account.
    let deposits = DepositBatch::new(vec![
        DepositRecord::new(fresh[0].0.clone(), 50).unwrap(),
        DepositRecord::new(fresh[1].0.clone(), 70).unwrap(),
        DepositRecord::new(fresh[2].0.clone(), 20).unwrap(),
        DepositRecord::new(live[16].0.clone(), 10).unwrap(),
    ])
    .unwrap();

    // Withdrawals: two idle closes, one credited close, one partial amount.
    let withdraw = |index: usize, action: WithdrawalAction| {
        SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            bytes::Bytes::from_static(b"destination"),
            action,
            99,
            &live[index].1,
        )
    };
    let withdrawals = WithdrawalBatch::new(vec![
        withdraw(12, WithdrawalAction::Close),
        withdraw(13, WithdrawalAction::Close),
        withdraw(5, WithdrawalAction::Close),
        withdraw(
            15,
            WithdrawalAction::Amount(core::num::NonZeroU64::new(30).unwrap()),
        ),
    ])
    .unwrap();
    let assignment = Assignment::new(Sha256::hash(&[b"close-test-committee"]), 3).unwrap();
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

    // Recipients: six live accounts (one of them closing), a deposited fresh account, and
    // a fresh account with no deposit (paid out). Sender i pays recipients (i + j + 1) mod 8.
    let recipients = live[..6]
        .iter()
        .chain([&fresh[2], &fresh[3]])
        .map(|(public, _)| public.clone())
        .collect::<Vec<_>>();
    let mut candidates =
        live.iter()
            .map(|(public, private)| (public.clone(), private.clone(), opening))
            .chain(fresh.iter().map(|(public, private)| {
                (public.clone(), private.clone(), AccountState::default())
            }))
            .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut vectors: alloc::collections::BTreeMap<VerifyingKey, OutVector<VerifyingKey>> =
        alloc::collections::BTreeMap::new();
    let mut incoming: alloc::collections::BTreeMap<
        VerifyingKey,
        Vec<TransposeEntry<VerifyingKey>>,
    > = alloc::collections::BTreeMap::new();
    for (index, (public, _)) in live.iter().enumerate().take(SENDERS) {
        let mut entries = (0..OUT_DEGREE)
            .map(|j| OutEntry {
                recipient: recipients[(index + j + 1) % recipients.len()].clone(),
                cumulative: 1,
                count: 1,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        for entry in &entries {
            assert_ne!(entry.recipient, *public, "no self payments");
            incoming
                .entry(entry.recipient.clone())
                .or_default()
                .push(TransposeEntry {
                    recipient: entry.recipient.clone(),
                    payer: public.clone(),
                    cumulative: entry.cumulative,
                    count: entry.count,
                });
        }
        vectors.insert(
            public.clone(),
            OutVector::new(epoch, public.clone(), entries).unwrap(),
        );
    }

    let mut transpose = Vec::new();
    let mut rows = Vec::new();
    let mut out_vectors = Vec::new();
    let mut acks = Vec::new();
    let mut operator_signatures = Vec::new();
    let mut prefix = Prefix::default();
    for (public, private, predecessor) in &candidates {
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
            predecessor,
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
            predecessor: *predecessor,
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
        accounts: candidates
            .into_iter()
            .map(|(public, private, _)| (public, private))
            .collect(),
        acks,
        operator,
        operator_bls_private,
        operator_bls,
    }
}

/// The successor live state of a close, sliced like the retained intervals.
fn successor_intervals(
    fixture: &Fixture,
) -> Vec<crate::bajillion::retained::Interval<VerifyingKey>> {
    let close = fixture.prepared.close();
    let mut leaves = close.unchanged.clone();
    leaves.extend(
        close
            .rows
            .iter()
            .filter(|row| row.successor.active)
            .map(|row| StateLeaf {
                account: row.account.clone(),
                state: row.successor,
            }),
    );
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    intervals_of(&leaves, fixture.context.assignment().slice_bits())
}

#[test]
fn runs_hydrate_and_advance_through_created_and_deleted_state() {
    let fixture = churn_fixture();
    fixture
        .prepared
        .validate::<Sha256, AckBatchVerifier, _>(
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &mut TestRng::new(31),
            &Sequential,
        )
        .unwrap();
    let close = fixture.prepared.close();
    let created = close
        .rows
        .iter()
        .filter(|row| !row.predecessor.active && row.successor.active)
        .count();
    let deleted = close
        .rows
        .iter()
        .filter(|row| row.predecessor.active && !row.successor.active)
        .count();
    let paid_out = close
        .rows
        .iter()
        .filter(|row| matches!(row.output, SettlementOutput::ExternalPayout(amount) if amount > 0))
        .count();
    assert_eq!((created, deleted, paid_out), (3, 3, 1));

    // Every span shape reproduces the dealt slices and advances the per-slice intervals to
    // the successor state: singles, a wrapped pair of spans, and the whole close.
    let slice_bits = fixture.context.assignment().slice_bits();
    let slice_count = 1_u16 << slice_bits;
    let split = slice_count / 2 + 1;
    let whole = 0..slice_count;
    let shapes: [Vec<core::ops::Range<u16>>; 3] = [
        single_spans(slice_bits),
        vec![split..slice_count, 0..split],
        vec![whole],
    ];
    let expected = successor_intervals(&fixture);
    let mut dealt = Vec::new();
    for spans in &shapes {
        let mut intervals = intervals_of(fixture.cache.leaves(), slice_bits);
        let (bytes, _) = dealt_round_trip(&fixture, &mut intervals, spans);
        assert_eq!(intervals, expected, "{spans:?}");
        dealt.push(bytes);
    }
    assert!(dealt[0] > dealt[1] && dealt[1] > dealt[2], "{dealt:?}");
}

/// One consistent rewrite of a close by a Byzantine operator, applied before every root and
/// the header are recommitted over the result.
type Tamper = fn(
    &CloseContext<VerifyingKey, ShaDigest>,
    &DepositBatch<VerifyingKey>,
    &WithdrawalBatch<VerifyingKey, ShaDigest>,
    &mut Close<VerifyingKey, ShaDigest>,
    &mut Vec<StateLeaf<VerifyingKey>>,
    &mut Vec<TransposeEntry<VerifyingKey>>,
);

/// Replaces or inserts one leaf in a key-sorted state vector.
fn upsert_leaf(leaves: &mut Vec<StateLeaf<VerifyingKey>>, leaf: StateLeaf<VerifyingKey>) {
    match leaves.binary_search_by(|candidate| candidate.account.cmp(&leaf.account)) {
        Ok(position) => leaves[position] = leaf,
        Err(position) => leaves.insert(position, leaf),
    }
}

/// Rewrites every row's prefix from the row equations over the (tampered) transpose.
fn rechain_prefixes(
    context: &CloseContext<VerifyingKey, ShaDigest>,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>,
    close: &mut Close<VerifyingKey, ShaDigest>,
    transpose: &[TransposeEntry<VerifyingKey>],
) {
    let mut prefix = Prefix::default();
    let mut cursor = 0;
    for (row, vector) in close.rows.iter_mut().zip(&close.out_vectors) {
        let start = cursor;
        while transpose
            .get(cursor)
            .is_some_and(|entry| entry.recipient == row.account)
        {
            cursor += 1;
        }
        let delta = validate_row::<Sha256, _, _>(
            context,
            deposits,
            withdrawals,
            row,
            vector,
            &transpose[start..cursor],
        )
        .expect("tampered rows stay internally consistent");
        prefix = prefix.checked_extend(delta).unwrap();
        row.prefix = prefix;
    }
    assert_eq!(cursor, transpose.len());
}

/// Credits one unit to a live, non-withdrawing recipient from a payer that never signed for
/// it, keeping the recipient's own equations and every prefix consistent: the fraud is
/// visible only where the two edge orderings are compared.
fn phantom_credit(
    context: &CloseContext<VerifyingKey, ShaDigest>,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>,
    close: &mut Close<VerifyingKey, ShaDigest>,
    successor: &mut Vec<StateLeaf<VerifyingKey>>,
    transpose: &mut Vec<TransposeEntry<VerifyingKey>>,
) {
    let row = close
        .rows
        .iter_mut()
        .find(|row| {
            row.successor.active
                && matches!(row.output, SettlementOutput::None)
                && transpose.iter().any(|entry| entry.recipient == row.account)
        })
        .expect("the fixture credits a live account that keeps its balance");
    row.successor.balance += 1;
    row.successor.cumulative_credit += 1;
    row.successor.receipt_count += 1;
    upsert_leaf(
        successor,
        StateLeaf {
            account: row.account.clone(),
            state: row.successor,
        },
    );
    let entry = TransposeEntry {
        recipient: row.account.clone(),
        payer: SigningKey::from_seed(ACCOUNT_SEED_START + 6_000).public_key(),
        cumulative: 1,
        count: 1,
    };
    let position = transpose
        .binary_search_by(|candidate| {
            (&candidate.recipient, &candidate.payer).cmp(&(&entry.recipient, &entry.payer))
        })
        .expect_err("the phantom payer is new");
    transpose.insert(position, entry);
    rechain_prefixes(context, deposits, withdrawals, close, transpose);
}

#[test]
fn byzantine_operator_cannot_certify_invalid_runs() {
    // Each rewrite is pinned to the first check that catches it in a whole-close span: a
    // successor vector whose length disagrees with the disclosed leaves fails the state range's
    // derived count, a rewritten predecessor side fails the predecessor opening, a rewritten
    // successor balance or a live closed account fails its row balance equation (the
    // derived withdrawal amount enters that equation before the output is compared), and a
    // credit without a debit reaches the terminal accumulator equality.
    type Expected = fn(&CloseError) -> bool;
    let cases: [(&str, Tamper, Expected); 7] = [
        (
            "minted successor leaf without a row",
            |_, _, _, _, successor, _| {
                upsert_leaf(
                    successor,
                    StateLeaf {
                        account: SigningKey::from_seed(ACCOUNT_SEED_START + 5_000).public_key(),
                        state: AccountState {
                            balance: 5,
                            active: true,
                            ..AccountState::default()
                        },
                    },
                );
            },
            |error| matches!(error, CloseError::SliceStateRange),
        ),
        (
            "silently deleted unchanged leaf",
            |_, _, _, close, successor, _| {
                let victim = close.unchanged[0].account.clone();
                successor.retain(|leaf| leaf.account != victim);
            },
            |error| matches!(error, CloseError::SliceStateRange),
        ),
        (
            "edited unchanged balance",
            |_, _, _, close, successor, _| {
                close.unchanged[0].state.balance += 1;
                upsert_leaf(successor, close.unchanged[0].clone());
            },
            |error| matches!(error, CloseError::Commitment(_)),
        ),
        (
            "balance moved between two rows",
            |_, _, _, close, successor, _| {
                let active = close
                    .rows
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| row.successor.active && row.successor.balance > 1)
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                let (from, to) = (active[0], active[active.len() - 1]);
                close.rows[from].successor.balance -= 1;
                close.rows[to].successor.balance += 1;
                for index in [from, to] {
                    let row = &close.rows[index];
                    upsert_leaf(
                        successor,
                        StateLeaf {
                            account: row.account.clone(),
                            state: row.successor,
                        },
                    );
                }
            },
            |error| matches!(error, CloseError::BalanceEquation),
        ),
        (
            "wrong predecessor for a live row",
            |_, _, _, close, successor, _| {
                let row = close
                    .rows
                    .iter_mut()
                    .find(|row| row.predecessor.active && row.successor.active)
                    .unwrap();
                row.predecessor.balance += 1;
                row.successor.balance += 1;
                upsert_leaf(
                    successor,
                    StateLeaf {
                        account: row.account.clone(),
                        state: row.successor,
                    },
                );
            },
            |error| matches!(error, CloseError::Commitment(_)),
        ),
        (
            "closed account kept alive",
            |_, _, _, close, successor, _| {
                let row = close
                    .rows
                    .iter_mut()
                    .find(|row| {
                        row.predecessor.active
                            && !row.successor.active
                            && matches!(row.output, SettlementOutput::Withdrawal(_))
                    })
                    .unwrap();
                let SettlementOutput::Withdrawal(amount) = row.output else {
                    unreachable!("selected a withdrawal row");
                };
                row.output = SettlementOutput::Withdrawal(amount - 1);
                row.successor = AccountState {
                    balance: 1,
                    active: true,
                    ..row.successor
                };
                upsert_leaf(
                    successor,
                    StateLeaf {
                        account: row.account.clone(),
                        state: row.successor,
                    },
                );
            },
            |error| matches!(error, CloseError::BalanceEquation),
        ),
        ("credit without a debit", phantom_credit, |error| {
            matches!(error, CloseError::MultisetMismatch)
        }),
    ];
    for (name, tamper, expected) in cases {
        let mut fixture = churn_fixture();
        let Fixture {
            prepared,
            context,
            cache,
            deposits,
            withdrawals,
            operator_bls,
            ..
        } = &mut fixture;
        prepared.recommit::<Sha256>(
            context,
            cache,
            withdrawals,
            |close, successor, transpose| {
                tamper(context, deposits, withdrawals, close, successor, transpose)
            },
        );
        let close = prepared.close();
        let slice_count = context.assignment().slice_count();
        let whole = 0..slice_count;
        let slice = prepared
            .assemble_slices(cache, core::slice::from_ref(&whole), &Sequential)
            .unwrap()
            .remove(0);
        let error = validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
            context,
            operator_bls,
            deposits,
            withdrawals,
            &close.header,
            &close.roots,
            &slice,
            &mut TestRng::new(37),
        )
        .expect_err(name);
        assert!(expected(&error), "{name}: {error:?}");

        // The dealt form, whether stripped from the slice or dealt by the operator's
        // chunked path, decodes and hydrates to the same rejected span or fails earlier.
        let slice_bits = context.assignment().slice_bits();
        let intervals = intervals_of(cache.leaves(), slice_bits);
        let interval = span_interval(&intervals, &whole);
        let stripped = crate::bajillion::retained::DealtSlice::strip(slice.clone(), slice_bits);
        let dealt = prepared
            .deal(cache, core::slice::from_ref(&whole), &Sequential)
            .unwrap()
            .encode_span(&whole)
            .encode();
        assert_eq!(dealt, stripped.encode(), "{name}");
        assert!(
            certify_dealt(&fixture, &interval, dealt.as_ref()).is_err(),
            "{name}: the dealt span was certified"
        );
    }
}

/// The stage at which a dealt wire was rejected on its way to certification.
#[derive(Debug, Eq, PartialEq)]
enum Rejected {
    Decode,
    Hydrate,
    Validate,
}

/// Decodes one dealt wire under the fixture's limits and hydrates it against a retained
/// interval, as a holder does before validating.
fn hydrate_dealt(
    fixture: &Fixture,
    interval: &Interval<VerifyingKey>,
    encoded: &[u8],
) -> Result<Result<ProofSlice<VerifyingKey, ShaDigest>, commonware_codec::Error>, Rejected> {
    let decoded =
        crate::bajillion::retained::decode_dealt_slice_bounded::<VerifyingKey, ShaDigest>(
            encoded,
            *fixture.context.limits(),
            encoded.len(),
        )
        .map_err(|_| Rejected::Decode)?;
    Ok(decoded.hydrate::<Sha256>(
        interval,
        &fixture.context,
        &fixture.deposits,
        &fixture.withdrawals,
    ))
}

/// Decodes, hydrates, and validates one dealt wire against a retained interval, as a
/// holder does before voting.
fn certify_dealt(
    fixture: &Fixture,
    interval: &Interval<VerifyingKey>,
    encoded: &[u8],
) -> Result<ProofSlice<VerifyingKey, ShaDigest>, Rejected> {
    let close = fixture.prepared.close();
    let hydrated = hydrate_dealt(fixture, interval, encoded)?.map_err(|_| Rejected::Hydrate)?;
    validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
        &fixture.context,
        &fixture.operator_bls,
        &fixture.deposits,
        &fixture.withdrawals,
        &close.header,
        &close.roots,
        &hydrated,
        &mut TestRng::new(47),
    )
    .map_err(|_| Rejected::Validate)?;
    Ok(hydrated)
}

/// Every span's chunk segments are the covered slices' single-span chunks, and a span
/// whose first slice has no rows still decodes and hydrates: the rank gap of a chunk's
/// first row counts from its own slice's first retained leaf, not from the previous chunk.
#[test]
fn dealt_chunks_do_not_depend_on_their_span() {
    let fixture = sparse_fixture(20, 3, 2, 2);
    let slice_bits = fixture.context.assignment().slice_bits();
    let slice_count = fixture.context.assignment().slice_count();
    let whole = 0..slice_count;
    let singles = single_spans(slice_bits);
    let boundaries = fixture
        .prepared
        .assemble_slices(&fixture.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap()
        .remove(0)
        .coverage
        .boundaries;
    let delta = |slice: u16, position: fn(&crate::bajillion::transition::SliceBoundary) -> u32| {
        position(&boundaries[usize::from(slice) + 1]) - position(&boundaries[usize::from(slice)])
    };
    let rows = |slice: u16| delta(slice, |boundary| boundary.change);
    let leaves = |slice: u16| delta(slice, |boundary| boundary.predecessor);

    // A span opening on a slice with leaves but no rows and closing on one with rows, and
    // its mirror: the second chunk's first gap counts from its own slice's first leaf.
    let leading = (0..slice_count - 1)
        .find(|slice| rows(*slice) == 0 && leaves(*slice) != 0 && rows(slice + 1) != 0)
        .map(|slice| slice..slice + 2)
        .expect("the fixture has a rowless slice before a slice with rows");
    let trailing = (1..slice_count)
        .find(|slice| rows(*slice) == 0 && leaves(*slice) != 0 && rows(slice - 1) != 0)
        .map(|slice| slice - 1..slice + 1)
        .expect("the fixture has a rowless slice after a slice with rows");
    let mut spans = singles.clone();
    spans.extend([whole.clone(), leading.clone(), trailing.clone()]);
    let dealings = fixture
        .prepared
        .deal(&fixture.cache, &spans, &Sequential)
        .unwrap();
    let chunks = singles
        .iter()
        .map(|span| dealings.encode_span(span).segments()[1].clone())
        .collect::<Vec<_>>();
    for span in &spans {
        let wire = dealings.encode_span(span);
        let (witness, dealt) = wire.segments().split_first().unwrap();

        // An API contract pin: a span's chunk segments are the covered slices' single-span
        // chunks, shared buffers today and equal bytes however the wire is assembled.
        assert_eq!(
            dealt,
            &chunks[usize::from(span.start)..usize::from(span.end)]
        );
        assert_eq!(
            witness.len() + dealt.iter().map(bytes::Bytes::len).sum::<usize>(),
            dealings.span_size(span)
        );
    }
    for spans in [singles, vec![whole], vec![leading], vec![trailing]] {
        dealt_round_trip(
            &fixture,
            &mut intervals_of(fixture.cache.leaves(), slice_bits),
            &spans,
        );
    }
}

/// A chunk moved to another slice's position or altered in place is caught on the way to
/// certification with a typed error, while the untouched wire certifies.
#[test]
fn tampered_dealt_chunks_are_rejected() {
    let fixture = churn_fixture();
    let slice_bits = fixture.context.assignment().slice_bits();
    let slice_count = fixture.context.assignment().slice_count();
    let whole = 0..slice_count;
    let intervals = intervals_of(fixture.cache.leaves(), slice_bits);
    let interval = span_interval(&intervals, &whole);
    let wire = fixture
        .prepared
        .deal(&fixture.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap()
        .encode_span(&whole);
    let segments = wire.segments();
    certify_dealt(&fixture, &interval, wire.encode().as_ref()).unwrap();
    let concat = |segments: &[bytes::Bytes]| {
        segments
            .iter()
            .flat_map(|segment| segment.iter().copied())
            .collect::<Vec<u8>>()
    };

    // Swap the two largest chunks, then swap a chunk with an empty one.
    let mut by_size = (1..segments.len()).collect::<Vec<_>>();
    by_size.sort_by_key(|index| core::cmp::Reverse(segments[*index].len()));
    let (largest, second) = (by_size[0], by_size[1]);
    let smallest = *by_size.last().unwrap();
    assert!(segments[second].len() > 1 && segments[smallest].len() == 1);
    for (from, to) in [(largest, second), (largest, smallest)] {
        let mut swapped = segments.to_vec();
        swapped.swap(from, to);
        let verdict = certify_dealt(&fixture, &interval, &concat(&swapped));
        assert!(
            verdict.is_err(),
            "chunks {from} and {to} swapped: {verdict:?}"
        );
    }

    // Flip one byte at a stride through the second-largest chunk, starting at its first row
    // tag: tags and counts fail decoding, signatures and amounts fail validation, and
    // nothing certifies.
    let mut rejected = [false; 3];
    for offset in (0..segments[second].len()).step_by(13) {
        let mut tampered = segments.to_vec();
        let mut chunk = tampered[second].to_vec();
        chunk[offset] ^= 0x40;
        tampered[second] = chunk.into();
        match certify_dealt(&fixture, &interval, &concat(&tampered)) {
            Err(Rejected::Decode) => rejected[0] = true,
            Err(Rejected::Hydrate) => rejected[1] = true,
            Err(Rejected::Validate) => rejected[2] = true,
            Ok(_) => panic!("chunk byte {offset} flipped and certified"),
        }
    }
    assert!(rejected[0] && rejected[2], "{rejected:?}");

    // A rank gap that stays within the retained count but runs past its own slice's
    // leaves decodes and is rejected by hydration: chunks resolve against their slice.
    // The tampered chunk opens with a live row in a slice holding fewer than every
    // retained leaf, so that slice's leaf count is the smallest gap running past it, and
    // with at most 128 retained leaves every gap below the count is a one-byte varint
    // that the tampered byte replaces whole.
    let retained = interval.leaves().len();
    assert!(retained <= 128, "{retained} retained leaves");
    let live = (1..segments.len())
        .find(|&index| {
            segments[index].len() > 1
                && (segments[index][0] & 0b10) == 0
                && intervals[index - 1].leaves().len() < retained
        })
        .expect("a chunk opens with a live row in a slice without every leaf");
    let mut tampered = segments.to_vec();
    let mut chunk = tampered[live].to_vec();
    chunk[1] = u8::try_from(intervals[live - 1].leaves().len()).unwrap();
    tampered[live] = chunk.into();
    assert!(matches!(
        hydrate_dealt(&fixture, &interval, &concat(&tampered)),
        Ok(Err(commonware_codec::Error::Invalid(
            "DealtSlice",
            "rank gap beyond the slice interval"
        )))
    ));
}

/// A witness whose retained count is not the coverage's predecessor position delta fails
/// decoding, so a peer cannot loosen the rank-gap and state-range decode bounds by lying.
#[test]
fn mismatched_retained_count_is_rejected() {
    let fixture = churn_fixture();
    let slice_count = fixture.context.assignment().slice_count();
    let whole = 0..slice_count;
    let wire = fixture
        .prepared
        .deal(&fixture.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap()
        .encode_span(&whole)
        .encode();
    let decode = |encoded: &[u8]| {
        crate::bajillion::retained::decode_dealt_slice_bounded::<VerifyingKey, ShaDigest>(
            encoded,
            *fixture.context.limits(),
            encoded.len(),
        )
    };
    decode(&wire).unwrap();

    // The whole span retains every predecessor leaf, and the count leads the witness.
    let retained = u32::try_from(fixture.cache.leaves().len()).unwrap();
    for count in [retained + 1, retained - 1] {
        let count = count.encode();
        let mut tampered = wire.to_vec();
        tampered[..count.len()].copy_from_slice(&count);
        assert!(matches!(
            decode(&tampered),
            Err(commonware_codec::Error::Invalid(
                "DealtSlice",
                "retained count does not match the coverage"
            ))
        ));
    }
}

/// Conservation is enforced by the holders of the terminal slice: a credit with no debit
/// keeps every interior slice consistent, and the span ending at the last boundary is the
/// one that rejects it, which quorum intersection makes sufficient.
#[test]
fn credit_without_debit_is_caught_at_the_terminal_boundary() {
    let mut fixture = churn_fixture();
    let Fixture {
        prepared,
        context,
        cache,
        deposits,
        withdrawals,
        operator_bls,
        ..
    } = &mut fixture;
    prepared.recommit::<Sha256>(
        context,
        cache,
        withdrawals,
        |close, successor, transpose| {
            phantom_credit(context, deposits, withdrawals, close, successor, transpose)
        },
    );
    let close = prepared.close();
    let slice_count = context.assignment().slice_count();
    let singles = single_spans(context.assignment().slice_bits());
    let slices = prepared
        .assemble_slices(cache, &singles, &Sequential)
        .unwrap();
    for slice in &slices {
        let verdict = validate_slice::<Sha256, _, _, AckBatchVerifier, _>(
            context,
            operator_bls,
            deposits,
            withdrawals,
            &close.header,
            &close.roots,
            slice,
            &mut TestRng::new(43),
        );
        if slice.span.end == slice_count {
            assert!(
                matches!(verdict, Err(CloseError::MultisetMismatch)),
                "{verdict:?}"
            );
        } else {
            verdict.unwrap();
        }
    }
}

/// The whole-close constructors a span index must reproduce byte for byte.
struct Whole<'a> {
    fixture: &'a Fixture,
    index: ChallengeIndex<VerifyingKey, ShaDigest>,
    successor: StateCache<VerifyingKey, ShaDigest>,
    transpose: Vec<TransposeEntry<VerifyingKey>>,
    transpose_tree: commitment::Tree<ShaDigest>,
}

impl<'a> Whole<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let mut leaves = close.unchanged.clone();
        leaves.extend(
            close
                .rows
                .iter()
                .filter(|row| row.successor.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: row.successor,
                }),
        );
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let successor = StateCache::new::<Sha256>(leaves).unwrap();
        assert_eq!(successor.root(), close.roots.successor);
        let transpose = close.rebuild_transpose().unwrap();
        let mut builder =
            commitment::Builder::<Sha256>::new(VectorKind::Transpose, transpose.len() as u32)
                .unwrap();
        builder.add_values(&transpose, &Sequential).unwrap();
        let transpose_tree = builder.build(&Sequential).unwrap();
        assert_eq!(transpose_tree.root(), close.roots.transpose);
        Self {
            fixture,
            index,
            successor,
            transpose,
            transpose_tree,
        }
    }
}

/// How many of each answer shape a span-index sweep exercised.
#[derive(Debug, Default)]
struct Tally {
    predecessor: usize,
    successor: usize,
    changed: usize,
    unchanged: usize,
    unknown: usize,
    entries: usize,
    no_entries: usize,
    withdrawals: usize,
    payouts: usize,
    credits: usize,
    not_held: usize,
}

impl Tally {
    fn add(&mut self, other: &Self) {
        self.predecessor += other.predecessor;
        self.successor += other.successor;
        self.changed += other.changed;
        self.unchanged += other.unchanged;
        self.unknown += other.unknown;
        self.entries += other.entries;
        self.no_entries += other.no_entries;
        self.withdrawals += other.withdrawals;
        self.payouts += other.payouts;
        self.credits += other.credits;
        self.not_held += other.not_held;
    }
}

/// Asserts every span-index answer for one held account equals the whole-close
/// constructor's answer and verifies against the close roots.
fn assert_served(
    whole: &Whole<'_>,
    served: &SpanIndex<'_, VerifyingKey, ShaDigest>,
    account: &VerifyingKey,
    recipients: &[VerifyingKey],
) -> Tally {
    let fixture = whole.fixture;
    let close = fixture.prepared.close();
    let roots = &close.roots;
    let predecessor_root = fixture.context.predecessor_root();
    let mut tally = Tally::default();

    match fixture.cache.opening(account) {
        Ok(expected) => {
            let opening = served.predecessor_opening::<Sha256>(account).unwrap();
            assert_eq!(opening, expected);
            opening
                .proof
                .verify::<Sha256>(
                    VectorKind::State,
                    predecessor_root,
                    opening.leaf.encode().as_ref(),
                )
                .unwrap();
            tally.predecessor += 1;
        }
        Err(_) => assert!(matches!(
            served.predecessor_opening::<Sha256>(account),
            Err(ServeError::Absent)
        )),
    }
    match whole.successor.opening(account) {
        Ok(expected) => {
            let opening = served.successor_opening::<Sha256>(account).unwrap();
            assert_eq!(opening, expected);
            opening
                .proof
                .verify::<Sha256>(
                    VectorKind::State,
                    &roots.successor,
                    opening.leaf.encode().as_ref(),
                )
                .unwrap();
            tally.successor += 1;
        }
        Err(_) => assert!(matches!(
            served.successor_opening::<Sha256>(account),
            Err(ServeError::Absent)
        )),
    }

    let expected = account_lookup::<Sha256, _, _>(&whole.index, &fixture.cache, account).unwrap();
    let lookup = served.account_lookup::<Sha256>(account).unwrap();
    assert_eq!(lookup, expected);
    lookup
        .resolve::<Sha256>(predecessor_root, &roots.change, account)
        .unwrap();
    match &lookup {
        AccountLookup::Present(_) => tally.changed += 1,
        AccountLookup::Absent { state, .. } => match **state {
            StateLookup::Present(_) => tally.unchanged += 1,
            StateLookup::Absent(_) => tally.unknown += 1,
        },
    }

    match whole.index.change_parts(account).unwrap() {
        ChangeParts::Present { leaf, proof } => {
            let opening = served.change_opening::<Sha256>(account).unwrap();
            assert_eq!(
                opening,
                ChangeOpening {
                    value: leaf.value(),
                    proof,
                }
            );
            opening
                .proof
                .verify::<Sha256>(
                    VectorKind::Change,
                    &roots.change,
                    leaf.guard::<Sha256>().encode().as_ref(),
                )
                .unwrap();
        }
        ChangeParts::Absent { .. } => assert!(matches!(
            served.change_opening::<Sha256>(account),
            Err(ServeError::Unchanged)
        )),
    }

    let out_vector = close
        .rows
        .binary_search_by(|row| row.account.cmp(account))
        .ok()
        .map(|index| &close.out_vectors[index]);
    for recipient in recipients {
        let expected =
            higher_entry_lookup::<Sha256, _, _>(&whole.index, account, out_vector, recipient)
                .unwrap();
        let lookup = served
            .higher_entry_lookup::<Sha256>(account, recipient)
            .unwrap();
        assert_eq!(lookup, expected);
        let (cumulative, _) = lookup
            .resolve::<Sha256>(&roots.change, account, recipient)
            .unwrap();
        if cumulative > 0 {
            tally.entries += 1;
        } else {
            tally.no_entries += 1;
        }
    }

    match fixture
        .prepared
        .withdrawal_claim(&fixture.withdrawals, account)
    {
        Ok(expected) => {
            let claim = served.withdrawal_claim::<Sha256>(account).unwrap();
            assert_eq!(claim, expected);
            claim.verify::<Sha256>(&roots.withdrawal_outputs).unwrap();
            tally.withdrawals += 1;
        }
        Err(_) => assert!(matches!(
            served.withdrawal_claim::<Sha256>(account),
            Err(ServeError::NoWithdrawal)
        )),
    }
    match fixture.prepared.external_payout_claim(account) {
        Ok(expected) => {
            let claim = served.external_payout_claim::<Sha256>(account).unwrap();
            assert_eq!(claim, expected);
            claim.verify::<Sha256>(&roots.change).unwrap();
            tally.payouts += 1;
        }
        Err(_) => assert!(matches!(
            served.external_payout_claim::<Sha256>(account),
            Err(ServeError::NoPayout)
        )),
    }

    let start = whole
        .transpose
        .partition_point(|entry| entry.recipient < *account);
    let end = whole
        .transpose
        .partition_point(|entry| entry.recipient <= *account);
    if start == end {
        assert!(matches!(
            served.credits::<Sha256>(account),
            Err(ServeError::NoCredit)
        ));
    } else {
        let (entries, opening) = served.credits::<Sha256>(account).unwrap();
        assert_eq!(entries, &whole.transpose[start..end]);
        assert_eq!(
            opening,
            whole
                .transpose_tree
                .range_opening(start as u32, (end - start) as u32)
                .unwrap()
        );
        let encoded = entries.iter().map(Encode::encode).collect::<Vec<_>>();
        opening
            .verify::<Sha256, _>(VectorKind::Transpose, &roots.transpose, &encoded)
            .unwrap();
        tally.credits += 1;
    }
    tally
}

fn assert_not_held<T>(result: Result<T, ServeError>, slice: u16) {
    assert!(matches!(result, Err(ServeError::NotHeld { slice: held }) if held == slice));
}

/// One fresh account per slice with no state and no row, so every span has an
/// authenticated-absence probe.
fn absent_probes(fixture: &Fixture, slice_bits: u8) -> Vec<VerifyingKey> {
    let mut probes: Vec<Option<VerifyingKey>> = vec![None; 1 << slice_bits];
    for seed in 0..1_000_u64 {
        if probes.iter().all(Option::is_some) {
            break;
        }
        let key = SigningKey::from_seed(ACCOUNT_SEED_START + 5_000 + seed).public_key();
        assert!(fixture.accounts.iter().all(|(public, _)| *public != key));
        let slice = usize::from(account_slice(&key, slice_bits).unwrap());
        probes[slice].get_or_insert(key);
    }
    probes.into_iter().map(Option::unwrap).collect()
}

#[test]
fn span_index_matches_whole_close_constructors() {
    let fixture = churn_fixture();
    let whole = Whole::new(&fixture);
    let close = fixture.prepared.close();
    let slice_bits = fixture.context.assignment().slice_bits();
    let slice_count = 1_u16 << slice_bits;
    let split = slice_count / 2 + 1;
    let whole_span = 0..slice_count;
    let shapes: [Vec<core::ops::Range<u16>>; 3] = [
        single_spans(slice_bits),
        vec![split..slice_count, 0..split],
        vec![whole_span],
    ];
    let intervals = intervals_of(fixture.cache.leaves(), slice_bits);

    // Every account in the state or the rows plus one unknown account per slice.
    let mut probes = fixture
        .accounts
        .iter()
        .map(|(public, _)| public.clone())
        .collect::<Vec<_>>();
    probes.extend(absent_probes(&fixture, slice_bits));

    let mut tally = Tally::default();
    for spans in &shapes {
        let slices = fixture
            .prepared
            .assemble_slices(&fixture.cache, spans, &Sequential)
            .unwrap();
        for slice in &slices {
            let interval = span_interval(&intervals, &slice.span);
            let served = SpanIndex::new::<Sha256>(
                slice,
                &interval,
                &fixture.context,
                &close.roots,
                &fixture.withdrawals,
            )
            .unwrap();
            assert_eq!(served.span(), &slice.span);

            // Both ends of the span: the first and last predecessor member, successor member,
            // and changed row.
            let mut advanced = interval.clone();
            advanced.advance(slice);
            let ends = [interval.leaves(), advanced.leaves()]
                .into_iter()
                .flat_map(|leaves| [leaves.first(), leaves.last()])
                .flatten()
                .map(|leaf| &leaf.account)
                .chain(
                    [slice.changes.rows.first(), slice.changes.rows.last()]
                        .into_iter()
                        .flatten()
                        .map(|row| &row.account),
                );
            for account in ends {
                tally.add(&assert_served(&whole, &served, account, &probes));
            }

            for account in &probes {
                let home = account_slice(account, slice_bits).unwrap();
                if slice.span.contains(&home) {
                    tally.add(&assert_served(&whole, &served, account, &probes));
                    continue;
                }
                assert_not_held(served.predecessor_opening::<Sha256>(account), home);
                assert_not_held(served.successor_opening::<Sha256>(account), home);
                assert_not_held(served.account_lookup::<Sha256>(account), home);
                assert_not_held(served.change_opening::<Sha256>(account), home);
                assert_not_held(
                    served.higher_entry_lookup::<Sha256>(account, &probes[0]),
                    home,
                );
                assert_not_held(served.withdrawal_claim::<Sha256>(account), home);
                assert_not_held(served.external_payout_claim::<Sha256>(account), home);
                assert_not_held(served.credits::<Sha256>(account), home);
                tally.not_held += 1;
            }
        }
    }
    assert!(
        tally.predecessor > 0
            && tally.successor > 0
            && tally.changed > 0
            && tally.unchanged > 0
            && tally.unknown > 0
            && tally.entries > 0
            && tally.no_entries > 0
            && tally.withdrawals > 0
            && tally.payouts > 0
            && tally.credits > 0
            && tally.not_held > 0,
        "{tally:?}"
    );
}

#[test]
fn span_index_rejects_wrong_intervals_and_unverifiable_openings() {
    let fixture = churn_fixture();
    let close = fixture.prepared.close();
    let whole = 0..fixture.context.assignment().slice_count();
    let slices = fixture
        .prepared
        .assemble_slices(&fixture.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap();
    let slice = &slices[0];
    let leaves = fixture.cache.leaves();
    let build = |interval: &Interval<VerifyingKey>, roots: &RootBundle<ShaDigest>| {
        SpanIndex::new::<Sha256>(
            slice,
            interval,
            &fixture.context,
            roots,
            &fixture.withdrawals,
        )
        .map(drop)
    };
    let interval = Interval::new(leaves.to_vec()).unwrap();
    build(&interval, &close.roots).unwrap();

    // An edited leaf, a dropped leaf, and a neighboring slice's interval are all rejected.
    let mut edited = leaves.to_vec();
    edited[3].state.balance += 1;
    assert!(matches!(
        build(&Interval::new(edited).unwrap(), &close.roots),
        Err(ServeError::Interval)
    ));
    let mut dropped = leaves.to_vec();
    dropped.remove(3);
    assert!(matches!(
        build(&Interval::new(dropped).unwrap(), &close.roots),
        Err(ServeError::Interval)
    ));
    let slice_bits = fixture.context.assignment().slice_bits();
    let partial = span_interval(&intervals_of(leaves, slice_bits), &(0..1));
    assert!(matches!(
        build(&partial, &close.roots),
        Err(ServeError::Interval)
    ));

    // Roots the derived openings cannot reproduce are reported, never served.
    let mut roots = close.roots;
    roots.change = close.roots.successor;
    roots.successor = close.roots.change;
    roots.withdrawal_outputs = close.roots.transpose;
    roots.transpose = close.roots.coverage;
    let served = SpanIndex::new::<Sha256>(
        slice,
        &interval,
        &fixture.context,
        &roots,
        &fixture.withdrawals,
    )
    .unwrap();
    let payer = &close.rows[0].account;
    let withdrawing = fixture.withdrawals.requests()[0].account();
    let live = &close.unchanged[0].account;
    let paid_out = &close
        .rows
        .iter()
        .find(|row| matches!(row.output, SettlementOutput::ExternalPayout(amount) if amount > 0))
        .unwrap()
        .account;
    let credited = &close
        .rows
        .iter()
        .find(|row| row.successor.cumulative_credit > row.predecessor.cumulative_credit)
        .unwrap()
        .account;
    assert!(matches!(
        served.credits::<Sha256>(credited),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.change_opening::<Sha256>(payer),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.account_lookup::<Sha256>(payer),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.account_lookup::<Sha256>(live),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.higher_entry_lookup::<Sha256>(payer, live),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.withdrawal_claim::<Sha256>(withdrawing),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.external_payout_claim::<Sha256>(paid_out),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.successor_opening::<Sha256>(live),
        Err(ServeError::Corrupt)
    ));
}

#[test]
fn span_index_rejects_structurally_inconsistent_slices() {
    let fixture = churn_fixture();
    let close = fixture.prepared.close();
    let whole = 0..fixture.context.assignment().slice_count();
    let slices = fixture
        .prepared
        .assemble_slices(&fixture.cache, core::slice::from_ref(&whole), &Sequential)
        .unwrap();
    let valid = &slices[0];
    let interval = Interval::new(fixture.cache.leaves().to_vec()).unwrap();
    let build = |slice: &ProofSlice<VerifyingKey, ShaDigest>,
                 withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>| {
        SpanIndex::new::<Sha256>(
            slice,
            &interval,
            &fixture.context,
            &close.roots,
            withdrawals,
        )
        .map(drop)
    };
    build(valid, &fixture.withdrawals).unwrap();
    assert!(valid.changes.rows.len() >= 2);
    assert!(!valid.transpose.is_empty());
    assert!(valid.withdrawal_opening.is_some());

    // Outgoing vectors must align one-for-one with the rows and belong to the row's payer.
    let mut short = valid.clone();
    short.out_vectors.pop();
    assert!(matches!(
        build(&short, &fixture.withdrawals),
        Err(ServeError::Corrupt)
    ));
    let mut swapped = valid.clone();
    swapped.out_vectors.swap(0, 1);
    assert!(matches!(
        build(&swapped, &fixture.withdrawals),
        Err(ServeError::Corrupt)
    ));

    // The transpose opening is present exactly when the transpose is nonempty.
    let mut unopened = valid.clone();
    unopened.transpose_opening = None;
    assert!(matches!(
        build(&unopened, &fixture.withdrawals),
        Err(ServeError::Corrupt)
    ));
    let mut emptied = valid.clone();
    emptied.transpose.clear();
    assert!(matches!(
        build(&emptied, &fixture.withdrawals),
        Err(ServeError::Corrupt)
    ));

    // The withdrawal opening is present exactly when a row carries a request.
    let mut unopened = valid.clone();
    unopened.withdrawal_opening = None;
    assert!(matches!(
        build(&unopened, &fixture.withdrawals),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        build(valid, &WithdrawalBatch::empty()),
        Err(ServeError::Corrupt)
    ));

    // A requested account's row must settle as a withdrawal.
    let mut relabeled = valid.clone();
    let requested = relabeled
        .changes
        .rows
        .iter()
        .position(|row| fixture.withdrawals.request_for(&row.account).is_some())
        .unwrap();
    relabeled.changes.rows[requested].output = SettlementOutput::None;
    assert!(matches!(
        build(&relabeled, &fixture.withdrawals),
        Err(ServeError::Corrupt)
    ));

    // A context bound to another predecessor root still indexes the slice, but nothing it
    // derives from the predecessor state verifies. The successor root comes from the bundle
    // and is unaffected.
    let foreign = CloseContext::from_parts(
        fixture.context.epoch_context().clone(),
        close.roots.successor,
    );
    let served = SpanIndex::new::<Sha256>(
        valid,
        &interval,
        &foreign,
        &close.roots,
        &fixture.withdrawals,
    )
    .unwrap();
    let live = &close.unchanged[0].account;
    assert!(matches!(
        served.predecessor_opening::<Sha256>(live),
        Err(ServeError::Corrupt)
    ));
    assert!(matches!(
        served.account_lookup::<Sha256>(live),
        Err(ServeError::Corrupt)
    ));
    served.successor_opening::<Sha256>(live).unwrap();
}
