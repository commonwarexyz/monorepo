use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    challenge::{
        AckWitness, Challenge, ChallengeError, ChallengeKind, EntryWitness, Verdict,
        account_lookup, adjudicate, higher_entry_lookup,
    },
    payment::{
        AckError, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody,
    },
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, ChallengeIndex, CloseContext, CloseLimits, EpochContext, PreparedClose,
        StateCache, TransitionError as CloseError, prepare_close_with_strategy,
        validate_close_with_strategy, validate_slice,
    },
    vector::{OutEntry, OutVector, TransposeEntry},
};
use commonware_codec::{DecodeExt, Encode};
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

    // Edge (i -> (i + j) % credited) for j in 0..out_degree, one unit each, from the first
    // `senders` accounts. Rows cover exactly the senders and the credited recipients.
    let mut incoming = vec![Vec::new(); live];
    let mut vectors_by_account = vec![None; live];
    for (index, (public, private)) in accounts.iter().enumerate().take(senders) {
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
    let mut acks = Vec::with_capacity(senders);
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
fn close_validates_deals_and_seals() {
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

    let slices = fixture
        .prepared
        .assemble_slices(&fixture.cache, &Sequential)
        .unwrap();
    assert_eq!(
        slices.len(),
        usize::from(fixture.context.assignment().slice_count())
    );
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

/// Builds a replica from a fixture's opening state vector.
fn replica_of(fixture: &Fixture) -> crate::bajillion::posted::Replica<VerifyingKey> {
    crate::bajillion::posted::Replica::genesis(fixture.cache.leaves()).unwrap()
}

/// Encodes, decodes, and validates one close as a delta stream against `replica`, asserting
/// exact sizing and parity with the in-memory close, then rolls the replica forward.
fn stream_round_trip(
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
    stream_round_trip(&first, &mut replica);
    let close = first.prepared.close();
    assert_eq!(replica.live(), posted_live, "no account went inactive");

    // Epoch two: build the next close on the carried states (different senders), and stream
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
    stream_round_trip(&second, &mut replica);
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
    let rejected = stale.map_or(true, |decoded| decoded != *close);
    assert!(rejected, "stale replica must not reproduce the close");

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

/// Strips, hydrates, validates, and advances every slice of a close against retained
/// intervals, asserting hydration parity and returning (dealt bytes, full bytes).
fn dealt_round_trip(
    fixture: &Fixture,
    intervals: &mut [crate::bajillion::retained::Interval<VerifyingKey>],
) -> (usize, usize) {
    let close = fixture.prepared.close();
    let slices = fixture
        .prepared
        .assemble_slices(&fixture.cache, &Sequential)
        .unwrap();
    let mut dealt_bytes = 0;
    let mut full_bytes = 0;
    for slice in slices {
        let index = usize::from(slice.index);
        full_bytes += slice.encoded_size();
        let expected = slice.clone();
        let dealt = crate::bajillion::retained::DealtSlice::strip(slice);
        dealt_bytes += dealt.encoded_size();

        // The dealt wire round-trips under the adversarial decode bounds before hydration.
        let encoded = dealt.encode();
        let decoded = crate::bajillion::retained::decode_dealt_slice_bounded::<
            VerifyingKey,
            ShaDigest,
        >(encoded.as_ref(), *fixture.context.limits(), encoded.len())
        .unwrap();
        assert_eq!(decoded, dealt, "dealt slice wire must round-trip exactly");
        let hydrated = decoded.hydrate(&intervals[index]);
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
        intervals[index].advance(&hydrated);
    }
    (dealt_bytes, full_bytes)
}

#[test]
fn dealt_slices_hydrate_validate_and_stream() {
    // Epoch one: 20 accounts, 12 senders, 5 idle. Retained intervals come from the
    // predecessor state, the dealt slices carry no unchanged leaves, and hydration must
    // reproduce the full slice byte for byte.
    let first = fixture_with(EPOCH, 20, 12, 8, 2, None);
    let slice_bits = first.context.assignment().slice_bits();
    let mut intervals = intervals_of(first.cache.leaves(), slice_bits);
    let stale = intervals.clone();
    let (dealt, full) = dealt_round_trip(&first, &mut intervals);
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

    // Epoch two on the carried states, with different senders: streaming works only if
    // every interval advanced exactly.
    let second = fixture_with(EPOCH + 1, 20, 9, 6, 3, Some(&carried));
    let mut advanced = intervals.clone();
    dealt_round_trip(&second, &mut advanced);

    // A stale interval (epoch one's predecessor state) hydrates epoch two's slices into
    // material that misses the certified roots.
    let second_slices = second
        .prepared
        .assemble_slices(&second.cache, &Sequential)
        .unwrap();
    let second_close = second.prepared.close();
    let mut rejected = false;
    for slice in second_slices {
        let index = usize::from(slice.index);
        let expected = slice.clone();
        let dealt = crate::bajillion::retained::DealtSlice::strip(slice);
        let hydrated = dealt.hydrate(&stale[index]);
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
    assert!(rejected, "stale intervals must not validate");
}
