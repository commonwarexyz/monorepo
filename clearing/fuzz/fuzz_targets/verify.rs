#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, assigned_slice_spans, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{
        AccountLookup, AckWitness, Challenge, ChallengeKind, EntryWitness, HigherEntryLookup,
        Verdict, account_lookup, adjudicate, decode_bounded, higher_entry_lookup,
    },
    commitment::{Builder, MultiOpening, Opening, VectorKind, VectorRoot, empty_root},
    payment::{
        AckError, EntryReceipt, PaymentContext, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE,
        VECTOR_ACK_SIGNATURE_NAMESPACE, VECTOR_SEND_SIGNATURE_NAMESPACE, VectorAck, VectorSendBody,
    },
    state::{AccountChange, AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, ChallengeIndex, Close, CloseContext, CloseLimits, EpochContext, Header,
        OperatorKey, OperatorSignature, OperatorVariant, PreparedClose, ProofSlice, RootBundle,
        StateCache, TransitionError, prepare_close_with_strategy, validate_close, validate_slice,
    },
    vector::{
        Error as VectorError, OutEntry, OutTipLookup, OutVector, TransposeEntry, read_transpose,
        transpose_encode_size, write_transpose,
    },
};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::{compute_public, sign_message},
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use core::ops::Range;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_VALUES: usize = 8;
const MAX_VALUE_BYTES: usize = 64;
const MAX_POSITIONS: usize = 8;
const MAX_PROOF_DIGESTS: usize = 64;
const MAX_STATES: usize = 16;
const MAX_ROWS: usize = 8;

// Bounds each sanitized transition leaf balance so the aggregate liability of
// every possible leaf count fits u64, keeping cache construction infallible.
const MAX_LEAF_BALANCE: u64 = u64::MAX / (MAX_STATES + MAX_ROWS) as u64;
const MAX_BOUNDARY_RECORDS: usize = 8;
const NON_WITHDRAWAL_SLICE_MUTATIONS: u8 = 37;
const SLICE_MUTATIONS: u8 = 41;

// Mutation selectors whose target field is populated only by a payment-bearing close.
const PAYMENT_SLICE_MUTATIONS: [u8; 4] = [31, 34, 35, 36];

type TestContext = PaymentContext<VerifyingKey, Digest>;
type TestCloseContext = CloseContext<VerifyingKey, Digest>;
type TestChallenge = Challenge<VerifyingKey, Digest>;
type BuiltRow = (
    AccountRow<VerifyingKey, Digest>,
    OutVector<VerifyingKey>,
    Option<OperatorSignature>,
);

#[allow(clippy::too_many_arguments)]
fn close_context(
    deployment: Digest,
    epoch: u64,
    operator: VerifyingKey,
    cache: &StateCache<VerifyingKey, Digest>,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    admission_deadline: u64,
    challenge_deadline: u64,
    limits: CloseLimits,
    assignment: Assignment<Digest>,
) -> Result<TestCloseContext, TransitionError> {
    EpochContext::new::<Sha256>(
        deployment,
        epoch,
        operator,
        deposits,
        withdrawals,
        cache.liability(),
        admission_deadline,
        challenge_deadline,
        limits,
        assignment,
    )
    .and_then(|epoch| epoch.bind::<Sha256>(cache, deposits, withdrawals))
}

#[derive(Arbitrary, Debug)]
struct PaymentCase {
    context: TestContext,
    authorization: SendAuthorization<VerifyingKey, Digest>,
    ack: VectorAck<VerifyingKey, Digest>,
    receipt: EntryReceipt<VerifyingKey, Digest>,
    seed: u64,
    amount: u8,
    fanout: u8,
}

#[derive(Arbitrary, Debug)]
struct ChallengeCase {
    header: Header<Digest>,
    roots: RootBundle<Digest>,
    challenge: Challenge<VerifyingKey, Digest>,
    seed: u64,
    amount: u8,
    mutation: u64,
}

#[derive(Arbitrary, Debug)]
struct CommitmentCase {
    opening: Opening<Digest>,
    multi: MultiOpening<Digest>,
    predecessor_root: VectorRoot<Digest>,
    opening_values: Vec<Vec<u8>>,
    positions: Vec<u8>,
    kind: VectorKind,
}

#[derive(Arbitrary, Debug)]
struct VectorCase {
    root: VectorRoot<Digest>,
    lookup: OutTipLookup<VerifyingKey, Digest>,
    vector: OutVector<VerifyingKey>,
    seed: u64,
    fanout: u8,
}

#[derive(Arbitrary, Debug)]
struct TransitionCase {
    deployment: Digest,
    challenge_deadline: u64,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    roots: RootBundle<Digest>,
    epoch: u64,
    unchanged: Vec<StateLeaf<VerifyingKey>>,
    rows: Vec<AccountRow<VerifyingKey, Digest>>,
    seed: u64,
}

#[derive(Arbitrary, Debug)]
struct AdmissionCase {
    seed: u64,
    slice_bits: u8,
    mutation: u8,
    certificate: bls12381::Certificate,
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Payment(Box<PaymentCase>),
    Challenge(Box<ChallengeCase>),
    Commitment(Box<CommitmentCase>),
    Vector(Box<VectorCase>),
    Transition(Box<TransitionCase>),
    Admission(Box<AdmissionCase>),
}

fn private_keys(seed: u64) -> (SigningKey, SigningKey, SigningKey, SigningKey) {
    (
        SigningKey::from_seed(seed),
        SigningKey::from_seed(seed.wrapping_add(1)),
        SigningKey::from_seed(seed.wrapping_add(2)),
        SigningKey::from_seed(seed.wrapping_add(3)),
    )
}

fn payment_context(seed: u64, operator: &SigningKey) -> TestContext {
    let seed = seed.to_be_bytes();
    PaymentContext::new(
        Sha256::hash(&[&seed]),
        seed[0] as u64,
        operator.public_key(),
    )
}

fn assignment(seed: u64) -> Assignment<Digest> {
    Assignment::new(
        Sha256::hash(&[b"fuzz-committee", &seed.to_be_bytes()]),
        seed.to_be_bytes()[0] % 9,
    )
    .expect("bounded fuzz assignment must be valid")
}

fn bls_pair(seed: u64) -> (Private, OperatorKey) {
    let private = Private::new(Scalar::from(seed.max(1)));
    let public = compute_public::<OperatorVariant>(&private);
    (private, public)
}

fn bls_ack(private: &Private, body: &VectorSendBody<VerifyingKey, Digest>) -> OperatorSignature {
    sign_message::<OperatorVariant>(
        private,
        VECTOR_ACK_AGGREGATE_NAMESPACE,
        body.encode().as_ref(),
    )
}

fn build_prepared(
    cache: &StateCache<VerifyingKey, Digest>,
    context: &TestCloseContext,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    rows: Vec<BuiltRow>,
    transpose: Vec<TransposeEntry<VerifyingKey>>,
) -> PreparedClose<VerifyingKey, Digest> {
    let mut split_rows = Vec::with_capacity(rows.len());
    let mut vectors = Vec::with_capacity(rows.len());
    let mut signatures = Vec::with_capacity(rows.len());
    for (row, vector, signature) in rows {
        split_rows.push(row);
        vectors.push(vector);
        signatures.push(signature);
    }
    let partials = vectors
        .iter()
        .map(OutVector::accumulator)
        .collect::<Vec<_>>();
    prepare_close_with_strategy::<Sha256, _, _>(
        cache,
        context,
        deposits,
        withdrawals,
        split_rows,
        vectors,
        &partials,
        &signatures,
        transpose,
        &Sequential,
    )
    .expect("constructed close must prepare")
}

fn fuzz_payment(case: PaymentCase) {
    // Arbitrary envelopes must fail only with typed errors.
    let _ = case.authorization.verify(&case.context);
    let _ = case.ack.verify(&case.context);
    let _ = case.receipt.verify::<Sha256>(&case.context);

    // An honestly dual-signed endpoint verifies and yields one receipt per committed entry.
    let (operator, payer, _, _) = private_keys(case.seed);
    let context = payment_context(case.seed, &operator);
    let fanout = usize::from(case.fanout % 4) + 1;
    let mut recipients = (0..fanout)
        .map(|index| SigningKey::from_seed(case.seed ^ (0x40 + index as u64)).public_key())
        .collect::<Vec<_>>();
    recipients.sort_unstable();
    recipients.dedup();
    let entries = recipients
        .into_iter()
        .enumerate()
        .map(|(index, recipient)| OutEntry {
            recipient,
            cumulative: u64::from(case.amount) + 1 + index as u64,
            count: 1 + index as u64,
        })
        .collect::<Vec<_>>();
    let vector = OutVector::new(context.epoch(), payer.public_key(), entries)
        .expect("bounded feasible entries are canonical");
    let (total, _) = vector.totals().expect("bounded totals cannot overflow");
    let root = vector
        .root::<Sha256, Digest>()
        .expect("bounded vector commits");
    let body = VectorSendBody::new(&context, payer.public_key(), 0, total, root);
    let ack = VectorAck::sign_by_authorities(body.clone(), &payer, &operator);
    assert!(ack.verify(&context).is_ok());
    let authorization = SendAuthorization::sign(body.clone(), &payer);
    assert!(authorization.verify(&context).is_ok());
    assert_eq!(authorization.payer_signature(), ack.payer_signature());

    let first = vector.entries()[0].recipient.clone();
    for entry in vector.entries() {
        let OutTipLookup::Present {
            cumulative,
            count,
            opening,
        } = vector
            .lookup::<Sha256, Digest>(&entry.recipient)
            .expect("committed entry has a lookup")
        else {
            panic!("committed entry is present");
        };
        let receipt = EntryReceipt {
            ack: ack.clone(),
            recipient: entry.recipient.clone(),
            cumulative,
            count,
            opening,
        };
        assert!(receipt.verify::<Sha256>(&context).is_ok());
    }

    // A foreign anchor, a wrong payer half, a wrong operator half, and an infeasible entry
    // each fail with their exact typed error.
    let foreign = PaymentContext::new(
        Sha256::hash(&[b"payment-foreign-anchor", &case.seed.to_be_bytes()]),
        context.epoch(),
        operator.public_key(),
    );
    assert!(matches!(ack.verify(&foreign), Err(AckError::WrongContext)));
    let wrong = SigningKey::from_seed(case.seed.wrapping_add(100));
    let encoded = body.encode();
    let bad_payer = VectorAck::from_raw_unchecked(
        body.clone(),
        wrong.sign(VECTOR_SEND_SIGNATURE_NAMESPACE, &encoded),
        ack.operator_signature().clone(),
    );
    assert!(matches!(
        bad_payer.verify(&context),
        Err(AckError::InvalidPayerSignature)
    ));
    let bad_operator = VectorAck::from_raw_unchecked(
        body,
        ack.payer_signature().clone(),
        wrong.sign(VECTOR_ACK_SIGNATURE_NAMESPACE, &encoded),
    );
    assert!(matches!(
        bad_operator.verify(&context),
        Err(AckError::InvalidOperatorSignature)
    ));
    let OutTipLookup::Present { opening, .. } = vector
        .lookup::<Sha256, Digest>(&first)
        .expect("first committed entry has a lookup")
    else {
        panic!("first committed entry is present");
    };
    let infeasible = EntryReceipt {
        ack,
        recipient: first,
        cumulative: 1,
        count: 2,
        opening,
    };
    assert!(matches!(
        infeasible.verify::<Sha256>(&context),
        Err(AckError::InfeasibleEntry)
    ));
}

fn invalidate_operator_half(
    challenge: &mut TestChallenge,
    context: &TestCloseContext,
    wrong: &SigningKey,
) {
    let ack = match challenge {
        Challenge::HigherAckDebit { ack, .. } => ack.as_mut(),
        Challenge::HigherAckEntry { entry, .. } => &mut entry.ack,
        Challenge::AckFork { left, .. } => left.as_mut(),
    };
    let body = VectorSendBody::new(
        context.payment(),
        ack.payer.clone(),
        ack.seq,
        ack.cumulative_debit,
        ack.send_root,
    );
    let encoded = body.encode();
    ack.operator_signature = wrong.sign(VECTOR_ACK_SIGNATURE_NAMESPACE, &encoded);
}

fn invalidate_scope(challenge: &mut TestChallenge) {
    match challenge {
        Challenge::HigherAckDebit { payer, .. } => match payer.as_mut() {
            AccountLookup::Present(opening) => opening.proof.proof.leaf_count ^= 1,
            AccountLookup::Absent { change, .. } => change.opening.proof.leaf_count ^= 1,
        },
        Challenge::HigherAckEntry { sender, .. } => match sender.as_mut() {
            HigherEntryLookup::Present { proof, .. } => proof.proof.leaf_count ^= 1,
            HigherEntryLookup::Absent(absence) => absence.opening.proof.leaf_count ^= 1,
        },
        Challenge::AckFork { left, right } => *right = left.clone(),
    }
}

fn exercise_challenge(
    context: &TestCloseContext,
    header: &Header<Digest>,
    roots: &RootBundle<Digest>,
    kind: ChallengeKind,
    challenge: &TestChallenge,
    wrong: &SigningKey,
    mutation: u8,
) {
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, challenge),
        Ok(Verdict::Proven(actual)) if actual == kind
    ));

    let encoded = challenge.encode();
    assert_eq!(encoded.len(), challenge.encode_size());
    assert!(encoded.len() <= MAX_INPUT_BYTES);
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, encoded.len())
        .expect("canonical bounded challenge must decode");
    assert_eq!(&decoded, challenge);
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, &decoded),
        Ok(Verdict::Proven(actual)) if actual == kind
    ));

    let mut unsigned = challenge.clone();
    invalidate_operator_half(&mut unsigned, context, wrong);
    assert!(adjudicate::<Sha256, _, _>(context, header, roots, &unsigned).is_err());
    let mut unscoped = challenge.clone();
    invalidate_scope(&mut unscoped);
    assert!(!matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, &unscoped),
        Ok(Verdict::Proven(_))
    ));

    let mut mutated = encoded.to_vec();
    let maximum = match mutation % 4 {
        0 => {
            let position = usize::from(mutation) % mutated.len();
            mutated[position] ^= 1;
            mutated.len()
        }
        1 => {
            mutated.pop();
            mutated.len()
        }
        2 => {
            mutated.push(mutation);
            mutated.len()
        }
        _ => mutated.len() - 1,
    };
    if let Ok(decoded) = decode_bounded::<VerifyingKey, Digest>(&mutated, maximum) {
        let _ = adjudicate::<Sha256, _, _>(context, header, roots, &decoded);
    }
}

fn exercise_no_contradiction(
    context: &TestCloseContext,
    header: &Header<Digest>,
    roots: &RootBundle<Digest>,
    challenge: &TestChallenge,
    wrong: &SigningKey,
) {
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, challenge),
        Ok(Verdict::NoContradiction)
    ));

    let encoded = challenge.encode();
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, encoded.len())
        .expect("canonical bounded challenge must decode");
    assert_eq!(&decoded, challenge);
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, &decoded),
        Ok(Verdict::NoContradiction)
    ));

    let mut unsigned = challenge.clone();
    invalidate_operator_half(&mut unsigned, context, wrong);
    assert!(adjudicate::<Sha256, _, _>(context, header, roots, &unsigned).is_err());
    let mut unscoped = challenge.clone();
    invalidate_scope(&mut unscoped);
    assert!(!matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, &unscoped),
        Ok(Verdict::Proven(_))
    ));
}

fn state_of(cache: &StateCache<VerifyingKey, Digest>, account: &VerifyingKey) -> AccountState {
    cache
        .leaves()
        .iter()
        .find(|leaf| &leaf.account == account)
        .expect("challenge fixture account is live")
        .state
}

fn fuzz_challenge(case: ChallengeCase) {
    let (operator, payer, recipient, other) = private_keys(case.seed);
    let (operator_ack, operator_bls) = bls_pair(case.seed ^ 0x5a5a_5a5a_5a5a_5a5a);
    let mut leaves = vec![
        StateLeaf {
            account: payer.public_key(),
            state: AccountState {
                balance: 512,
                active: true,
                ..AccountState::default()
            },
        },
        StateLeaf {
            account: recipient.public_key(),
            state: AccountState {
                balance: 256,
                active: true,
                ..AccountState::default()
            },
        },
        StateLeaf {
            account: other.public_key(),
            state: AccountState {
                balance: 128,
                active: true,
                ..AccountState::default()
            },
        },
    ];
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let Ok(cache) = StateCache::<VerifyingKey, Digest>::new::<Sha256>(leaves) else {
        return;
    };
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = close_context(
        Sha256::hash(&[b"challenge-fuzz-deployment", &case.seed.to_be_bytes()]),
        case.seed,
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        98,
        99,
        CloseLimits::protocol_maximum(),
        Assignment::new(Sha256::hash(&[b"challenge-fuzz-committee"]), 0)
            .expect("zero-bit assignment is valid"),
    )
    .expect("bounded challenge context must be valid");

    // Arbitrary adjudication inputs must fail only with typed errors.
    let _ = adjudicate::<Sha256, _, _>(&context, &case.header, &case.roots, &case.challenge);

    // One acknowledged send from the payer to the recipient forms the certified close.
    let amount = u64::from(case.amount) + 1;
    let epoch = context.payment().epoch();
    let payer_public = payer.public_key();
    let recipient_public = recipient.public_key();
    let out_vector = OutVector::new(
        epoch,
        payer_public.clone(),
        vec![OutEntry {
            recipient: recipient_public.clone(),
            cumulative: amount,
            count: 1,
        }],
    )
    .expect("one positive entry is canonical");
    let body = VectorSendBody::new(
        context.payment(),
        payer_public.clone(),
        1,
        amount,
        out_vector
            .root::<Sha256, Digest>()
            .expect("bounded vector commits"),
    );
    let committed_ack = VectorAck::sign_by_authorities(body.clone(), &payer, &operator);
    let payer_state = state_of(&cache, &payer_public);
    let recipient_state = state_of(&cache, &recipient_public);
    let mut entries = vec![
        (
            AccountRow {
                account: payer_public.clone(),
                predecessor: payer_state,
                successor: AccountState {
                    balance: payer_state.balance - amount,
                    cumulative_debit: amount,
                    ..payer_state
                },
                outgoing: Some(SendAuthorization::from_raw_unchecked(
                    body,
                    committed_ack.payer_signature().clone(),
                )),
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            out_vector.clone(),
            Some(bls_ack(&operator_ack, committed_ack.body())),
        ),
        (
            AccountRow {
                account: recipient_public.clone(),
                predecessor: recipient_state,
                successor: AccountState {
                    balance: recipient_state.balance + amount,
                    cumulative_credit: amount,
                    receipt_count: 1,
                    ..recipient_state
                },
                outgoing: None,
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            OutVector::empty(epoch, recipient_public.clone()),
            None,
        ),
    ];
    entries.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
    let mut prefix = Prefix::default();
    for (row, vector, _) in &mut entries {
        let (debit, credit, receipts) = row
            .checked_deltas()
            .expect("bounded challenge fixture counters are monotonic");
        prefix = prefix
            .checked_extend(Prefix {
                debit,
                credit,
                out_count: u64::try_from(vector.entries().len())
                    .expect("bounded entry count fits in u64"),
                in_count: receipts,
                ..Prefix::default()
            })
            .expect("bounded challenge fixture prefix cannot overflow");
        row.prefix = prefix;
    }
    let transpose = vec![TransposeEntry {
        recipient: recipient_public.clone(),
        payer: payer_public.clone(),
        cumulative: amount,
        count: 1,
    }];
    let prepared = build_prepared(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        entries,
        transpose,
    );
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &mut test_rng(),
            &Sequential,
        )
        .expect("constructed challenge close must validate");
    let close = prepared.close();
    let index = ChallengeIndex::new::<Sha256>(&context, close)
        .expect("validated close has a canonical challenge index");
    let payer_position = close
        .rows
        .binary_search_by(|row| row.account.cmp(&payer_public))
        .expect("payer has a changed row");
    let committed_vector = &close.out_vectors[payer_position];

    // The operator privately acknowledged one more unit on the committed edge.
    let mut retained_entries = committed_vector.entries().to_vec();
    retained_entries[0].cumulative += 1;
    retained_entries[0].count += 1;
    let retained = OutVector::new(epoch, payer_public.clone(), retained_entries)
        .expect("bumped retained vector is canonical");
    let retained_root = retained
        .root::<Sha256, Digest>()
        .expect("bounded retained vector commits");
    let retained_ack = VectorAck::sign_by_authorities(
        VectorSendBody::new(
            context.payment(),
            payer_public.clone(),
            2,
            amount + 1,
            retained_root,
        ),
        &payer,
        &operator,
    );
    let payer_lookup = account_lookup::<Sha256, _, _>(&index, &cache, &payer_public)
        .expect("validated close has canonical payer evidence");
    let higher_debit = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&retained_ack)),
        payer: Box::new(payer_lookup.clone()),
    };

    // A live account outside the close convicts from the zero terminal.
    let other_public = other.public_key();
    let absent_ack = VectorAck::sign_by_authorities(
        VectorSendBody::new(context.payment(), other_public.clone(), 0, 1, retained_root),
        &other,
        &operator,
    );
    let absent_debit = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&absent_ack)),
        payer: Box::new(
            account_lookup::<Sha256, _, _>(&index, &cache, &other_public)
                .expect("validated close has canonical absent-payer evidence"),
        ),
    };

    let OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = retained
        .lookup::<Sha256, Digest>(&recipient_public)
        .expect("retained entry has a lookup")
    else {
        panic!("retained entry is present");
    };
    let higher_entry = Challenge::HigherAckEntry {
        entry: Box::new(EntryWitness {
            ack: AckWitness::from_ack(&retained_ack),
            recipient: recipient_public.clone(),
            cumulative,
            count,
            opening,
        }),
        sender: Box::new(
            higher_entry_lookup::<Sha256, _, _>(
                &index,
                &payer_public,
                Some(committed_vector),
                &recipient_public,
            )
            .expect("validated close has canonical composed sender evidence"),
        ),
    };

    // Two operator countersignatures at one payer sequence number with different bodies.
    let fork = Challenge::AckFork {
        left: Box::new(AckWitness::from_ack(&committed_ack)),
        right: Box::new(AckWitness::from_ack(&VectorAck::sign_by_authorities(
            VectorSendBody::new(
                context.payment(),
                payer_public.clone(),
                committed_ack.body().seq(),
                amount + 5,
                retained_root,
            ),
            &payer,
            &operator,
        ))),
    };

    let wrong = SigningKey::from_seed(case.seed.wrapping_add(100));
    let challenges = [
        (ChallengeKind::HigherAckDebit, higher_debit),
        (ChallengeKind::HigherAckDebit, absent_debit),
        (ChallengeKind::HigherAckEntry, higher_entry),
        (ChallengeKind::AckFork, fork),
    ];
    for (offset, (kind, challenge)) in challenges.iter().enumerate() {
        exercise_challenge(
            &context,
            &close.header,
            &close.roots,
            *kind,
            challenge,
            &wrong,
            case.mutation.to_be_bytes()[offset],
        );
    }

    // The committed acknowledgment, its committed entry, and an identical fork pair are all
    // authentic but contradiction-free.
    let clean_debit = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&committed_ack)),
        payer: Box::new(payer_lookup),
    };
    exercise_no_contradiction(&context, &close.header, &close.roots, &clean_debit, &wrong);
    let OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = committed_vector
        .lookup::<Sha256, Digest>(&recipient_public)
        .expect("committed entry has a lookup")
    else {
        panic!("committed entry is present");
    };
    let clean_entry = Challenge::HigherAckEntry {
        entry: Box::new(EntryWitness {
            ack: AckWitness::from_ack(&committed_ack),
            recipient: recipient_public.clone(),
            cumulative,
            count,
            opening,
        }),
        sender: Box::new(
            higher_entry_lookup::<Sha256, _, _>(
                &index,
                &payer_public,
                Some(committed_vector),
                &recipient_public,
            )
            .expect("validated close has canonical composed sender evidence"),
        ),
    };
    exercise_no_contradiction(&context, &close.header, &close.roots, &clean_entry, &wrong);
    let clean_fork = Challenge::AckFork {
        left: Box::new(AckWitness::from_ack(&committed_ack)),
        right: Box::new(AckWitness::from_ack(&committed_ack)),
    };
    exercise_no_contradiction(&context, &close.header, &close.roots, &clean_fork, &wrong);
}

fn bounded_values(mut values: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    values.truncate(MAX_VALUES);
    for value in &mut values {
        value.truncate(MAX_VALUE_BYTES);
    }
    values
}

fn fuzz_commitment(mut case: CommitmentCase) {
    case.opening.proof.siblings.truncate(MAX_PROOF_DIGESTS);
    case.multi.positions.truncate(MAX_POSITIONS);
    case.multi.proof.siblings.truncate(MAX_PROOF_DIGESTS);
    let opening_values = bounded_values(case.opening_values);
    let first = opening_values.first().map_or(&[][..], Vec::as_slice);

    let _ = case
        .opening
        .verify::<Sha256>(case.kind, &case.predecessor_root, first);
    let _ = case.opening.reconstruct::<Sha256>(case.kind, first);
    let _ = case
        .multi
        .verify::<Sha256, _>(case.kind, &case.predecessor_root, &opening_values);
    let mut builder = Builder::<Sha256>::new(case.kind, opening_values.len() as u32)
        .expect("small vector must fit the protocol bound");
    for value in &opening_values {
        builder
            .add_encoded(value)
            .expect("small encoded value must be length-framable");
    }
    let tree = builder
        .build(&Sequential)
        .expect("builder received its declared length");
    let root = tree.root();
    if opening_values.is_empty() {
        let multi = tree
            .multi_opening(&[])
            .expect("empty vector has a canonical empty multiproof");
        assert!(
            multi
                .verify::<Sha256, Vec<u8>>(case.kind, &root, &[])
                .is_ok()
        );
        return;
    }

    let selected =
        usize::from(case.positions.first().copied().unwrap_or_default()) % opening_values.len();
    let opening = tree
        .opening(selected as u32)
        .expect("selected position is in range");
    assert!(
        opening
            .verify::<Sha256>(case.kind, &root, &opening_values[selected])
            .is_ok()
    );

    let mut positions = case
        .positions
        .into_iter()
        .take(MAX_POSITIONS)
        .map(|position| u32::from(position) % opening_values.len() as u32)
        .collect::<Vec<_>>();
    if positions.is_empty() {
        positions.push(selected as u32);
    }
    positions.sort_unstable();
    positions.dedup();
    let disclosed = positions
        .iter()
        .map(|&position| opening_values[position as usize].clone())
        .collect::<Vec<_>>();
    let multi = tree
        .multi_opening(&positions)
        .expect("normalized positions are canonical");
    assert!(
        multi
            .verify::<Sha256, _>(case.kind, &root, &disclosed)
            .is_ok()
    );
}

fn fuzz_vector(case: VectorCase) {
    // Arbitrary lookups and vectors must fail only with typed errors.
    let probe = SigningKey::from_seed(case.seed.wrapping_add(50)).public_key();
    let _ = case.lookup.reconstruct::<Sha256>(&probe);
    let _ = case.lookup.resolve::<Sha256>(&case.root, &probe);
    let _ = case.vector.root::<Sha256, Digest>();
    let _ = case.vector.totals();
    let _ = case.vector.lookup::<Sha256, Digest>(&probe);

    // A constructed vector resolves exact membership and ordered absence.
    let fanout = usize::from(case.fanout % 5) + 1;
    let mut recipients = (0..fanout)
        .map(|index| SigningKey::from_seed(case.seed ^ (0x900 + index as u64)).public_key())
        .collect::<Vec<_>>();
    recipients.sort_unstable();
    recipients.dedup();
    let entries = recipients
        .into_iter()
        .enumerate()
        .map(|(index, recipient)| OutEntry {
            recipient,
            cumulative: 10 + index as u64,
            count: 1 + index as u64,
        })
        .collect::<Vec<_>>();
    let payer = SigningKey::from_seed(case.seed.wrapping_add(1_000)).public_key();
    let vector =
        OutVector::new(7, payer.clone(), entries).expect("bounded feasible entries are canonical");
    let root = vector
        .root::<Sha256, Digest>()
        .expect("bounded vector commits");
    for entry in vector.entries() {
        let lookup = vector
            .lookup::<Sha256, Digest>(&entry.recipient)
            .expect("committed entry has a lookup");
        assert_eq!(
            lookup
                .resolve::<Sha256>(&root, &entry.recipient)
                .expect("committed entry resolves"),
            (entry.cumulative, entry.count)
        );
    }
    let missing = SigningKey::from_seed(case.seed.wrapping_add(2_000)).public_key();
    if vector
        .entries()
        .binary_search_by(|entry| entry.recipient.cmp(&missing))
        .is_err()
    {
        let lookup = vector
            .lookup::<Sha256, Digest>(&missing)
            .expect("absent recipient has an ordered lookup");
        assert_eq!(
            lookup
                .resolve::<Sha256>(&root, &missing)
                .expect("absent recipient resolves to zero"),
            (0, 0)
        );
    }

    // Any entry change moves the edge accumulator.
    let mut bumped = vector.entries().to_vec();
    bumped[0].cumulative += 1;
    let bumped = OutVector::new(7, payer.clone(), bumped).expect("bumped entries remain canonical");
    assert_ne!(
        vector.accumulator().checksum(),
        bumped.accumulator().checksum()
    );

    // The recipient-grouped transpose wire form round-trips with an exact size.
    let transpose = vector
        .entries()
        .iter()
        .map(|entry| TransposeEntry {
            recipient: entry.recipient.clone(),
            payer: payer.clone(),
            cumulative: entry.cumulative,
            count: entry.count,
        })
        .collect::<Vec<_>>();
    let mut encoded = Vec::new();
    write_transpose(&transpose, &mut encoded);
    assert_eq!(encoded.len(), transpose_encode_size(&transpose));
    let decoded = read_transpose::<VerifyingKey>(&mut &encoded[..], transpose.len())
        .expect("encoded transpose interval decodes");
    assert_eq!(decoded, transpose);
    assert!(read_transpose::<VerifyingKey>(&mut &encoded[..], transpose.len() - 1).is_err());

    // Non-canonical and infeasible vectors are rejected.
    let mut reversed = vector.entries().to_vec();
    reversed.reverse();
    if reversed.len() > 1 {
        assert!(matches!(
            OutVector::new(7, payer.clone(), reversed),
            Err(VectorError::NonCanonicalOrder)
        ));
    }
    let infeasible = vec![OutEntry {
        recipient: missing,
        cumulative: 2,
        count: 3,
    }];
    assert!(matches!(
        OutVector::new(7, payer, infeasible),
        Err(VectorError::InfeasibleEntry)
    ));
}

fn bounded_deposits(batch: DepositBatch<VerifyingKey>) -> DepositBatch<VerifyingKey> {
    DepositBatch::new(
        batch
            .records()
            .iter()
            .take(MAX_BOUNDARY_RECORDS)
            .cloned()
            .collect(),
    )
    .unwrap_or_default()
}

fn bounded_withdrawals(
    batch: WithdrawalBatch<VerifyingKey, Digest>,
) -> WithdrawalBatch<VerifyingKey, Digest> {
    WithdrawalBatch::new(
        batch
            .requests()
            .iter()
            .take(MAX_BOUNDARY_RECORDS)
            .cloned()
            .collect(),
    )
    .unwrap_or_default()
}

/// Deals every slice of `context` as its own span.
fn single_spans(context: &TestCloseContext) -> Vec<Range<u16>> {
    (0..context.assignment().slice_count())
        .map(|slice| slice..slice + 1)
        .collect()
}

fn mutate_slice(
    slice: &ProofSlice<VerifyingKey, Digest>,
    selector: u8,
) -> ProofSlice<VerifyingKey, Digest> {
    let mut mutated = slice.clone();
    let last = mutated
        .coverage
        .boundaries
        .len()
        .checked_sub(1)
        .expect("a coverage range holds at least two boundaries");
    let marker = Sha256::hash(&[b"transition-slice-mutation", &[selector]]);
    let live_overlap = mutated.changes.rows.first().map(|row| StateLeaf {
        account: row.account.clone(),
        state: AccountState {
            balance: 1,
            active: true,
            ..AccountState::default()
        },
    });
    match selector % SLICE_MUTATIONS {
        0 => mutated.span = u16::MAX - 1..u16::MAX,
        1 => mutated.coverage.boundaries[0].predecessor ^= 1,
        2 => mutated.coverage.boundaries[0].change ^= 1,
        3 => mutated.coverage.boundaries[0].successor ^= 1,
        4 => mutated.coverage.boundaries[0].prefix.payout ^= 1,
        5 => mutated.coverage.boundaries[last].predecessor ^= 1,
        6 => mutated.coverage.boundaries[last].change ^= 1,
        7 => mutated.coverage.boundaries[last].successor ^= 1,
        8 => mutated.coverage.boundaries[last].prefix.payout ^= 1,
        9 => mutated.coverage.opening.start = u32::MAX,
        10 => mutated.coverage.opening.proof.leaf_count ^= 1,
        11 => mutated.coverage.opening.proof.siblings.push(marker),
        12 => mutated.changes.opening.start = u32::MAX,
        13 => mutated.changes.opening.proof.leaf_count ^= 1,
        14 => mutated.changes.opening.proof.siblings.push(marker),
        15 => {
            if let Some(row) = mutated.changes.rows.first_mut() {
                row.prefix.payout ^= 1;
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        16 => {
            if mutated.out_vectors.is_empty() {
                mutated.changes.opening.start = u32::MAX;
            } else {
                mutated.out_vectors.clear();
            }
        }
        17 => {
            if let Some(leaf) = live_overlap.clone() {
                mutated.unchanged.push(leaf);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        18 => {
            if let Some(leaf) = live_overlap.clone() {
                mutated.predecessor.predecessor = Some(leaf);
            } else {
                mutated.predecessor.opening.start = u32::MAX;
            }
        }
        19 => {
            if let Some(leaf) = live_overlap.clone() {
                mutated.predecessor.successor = Some(leaf);
            } else {
                mutated.predecessor.opening.start = u32::MAX;
            }
        }
        20 => mutated.predecessor.opening.start = u32::MAX,
        21 => mutated.predecessor.opening.proof.leaf_count ^= 1,
        22 => mutated.predecessor.opening.proof.siblings.push(marker),
        23 => {
            if let Some(leaf) = live_overlap.clone() {
                mutated.successor.predecessor = Some(leaf);
            } else {
                mutated.successor.opening.start = u32::MAX;
            }
        }
        24 => {
            if let Some(leaf) = live_overlap {
                mutated.successor.successor = Some(leaf);
            } else {
                mutated.successor.opening.start = u32::MAX;
            }
        }
        25 => mutated.successor.opening.start = u32::MAX,
        26 => mutated.successor.opening.proof.leaf_count ^= 1,
        27 => mutated.successor.opening.proof.siblings.push(marker),
        28 => {
            if let Some(row) = mutated.changes.rows.first().cloned() {
                mutated.changes.rows.push(row);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        29 => {
            let guard = mutated
                .changes
                .rows
                .first()
                .zip(mutated.out_vectors.first())
                .map(|(row, vector)| {
                    let send_root = vector
                        .root::<Sha256, Digest>()
                        .expect("validated slice vector commits");
                    AccountChange::from_row::<Sha256>(row, send_root).guard::<Sha256>()
                });
            if let Some(guard) = guard {
                mutated.changes.predecessor = Some(guard);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        30 => {
            let guard = mutated
                .changes
                .rows
                .last()
                .zip(mutated.out_vectors.last())
                .map(|(row, vector)| {
                    let send_root = vector
                        .root::<Sha256, Digest>()
                        .expect("validated slice vector commits");
                    AccountChange::from_row::<Sha256>(row, send_root).guard::<Sha256>()
                });
            if let Some(guard) = guard {
                mutated.changes.successor = Some(guard);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        31 => {
            if let Some(vector) = mutated.out_vectors.first_mut() {
                *vector = OutVector::empty(vector.epoch().wrapping_add(1), vector.payer().clone());
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        32 => mutated.out_start.add(b"transition-slice-mutation"),
        33 => mutated.in_start.add(b"transition-slice-mutation"),
        34 => {
            if let Some(aggregate) = mutated
                .operator_aggregates
                .iter_mut()
                .find(|aggregate| aggregate.is_some())
            {
                *aggregate = None;
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        35 => {
            if let Some(entry) = mutated.transpose.first_mut() {
                entry.cumulative = entry
                    .cumulative
                    .checked_add(1)
                    .expect("bounded fixture edge cannot overflow");
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        36 => {
            if let Some(opening) = mutated.transpose_opening.as_mut() {
                opening.start ^= 1;
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        37 => {
            mutated
                .withdrawal_opening
                .as_mut()
                .expect("withdrawal mutation requires a present output range")
                .start ^= 1;
        }
        38 => {
            mutated
                .withdrawal_opening
                .as_mut()
                .expect("withdrawal mutation requires a present output range")
                .proof
                .leaf_count ^= 1;
        }
        39 => {
            mutated
                .withdrawal_opening
                .as_mut()
                .expect("withdrawal mutation requires a present output range")
                .proof
                .siblings
                .push(marker);
        }
        _ => mutated.withdrawal_opening = None,
    }
    mutated
}

#[allow(clippy::too_many_arguments)]
fn exercise_slice_mutation(
    context: &TestCloseContext,
    operator: &OperatorKey,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    close: &Close<VerifyingKey, Digest>,
    slices: &[ProofSlice<VerifyingKey, Digest>],
    selector: u8,
) {
    let slice = slices
        .iter()
        .find(|slice| !slice.changes.rows.is_empty())
        .expect("a nonempty close has a nonempty proof slice");
    validate_slice::<Sha256, _, _, PaymentBatchVerifier, _>(
        context,
        operator,
        deposits,
        withdrawals,
        &close.header,
        &close.roots,
        slice,
        &mut test_rng(),
    )
    .expect("canonical nonempty slice must validate");
    let mutated = mutate_slice(slice, selector);
    assert!(
        validate_slice::<Sha256, _, _, PaymentBatchVerifier, _>(
            context,
            operator,
            deposits,
            withdrawals,
            &close.header,
            &close.roots,
            &mutated,
            &mut test_rng(),
        )
        .is_err()
    );
}

fn fuzz_transition(mut case: TransitionCase) {
    case.challenge_deadline = case.challenge_deadline.clamp(1, u64::MAX - 1);
    let admission_deadline = case.challenge_deadline - 1;
    let deposits = bounded_deposits(case.deposits);
    let withdrawals = bounded_withdrawals(case.withdrawals);
    case.unchanged.truncate(MAX_STATES);
    case.rows.truncate(MAX_ROWS);
    let mut leaves = case
        .unchanged
        .iter()
        .cloned()
        .map(|mut leaf| {
            leaf.state.active = true;
            leaf.state.balance = (leaf.state.balance % MAX_LEAF_BALANCE).max(1);
            leaf
        })
        .chain(
            case.rows
                .iter()
                .filter(|row| row.predecessor.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: AccountState {
                        balance: (row.predecessor.balance % MAX_LEAF_BALANCE).max(1),
                        ..row.predecessor
                    },
                }),
        )
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    leaves.dedup_by(|left, right| left.account == right.account);
    let cache =
        StateCache::new::<Sha256>(leaves).expect("sanitized arbitrary opening cache must be valid");
    let (operator, _, _, _) = private_keys(case.seed);
    let (_, operator_bls) = bls_pair(case.seed ^ 0x5a5a_5a5a_5a5a_5a5a);
    let _ = close_context(
        case.deployment,
        case.epoch,
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment(case.seed),
    );

    // An arbitrary corpus under a well-formed header must fail only with typed errors.
    let empty_deposits = DepositBatch::empty();
    let empty_withdrawals = WithdrawalBatch::empty();
    let context = close_context(
        case.deployment,
        case.epoch,
        operator.public_key(),
        &cache,
        &empty_deposits,
        &empty_withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment(case.seed),
    )
    .expect("empty sealed boundaries over a valid cache must be valid");
    let out_vectors = case
        .rows
        .iter()
        .map(|row| OutVector::empty(context.payment().epoch(), row.account.clone()))
        .collect::<Vec<_>>();
    let operator_aggregates = vec![None; usize::from(context.assignment().slice_count())];
    let roots = case.roots;
    let header = Header::new::<Sha256, _>(&context, &roots);
    let close = Close {
        header,
        roots,
        unchanged: case.unchanged,
        rows: case.rows,
        out_vectors,
        operator_aggregates,
    };
    let _ = validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
        &context,
        &operator_bls,
        &empty_deposits,
        &empty_withdrawals,
        &close,
        &mut test_rng(),
    );

    // An empty prepared close validates, deals, and proves its zero terminal.
    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(Vec::new())
        .expect("empty state cache must be valid");
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = close_context(
        Sha256::hash(&[b"fuzz-deployment", &case.seed.to_be_bytes()]),
        case.seed,
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment(case.seed),
    )
    .expect("empty close context must be valid");
    let prepared = build_prepared(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        Vec::new(),
        Vec::new(),
    );
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &mut test_rng(),
            &Sequential,
        )
        .expect("constructed empty close must validate");
    let close = prepared.close();
    validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
        &context,
        &operator_bls,
        &deposits,
        &withdrawals,
        close,
        &mut test_rng(),
    )
    .expect("constructed empty close must validate from the corpus");
    let slices = prepared
        .assemble_slices(&cache, &single_spans(&context), &Sequential)
        .expect("constructed empty close must split into valid slices");
    for slice in &slices {
        validate_slice::<Sha256, _, _, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
            &mut test_rng(),
        )
        .expect("constructed slice must validate");
    }
    let totals = prepared
        .terminal_proof()
        .expect("constructed empty close has a terminal proof")
        .verify::<Sha256, _>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
        )
        .expect("constructed empty terminal proof must verify");
    assert_eq!(totals.debit, 0);
    assert_eq!(totals.credit, 0);

    // A deposit-creation close validates, and every slice mutation is rejected.
    let account = SigningKey::from_seed(case.seed.wrapping_add(10));
    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(Vec::new())
        .expect("empty opening cache is valid");
    let amount = case.seed.to_be_bytes()[0] as u64 + 1;
    let deposits = DepositBatch::new(vec![
        DepositRecord::new(account.public_key(), amount)
            .expect("positive fuzz deposit must be valid"),
    ])
    .expect("singleton fuzz deposit batch must be valid");
    let context = close_context(
        Sha256::hash(&[b"fuzz-deployment", &case.seed.to_be_bytes()]),
        case.seed.wrapping_add(1),
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment(case.seed),
    )
    .expect("deposit creation close context must be valid");
    let row = AccountRow {
        account: account.public_key(),
        predecessor: AccountState::default(),
        successor: AccountState {
            balance: amount,
            active: true,
            ..AccountState::default()
        },
        outgoing: None,
        output: SettlementOutput::None,
        prefix: Prefix {
            deposit: amount,
            ..Prefix::default()
        },
    };
    let vector = OutVector::empty(context.payment().epoch(), account.public_key());
    let prepared = build_prepared(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![(row, vector, None)],
        Vec::new(),
    );
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &mut test_rng(),
            &Sequential,
        )
        .expect("constructed deposit creation must validate");
    let close = prepared.close();
    assert_eq!(
        *context.predecessor_root(),
        empty_root::<Sha256>(VectorKind::State)
    );
    assert_ne!(
        close.roots.successor,
        empty_root::<Sha256>(VectorKind::State)
    );
    validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
        &context,
        &operator_bls,
        &deposits,
        &withdrawals,
        close,
        &mut test_rng(),
    )
    .expect("constructed deposit creation must validate from the corpus");
    let slices = prepared
        .assemble_slices(&cache, &single_spans(&context), &Sequential)
        .expect("constructed deposit close must split into valid slices");
    for slice in &slices {
        validate_slice::<Sha256, _, _, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
            &mut test_rng(),
        )
        .expect("constructed deposit slice must validate");
    }
    exercise_slice_mutation(
        &context,
        &operator_bls,
        &deposits,
        &withdrawals,
        close,
        &slices,
        case.seed.to_be_bytes()[2] % NON_WITHDRAWAL_SLICE_MUTATIONS,
    );

    // A close-withdrawal empties the single account and its claim verifies.
    let account = SigningKey::from_seed(case.seed.wrapping_add(20));
    let opening_balance = case.seed.to_be_bytes()[1] as u64 + 2;
    let opening = AccountState {
        balance: opening_balance,
        active: true,
        ..AccountState::default()
    };
    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(vec![StateLeaf {
        account: account.public_key(),
        state: opening,
    }])
    .expect("single active account is a valid opening cache");
    let deployment = Sha256::hash(&[b"fuzz-withdrawal-deployment", &case.seed.to_be_bytes()]);
    let authorization_root = cache.root().digest;
    let withdrawal = SignedWithdrawal::sign(
        deployment,
        authorization_root,
        Bytes::from_static(b"fuzz-destination"),
        WithdrawalAction::Close,
        case.challenge_deadline,
        &account,
    );
    let withdrawals = WithdrawalBatch::new(vec![withdrawal])
        .expect("singleton withdrawal batch must be canonical");
    let deposits = DepositBatch::empty();
    let context = close_context(
        deployment,
        case.seed.wrapping_add(2),
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment(case.seed),
    )
    .expect("covered withdrawal close context must be valid");
    let row = AccountRow {
        account: account.public_key(),
        predecessor: opening,
        successor: AccountState::default(),
        outgoing: None,
        output: SettlementOutput::Withdrawal(opening.balance),
        prefix: Prefix {
            withdrawal: opening.balance,
            withdrawal_count: 1,
            ..Prefix::default()
        },
    };
    let vector = OutVector::empty(context.payment().epoch(), account.public_key());
    let prepared = build_prepared(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![(row, vector, None)],
        Vec::new(),
    );
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &mut test_rng(),
            &Sequential,
        )
        .expect("constructed close withdrawal must validate");
    let close = prepared.close();
    assert_eq!(
        close.roots.successor,
        empty_root::<Sha256>(VectorKind::State)
    );
    validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
        &context,
        &operator_bls,
        &deposits,
        &withdrawals,
        close,
        &mut test_rng(),
    )
    .expect("constructed close withdrawal must validate again");
    let claim = prepared
        .withdrawal_claim(&withdrawals, &account.public_key())
        .expect("constructed withdrawal must have a claim");
    let output = claim
        .verify::<Sha256>(&close.roots.withdrawal_outputs)
        .expect("constructed withdrawal claim must verify");
    assert_eq!(
        output.destination(),
        withdrawals.requests()[0].body().destination()
    );
    assert_eq!(output.amount(), opening.balance);
    let slices = prepared
        .assemble_slices(&cache, &single_spans(&context), &Sequential)
        .expect("constructed destruction close must split into slices");
    assert!(slices.iter().all(|slice| {
        validate_slice::<Sha256, _, _, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
            &mut test_rng(),
        )
        .is_ok()
    }));
    for selector in NON_WITHDRAWAL_SLICE_MUTATIONS..SLICE_MUTATIONS {
        exercise_slice_mutation(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            close,
            &slices,
            selector,
        );
    }

    // An acknowledged send crediting an absent recipient classifies as an external payout.
    let (payer_ack, payer_bls) = bls_pair(case.seed.wrapping_add(40).max(1));
    let payer = SigningKey::from_seed(case.seed.wrapping_add(30));
    let recipient = SigningKey::from_seed(case.seed.wrapping_add(31));
    let payout = u64::from(case.seed.to_be_bytes()[3]) + 1;
    let payer_opening = AccountState {
        balance: payout + 1,
        active: true,
        ..AccountState::default()
    };
    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(vec![StateLeaf {
        account: payer.public_key(),
        state: payer_opening,
    }])
    .expect("single live payout payer is a valid opening cache");
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = close_context(
        Sha256::hash(&[b"fuzz-payout-deployment", &case.seed.to_be_bytes()]),
        case.seed.wrapping_add(3),
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        Assignment::new(Sha256::hash(&[b"fuzz-payout-committee"]), 0)
            .expect("zero-bit payout assignment is valid"),
    )
    .expect("external payout close context must be valid");
    let epoch = context.payment().epoch();
    let out_vector = OutVector::new(
        epoch,
        payer.public_key(),
        vec![OutEntry {
            recipient: recipient.public_key(),
            cumulative: payout,
            count: 1,
        }],
    )
    .expect("one positive payout entry is canonical");
    let body = VectorSendBody::new(
        context.payment(),
        payer.public_key(),
        1,
        payout,
        out_vector
            .root::<Sha256, Digest>()
            .expect("bounded payout vector commits"),
    );
    let operator_signature = bls_ack(&payer_ack, &body);
    let outgoing = SendAuthorization::sign(body, &payer);
    let transpose = vec![TransposeEntry {
        recipient: recipient.public_key(),
        payer: payer.public_key(),
        cumulative: payout,
        count: 1,
    }];
    let mut pairs = vec![
        (
            AccountRow {
                account: payer.public_key(),
                predecessor: payer_opening,
                successor: AccountState {
                    balance: 1,
                    cumulative_debit: payout,
                    ..payer_opening
                },
                outgoing: Some(outgoing),
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            out_vector,
            Some(operator_signature),
        ),
        (
            AccountRow {
                account: recipient.public_key(),
                predecessor: AccountState::default(),
                successor: AccountState {
                    cumulative_credit: payout,
                    receipt_count: 1,
                    ..AccountState::default()
                },
                outgoing: None,
                output: SettlementOutput::ExternalPayout(payout),
                prefix: Prefix::default(),
            },
            OutVector::empty(epoch, recipient.public_key()),
            None,
        ),
    ];
    pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
    let mut prefix = Prefix::default();
    for (row, vector, _) in &mut pairs {
        let (debit, credit, receipts) = row
            .checked_deltas()
            .expect("bounded payout counters are monotonic");
        let payout_delta = if row.predecessor.active { 0 } else { credit };
        prefix = prefix
            .checked_extend(Prefix {
                debit,
                credit,
                payout: payout_delta,
                out_count: u64::try_from(vector.entries().len())
                    .expect("bounded entry count fits in u64"),
                in_count: receipts,
                ..Prefix::default()
            })
            .expect("bounded payout prefixes cannot overflow");
        row.prefix = prefix;
    }
    let prepared = build_prepared(&cache, &context, &deposits, &withdrawals, pairs, transpose);
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &payer_bls,
            &deposits,
            &withdrawals,
            &mut test_rng(),
            &Sequential,
        )
        .expect("constructed external payout must validate");
    let terminal_proof = prepared
        .terminal_proof()
        .expect("constructed external payout has a canonical terminal proof");
    let close = prepared.close();
    assert_eq!(
        close
            .rows
            .last()
            .expect("payout close has changed rows")
            .prefix
            .payout,
        payout
    );
    let totals = terminal_proof
        .verify::<Sha256, VerifyingKey>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
        )
        .expect("constructed terminal proof must verify");
    assert_eq!(totals.payout, payout);
    let claim = prepared
        .external_payout_claim(&recipient.public_key())
        .expect("constructed external payout must have a claim");
    let claimed = claim
        .verify::<Sha256>(&close.roots.change)
        .expect("constructed external payout claim must verify");
    assert_eq!(claimed.recipient, recipient.public_key());
    assert_eq!(claimed.amount, payout);
    let payout_row = close
        .rows
        .iter()
        .find(|row| row.account == recipient.public_key())
        .expect("constructed external payout retains its recipient row");
    assert_eq!(payout_row.predecessor, AccountState::default());
    assert!(!payout_row.successor.active);
    assert_eq!(payout_row.successor.balance, 0);
    assert!(payout_row.outgoing.is_none());
    assert_eq!(payout_row.checked_deltas(), Some((0, payout, 1)));
    validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
        &context,
        &payer_bls,
        &deposits,
        &withdrawals,
        close,
        &mut test_rng(),
    )
    .expect("constructed external payout must validate again");
    let slices = prepared
        .assemble_slices(&cache, &single_spans(&context), &Sequential)
        .expect("external payout close must split into slices");
    assert!(slices.iter().all(|slice| {
        validate_slice::<Sha256, _, _, PaymentBatchVerifier, _>(
            &context,
            &payer_bls,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
            &mut test_rng(),
        )
        .is_ok()
    }));
    for selector in PAYMENT_SLICE_MUTATIONS {
        exercise_slice_mutation(
            &context,
            &payer_bls,
            &deposits,
            &withdrawals,
            close,
            &slices,
            selector,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn assignment_is_rejected(
    scheme: &bls12381::Scheme,
    context: &TestCloseContext,
    operator: &OperatorKey,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    header: &Header<Digest>,
    roots: &RootBundle<Digest>,
    slices: Vec<ProofSlice<VerifyingKey, Digest>>,
) -> bool {
    seal::<Sha256, _, _, PaymentBatchVerifier, _>(
        scheme,
        context,
        operator,
        deposits,
        withdrawals,
        header,
        roots,
        slices,
        &mut test_rng(),
        &Sequential,
    )
    .is_err()
}

fn fuzz_admission(case: AdmissionCase) {
    let seed = case.seed;
    let challenge_deadline = seed.clamp(1, u64::MAX - 1);
    let admission_deadline = challenge_deadline - 1;
    let validators = (0..4)
        .map(|offset| Private::new(Scalar::from(seed.wrapping_add(offset).max(1))))
        .collect::<Vec<_>>();
    let Ok(committee) = Committee::new(
        validators
            .iter()
            .map(compute_public::<MinSig>)
            .collect::<Vec<_>>(),
    ) else {
        return;
    };
    let operator = SigningKey::from_seed(seed.wrapping_add(100));
    let (_, operator_bls) = bls_pair(seed.wrapping_add(300));
    let account = SigningKey::from_seed(seed.wrapping_add(200));
    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(Vec::new())
        .expect("empty admission opening cache is valid");
    let amount = u64::from(case.mutation) + 1;
    let deposits = DepositBatch::new(vec![
        DepositRecord::new(account.public_key(), amount)
            .expect("positive admission deposit is valid"),
    ])
    .expect("singleton admission deposit is canonical");
    let withdrawals = WithdrawalBatch::empty();
    let assignment = Assignment::new(committee.commitment::<Sha256>(), case.slice_bits % 3 + 2)
        .expect("fuzz slice bits are bounded");
    let context = close_context(
        Sha256::hash(&[b"fuzz-admission-deployment", &seed.to_be_bytes()]),
        seed,
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment,
    )
    .expect("bounded admission context must be valid");
    let row = AccountRow {
        account: account.public_key(),
        predecessor: AccountState::default(),
        successor: AccountState {
            balance: amount,
            active: true,
            ..AccountState::default()
        },
        outgoing: None,
        output: SettlementOutput::None,
        prefix: Prefix {
            deposit: amount,
            ..Prefix::default()
        },
    };
    let vector = OutVector::empty(context.payment().epoch(), account.public_key());
    let prepared = build_prepared(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![(row, vector, None)],
        Vec::new(),
    );
    prepared
        .validate::<Sha256, PaymentBatchVerifier, _>(
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &mut test_rng(),
            &Sequential,
        )
        .expect("nonempty admission close must validate");
    let close = prepared.close();
    let all = prepared
        .assemble_slices(&cache, &single_spans(&context), &Sequential)
        .expect("admission slices must build");
    let nonempty = all
        .iter()
        .find(|slice| !slice.changes.rows.is_empty())
        .expect("deposit creation has one nonempty slice")
        .span
        .start;
    let mut votes = Vec::new();
    let mut checked_nonempty_mutation = false;
    for (validator, private) in validators.iter().enumerate() {
        let scheme = bls12381::Scheme::signer(committee.clone(), private.clone())
            .expect("validator belongs to committee");
        let spans = assigned_slice_spans::<Sha256, _>(
            &committee,
            context.assignment(),
            scheme.me().expect("signer has a committee index"),
        )
        .expect("assignment matches committee");
        let assigned = prepared
            .assemble_slices(&cache, &spans, &Sequential)
            .expect("assigned dealing must build");
        let canonical = assigned.clone();
        let (vote, sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            assigned,
            &mut test_rng(),
            &Sequential,
        )
        .expect("complete valid assignment must sign");
        assert!(sealed.slices().iter().all(|slice| {
            slice
                .span
                .clone()
                .all(|index| sealed.serve(index).is_some())
        }));
        if validator == 0 {
            let position = usize::from(case.mutation) % canonical.len();
            let mut omitted = canonical.clone();
            omitted.remove(position);
            assert!(assignment_is_rejected(
                &scheme,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                omitted,
            ));

            let mut duplicate = canonical.clone();
            duplicate.insert(position, canonical[position].clone());
            assert!(assignment_is_rejected(
                &scheme,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                duplicate,
            ));

            let mut reordered = canonical.clone();
            let last = reordered.len() - 1;
            reordered.swap(0, last);
            assert!(assignment_is_rejected(
                &scheme,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                reordered,
            ));
        }
        if let Some(position) = canonical
            .iter()
            .position(|slice| slice.span.contains(&nonempty))
            .filter(|_| !checked_nonempty_mutation)
        {
            let mut malformed = canonical.clone();
            malformed[position] = mutate_slice(
                &malformed[position],
                case.mutation % NON_WITHDRAWAL_SLICE_MUTATIONS,
            );
            assert!(assignment_is_rejected(
                &scheme,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                malformed,
            ));
            checked_nonempty_mutation = true;
        }
        votes.push(vote);
    }
    assert!(checked_nonempty_mutation);
    let verifier = bls12381::Scheme::verifier(committee.clone());
    let _ = verifier.verify_exact(&close.header, &case.certificate);
    let certificate = verifier
        .assemble_exact(votes.into_iter().take(committee.quorum()))
        .expect("exact valid quorum must assemble");
    assert!(verifier.verify_exact(&close.header, &certificate));
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Ok(input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };

    match input {
        FuzzInput::Payment(case) => fuzz_payment(*case),
        FuzzInput::Challenge(case) => fuzz_challenge(*case),
        FuzzInput::Commitment(case) => fuzz_commitment(*case),
        FuzzInput::Vector(case) => fuzz_vector(*case),
        FuzzInput::Transition(case) => fuzz_transition(*case),
        FuzzInput::Admission(case) => fuzz_admission(*case),
    }
});
