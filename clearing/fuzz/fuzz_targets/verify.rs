#![no_main]

mod support;

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, WithdrawalBatch},
    challenge::{
        AccountLookup, AckWitness, Challenge, ChallengeError, ChallengeKind, EntryWitness,
        HigherEntryLookup, Verdict, account_lookup, adjudicate, decode_bounded,
        higher_entry_lookup,
    },
    commitment::{Builder, MultiOpening, Opening, RangeOpening, VectorKind, VectorRoot},
    payment::{
        AckError, EntryReceipt, PaymentContext, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE,
        VECTOR_ACK_SIGNATURE_NAMESPACE, VECTOR_SEND_SIGNATURE_NAMESPACE, VectorAck, VectorSendBody,
    },
    posted,
    qmdb::{State, StateOpening, StateRoot, account_key},
    transition::{
        ChallengeIndex, Close, CloseAmounts, CloseContext, CloseLimits, Header, OperatorKey,
        OperatorSignature, OperatorVariant, RootBundle, Terminal, prepare_close_with_strategy,
        validate_close_with_strategy,
    },
    vector::{Error as VectorError, OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{Decode, Encode, EncodeSize};
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
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::test_rng;
use core::num::NonZeroU64;
use libfuzzer_sys::fuzz_target;
use support::{TestState, close_context};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_VALUES: usize = 8;
const MAX_VALUE_BYTES: usize = 64;
const MAX_POSITIONS: usize = 8;
const MAX_PROOF_DIGESTS: usize = 64;
type TestContext = PaymentContext<VerifyingKey, Digest>;
type TestCloseContext = CloseContext<VerifyingKey, Digest>;
type TestChallenge = Challenge<VerifyingKey, Digest>;
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
    range: RangeOpening<Digest>,
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
    seed: u64,
    amount: u8,
    mutation: u8,
    zero_net: bool,
    delete: bool,
}

#[derive(Arbitrary, Debug)]
struct AdmissionCase {
    seed: u64,
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
            AccountLookup::Absent(change) => change.opening.proof.leaf_count ^= 1,
        },
        Challenge::HigherAckEntry { sender, .. } => match sender.as_mut() {
            HigherEntryLookup::Present { proof, .. } => proof.proof.leaf_count ^= 1,
            HigherEntryLookup::Absent(absence) => absence.opening.proof.leaf_count ^= 1,
        },
        Challenge::AckFork { left, right } => *right = left.clone(),
    }
}

// Claims one more unit than the genuine entry opening authenticates. Returns whether the
// challenge carries an entry to forge.
fn forge_entry(challenge: &mut TestChallenge) -> bool {
    match challenge {
        Challenge::HigherAckEntry { entry, .. } => {
            entry.cumulative += 1;
            true
        }
        Challenge::HigherAckDebit { .. } | Challenge::AckFork { .. } => false,
    }
}

fn assert_forged_entry_rejected(
    context: &TestCloseContext,
    close: &Close<VerifyingKey, Digest>,
    challenge: &TestChallenge,
) {
    let mut forged = challenge.clone();
    if forge_entry(&mut forged) {
        assert!(matches!(
            adjudicate::<Sha256, _, _>(
                context,
                &close.header,
                &close.roots,
                &close.amounts,
                &forged
            ),
            Err(ChallengeError::Ack(AckError::InvalidEntryOpening))
        ));
    }
}

fn exercise_challenge(
    context: &TestCloseContext,
    close: &Close<VerifyingKey, Digest>,
    kind: ChallengeKind,
    challenge: &TestChallenge,
    wrong: &SigningKey,
    mutation: u8,
) {
    let Close {
        header,
        roots,
        amounts,
        ..
    } = close;
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, challenge),
        Ok(Verdict::Proven(actual)) if actual == kind
    ));

    let encoded = challenge.encode();
    assert_eq!(encoded.len(), challenge.encode_size());
    assert!(encoded.len() <= MAX_INPUT_BYTES);
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, encoded.len())
        .expect("canonical bounded challenge must decode");
    assert_eq!(&decoded, challenge);
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, &decoded),
        Ok(Verdict::Proven(actual)) if actual == kind
    ));

    let mut unsigned = challenge.clone();
    invalidate_operator_half(&mut unsigned, context, wrong);
    assert!(adjudicate::<Sha256, _, _>(context, header, roots, amounts, &unsigned).is_err());
    let mut unscoped = challenge.clone();
    invalidate_scope(&mut unscoped);
    assert!(!matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, &unscoped),
        Ok(Verdict::Proven(_))
    ));
    assert_forged_entry_rejected(context, close, challenge);

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
        let _ = adjudicate::<Sha256, _, _>(context, header, roots, amounts, &decoded);
    }
}

fn exercise_no_contradiction(
    context: &TestCloseContext,
    close: &Close<VerifyingKey, Digest>,
    challenge: &TestChallenge,
    wrong: &SigningKey,
) {
    let Close {
        header,
        roots,
        amounts,
        ..
    } = close;
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, challenge),
        Ok(Verdict::NoContradiction)
    ));

    let encoded = challenge.encode();
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, encoded.len())
        .expect("canonical bounded challenge must decode");
    assert_eq!(&decoded, challenge);
    assert!(matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, &decoded),
        Ok(Verdict::NoContradiction)
    ));

    let mut unsigned = challenge.clone();
    invalidate_operator_half(&mut unsigned, context, wrong);
    assert!(adjudicate::<Sha256, _, _>(context, header, roots, amounts, &unsigned).is_err());
    let mut unscoped = challenge.clone();
    invalidate_scope(&mut unscoped);
    assert!(!matches!(
        adjudicate::<Sha256, _, _>(context, header, roots, amounts, &unscoped),
        Ok(Verdict::Proven(_))
    ));
    assert_forged_entry_rejected(context, close, challenge);
}

async fn fuzz_challenge(case: ChallengeCase, runtime: deterministic::Context) {
    let (operator, payer, recipient, other) = private_keys(case.seed);
    let (operator_ack, operator_bls) = bls_pair(case.seed ^ 0x5a5a_5a5a_5a5a_5a5a);
    let cache = support::new_state(
        runtime,
        "challenge",
        vec![
            (payer.public_key(), 512),
            (recipient.public_key(), 256),
            (other.public_key(), 128),
        ],
    )
    .await;
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
        Sha256::hash(&[b"challenge-fuzz-committee"]),
    )
    .await;
    let _ = adjudicate::<Sha256, _, _>(
        &context,
        &case.header,
        &case.roots,
        &CloseAmounts::default(),
        &case.challenge,
    );
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
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![Terminal {
            authorization: SendAuthorization::sign(body.clone(), &payer),
            vector: out_vector,
            operator_signature: bls_ack(&operator_ack, &body),
        }],
        &Sequential,
    )
    .await
    .unwrap();
    let dealing = posted::decode(prepared.encoded().clone(), &context).unwrap();
    let prepared = validate_close_with_strategy::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
        &cache,
        &context,
        &operator_bls,
        &deposits,
        &withdrawals,
        dealing,
        &mut test_rng(),
        &Sequential,
    )
    .await
    .unwrap();
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
    let payer_lookup = account_lookup::<Sha256, _, _>(&index, &payer_public)
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
            account_lookup::<Sha256, _, _>(&index, &other_public)
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
            close,
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
    exercise_no_contradiction(&context, close, &clean_debit, &wrong);
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
    exercise_no_contradiction(&context, close, &clean_entry, &wrong);
    let clean_fork = Challenge::AckFork {
        left: Box::new(AckWitness::from_ack(&committed_ack)),
        right: Box::new(AckWitness::from_ack(&committed_ack)),
    };
    exercise_no_contradiction(&context, close, &clean_fork, &wrong);
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
    case.range.proof.siblings.truncate(MAX_PROOF_DIGESTS);
    let opening_values = bounded_values(case.opening_values);
    let first = opening_values.first().map_or(&[][..], Vec::as_slice);

    let _ = case
        .opening
        .verify::<Sha256>(case.kind, &case.predecessor_root, first);
    let _ = case.opening.reconstruct::<Sha256>(case.kind, first);
    let _ = case
        .multi
        .verify::<Sha256, _>(case.kind, &case.predecessor_root, &opening_values);

    // Arbitrary range openings verify, narrow, and open only with typed errors.
    let probe_start = case.range.start.wrapping_add(u32::from(
        case.positions.first().copied().unwrap_or_default(),
    ));
    let probe_count = u32::from(case.positions.get(1).copied().unwrap_or_default());
    let _ = case
        .range
        .verify::<Sha256, _>(case.kind, &case.predecessor_root, &opening_values);
    let _ = case
        .range
        .narrow::<Sha256, _>(case.kind, &opening_values, probe_start, probe_count);
    let _ = case
        .range
        .open::<Sha256, _>(case.kind, &opening_values, probe_start);
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

    // Narrowing a verified range opening reproduces the direct sub-range and single openings,
    // and each result verifies against the same root.
    let start = positions[0];
    let end = positions[positions.len() - 1] + 1;
    let covered = &opening_values[start as usize..end as usize];
    let range = tree
        .range_opening(start, end - start)
        .expect("covered range is in bounds");
    range
        .verify::<Sha256, _>(case.kind, &root, covered)
        .expect("direct range opening verifies");
    for (index, &sub_start) in positions.iter().enumerate() {
        for &sub_last in &positions[index..] {
            let sub_count = sub_last - sub_start + 1;
            let narrowed = range
                .narrow::<Sha256, _>(case.kind, covered, sub_start, sub_count)
                .expect("sub-range lies inside the verified range");
            assert_eq!(
                narrowed,
                tree.range_opening(sub_start, sub_count)
                    .expect("sub-range is in bounds")
            );
            assert!(
                narrowed
                    .verify::<Sha256, _>(
                        case.kind,
                        &root,
                        &opening_values[sub_start as usize..=sub_last as usize],
                    )
                    .is_ok()
            );
        }
        let opened = range
            .open::<Sha256, _>(case.kind, covered, sub_start)
            .expect("position lies inside the verified range");
        assert_eq!(
            opened,
            tree.opening(sub_start).expect("position is in bounds")
        );
        assert!(
            opened
                .verify::<Sha256>(case.kind, &root, &opening_values[sub_start as usize])
                .is_ok()
        );
    }
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

    // The vector root authenticates each edge's exact value.
    let mut bumped = vector.entries().to_vec();
    bumped[0].cumulative += 1;
    let bumped = OutVector::new(7, payer.clone(), bumped).unwrap();
    assert_ne!(root, bumped.root::<Sha256, Digest>().unwrap());

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

async fn validate_bytes(
    state: &TestState,
    context: &TestCloseContext,
    operator: &OperatorKey,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    encoded: Bytes,
) -> bool {
    let before = *state.head();
    let accepted = match posted::decode(encoded, context) {
        Ok(dealing) => validate_close_with_strategy::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
            state,
            context,
            operator,
            deposits,
            withdrawals,
            dealing,
            &mut test_rng(),
            &Sequential,
        )
        .await
        .is_ok(),
        Err(_) => false,
    };
    assert_eq!(*state.head(), before);
    accepted
}

async fn fuzz_transition(case: TransitionCase, runtime: deterministic::Context) {
    let (operator, payer, recipient, absent) = private_keys(case.seed);
    let (ack_key, operator_bls) = bls_pair(case.seed ^ 0x55aa);
    let amount = u64::from(case.amount) + 1;
    let balance = if case.delete && !case.zero_net {
        amount
    } else {
        amount + 1
    };
    let mut state = support::new_state(
        runtime.child("replica"),
        "transition",
        vec![
            (payer.public_key(), balance),
            (recipient.public_key(), balance),
        ],
    )
    .await;
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = close_context(
        Sha256::hash(&[b"transition", &case.seed.to_be_bytes()]),
        case.seed,
        operator.public_key(),
        &state,
        &deposits,
        &withdrawals,
        98,
        99,
        CloseLimits::new(4, 4, 4, 4, 8, u64::MAX, u64::MAX, u64::MAX),
        Sha256::hash(&[b"committee"]),
    )
    .await;
    let mut terminals = Vec::new();
    for (sender, receiver) in [(&payer, &recipient), (&recipient, &payer)]
        .into_iter()
        .take(if case.zero_net { 2 } else { 1 })
    {
        let vector = OutVector::new(
            context.payment().epoch(),
            sender.public_key(),
            vec![OutEntry {
                recipient: receiver.public_key(),
                cumulative: amount,
                count: 1,
            }],
        )
        .unwrap();
        let body = VectorSendBody::new(
            context.payment(),
            sender.public_key(),
            1,
            amount,
            vector.root::<Sha256, Digest>().unwrap(),
        );
        terminals.push(Terminal {
            authorization: SendAuthorization::sign(body.clone(), sender),
            vector,
            operator_signature: bls_ack(&ack_key, &body),
        });
    }
    terminals.sort_unstable_by(|a, b| {
        a.authorization
            .body()
            .payer()
            .cmp(b.authorization.body().payer())
    });
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        terminals.clone(),
        &Sequential,
    )
    .await
    .unwrap();
    let encoded = prepared.encoded().clone();
    assert!(
        validate_bytes(
            &state,
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            encoded.clone()
        )
        .await
    );
    let mut wrong_terminal = terminals.clone();
    let original = wrong_terminal[0].authorization.body().clone();
    wrong_terminal[0].authorization = SendAuthorization::from_raw_unchecked(
        original.clone(),
        absent.sign(VECTOR_SEND_SIGNATURE_NAMESPACE, &original.encode()),
    );
    let bad = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        wrong_terminal,
        &Sequential,
    )
    .await
    .unwrap();
    assert!(
        !validate_bytes(
            &state,
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            bad.encoded().clone()
        )
        .await
    );
    let mut duplicate_terminal = terminals.clone();
    duplicate_terminal.insert(0, terminals[0].clone());
    assert!(
        prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &withdrawals,
            duplicate_terminal,
            &Sequential
        )
        .await
        .is_err()
    );
    let before = *state.head();
    assert_eq!(prepared.close().rows.len(), 2);
    assert_eq!(
        prepared.state().mutations().len(),
        if case.zero_net { 0 } else { 2 }
    );
    let index = ChallengeIndex::new::<Sha256>(&context, prepared.close()).unwrap();
    for terminal in &terminals {
        let account = terminal.authorization.body().payer();
        let lookup = account_lookup::<Sha256, _, _>(&index, account).unwrap();
        assert_eq!(
            lookup
                .resolve::<Sha256>(&prepared.close().roots.change, account)
                .unwrap()
                .0,
            amount
        );
    }
    assert_eq!(
        account_lookup::<Sha256, _, _>(&index, &absent.public_key())
            .unwrap()
            .resolve::<Sha256>(&prepared.close().roots.change, &absent.public_key())
            .unwrap(),
        (0, None)
    );

    // A complete frame binds the claimed header, canonical keys, signatures and vector data.
    let second_key = 33
        + 33
        + prepared.close().rows[0]
            .outgoing
            .as_ref()
            .map_or(0, |send| 1 + send.payer_signature().encode_size());
    let mut duplicate = encoded.to_vec();
    duplicate.copy_within(33..65, second_key);
    assert!(posted::decode::<VerifyingKey, Digest>(duplicate.into(), &context).is_err());
    let mut reordered = encoded.to_vec();
    for offset in 0..32 {
        reordered.swap(33 + offset, second_key + offset);
    }
    assert!(posted::decode::<VerifyingKey, Digest>(reordered.into(), &context).is_err());
    let vectors_start = second_key
        + 33
        + prepared.close().rows[1]
            .outgoing
            .as_ref()
            .map_or(0, |send| 1 + send.payer_signature().encode_size());
    let sender_vector = vectors_start + usize::from(prepared.close().rows[0].outgoing.is_none());
    let mut bad_index = encoded.to_vec();
    bad_index[sender_vector + 1] = 2;
    assert!(posted::decode::<VerifyingKey, Digest>(bad_index.into(), &context).is_err());
    let mut duplicate_entry = encoded.to_vec();
    duplicate_entry[sender_vector] = 2;
    duplicate_entry.splice(sender_vector + 1..sender_vector + 1, [0, 1, 1]);
    duplicate_entry[sender_vector + 4] = 0;
    assert!(posted::decode::<VerifyingKey, Digest>(duplicate_entry.into(), &context).is_err());

    let mut malformed = encoded.to_vec();
    match case.mutation % 8 {
        0 => malformed[0] ^= 1,
        1 => {
            malformed.pop();
        }
        2 => malformed.push(0),
        3 => malformed[32] = 0x7f,
        4 => malformed[33] ^= 1,
        5 => {
            let position = malformed.len() - 2;
            malformed[position] ^= 1;
        }
        6 => {
            malformed.insert(33, 0);
            malformed[32] |= 0x80;
        }
        _ => malformed.truncate(32),
    }
    assert!(
        !validate_bytes(
            &state,
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            malformed.into()
        )
        .await
    );
    let wrong = close_context(
        Sha256::hash(&[b"wrong-context"]),
        case.seed,
        operator.public_key(),
        &state,
        &deposits,
        &withdrawals,
        98,
        99,
        *context.limits(),
        *context.committee(),
    )
    .await;
    assert!(
        !validate_bytes(
            &state,
            &wrong,
            &operator_bls,
            &deposits,
            &withdrawals,
            encoded.clone()
        )
        .await
    );
    let (_, wrong_operator) = bls_pair(case.seed ^ 0x33cc);
    assert!(
        !validate_bytes(
            &state,
            &context,
            &wrong_operator,
            &deposits,
            &withdrawals,
            encoded.clone()
        )
        .await
    );
    let close = prepared.close();
    for which in 0..5 {
        let mut roots = close.roots;
        let mut amounts = close.amounts;
        let changed = Sha256::hash(&[b"wrong-header-field", &[which]]);
        match which {
            0 => roots.change.digest = changed,
            1 => roots.withdrawal_outputs.digest = changed,
            2 => roots.successor.digest = changed,
            3 => amounts.withdrawal += 1,
            _ => amounts.payout += 1,
        }
        assert!(!close.header.verify::<Sha256, _>(&context, &roots, &amounts));
        let header = Header::new::<Sha256, _>(&context, &roots, &amounts);
        let mut bytes = encoded.to_vec();
        bytes[..32].copy_from_slice(header.encode().as_ref());
        assert!(
            !validate_bytes(
                &state,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                bytes.into()
            )
            .await
        );
    }
    assert_eq!(*state.head(), before);
    let old_opening = state.opening(payer.public_key()).await.unwrap();
    assert_eq!(
        old_opening.verify::<Sha256>(&before.root()).unwrap().get(),
        balance
    );
    let mut corrupt = old_opening.clone();
    corrupt.balance = NonZeroU64::new(balance + 1).unwrap();
    assert!(corrupt.verify::<Sha256>(&before.root()).is_err());
    corrupt = old_opening.clone();
    corrupt.account = absent.public_key();
    assert!(corrupt.verify::<Sha256>(&before.root()).is_err());
    let proof_bytes = old_opening.encode();
    assert_eq!(
        StateOpening::<VerifyingKey, Digest>::decode_cfg(proof_bytes.clone(), &MAX_PROOF_DIGESTS)
            .unwrap(),
        old_opening
    );
    assert!(
        StateOpening::<VerifyingKey, Digest>::decode_cfg(
            &proof_bytes[..proof_bytes.len() - 1],
            &MAX_PROOF_DIGESTS
        )
        .is_err()
    );
    let absent_key = account_key(&absent.public_key()).unwrap();
    assert_eq!(
        state
            .lookup(&absent_key)
            .await
            .unwrap()
            .resolve::<Sha256>(&state.root(), &absent_key)
            .unwrap(),
        None
    );
    let (next, close) = prepared.apply(state).await.unwrap();
    state = next.commit().await.unwrap();
    let expected_payer = if case.zero_net {
        balance
    } else {
        balance - amount
    };
    let expected_recipient = if case.zero_net {
        balance
    } else {
        balance + amount
    };
    for (account, expected) in [
        (payer.public_key(), expected_payer),
        (recipient.public_key(), expected_recipient),
    ] {
        let key = account_key(&account).unwrap();
        assert_eq!(
            state
                .get(&key)
                .await
                .unwrap()
                .map(NonZeroU64::get)
                .unwrap_or(0),
            expected
        );
        assert_eq!(
            state
                .lookup(&key)
                .await
                .unwrap()
                .resolve::<Sha256>(&state.root(), &key)
                .unwrap()
                .map(NonZeroU64::get)
                .unwrap_or(0),
            expected
        );
        assert_eq!(
            state
                .lookup_at(before.root(), before.operations(), &key)
                .await
                .unwrap()
                .resolve::<Sha256>(&before.root(), &key)
                .unwrap()
                .unwrap()
                .get(),
            balance
        );
    }
    assert_eq!(state.root(), close.roots.successor);
    assert_eq!(state.liability(), balance * 2);
    let current = *state.head();
    let foreign_root = StateRoot::new(Sha256::hash(&[b"unretained"]));
    assert!(
        state
            .lookup_at(foreign_root, before.operations(), &absent_key)
            .await
            .is_err()
    );
    assert_eq!(*state.head(), current);
    drop(state);
    let reopened = State::<_, Sha256>::open(
        runtime.child("replica"),
        support::config(&runtime, "transition"),
    )
    .await
    .unwrap();
    assert_eq!(*reopened.head(), current);
    assert_eq!(
        reopened
            .get(&account_key(&payer.public_key()).unwrap())
            .await
            .unwrap()
            .map(NonZeroU64::get)
            .unwrap_or(0),
        expected_payer
    );
}

async fn fuzz_admission(case: AdmissionCase, runtime: deterministic::Context) {
    let validators = (0..4)
        .map(|offset| Private::new(Scalar::from(case.seed.wrapping_add(offset).max(1))))
        .collect::<Vec<_>>();
    let Ok(committee) = Committee::new(validators.iter().map(compute_public::<MinSig>).collect())
    else {
        return;
    };
    let operator = SigningKey::from_seed(case.seed.wrapping_add(100));
    let (_, operator_bls) = bls_pair(case.seed.wrapping_add(300));
    let account = SigningKey::from_seed(case.seed.wrapping_add(200));
    let state = support::new_state(runtime, "admission", Vec::new()).await;
    let deposits = DepositBatch::new(vec![
        DepositRecord::new(account.public_key(), u64::from(case.mutation) + 1).unwrap(),
    ])
    .unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let context = close_context(
        Sha256::hash(&[b"admission"]),
        case.seed,
        operator.public_key(),
        &state,
        &deposits,
        &withdrawals,
        98,
        99,
        CloseLimits::protocol_maximum(),
        committee.commitment::<Sha256>(),
    )
    .await;
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        Vec::new(),
        &Sequential,
    )
    .await
    .unwrap();
    let before = *state.head();
    let mut votes = Vec::new();
    for private in validators {
        let scheme = bls12381::Scheme::signer(committee.clone(), private).unwrap();
        let (vote, validated) = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &state,
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            prepared.encoded().clone(),
            &mut test_rng(),
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(validated.close().header, prepared.close().header);
        assert_eq!(validated.encoded(), prepared.encoded());
        assert!(scheme.verify_vote(&prepared.close().header, &vote));
        let mut bytes = prepared.encoded().to_vec();
        bytes[0] ^= 1;
        assert!(
            seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &state,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                bytes.into(),
                &mut test_rng(),
                &Sequential
            )
            .await
            .is_err()
        );
        votes.push(vote);
    }
    assert_eq!(*state.head(), before);
    let verifier = bls12381::Scheme::verifier(committee.clone());
    let _ = verifier.verify_exact(&prepared.close().header, &case.certificate);
    assert!(
        verifier
            .assemble_exact(votes.iter().take(committee.quorum() - 1).cloned())
            .is_err()
    );
    assert!(
        verifier
            .assemble_exact(vec![votes[0].clone(); committee.quorum()])
            .is_err()
    );
    let certificate = verifier
        .assemble_exact(votes.into_iter().take(committee.quorum()))
        .unwrap();
    assert!(verifier.verify_exact(&prepared.close().header, &certificate));
    let mut amounts = prepared.close().amounts;
    amounts.payout += 1;
    let wrong = Header::new::<Sha256, _>(&context, &prepared.close().roots, &amounts);
    assert!(!verifier.verify_exact(&wrong, &certificate));
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Ok(input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };
    match input {
        FuzzInput::Payment(case) => fuzz_payment(*case),
        FuzzInput::Challenge(case) => deterministic::Runner::seeded(case.seed)
            .start(|runtime| async move { fuzz_challenge(*case, runtime).await }),
        FuzzInput::Commitment(case) => fuzz_commitment(*case),
        FuzzInput::Vector(case) => fuzz_vector(*case),
        FuzzInput::Transition(case) => deterministic::Runner::seeded(case.seed)
            .start(|runtime| async move { fuzz_transition(*case, runtime).await }),
        FuzzInput::Admission(case) => deterministic::Runner::seeded(case.seed)
            .start(|runtime| async move { fuzz_admission(*case, runtime).await }),
    }
});
