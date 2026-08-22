#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{Committee, assigned_slice_indices, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalBatch},
    challenge::{
        AccountLookup, Challenge, ChallengeKind, RangeLower, StateLookup, Verdict, adjudicate,
        decode_bounded,
    },
    commitment::{Builder, MultiOpening, Opening, VectorKind, VectorRoot, empty_root},
    credit::{CreditRoot, ShardHead, ShardLookup, ShardOpening, ShardSet, verify_opening},
    payment::{
        Payment, PaymentContext, ReceiptBody, SignedReceipt, SignedSend, receipt_range_is_feasible,
        verify_consecutive_receipts, verify_receipt_range, verify_receipt_step,
    },
    state::{AccountRow, AccountState, Prefix, StateLeaf},
    transition::{
        Assignment, Close, CloseContext, CloseLimits, Header, ProofSlice, RootBundle, StateCache,
        assemble_slices, build_close, prepare_close_with_strategy, validate_close, validate_slice,
    },
};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_VALUES: usize = 8;
const MAX_VALUE_BYTES: usize = 64;
const MAX_POSITIONS: usize = 8;
const MAX_PROOF_DIGESTS: usize = 64;
const MAX_STATES: usize = 16;
const MAX_ROWS: usize = 8;
const MAX_SHARDS_PER_ACCOUNT: usize = 8;
const MAX_BOUNDARY_RECORDS: usize = 8;

type TestPayment = Payment<VerifyingKey, Digest>;
type TestContext = PaymentContext<VerifyingKey, Digest>;
type TestCloseContext = CloseContext<VerifyingKey, Digest>;
type TestChallenge = Challenge<VerifyingKey, Digest>;

#[derive(Arbitrary, Debug)]
struct PaymentCase {
    context: TestContext,
    first: TestPayment,
    second: TestPayment,
    previous_debit: u64,
    lower_credit: u64,
    lower_index: u64,
    upper_credit: u64,
    upper_index: u64,
    seed: u64,
    amount: u8,
    next_amount: u8,
    valid_previous_debit: u32,
    valid_previous_credit: u32,
    valid_previous_index: u32,
    shard: u64,
}

#[derive(Arbitrary, Debug)]
struct ChallengeCase {
    header: Header<Digest>,
    roots: RootBundle<Digest>,
    now: u64,
    challenge: Challenge<VerifyingKey, Digest>,
    seed: u64,
    left_amount: u8,
    right_amount: u8,
    shard: u64,
}

#[derive(Arbitrary, Debug)]
struct CommitmentCase {
    opening: Opening<Digest>,
    multi: MultiOpening<Digest>,
    opening_root: VectorRoot<Digest>,
    opening_values: Vec<Vec<u8>>,
    positions: Vec<u8>,
    kind: VectorKind,
}

#[derive(Arbitrary, Debug)]
struct CreditCase {
    epoch: u64,
    recipient: VerifyingKey,
    root: CreditRoot<Digest>,
    opening: ShardOpening<VerifyingKey, Digest>,
    lookup: ShardLookup<VerifyingKey, Digest>,
    set: ShardSet<VerifyingKey, Digest>,
    shard: u64,
    seed: u64,
    amount: u8,
}

#[derive(Arbitrary, Debug)]
struct HeaderInput {
    context: TestContext,
    roots: RootBundle<Digest>,
}

#[derive(Arbitrary, Debug)]
struct TransitionCase {
    deployment: Digest,
    challenge_deadline: u64,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    header: HeaderInput,
    unchanged: Vec<StateLeaf<VerifyingKey>>,
    rows: Vec<AccountRow<VerifyingKey, Digest>>,
    shard_sets: Vec<ShardSet<VerifyingKey, Digest>>,
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
    Credit(Box<CreditCase>),
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

#[allow(clippy::too_many_arguments)]
fn make_payment(
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &SigningKey,
    amount: u64,
    previous_debit: u64,
    shard: u64,
    previous_credit: u64,
    previous_index: u64,
) -> TestPayment {
    let send = SignedSend::sign_next(
        context,
        payer,
        recipient.public_key(),
        amount,
        previous_debit,
    )
    .expect("bounded positive payment must not overflow");
    let receipt = SignedReceipt::issue_next::<Sha256, _>(
        context,
        &send,
        shard,
        previous_credit,
        previous_index,
        operator,
    )
    .expect("bounded positive receipt must not overflow");
    Payment::new::<Sha256>(context, send, receipt)
        .expect("honestly constructed payment must verify")
}

fn payment_context(seed: u64, operator: &SigningKey) -> TestContext {
    let seed = seed.to_be_bytes();
    PaymentContext::new(
        Sha256::hash(&[&seed]),
        seed[0] as u64,
        operator.public_key(),
    )
}

#[derive(Clone, Copy)]
struct ReceiptEndpoint {
    previous_debit: u64,
    shard: u64,
    credit: u64,
    index: u64,
}

fn payment_with_endpoint(
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &SigningKey,
    amount: u64,
    endpoint: ReceiptEndpoint,
) -> TestPayment {
    let send = SignedSend::sign_next(
        context,
        payer,
        recipient.public_key(),
        amount,
        endpoint.previous_debit,
    )
    .expect("bounded positive payment must not overflow");
    let receipt = SignedReceipt::sign_body_by_authority(
        ReceiptBody::from_raw_unchecked(
            *context.anchor(),
            context.epoch(),
            recipient.public_key(),
            endpoint.shard,
            amount,
            send.tx_id::<Sha256>(),
            endpoint.credit,
            endpoint.index,
        ),
        operator,
    );
    Payment::new::<Sha256>(context, send, receipt)
        .expect("an authority-signed endpoint must remain linked")
}

fn assignment(seed: u64) -> Assignment<Digest> {
    Assignment::new(
        Sha256::hash(&[b"fuzz-committee", &seed.to_be_bytes()]),
        seed.to_be_bytes()[0] % 9,
    )
    .expect("bounded fuzz assignment must be valid")
}

fn fuzz_payment(case: PaymentCase) {
    let _ = case.first.send().verify(&case.context);
    let _ = case
        .first
        .send()
        .verify_next(&case.context, case.previous_debit);
    let _ = case.first.receipt().verify(&case.context);
    let _ = case.first.verify_linked::<Sha256>(&case.context);
    let _ = case
        .first
        .verify_linked_next::<Sha256>(&case.context, case.previous_debit);
    let _ = case.first.verify_terminal::<Sha256>(&case.context);
    let _ = verify_receipt_step(case.lower_credit, case.lower_index, &case.first);
    let _ = verify_receipt_range::<Sha256, _, _>(&case.context, &case.first, &case.second);
    let _ = verify_consecutive_receipts::<Sha256, _, _>(&case.context, &case.first, &case.second);
    let _ = receipt_range_is_feasible(
        case.lower_credit,
        case.lower_index,
        case.first.amount(),
        case.upper_credit,
        case.upper_index,
    );

    let (operator, payer, recipient, next_payer) = private_keys(case.seed);
    let context = payment_context(case.seed, &operator);
    let previous_debit = u64::from(case.valid_previous_debit);
    let previous_credit = u64::from(case.valid_previous_credit);
    let previous_index = u64::from(case.valid_previous_index);
    let first = make_payment(
        &context,
        &operator,
        &payer,
        &recipient,
        u64::from(case.amount) + 1,
        previous_debit,
        case.shard,
        previous_credit,
        previous_index,
    );
    assert!(
        first
            .verify_linked_next::<Sha256>(&context, previous_debit)
            .is_ok()
    );

    let terminal = make_payment(
        &context,
        &operator,
        &payer,
        &recipient,
        u64::from(case.amount) + 1,
        previous_debit,
        case.shard,
        0,
        0,
    );
    assert!(terminal.verify_terminal::<Sha256>(&context).is_ok());

    let first_receipt = first.receipt().body();
    let second = make_payment(
        &context,
        &operator,
        &next_payer,
        &recipient,
        u64::from(case.next_amount) + 1,
        0,
        case.shard,
        first_receipt.cumulative_shard_credit(),
        first_receipt.index(),
    );
    assert!(verify_consecutive_receipts::<Sha256, _, _>(&context, &first, &second).is_ok());
    assert!(verify_receipt_range::<Sha256, _, _>(&context, &first, &second).is_ok());
}

fn unchanged_lookup(
    cache: &StateCache<VerifyingKey, Digest>,
    account: &VerifyingKey,
) -> AccountLookup<VerifyingKey, Digest> {
    AccountLookup::Absent {
        state: Box::new(
            cache
                .lookup(account)
                .expect("fixture account has a canonical live-state lookup"),
        ),
        predecessor: None,
        successor: None,
    }
}

fn invalidate_lookup(lookup: &mut AccountLookup<VerifyingKey, Digest>) {
    match lookup {
        AccountLookup::Present(opening) => opening.proof.proof.leaf_count ^= 1,
        AccountLookup::Absent { state, .. } => {
            let StateLookup::Present(opening) = state.as_mut() else {
                panic!("constructed unchanged lookup must prove live-state membership");
            };
            opening.proof.proof.leaf_count ^= 1;
        }
    }
}

fn invalidate_payment(payment: &TestPayment, wrong: &SigningKey) -> TestPayment {
    Payment::from_parts_unchecked(
        SignedSend::sign_body_by_authority(payment.send().body().clone(), wrong),
        payment.receipt().clone(),
    )
}

fn invalidate_challenge_body(challenge: &mut TestChallenge, wrong: &SigningKey) {
    let payment = match challenge {
        Challenge::LatestAcknowledgedSend { payment, .. }
        | Challenge::HigherShardTip { payment, .. } => payment,
        Challenge::InconsistentReceiptRange { upper, .. } => upper,
        Challenge::ReceiptFork { left, .. } => left,
    };
    **payment = invalidate_payment(payment, wrong);
}

fn invalidate_challenge_scope(challenge: &mut TestChallenge) {
    match challenge {
        Challenge::LatestAcknowledgedSend { payer, .. } => invalidate_lookup(payer),
        Challenge::HigherShardTip { shard, .. } => match shard.as_mut() {
            ShardLookup::Present { opening } => opening.value.shard ^= 1,
            ShardLookup::Absent { shard, .. } => *shard ^= 1,
        },
        Challenge::InconsistentReceiptRange { upper, lower, .. } => {
            *lower = RangeLower::Payment(upper.clone());
        }
        Challenge::ReceiptFork { left, right, .. } => std::mem::swap(left, right),
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
    let now = context.challenge_deadline();
    assert!(matches!(
        adjudicate::<Sha256, _>(context, header, roots, now, challenge),
        Ok(Verdict::Proven(actual)) if actual == kind
    ));
    assert!(adjudicate::<Sha256, _>(context, header, roots, now + 1, challenge).is_err());

    let encoded = challenge.encode();
    assert_eq!(encoded.len(), challenge.encode_size());
    assert!(encoded.len() <= MAX_INPUT_BYTES);
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, encoded.len())
        .expect("canonical bounded challenge must decode");
    assert_eq!(&decoded, challenge);
    assert!(matches!(
        adjudicate::<Sha256, _>(context, header, roots, now, &decoded),
        Ok(Verdict::Proven(actual)) if actual == kind
    ));

    let mut invalid_body = challenge.clone();
    invalidate_challenge_body(&mut invalid_body, wrong);
    assert!(adjudicate::<Sha256, _>(context, header, roots, now, &invalid_body).is_err());
    let mut invalid_scope = challenge.clone();
    invalidate_challenge_scope(&mut invalid_scope);
    assert!(adjudicate::<Sha256, _>(context, header, roots, now, &invalid_scope).is_err());

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
        let _ = adjudicate::<Sha256, _>(context, header, roots, now, &decoded);
    }
}

fn fuzz_challenge(case: ChallengeCase) {
    let (operator, payer, recipient, other_payer) = private_keys(case.seed);
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
            account: other_payer.public_key(),
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
    let challenge_deadline = case.now % 1_024 + 1;
    let context = CloseContext::new::<Sha256>(
        Sha256::hash(&[b"challenge-fuzz-deployment", &case.seed.to_be_bytes()]),
        case.seed,
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        challenge_deadline - 1,
        challenge_deadline,
        CloseLimits::protocol_maximum(),
        Assignment::new(Sha256::hash(&[b"challenge-fuzz-committee"]), 0)
            .expect("zero-bit assignment is valid"),
    )
    .expect("bounded empty-close context must be valid");
    let _ = adjudicate::<Sha256, _>(
        &context,
        &case.header,
        &case.roots,
        case.now,
        &case.challenge,
    );
    let close = build_close::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        Vec::new(),
        Vec::new(),
    )
    .expect("unchanged state must form a valid close");
    let header = close.header;
    let batch = header.batch_id::<Sha256>();
    let amount = u64::from(case.left_amount) + 1;
    let acknowledged = make_payment(
        context.payment(),
        &operator,
        &payer,
        &recipient,
        amount,
        0,
        case.shard,
        0,
        0,
    );
    let latest = Challenge::LatestAcknowledgedSend {
        batch,
        payment: Box::new(acknowledged.clone()),
        payer: Box::new(unchanged_lookup(&cache, &payer.public_key())),
    };
    let higher = Challenge::HigherShardTip {
        batch,
        payment: Box::new(acknowledged.clone()),
        recipient: Box::new(unchanged_lookup(&cache, &recipient.public_key())),
        shard: Box::new(
            ShardSet::empty(context.payment().epoch(), recipient.public_key())
                .lookup::<Sha256>(case.shard)
                .expect("empty shard set has a canonical absence proof"),
        ),
    };

    let lower = make_payment(
        context.payment(),
        &operator,
        &payer,
        &recipient,
        amount,
        0,
        case.shard,
        0,
        0,
    );
    let upper_amount = u64::from(case.right_amount) + 1;
    let lower_receipt = lower.receipt().body();
    let upper = payment_with_endpoint(
        context.payment(),
        &operator,
        &other_payer,
        &recipient,
        upper_amount,
        ReceiptEndpoint {
            previous_debit: 0,
            shard: case.shard,
            credit: lower_receipt
                .cumulative_shard_credit()
                .checked_add(upper_amount - 1)
                .expect("bounded receipt endpoint cannot overflow"),
            index: lower_receipt.index() + 1,
        },
    );
    let from_start = case.seed & 1 != 0;
    let lower = if from_start {
        RangeLower::ShardStart
    } else {
        RangeLower::Payment(Box::new(lower))
    };
    let inconsistent_upper = if from_start {
        payment_with_endpoint(
            context.payment(),
            &operator,
            &other_payer,
            &recipient,
            upper_amount,
            ReceiptEndpoint {
                previous_debit: 0,
                shard: case.shard,
                credit: 0,
                index: 0,
            },
        )
    } else {
        upper
    };
    let inconsistent = Challenge::InconsistentReceiptRange {
        batch,
        upper: Box::new(inconsistent_upper),
        lower,
    };

    let right = make_payment(
        context.payment(),
        &operator,
        &other_payer,
        &recipient,
        u64::from(case.right_amount) + 1,
        0,
        case.shard,
        0,
        0,
    );
    let fork = Challenge::receipt_fork(batch, acknowledged, right);
    let challenges = [
        (ChallengeKind::LatestAcknowledgedSend, latest),
        (ChallengeKind::HigherShardTip, higher),
        (ChallengeKind::InconsistentReceiptRange, inconsistent),
        (ChallengeKind::ReceiptFork, fork),
    ];
    let wrong = SigningKey::from_seed(case.seed.wrapping_add(100));
    for (offset, (kind, challenge)) in challenges.iter().enumerate() {
        exercise_challenge(
            &context,
            &header,
            &close.roots,
            *kind,
            challenge,
            &wrong,
            case.shard.to_be_bytes()[offset],
        );
    }
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
        .verify::<Sha256>(case.kind, &case.opening_root, first);
    let _ = case.opening.reconstruct::<Sha256>(case.kind, first);
    let _ = case
        .multi
        .verify::<Sha256, _>(case.kind, &case.opening_root, &opening_values);
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

fn bounded_set(set: ShardSet<VerifyingKey, Digest>) -> ShardSet<VerifyingKey, Digest> {
    let epoch = set.epoch();
    let recipient = set.recipient().clone();
    let heads = set
        .heads()
        .iter()
        .take(MAX_SHARDS_PER_ACCOUNT)
        .cloned()
        .collect();
    ShardSet::new(epoch, recipient.clone(), heads)
        .unwrap_or_else(|_| ShardSet::empty(epoch, recipient))
}

fn fuzz_credit(case: CreditCase) {
    let set = bounded_set(case.set);
    let _ = verify_opening::<Sha256, _>(case.epoch, &case.recipient, &case.root, &case.opening);
    let _ = case
        .lookup
        .resolve::<Sha256>(case.epoch, &case.recipient, &case.root, case.shard);
    let _ = set.root::<Sha256>();
    let _ = set.verify_root::<Sha256>(&case.root);
    let _ = set.lookup::<Sha256>(case.shard);

    let (operator, payer, recipient, _) = private_keys(case.seed);
    let context = payment_context(case.seed, &operator);
    let payment = make_payment(
        &context,
        &operator,
        &payer,
        &recipient,
        u64::from(case.amount) + 1,
        0,
        case.shard,
        0,
        0,
    );
    let set = ShardSet::new(
        context.epoch(),
        recipient.public_key(),
        vec![ShardHead::new(case.shard, payment)],
    )
    .expect("constructed singleton shard set must be canonical");
    let root = set.root::<Sha256>().expect("singleton set must commit");
    assert!(set.verify_root::<Sha256>(&root).is_ok());
    let present = set
        .lookup::<Sha256>(case.shard)
        .expect("present lookup must be constructible");
    assert!(matches!(
        present.resolve::<Sha256>(context.epoch(), set.recipient(), &root, case.shard),
        Ok(Some(_))
    ));
    let absent_shard = case.shard ^ 1;
    let absent = set
        .lookup::<Sha256>(absent_shard)
        .expect("absent lookup must be constructible");
    assert!(matches!(
        absent.resolve::<Sha256>(context.epoch(), set.recipient(), &root, absent_shard),
        Ok(None)
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

fn mutate_slice(
    slice: &ProofSlice<VerifyingKey, Digest>,
    selector: u8,
) -> ProofSlice<VerifyingKey, Digest> {
    let mut mutated = slice.clone();
    let marker = Sha256::hash(&[b"transition-slice-mutation", &[selector]]);
    let live_overlap = mutated.changes.rows.first().map(|row| StateLeaf {
        account: row.account.clone(),
        state: AccountState {
            balance: 1,
            active: true,
            ..AccountState::default()
        },
    });
    match selector % 32 {
        0 => mutated.index = u16::MAX,
        1 => mutated.layout.start.opening ^= 1,
        2 => mutated.layout.start.change ^= 1,
        3 => mutated.layout.start.closing ^= 1,
        4 => mutated.layout.start.prefix.payout ^= 1,
        5 => mutated.layout.end.opening ^= 1,
        6 => mutated.layout.end.change ^= 1,
        7 => mutated.layout.end.closing ^= 1,
        8 => mutated.layout.end.prefix.payout ^= 1,
        9 => mutated.layout.opening.start = u32::MAX,
        10 => mutated.layout.opening.proof.leaf_count ^= 1,
        11 => mutated.layout.opening.proof.siblings.push(marker),
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
            if mutated.shard_sets.is_empty() {
                mutated.changes.opening.start = u32::MAX;
            } else {
                mutated.shard_sets.clear();
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
                mutated.opening.predecessor = Some(leaf);
            } else {
                mutated.opening.opening.start = u32::MAX;
            }
        }
        19 => {
            if let Some(leaf) = live_overlap.clone() {
                mutated.opening.successor = Some(leaf);
            } else {
                mutated.opening.opening.start = u32::MAX;
            }
        }
        20 => mutated.opening.opening.start = u32::MAX,
        21 => mutated.opening.opening.proof.leaf_count ^= 1,
        22 => mutated.opening.opening.proof.siblings.push(marker),
        23 => {
            if let Some(leaf) = live_overlap.clone() {
                mutated.closing.predecessor = Some(leaf);
            } else {
                mutated.closing.opening.start = u32::MAX;
            }
        }
        24 => {
            if let Some(leaf) = live_overlap {
                mutated.closing.successor = Some(leaf);
            } else {
                mutated.closing.opening.start = u32::MAX;
            }
        }
        25 => mutated.closing.opening.start = u32::MAX,
        26 => mutated.closing.opening.proof.leaf_count ^= 1,
        27 => mutated.closing.opening.proof.siblings.push(marker),
        28 => {
            if let Some(row) = mutated.changes.rows.first().cloned() {
                mutated.changes.rows.push(row);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        29 => {
            if let Some(row) = mutated.changes.rows.first().cloned() {
                mutated.changes.predecessor = Some(row);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        30 => {
            if let Some(row) = mutated.changes.rows.last().cloned() {
                mutated.changes.successor = Some(row);
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
        _ => {
            if let Some(shards) = mutated.shard_sets.first_mut() {
                *shards =
                    ShardSet::empty(shards.epoch().wrapping_add(1), shards.recipient().clone());
            } else {
                mutated.changes.opening.start = u32::MAX;
            }
        }
    }
    mutated
}

#[allow(clippy::too_many_arguments)]
fn exercise_slice_mutation(
    context: &CloseContext<VerifyingKey, Digest>,
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
    validate_slice::<Sha256, _, _>(
        context,
        deposits,
        withdrawals,
        &close.header,
        &close.roots,
        slice,
    )
    .expect("canonical nonempty slice must validate");
    let mutated = mutate_slice(slice, selector);
    assert!(
        validate_slice::<Sha256, _, _>(
            context,
            deposits,
            withdrawals,
            &close.header,
            &close.roots,
            &mutated,
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
    case.shard_sets.truncate(MAX_ROWS);
    let mut leaves = case
        .unchanged
        .iter()
        .cloned()
        .map(|mut leaf| {
            leaf.state.active = true;
            leaf.state.balance = leaf.state.balance.max(1);
            leaf
        })
        .chain(
            case.rows
                .iter()
                .filter(|row| row.opening.active)
                .map(|row| StateLeaf {
                    account: row.account.clone(),
                    state: AccountState {
                        balance: row.opening.balance.max(1),
                        ..row.opening
                    },
                }),
        )
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    leaves.dedup_by(|left, right| left.account == right.account);
    let cache =
        StateCache::new::<Sha256>(leaves).expect("sanitized arbitrary opening cache must be valid");
    let (operator, _, _, _) = private_keys(case.seed);
    let _ = CloseContext::new::<Sha256>(
        case.deployment,
        case.header.context.epoch(),
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        admission_deadline,
        case.challenge_deadline,
        CloseLimits::protocol_maximum(),
        assignment(case.seed),
    );

    let empty_deposits = DepositBatch::empty();
    let empty_withdrawals = WithdrawalBatch::empty();
    let context = CloseContext::new::<Sha256>(
        case.deployment,
        case.header.context.epoch(),
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
    let shard_sets = case
        .shard_sets
        .into_iter()
        .map(bounded_set)
        .collect::<Vec<_>>();
    let roots = case.header.roots;
    let header = Header::new::<Sha256, _>(context.payment(), &roots);
    let close = Close {
        header,
        roots,
        unchanged: case.unchanged,
        rows: case.rows,
        shard_sets,
    };
    let _ = validate_close::<Sha256, _, _>(&context, &empty_deposits, &empty_withdrawals, &close);

    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(Vec::new())
        .expect("empty state cache must be valid");
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = CloseContext::new::<Sha256>(
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
    let close = build_close::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        Vec::new(),
        Vec::new(),
    )
    .expect("empty close must satisfy construction invariants");
    validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close)
        .expect("constructed empty close must validate");
    let slices = assemble_slices::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        &close,
        &Sequential,
    )
    .expect("constructed empty close must split into valid slices");
    for slice in &slices {
        validate_slice::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
        )
        .expect("constructed slice must validate");
    }

    let account = SigningKey::from_seed(case.seed.wrapping_add(10));
    let cache = StateCache::<VerifyingKey, Digest>::new::<Sha256>(Vec::new())
        .expect("empty opening cache is valid");
    let amount = case.seed.to_be_bytes()[0] as u64 + 1;
    let deposits = DepositBatch::new(vec![
        DepositRecord::new(account.public_key(), amount)
            .expect("positive fuzz deposit must be valid"),
    ])
    .expect("singleton fuzz deposit batch must be valid");
    let context = CloseContext::new::<Sha256>(
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
    let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
    let row = AccountRow {
        account: account.public_key(),
        opening: AccountState::default(),
        closing: AccountState {
            balance: amount,
            active: true,
            ..AccountState::default()
        },
        outgoing: None,
        credit_root: shards
            .root::<Sha256>()
            .expect("empty fuzz shard set must commit"),
        prefix: Prefix {
            deposit: amount,
            ..Prefix::default()
        },
    };
    let close = build_close::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![row],
        vec![shards],
    )
    .expect("constructed deposit creation must validate");
    assert_eq!(close.roots.opening, empty_root::<Sha256>(VectorKind::State));
    assert_ne!(close.roots.closing, empty_root::<Sha256>(VectorKind::State));
    validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close)
        .expect("constructed deposit creation must validate");
    let slices = assemble_slices::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        &close,
        &Sequential,
    )
    .expect("constructed deposit close must split into valid slices");
    for slice in &slices {
        validate_slice::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
        )
        .expect("constructed deposit slice must validate");
    }
    exercise_slice_mutation(
        &context,
        &deposits,
        &withdrawals,
        &close,
        &slices,
        case.seed.to_be_bytes()[2],
    );

    let account = SigningKey::from_seed(case.seed.wrapping_add(20));
    let requested_amount = case.seed.to_be_bytes()[1] as u64 + 1;
    let opening = AccountState {
        balance: requested_amount + 1,
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
        requested_amount,
        true,
        case.challenge_deadline,
        &account,
    )
    .expect("positive covered withdrawal must sign");
    let withdrawals = WithdrawalBatch::new(vec![withdrawal])
        .expect("singleton withdrawal batch must be canonical");
    let deposits = DepositBatch::empty();
    let context = CloseContext::new::<Sha256>(
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
    let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
    let row = AccountRow {
        account: account.public_key(),
        opening,
        closing: AccountState::default(),
        outgoing: None,
        credit_root: shards
            .root::<Sha256>()
            .expect("empty withdrawal shard set must commit"),
        prefix: Prefix {
            withdrawal: opening.balance,
            withdrawals: 1,
            ..Prefix::default()
        },
    };
    let close = build_close::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![row],
        vec![shards],
    )
    .expect("constructed full-close withdrawal must validate");
    assert_eq!(close.roots.closing, empty_root::<Sha256>(VectorKind::State));
    validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close)
        .expect("constructed full-close withdrawal must validate again");
    let slices = assemble_slices::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        &close,
        &Sequential,
    )
    .expect("constructed destruction close must split into slices");
    assert!(slices.iter().all(|slice| {
        validate_slice::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
        )
        .is_ok()
    }));

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
    let context = CloseContext::new::<Sha256>(
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
    let payment = make_payment(
        context.payment(),
        &operator,
        &payer,
        &recipient,
        payout,
        0,
        case.seed,
        0,
        0,
    );
    let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
    let recipient_shards = ShardSet::new(
        context.payment().epoch(),
        recipient.public_key(),
        vec![ShardHead::new(case.seed, payment.clone())],
    )
    .expect("singleton payout shard set is canonical");
    let mut pairs = vec![
        (
            AccountRow {
                account: payer.public_key(),
                opening: payer_opening,
                closing: AccountState {
                    balance: 1,
                    cumulative_debit: payout,
                    ..payer_opening
                },
                outgoing: Some(payment),
                credit_root: payer_shards
                    .root::<Sha256>()
                    .expect("empty payer shard set commits"),
                prefix: Prefix::default(),
            },
            payer_shards,
            Prefix {
                debit: payout,
                ..Prefix::default()
            },
        ),
        (
            AccountRow {
                account: recipient.public_key(),
                opening: AccountState::default(),
                closing: AccountState {
                    cumulative_credit: payout,
                    receipt_count: 1,
                    ..AccountState::default()
                },
                outgoing: None,
                credit_root: recipient_shards
                    .root::<Sha256>()
                    .expect("payout shard set commits"),
                prefix: Prefix::default(),
            },
            recipient_shards,
            Prefix {
                credit: payout,
                payout,
                shards: 1,
                ..Prefix::default()
            },
        ),
    ];
    pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
    let mut prefix = Prefix::default();
    for (row, _, delta) in &mut pairs {
        prefix = prefix
            .checked_extend(*delta)
            .expect("bounded payout prefixes cannot overflow");
        row.prefix = prefix;
    }
    let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs
        .into_iter()
        .map(|(row, shards, _)| (row, shards))
        .unzip();
    let prepared = prepare_close_with_strategy::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        rows,
        shard_sets,
        &Sequential,
    )
    .expect("constructed external payout must prepare");
    prepared
        .validate::<Sha256>(&context, &deposits, &withdrawals)
        .expect("constructed external payout must validate");
    let payout_proof = prepared
        .payout_proof(&deposits, &withdrawals)
        .expect("constructed external payout has a canonical extraction proof");
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
    let external_payouts = payout_proof
        .verify::<Sha256>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
        )
        .expect("constructed external payout proof must verify");
    assert_eq!(external_payouts.len(), 1);
    assert_eq!(external_payouts[0].recipient, recipient.public_key());
    assert_eq!(external_payouts[0].amount, payout);
    validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, close)
        .expect("constructed external payout must validate again");
    let slices = prepared
        .assemble_slices(&cache, &Sequential)
        .expect("external payout close must split into slices");
    assert!(slices.iter().all(|slice| {
        validate_slice::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slice,
        )
        .is_ok()
    }));
}

#[allow(clippy::too_many_arguments)]
fn assignment_is_rejected(
    scheme: &bls12381::Scheme,
    context: &CloseContext<VerifyingKey, Digest>,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    header: &Header<Digest>,
    roots: &RootBundle<Digest>,
    slices: Vec<ProofSlice<VerifyingKey, Digest>>,
) -> bool {
    seal::<Sha256, _, _, PaymentBatchVerifier, _>(
        scheme,
        context,
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
    let context = CloseContext::new::<Sha256>(
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
    let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
    let row = AccountRow {
        account: account.public_key(),
        opening: AccountState::default(),
        closing: AccountState {
            balance: amount,
            active: true,
            ..AccountState::default()
        },
        outgoing: None,
        credit_root: shards
            .root::<Sha256>()
            .expect("empty admission shard set commits"),
        prefix: Prefix {
            deposit: amount,
            ..Prefix::default()
        },
    };
    let close = build_close::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        vec![row],
        vec![shards],
    )
    .expect("nonempty admission close must be valid");
    validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close)
        .expect("nonempty admission close must validate");
    let all = assemble_slices::<Sha256, _, _>(
        &cache,
        &context,
        &deposits,
        &withdrawals,
        &close,
        &Sequential,
    )
    .expect("admission slices must build");
    let nonempty = all
        .iter()
        .find(|slice| !slice.changes.rows.is_empty())
        .expect("deposit creation has one nonempty slice")
        .index;
    let mut votes = Vec::new();
    let mut checked_nonempty_mutation = false;
    for (validator, private) in validators.iter().enumerate() {
        let scheme = bls12381::Scheme::signer(committee.clone(), private.clone())
            .expect("validator belongs to committee");
        let assigned = assigned_slice_indices::<Sha256, _>(
            &committee,
            context.assignment(),
            scheme.me().expect("signer has a committee index"),
        )
        .expect("assignment matches committee")
        .into_iter()
        .map(|slice| all[usize::from(slice)].clone())
        .collect::<Vec<_>>();
        let canonical = assigned.clone();
        let (vote, retained) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            assigned,
            &mut test_rng(),
            &Sequential,
        )
        .expect("complete valid assignment must sign");
        assert!(
            retained
                .slices()
                .iter()
                .all(|slice| retained.serve(slice.index).is_some())
        );
        if validator == 0 {
            let position = usize::from(case.mutation) % canonical.len();
            let mut omitted = canonical.clone();
            omitted.remove(position);
            assert!(assignment_is_rejected(
                &scheme,
                &context,
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
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                reordered,
            ));
        }
        if let Some(position) = canonical
            .iter()
            .position(|slice| slice.index == nonempty)
            .filter(|_| !checked_nonempty_mutation)
        {
            let mut malformed = canonical.clone();
            malformed[position] = mutate_slice(&malformed[position], case.mutation);
            assert!(assignment_is_rejected(
                &scheme,
                &context,
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
        FuzzInput::Credit(case) => fuzz_credit(*case),
        FuzzInput::Transition(case) => fuzz_transition(*case),
        FuzzInput::Admission(case) => fuzz_admission(*case),
    }
});
