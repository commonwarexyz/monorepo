use commonware_clearing::bajillion::{
    payment::{EntryReceipt, PaymentContext, SendAuthorization, VectorAck, VectorSendBody},
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_cryptography::{Hasher, Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as VerifyingKey};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const EPOCH: u64 = 7;
const ENTRIES: usize = 16;
const OPERATOR_SEED: u64 = 1;
const PAYER_SEED: u64 = 2;
const RECIPIENT_SEED_START: u64 = 100;

struct AckFixture {
    context: PaymentContext<VerifyingKey, Digest>,
    receipt: EntryReceipt<VerifyingKey, Digest>,
    authorization: SendAuthorization<VerifyingKey, Digest>,
}

fn ack_fixture() -> AckFixture {
    let operator = SigningKey::from_seed(OPERATOR_SEED);
    let payer = SigningKey::from_seed(PAYER_SEED);
    let context = PaymentContext::new(
        Sha256::hash(&[b"clearing-benchmark-anchor"]),
        EPOCH,
        operator.public_key(),
    );

    // One acknowledged batch paying one unit to each of `ENTRIES` recipients, opened at its
    // first entry.
    let mut entries = (0..ENTRIES)
        .map(|index| OutEntry {
            recipient: SigningKey::from_seed(RECIPIENT_SEED_START + index as u64).public_key(),
            cumulative: 1,
            count: 1,
        })
        .collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
    let recipient = entries[0].recipient.clone();
    let vector = OutVector::new(EPOCH, payer.public_key(), entries).expect("vector is canonical");
    let send_root = vector
        .root::<Sha256, Digest>()
        .expect("vector root is valid");
    let body = VectorSendBody::new(&context, payer.public_key(), 0, ENTRIES as u64, send_root);
    let ack = VectorAck::sign_by_authorities(body, &payer, &operator);
    let authorization =
        SendAuthorization::from_raw_unchecked(ack.body().clone(), ack.payer_signature().clone());
    let OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = vector
        .lookup::<Sha256, Digest>(&recipient)
        .expect("fixture lookup is aligned")
    else {
        panic!("fixture entry is present");
    };
    let receipt = EntryReceipt {
        ack,
        recipient,
        cumulative,
        count,
        opening,
    };
    receipt
        .verify::<Sha256>(&context)
        .expect("benchmark receipt is valid");
    authorization
        .verify(&context)
        .expect("benchmark authorization is valid");
    AckFixture {
        context,
        receipt,
        authorization,
    }
}

fn bench_verify_ack(c: &mut Criterion) {
    let fixture = ack_fixture();
    c.bench_function(
        &format!(
            "{}/kind=receipt entries={ENTRIES} backend=curve25519 hash=sha256",
            module_path!()
        ),
        |b| {
            b.iter(|| {
                black_box(&fixture.receipt)
                    .verify::<Sha256>(black_box(&fixture.context))
                    .expect("benchmark receipt is valid");
            });
        },
    );
    c.bench_function(
        &format!("{}/kind=authorization backend=curve25519", module_path!()),
        |b| {
            b.iter(|| {
                black_box(&fixture.authorization)
                    .verify(black_box(&fixture.context))
                    .expect("benchmark authorization is valid");
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_ack,
}
