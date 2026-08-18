use commonware_cryptography::{
    bls12381::primitives::group::Scalar,
    transcript::{Transcript, Version},
    zk::{
        circuit::{Context, Var, build, build_with_values},
        pari::{
            Claim, InputLayout, Opening, Proof, ProvingKey, Relation, VerifyingKey, Witness, prove,
            setup, verify,
        },
    },
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

const MULTIPLICATIONS: [usize; 3] = [8, 16, 32];

struct ProvingFixture {
    relation: Relation,
    proving_key: ProvingKey,
    verifying_key: VerifyingKey,
    claim: Claim,
    witness: Witness,
}

struct VerifyingFixture {
    relation: Relation,
    verifying_key: VerifyingKey,
    claim: Claim,
    proof: Proof,
}

fn circuit(ctx: Context<'_, Scalar>, multiplications: usize) -> Vec<Var<'_, Scalar>> {
    let input = Var::witness(ctx, |_| Scalar::from(2u64));
    let mut output = input.clone();
    for _ in 0..multiplications {
        output *= &input;
    }
    vec![output, input]
}

fn make_relation(multiplications: usize) -> (Relation, InputLayout) {
    let (circuit, selected) = build(|ctx| circuit(ctx, multiplications));
    let layout = InputLayout::new(vec![selected[0]], vec![selected[1]])
        .expect("benchmark layout should be valid");
    let relation = Relation::compile(&circuit, &layout).expect("benchmark circuit should compile");
    (relation, layout)
}

fn make_proving_fixture(multiplications: usize) -> ProvingFixture {
    let (relation, layout) = make_relation(multiplications);
    let (valued, _) = build_with_values(|ctx| circuit(ctx, multiplications));
    let mut rng = test_rng();
    let (proving_key, verifying_key) =
        setup(&relation, &mut rng, &Sequential).expect("setup should succeed");
    let witness = relation
        .witness(&valued, &layout, Opening::random(&mut rng))
        .expect("benchmark witness should compile");
    let claim = witness
        .claim(proving_key.commitment_key(), &Sequential)
        .expect("benchmark claim should be valid");
    ProvingFixture {
        relation,
        proving_key,
        verifying_key,
        claim,
        witness,
    }
}

fn make_verifying_fixture(multiplications: usize) -> VerifyingFixture {
    let fixture = make_proving_fixture(multiplications);
    let mut rng = test_rng();
    let proof = prove(
        &mut rng,
        &mut transcript(),
        &fixture.proving_key,
        &fixture.relation,
        &fixture.claim,
        &fixture.witness,
        &Sequential,
    )
    .expect("proof should succeed");
    assert!(verify(
        &mut transcript(),
        &fixture.verifying_key,
        &fixture.relation,
        &fixture.claim,
        &proof,
    ));
    VerifyingFixture {
        relation: fixture.relation,
        verifying_key: fixture.verifying_key,
        claim: fixture.claim,
        proof,
    }
}

fn transcript() -> Transcript {
    let mut transcript = Transcript::new(b"pari-bench", Version::V1);
    transcript.commit(&b"context"[..]);
    transcript
}

fn bench_setup(c: &mut Criterion) {
    for multiplications in MULTIPLICATIONS {
        let (relation, _) = make_relation(multiplications);
        c.bench_function(
            &format!(
                "{}::setup/multiplications={multiplications}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    test_rng,
                    |mut rng| {
                        black_box(
                            setup(&relation, &mut rng, &Sequential).expect("setup should succeed"),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn bench_prove(c: &mut Criterion) {
    for multiplications in MULTIPLICATIONS {
        let fixture = make_proving_fixture(multiplications);
        c.bench_function(
            &format!(
                "{}::prove/multiplications={multiplications}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || (test_rng(), transcript()),
                    |(mut rng, mut transcript)| {
                        black_box(
                            prove(
                                &mut rng,
                                &mut transcript,
                                &fixture.proving_key,
                                &fixture.relation,
                                &fixture.claim,
                                &fixture.witness,
                                &Sequential,
                            )
                            .expect("proof should succeed"),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn bench_verify(c: &mut Criterion) {
    for multiplications in MULTIPLICATIONS {
        let fixture = make_verifying_fixture(multiplications);
        c.bench_function(
            &format!(
                "{}::verify/multiplications={multiplications}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    transcript,
                    |mut transcript| {
                        black_box(verify(
                            &mut transcript,
                            &fixture.verifying_key,
                            &fixture.relation,
                            &fixture.claim,
                            &fixture.proof,
                        ))
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_setup, bench_prove, bench_verify
}
