use super::{
    admission_fixtures::{FAULTS, QUORUM, SLICE_BITS, SLICES, VALIDATORS, Validators},
    fixtures::{
        ActiveProfile, CloseFixture, WORKERS, active_chain_fixture, selected_active_profiles,
        strategy,
    },
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{RetainedAssignment, Vote, bls12381, seal},
    challenge::{
        AccountLookup, Challenge, ChallengeKind, Verdict, adjudicate_with_strategy, decode_bounded,
    },
    credit::{ShardLookup, ShardSet},
    settlement::{BatchStatus, HardFaultReason, SettlementChain, SettlementConfig},
    state::AccountRow,
    transition::{
        BatchId, Header, PreparedClose, ProofSlice, RootBundle, prepare_close_with_strategy,
        validate_close, validate_header,
    },
};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, StrictVerifyingKey as VerifyingKey,
};
use commonware_utils::{Participant, TestRng};
use criterion::{BatchSize, Criterion, criterion_group};
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

type CommitmentPayload = (Header<Digest>, RootBundle<Digest>, bls12381::Certificate);
type TestChain = SettlementChain<Sha256, VerifyingKey>;

struct Metrics {
    close_bytes: usize,
    slice_corpus_bytes: usize,
    dealing_bytes: usize,
    dealing_slices: usize,
    header_bytes: usize,
    root_bundle_witness_bytes: usize,
    external_certificate_bytes: usize,
    external_package_bytes: usize,
    validator_chain_commitment_bytes: usize,
    challenge_row_lookup_bytes: usize,
    challenge_shard_lookup_bytes: usize,
    challenge_bytes: usize,
}

struct BlogChainFixture {
    close: CloseFixture,
    validator: Participant,
    validator_scheme: bls12381::Scheme,
    dealing: Vec<ProofSlice<VerifyingKey, Digest>>,
    commitment: CommitmentPayload,
    verifier: bls12381::Scheme,
    encoded_challenge: Bytes,
    metrics: Metrics,
}

impl BlogChainFixture {
    fn new(profile: ActiveProfile) -> Self {
        let validators = Validators::new();
        assert_eq!(validators.committee().members().len(), VALIDATORS);
        assert_eq!(validators.committee().faults(), FAULTS);
        assert_eq!(validators.committee().quorum(), QUORUM);

        let assignment = validators.assignment();
        let (close, challenge) = active_chain_fixture(profile, assignment);
        assert_eq!(close.context.assignment().slice_bits(), SLICE_BITS);
        assert_eq!(
            close.context.assignment().committee(),
            &validators.committee().commitment::<Sha256>()
        );
        assert!(close.deposits.is_empty());
        assert!(close.withdrawals.is_empty());

        validate_close::<Sha256, _, _>(
            &close.context,
            &close.deposits,
            &close.withdrawals,
            close.prepared.close(),
        )
        .expect("benchmark close is publicly valid");
        let all_slices = close
            .prepared
            .assemble_slices(&close.cache, strategy())
            .expect("benchmark slices are valid");
        assert_eq!(all_slices.len(), SLICES);
        let close_bytes = close.prepared.close().encode_size();
        let slice_corpus_bytes = all_slices.iter().map(EncodeSize::encode_size).sum();
        let (validator, indices, dealing_bytes) =
            validators.largest_assignment(close.context.assignment(), &all_slices);
        let dealing = indices
            .iter()
            .map(|index| all_slices[usize::from(*index)].clone())
            .collect::<Vec<_>>();
        let validator_scheme = validators.signer(validator);
        drop(all_slices);

        let header = close.prepared.close().header;
        let certificate = exact_certificate(&validators, &header);
        let external_package = (header, certificate.clone());
        let external_package_bytes = external_package.encode_size();
        assert_eq!(external_package.encode().len(), external_package_bytes);
        let commitment = (header, close.prepared.close().roots, certificate);

        let (challenge_row_lookup_bytes, challenge_shard_lookup_bytes) = match &challenge {
            Challenge::HigherShardTip {
                batch,
                payment,
                recipient,
                shard,
            } => {
                assert_eq!(batch, &header.batch_id::<Sha256>());
                assert_eq!(payment.receipt().body().shard(), 0);
                assert!(matches!(recipient.as_ref(), AccountLookup::Present(_)));
                assert!(matches!(shard.as_ref(), ShardLookup::Present { .. }));
                (recipient.encode_size(), shard.encode_size())
            }
            _ => unreachable!("the blog benchmark uses a higher-shard-tip challenge"),
        };
        let encoded_challenge = challenge.encode();
        let challenge_bytes = challenge.encode_size();
        assert_eq!(encoded_challenge.len(), challenge_bytes);
        assert_eq!(
            decode_bounded::<VerifyingKey, Digest>(
                encoded_challenge.as_ref(),
                encoded_challenge.len(),
            )
            .expect("canonical benchmark challenge decodes"),
            challenge
        );

        preflight_chain(&close, &validators, &commitment, encoded_challenge.as_ref());
        seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &validator_scheme,
            &close.context,
            &close.deposits,
            &close.withdrawals,
            &close.prepared.close().header,
            &close.prepared.close().roots,
            dealing.clone(),
            &mut TestRng::new(0),
            strategy(),
        )
        .expect("benchmark validator dealing is valid");
        let verifier = bls12381::Scheme::verifier(validators.committee().clone());
        let header_bytes = commitment.0.encode_size();
        let root_bundle_witness_bytes = commitment.1.encode_size();
        let external_certificate_bytes = commitment.2.encode_size();
        let validator_chain_commitment_bytes = header_bytes;
        assert_eq!(header_bytes, 32);
        assert_eq!(root_bundle_witness_bytes, 128);
        assert_eq!(external_certificate_bytes, 69);
        assert_eq!(external_package_bytes, 101);
        assert_eq!(validator_chain_commitment_bytes, 32);
        let metrics = Metrics {
            close_bytes,
            slice_corpus_bytes,
            dealing_bytes,
            dealing_slices: dealing.len(),
            header_bytes,
            root_bundle_witness_bytes,
            external_certificate_bytes,
            external_package_bytes,
            validator_chain_commitment_bytes,
            challenge_row_lookup_bytes,
            challenge_shard_lookup_bytes,
            challenge_bytes,
        };

        Self {
            close,
            validator,
            validator_scheme,
            dealing,
            commitment,
            verifier,
            encoded_challenge,
            metrics,
        }
    }

    fn prepare(
        &self,
        rows: Vec<AccountRow<VerifyingKey, Digest>>,
        shard_sets: Vec<ShardSet<VerifyingKey, Digest>>,
    ) -> PreparedClose<VerifyingKey, Digest> {
        prepare_close_with_strategy::<Sha256, _, _>(
            &self.close.cache,
            &self.close.context,
            &self.close.deposits,
            &self.close.withdrawals,
            rows,
            shard_sets,
            strategy(),
        )
        .expect("benchmark preparation is valid")
    }

    fn deal(&self) -> Vec<ProofSlice<VerifyingKey, Digest>> {
        self.close
            .prepared
            .assemble_slices(&self.close.cache, strategy())
            .expect("benchmark slices are valid")
    }

    fn seal(
        &self,
        dealing: Vec<ProofSlice<VerifyingKey, Digest>>,
        rng: &mut TestRng,
    ) -> (Vote, RetainedAssignment<VerifyingKey, Digest>) {
        seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &self.validator_scheme,
            &self.close.context,
            &self.close.deposits,
            &self.close.withdrawals,
            &self.close.prepared.close().header,
            &self.close.prepared.close().roots,
            dealing,
            rng,
            strategy(),
        )
        .expect("benchmark validator dealing is valid")
    }

    // Repeatable root-witness and certificate validation. The mutating admission path, including
    // payout extraction, is preflighted separately because its state cannot be reused per sample.
    fn check_certified_commitment(&self) -> BatchId<Digest> {
        let (header, roots, certificate) = &self.commitment;
        validate_header::<Sha256, _, _>(&self.close.context, header, roots)
            .expect("benchmark header matches its registration");
        assert!(self.verifier.verify_exact(header, certificate));
        header.batch_id::<Sha256>()
    }

    // Repeatable bounded decode and adjudication performed by challenge_encoded.
    fn check_challenge(&self) -> Verdict {
        let challenge = decode_bounded::<VerifyingKey, Digest>(
            self.encoded_challenge.as_ref(),
            self.encoded_challenge.len(),
        )
        .expect("benchmark challenge decodes within its exact bound");
        adjudicate_with_strategy::<Sha256, _>(
            &self.close.context,
            &self.commitment.0,
            &self.commitment.1,
            self.close.context.challenge_deadline(),
            &challenge,
            strategy(),
        )
        .expect("benchmark challenge is well formed")
    }
}

fn exact_certificate(validators: &Validators, header: &Header<Digest>) -> bls12381::Certificate {
    let attestations = validators.attestations(header);
    assert_eq!(attestations.len(), QUORUM);
    let certificate = validators
        .signer(Participant::new(0))
        .assemble_exact(attestations)
        .expect("benchmark attestations form an exact certificate");
    assert_eq!(certificate.signers.len(), VALIDATORS);
    assert_eq!(certificate.signers.count(), QUORUM);
    assert!(certificate.signers.iter().map(usize::from).eq(0..QUORUM));
    certificate
}

fn chain(close: &CloseFixture, validators: &Validators) -> TestChain {
    let live_accounts =
        NonZeroUsize::new(close.cache.len()).expect("live account state is nonempty");
    let notice = NonZeroU64::new(1).expect("benchmark notice is nonzero");
    TestChain::new(
        *close.context.deployment(),
        close.context.payment().operator().clone(),
        validators.committee().clone(),
        &close.cache,
        close.context.payment().epoch(),
        SettlementConfig::new(
            NonZeroUsize::new(1).expect("benchmark pipeline bound is nonzero"),
            notice,
            notice,
            live_accounts,
            0,
            live_accounts,
        ),
    )
    .expect("benchmark settlement chain is valid")
}

fn preflight_chain(
    close: &CloseFixture,
    validators: &Validators,
    commitment: &CommitmentPayload,
    encoded_challenge: &[u8],
) {
    let payout_proof = close
        .prepared
        .payout_proof(&close.deposits, &close.withdrawals)
        .expect("benchmark payout proof is valid");
    let mut chain = chain(close, validators);
    chain
        .register(
            0,
            close.context.clone(),
            close.deposits.clone(),
            close.withdrawals.clone(),
        )
        .expect("benchmark close can be registered");
    let batch = chain
        .admit(
            0,
            commitment.0,
            commitment.1,
            payout_proof,
            commitment.2.clone(),
        )
        .expect("benchmark commitment can be admitted");
    assert_eq!(batch, commitment.0.batch_id::<Sha256>());
    let verdict = chain
        .challenge_encoded_with_strategy(
            close.context.challenge_deadline(),
            encoded_challenge,
            encoded_challenge.len(),
            strategy(),
        )
        .expect("benchmark challenge can be checked");
    assert_eq!(verdict, Verdict::Proven(ChallengeKind::HigherShardTip));
    assert!(matches!(
        chain.pending().map(|pending| &pending.status),
        Some(BatchStatus::Challenged(ChallengeKind::HigherShardTip))
    ));
    assert_eq!(chain.invalid_from(), Some(batch));
    assert_eq!(
        chain.admission_fence_epoch(),
        close.context.payment().epoch().checked_add(1)
    );
    assert!(matches!(
        chain.hard_fault(),
        Some(HardFaultReason::ProvenChallenge { batch_id, kind })
            if *batch_id == batch && *kind == ChallengeKind::HigherShardTip
    ));
}

fn bench_blog_chain(c: &mut Criterion) {
    for (profile_index, profile) in selected_active_profiles() {
        let fixture = BlogChainFixture::new(profile);
        let live_accounts = profile.live_accounts;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        eprintln!(
            "clearing blog chain metrics: profile={profile_index} N={live_accounts} A={changed} B={credited} h={shards} n={VALIDATORS} f={FAULTS} q={QUORUM} slices={SLICES} workers={WORKERS} close_bytes={} slice_corpus_bytes={} validator={} dealing_bytes={} dealing_slices={} header_bytes={} root_bundle_witness_bytes={} external_certificate_bytes={} external_package_bytes={} validator_chain_commitment_bytes={} challenge_row_lookup_bytes={} challenge_shard_lookup_bytes={} challenge_bytes={}",
            fixture.metrics.close_bytes,
            fixture.metrics.slice_corpus_bytes,
            usize::from(fixture.validator),
            fixture.metrics.dealing_bytes,
            fixture.metrics.dealing_slices,
            fixture.metrics.header_bytes,
            fixture.metrics.root_bundle_witness_bytes,
            fixture.metrics.external_certificate_bytes,
            fixture.metrics.external_package_bytes,
            fixture.metrics.validator_chain_commitment_bytes,
            fixture.metrics.challenge_row_lookup_bytes,
            fixture.metrics.challenge_shard_lookup_bytes,
            fixture.metrics.challenge_bytes,
        );

        let labels = format!(
            "N={live_accounts} A={changed} B={credited} h={shards} n={VALIDATORS} q={QUORUM} slices={SLICES} w={WORKERS}"
        );
        c.bench_function(
            &format!("{}/p={profile_index} op=prepare {labels}", module_path!()),
            |b| {
                b.iter_batched(
                    || (fixture.close.rows.clone(), fixture.close.shard_sets.clone()),
                    |(rows, shard_sets)| black_box(fixture.prepare(rows, shard_sets)),
                    BatchSize::PerIteration,
                );
            },
        );
        c.bench_function(
            &format!("{}/p={profile_index} op=deal {labels}", module_path!()),
            |b| {
                b.iter_batched(
                    || (),
                    |()| black_box(fixture.deal()),
                    BatchSize::PerIteration,
                );
            },
        );
        c.bench_function(
            &format!("{}/p={profile_index} op=seal {labels}", module_path!()),
            |b| {
                let mut dealing = Some(fixture.dealing.clone());
                let mut rng = TestRng::new(0);
                b.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let input = dealing.take().expect("benchmark dealing is available");
                        let start = Instant::now();
                        let (vote, retained) = fixture.seal(input, black_box(&mut rng));
                        elapsed += start.elapsed();
                        black_box(vote);
                        dealing = Some(retained.into_slices());
                    }
                    elapsed
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/p={profile_index} op=check-certified-commitment {labels}",
                module_path!()
            ),
            |b| {
                b.iter(|| black_box(fixture.check_certified_commitment()));
            },
        );
        c.bench_function(
            &format!(
                "{}/p={profile_index} op=check-challenge {labels}",
                module_path!()
            ),
            |b| {
                b.iter(|| black_box(fixture.check_challenge()));
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(10))
        .measurement_time(Duration::from_secs(20));
    targets = bench_blog_chain,
}
