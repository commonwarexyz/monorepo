use super::{
    admission_fixtures::{FAULTS, QUORUM, SLICE_BITS, SLICES, VALIDATORS, Validators},
    fixtures::{
        ActiveProfile, CloseFixture, WORKERS, active_chain_fixture, selected_active_profiles,
        strategy,
    },
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{RetainedAssignment, Vote, curve25519, seal},
    challenge::{
        AccountLookup, Challenge, ChallengeKind, RowOpening, Verdict, adjudicate_with_strategy,
        decode_bounded,
    },
    credit::{ShardLookup, ShardSet},
    settlement::{BatchStatus, HardFaultReason, SettlementChain, SettlementConfig},
    state::AccountRow,
    transition::{
        BatchId, Header, PreparedClose, ProofSlice, prepare_close_with_strategy, validate_close,
        validate_header,
    },
};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::{
    Sha256,
    curve25519::{BatchVerifier as PaymentBatchVerifier, VerifyingKey},
    sha256::Digest,
};
use commonware_utils::{Participant, TestRng};
use criterion::{BatchSize, Criterion, criterion_group};
use std::{
    hint::black_box,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

type CommitmentPayload = (
    Header<VerifyingKey, Digest>,
    curve25519::Certificate,
    Option<RowOpening<VerifyingKey, Digest>>,
);
type TestChain = SettlementChain<Sha256, VerifyingKey>;

struct Metrics {
    close_bytes: usize,
    slice_corpus_bytes: usize,
    assignment_bytes: usize,
    assigned_slices: usize,
    header_bytes: usize,
    certificate_bytes: usize,
    terminal_opening_bytes: usize,
    commitment_bytes: usize,
    challenge_row_lookup_bytes: usize,
    challenge_shard_lookup_bytes: usize,
    challenge_bytes: usize,
}

struct BlogChainFixture {
    close: CloseFixture,
    validators: Validators,
    validator: Participant,
    validator_scheme: curve25519::Scheme<VerifyingKey>,
    validator_slices: Vec<ProofSlice<VerifyingKey, Digest>>,
    commitment: CommitmentPayload,
    verifier: curve25519::Scheme<VerifyingKey>,
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
        let (close, terminal, challenge) = active_chain_fixture(profile, assignment);
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
        let (validator, indices, assignment_bytes) =
            validators.largest_assignment(close.context.assignment(), &all_slices);
        let validator_slices = indices
            .iter()
            .map(|index| all_slices[usize::from(*index)].clone())
            .collect::<Vec<_>>();
        let validator_scheme = validators.signer(validator);
        drop(all_slices);

        let header = close.prepared.close().header.clone();
        let certificate = exact_certificate(&validators, &header);
        let commitment = (header.clone(), certificate, Some(terminal));
        let encoded_commitment = commitment.encode();
        let commitment_bytes = commitment.encode_size();
        assert_eq!(encoded_commitment.len(), commitment_bytes);

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
            validators.committee(),
            &close.context,
            &close.deposits,
            &close.withdrawals,
            &close.prepared.close().header,
            validator_slices.clone(),
            &mut TestRng::new(0),
            strategy(),
        )
        .expect("benchmark validator assignment is valid");
        let verifier = curve25519::Scheme::verifier(validators.committee().clone());
        let metrics = Metrics {
            close_bytes,
            slice_corpus_bytes,
            assignment_bytes,
            assigned_slices: validator_slices.len(),
            header_bytes: commitment.0.encode_size(),
            certificate_bytes: commitment.1.encode_size(),
            terminal_opening_bytes: commitment.2.encode_size(),
            commitment_bytes,
            challenge_row_lookup_bytes,
            challenge_shard_lookup_bytes,
            challenge_bytes,
        };

        Self {
            close,
            validators,
            validator,
            validator_scheme,
            validator_slices,
            commitment,
            verifier,
            encoded_challenge,
            metrics,
        }
    }

    fn build_roots(
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
        .expect("benchmark roots are valid")
    }

    fn assemble_proof_slices(&self) -> Vec<ProofSlice<VerifyingKey, Digest>> {
        self.close
            .prepared
            .assemble_slices(&self.close.cache, strategy())
            .expect("benchmark slices are valid")
    }

    fn seal(
        &self,
        slices: Vec<ProofSlice<VerifyingKey, Digest>>,
        rng: &mut TestRng,
    ) -> (Vote<VerifyingKey>, RetainedAssignment<VerifyingKey, Digest>) {
        seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &self.validator_scheme,
            self.validators.committee(),
            &self.close.context,
            &self.close.deposits,
            &self.close.withdrawals,
            &self.close.prepared.close().header,
            slices,
            rng,
            strategy(),
        )
        .expect("benchmark validator assignment is valid")
    }

    // This is the repeatable verification portion of SettlementChain::admit after registration.
    fn verify_commitment(&self, rng: &mut TestRng) -> BatchId<Digest> {
        let (header, certificate, terminal) = &self.commitment;
        validate_header(&self.close.context, header)
            .expect("benchmark header matches its registration");
        assert_eq!(header.totals.deposit, 0);
        assert_eq!(header.totals.withdrawal, 0);
        assert_eq!(header.totals.withdrawals, 0);
        let terminal = terminal
            .as_ref()
            .expect("every active profile has a terminal row");
        terminal
            .proof
            .verify::<Sha256>(&header.change_root, terminal.row.encode().as_ref())
            .expect("benchmark terminal row authenticates");
        assert_eq!(
            terminal.proof.position.checked_add(1),
            Some(header.change_root.len)
        );
        assert_eq!(terminal.row.prefix, header.totals);
        assert!(
            self.verifier
                .verify_exact(rng, header, certificate, strategy())
        );
        header.batch_id::<Sha256>()
    }

    // This is the repeatable decode-and-adjudicate portion of challenge_encoded.
    fn verify_challenge(&self) -> Verdict {
        let challenge = decode_bounded::<VerifyingKey, Digest>(
            self.encoded_challenge.as_ref(),
            self.encoded_challenge.len(),
        )
        .expect("benchmark challenge decodes within its exact bound");
        adjudicate_with_strategy::<Sha256, _>(
            &self.commitment.0,
            self.commitment.0.challenge_deadline,
            &challenge,
            strategy(),
        )
        .expect("benchmark challenge is well formed")
    }
}

fn exact_certificate(
    validators: &Validators,
    header: &Header<VerifyingKey, Digest>,
) -> curve25519::Certificate {
    let attestations = validators.attestations(header);
    assert_eq!(attestations.len(), QUORUM);
    let certificate = validators
        .signer(Participant::new(0))
        .assemble_exact(attestations, strategy())
        .expect("benchmark attestations form an exact certificate");
    assert_eq!(certificate.signers.len(), VALIDATORS);
    assert_eq!(certificate.signers.count(), QUORUM);
    assert_eq!(certificate.signatures.len(), QUORUM);
    assert!(certificate.signers.iter().map(usize::from).eq(0..QUORUM));
    certificate
}

fn chain(close: &CloseFixture, validators: &Validators) -> TestChain {
    let registry = NonZeroUsize::new(close.cache.len()).expect("active registry is nonempty");
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
            registry,
            0,
            registry,
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
    let mut chain = chain(close, validators);
    chain
        .register(
            0,
            close.context.clone(),
            close.deposits.clone(),
            close.withdrawals.clone(),
        )
        .expect("benchmark close can be registered");
    let mut rng = TestRng::new(0);
    let batch = chain
        .admit(
            0,
            commitment.0.clone(),
            commitment.1.clone(),
            commitment.2.as_ref(),
            &mut rng,
            strategy(),
        )
        .expect("benchmark commitment can be admitted");
    assert_eq!(batch, commitment.0.batch_id::<Sha256>());
    let verdict = chain
        .challenge_encoded_with_strategy(
            commitment.0.challenge_deadline,
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
        let registry = profile.registry;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        eprintln!(
            "clearing blog chain metrics: profile={profile_index} N={registry} A={changed} B={credited} h={shards} n={VALIDATORS} f={FAULTS} q={QUORUM} slices={SLICES} workers={WORKERS} close_bytes={} slice_corpus_bytes={} validator={} assignment_bytes={} assigned_slices={} header_bytes={} certificate_bytes={} terminal_opening_bytes={} commitment_bytes={} challenge_row_lookup_bytes={} challenge_shard_lookup_bytes={} challenge_bytes={}",
            fixture.metrics.close_bytes,
            fixture.metrics.slice_corpus_bytes,
            usize::from(fixture.validator),
            fixture.metrics.assignment_bytes,
            fixture.metrics.assigned_slices,
            fixture.metrics.header_bytes,
            fixture.metrics.certificate_bytes,
            fixture.metrics.terminal_opening_bytes,
            fixture.metrics.commitment_bytes,
            fixture.metrics.challenge_row_lookup_bytes,
            fixture.metrics.challenge_shard_lookup_bytes,
            fixture.metrics.challenge_bytes,
        );

        let labels = format!(
            "N={registry} A={changed} B={credited} h={shards} n={VALIDATORS} q={QUORUM} slices={SLICES} w={WORKERS}"
        );
        c.bench_function(
            &format!(
                "{}/p={profile_index} op=build-roots {labels}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || (fixture.close.rows.clone(), fixture.close.shard_sets.clone()),
                    |(rows, shard_sets)| black_box(fixture.build_roots(rows, shard_sets)),
                    BatchSize::PerIteration,
                );
            },
        );
        c.bench_function(
            &format!(
                "{}/p={profile_index} op=assemble-proof-slices {labels}",
                module_path!()
            ),
            |b| b.iter(|| black_box(fixture.assemble_proof_slices())),
        );
        c.bench_function(
            &format!("{}/p={profile_index} op=seal {labels}", module_path!()),
            |b| {
                let mut slices = Some(fixture.validator_slices.clone());
                let mut rng = TestRng::new(0);
                b.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let input = slices.take().expect("benchmark assignment is available");
                        let start = Instant::now();
                        let (vote, retained) = fixture.seal(input, black_box(&mut rng));
                        elapsed += start.elapsed();
                        black_box(vote);
                        slices = Some(retained.into_slices());
                    }
                    elapsed
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/p={profile_index} op=check-commitment {labels}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || TestRng::new(0),
                    |mut rng| black_box(fixture.verify_commitment(black_box(&mut rng))),
                    BatchSize::SmallInput,
                );
            },
        );
        c.bench_function(
            &format!(
                "{}/p={profile_index} op=check-challenge {labels}",
                module_path!()
            ),
            |b| {
                b.iter(|| black_box(fixture.verify_challenge()));
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
