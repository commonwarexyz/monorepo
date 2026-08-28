use super::{
    admission_fixtures::{FAULTS, QUORUM, SLICE_BITS, SLICES, VALIDATORS, Validators},
    fixtures::{
        ActiveProfile, CloseFixture, WORKERS, active_chain_fixture, selected_active_profiles,
        strategy,
    },
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{SealedDealing, Vote, bls12381, seal},
    boundary::{SignedWithdrawal, WithdrawalAction},
    challenge::{
        Challenge, ChallengeKind, HigherShardTipLookup, Verdict, adjudicate_with_strategy,
        decode_bounded,
    },
    commitment::{Builder, Tree, VectorKind, VectorRoot},
    credit::{CreditTipLookup, ShardSet},
    settlement::{
        BatchStatus, EpochDeadlinePolicy, HardFaultReason, SettlementChain, SettlementConfig,
    },
    state::AccountRow,
    transition::{
        BatchId, Header, PreparedClose, ProofSlice, RootBundle, TerminalProof, WithdrawalClaim,
        WithdrawalOutput, prepare_close_with_strategy, validate_close,
    },
};
use commonware_codec::{Decode, Encode, EncodeSize, RangeCfg};
use commonware_cryptography::{Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
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

const WITHDRAWAL_DESTINATION: &[u8] = b"benchmark-destination";
const WITHDRAWAL_DEADLINE: u64 = 100;

struct WithdrawalClaimFixture {
    withdrawal_outputs: VectorRoot<Digest>,
    claim: WithdrawalClaim<Digest>,
}

struct WithdrawalClaims {
    total: u32,
    amount: WithdrawalClaimFixture,
    close: WithdrawalClaimFixture,
}

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
    challenge_recipient_lookup_bytes: usize,
    challenge_bytes: usize,
}

struct BlogChainFixture {
    close: CloseFixture,
    validator: Participant,
    validator_scheme: bls12381::Scheme,
    dealing: Vec<ProofSlice<VerifyingKey, Digest>>,
    commitment: CommitmentPayload,
    terminal_proof: TerminalProof<Digest>,
    verifier: bls12381::Scheme,
    encoded_challenge: Bytes,
    claims: [WithdrawalClaims; 2],
    metrics: Metrics,
}

impl BlogChainFixture {
    fn new(profile: ActiveProfile) -> Self {
        let validators = Validators::new();
        assert_eq!(validators.committee().members().len(), VALIDATORS);
        assert_eq!(validators.committee().faults(), FAULTS);
        assert_eq!(validators.committee().quorum(), QUORUM);

        let assignment = validators.assignment();
        let (close, challenge, claim_signer) = active_chain_fixture(profile, assignment);
        // Claim fixtures cover the single-output floor and a full withdrawal surge
        // in which every live account exits through one certified close.
        let surge = u32::try_from(profile.live_accounts)
            .expect("benchmark account count fits the vector bound");
        let claims = [1, surge].map(|total| WithdrawalClaims {
            total,
            amount: amount_withdrawal_claim_fixture(&close, &claim_signer, total),
            close: close_withdrawal_claim_fixture(&close, &claim_signer, total),
        });
        for claims in &claims {
            for fixture in [&claims.amount, &claims.close] {
                assert_eq!(fixture.claim.encode().len(), fixture.claim.encode_size());
            }
        }
        assert_eq!(close.context.assignment().slice_bits(), SLICE_BITS);
        assert_eq!(
            close.context.assignment().committee(),
            &validators.committee().commitment::<Sha256>()
        );
        assert!(close.deposits.is_empty());
        assert!(close.withdrawals.is_empty());

        validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
            &close.context,
            &close.deposits,
            &close.withdrawals,
            close.prepared.close(),
            &mut TestRng::new(0),
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
        let terminal_proof = close
            .prepared
            .terminal_proof()
            .expect("benchmark terminal proof is valid");

        let challenge_recipient_lookup_bytes = match &challenge {
            Challenge::HigherShardTip { payment, recipient } => {
                assert!(matches!(
                    recipient.as_ref(),
                    HigherShardTipLookup::Present {
                        tip: CreditTipLookup::Present { .. },
                        ..
                    }
                ));
                assert_eq!(payment.shard(), 0);
                recipient.encode_size()
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

        preflight_chain(
            &close,
            &validators,
            &commitment,
            &terminal_proof,
            encoded_challenge.as_ref(),
        );
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
            challenge_recipient_lookup_bytes,
            challenge_bytes,
        };

        Self {
            close,
            validator,
            validator_scheme,
            dealing,
            commitment,
            terminal_proof,
            verifier,
            encoded_challenge,
            claims,
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
    ) -> (Vote, SealedDealing<VerifyingKey, Digest>) {
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

    // Admission authenticates aggregate boundary flows before mutating settlement state. The
    // retained proof and certificate make that verification repeatable across Criterion samples.
    fn check_certified_commitment(&self) -> BatchId<Digest> {
        let (header, roots, certificate) = &self.commitment;
        self.terminal_proof
            .verify::<Sha256, _>(
                &self.close.context,
                &self.close.deposits,
                &self.close.withdrawals,
                header,
                roots,
            )
            .expect("benchmark terminal proof matches its registration");
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

fn check_withdrawal_claim(fixture: &WithdrawalClaimFixture) -> WithdrawalOutput {
    fixture
        .claim
        .verify::<Sha256>(&fixture.withdrawal_outputs)
        .expect("benchmark withdrawal claim is valid")
}

fn withdrawal_output_tree(
    close: &CloseFixture,
    signer: &SigningKey,
    action: WithdrawalAction,
    amount: u64,
    total: u32,
) -> (WithdrawalOutput, Tree<Digest>, u32) {
    let account = signer.public_key();
    assert_eq!(close.rows[1].account, account);
    let request = SignedWithdrawal::sign(
        *close.context.deployment(),
        close.cache.root().digest,
        Bytes::from_static(WITHDRAWAL_DESTINATION),
        action,
        WITHDRAWAL_DEADLINE,
        signer,
    );
    let output = WithdrawalOutput::decode_cfg(
        (request.body().destination().clone(), amount).encode(),
        &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
    )
    .expect("validator-derived benchmark output decodes");

    // The claimed output sits mid-vector among `total` outputs queued by the
    // same certified close.
    let position = total / 2;
    let outputs = (0..total)
        .map(|index| {
            if index == position {
                return output.clone();
            }
            let destination = Bytes::from(format!("exit-{index:016}").into_bytes());
            assert_eq!(destination.len(), WITHDRAWAL_DESTINATION.len());
            WithdrawalOutput::decode_cfg(
                (destination, u64::from(index) + 1).encode(),
                &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
            )
            .expect("benchmark filler output decodes")
        })
        .collect::<Vec<_>>();
    let mut output_builder = Builder::<Sha256>::new(VectorKind::WithdrawalOutput, total)
        .expect("benchmark withdrawal output count is valid");
    output_builder
        .add_values(&outputs, strategy())
        .expect("benchmark withdrawal outputs can be committed");
    let output_tree = output_builder
        .build(strategy())
        .expect("benchmark withdrawal output tree is valid");
    (output, output_tree, position)
}

fn amount_withdrawal_claim_fixture(
    close: &CloseFixture,
    signer: &SigningKey,
    total: u32,
) -> WithdrawalClaimFixture {
    let amount = NonZeroU64::MIN.get();
    let (output, output_tree, position) = withdrawal_output_tree(
        close,
        signer,
        WithdrawalAction::Amount(NonZeroU64::MIN),
        amount,
        total,
    );
    let encoded = (
        output.clone(),
        output_tree
            .opening(position)
            .expect("benchmark withdrawal output can be opened"),
    )
        .encode();
    let claim = WithdrawalClaim::decode_cfg(
        encoded.clone(),
        &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
    )
    .expect("canonical benchmark amount claim decodes");
    assert_eq!(claim.encode(), encoded);
    assert_eq!(
        claim
            .verify::<Sha256>(&output_tree.root())
            .expect("benchmark amount claim is valid"),
        output
    );

    WithdrawalClaimFixture {
        withdrawal_outputs: output_tree.root(),
        claim,
    }
}

fn close_withdrawal_claim_fixture(
    close: &CloseFixture,
    signer: &SigningKey,
    total: u32,
) -> WithdrawalClaimFixture {
    let row = 1_usize;
    let amount = close.rows[row].successor.balance;
    assert!(amount > 0);
    let (output, output_tree, position) =
        withdrawal_output_tree(close, signer, WithdrawalAction::Close, amount, total);

    let encoded = (
        output.clone(),
        output_tree
            .opening(position)
            .expect("benchmark withdrawal output can be opened"),
    )
        .encode();
    let claim = WithdrawalClaim::decode_cfg(
        encoded.clone(),
        &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
    )
    .expect("canonical benchmark close claim decodes");
    assert_eq!(claim.encode(), encoded);
    assert_eq!(
        claim
            .verify::<Sha256>(&output_tree.root())
            .expect("benchmark close claim is valid"),
        output
    );

    WithdrawalClaimFixture {
        withdrawal_outputs: output_tree.root(),
        claim,
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
            NonZeroUsize::new(2).expect("benchmark pipeline bound is nonzero"),
            EpochDeadlinePolicy::new(
                NonZeroU64::new(100).expect("benchmark admission delay is nonzero"),
                notice,
                notice,
            ),
            notice,
            notice,
            notice,
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
    terminal_proof: &TerminalProof<Digest>,
    encoded_challenge: &[u8],
) {
    let mut chain = chain(close, validators);
    chain
        .register_close(
            0,
            close.context.clone(),
            close.withdrawals.clone(),
            &[],
            |_| true,
        )
        .expect("benchmark close can be registered");
    let batch = chain
        .admit(
            0,
            commitment.0,
            commitment.1,
            terminal_proof.clone(),
            commitment.2.clone(),
        )
        .expect("benchmark commitment can be admitted");
    assert_eq!(batch, commitment.0.batch_id::<Sha256>());
    let verdict = chain
        .challenge_encoded_with_strategy(
            close.context.challenge_deadline(),
            batch,
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
            "clearing blog chain metrics: profile={profile_index} N={live_accounts} A={changed} B={credited} h={shards} close_W=0 n={VALIDATORS} f={FAULTS} q={QUORUM} slices={SLICES} workers={WORKERS} close_bytes={} slice_corpus_bytes={} validator={} dealing_bytes={} dealing_slices={} header_bytes={} root_bundle_witness_bytes={} external_certificate_bytes={} external_package_bytes={} validator_chain_commitment_bytes={} challenge_recipient_lookup_bytes={} challenge_bytes={}",
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
            fixture.metrics.challenge_recipient_lookup_bytes,
            fixture.metrics.challenge_bytes,
        );
        for claims in &fixture.claims {
            eprintln!(
                "clearing blog chain claim metrics: profile={profile_index} W={} amount_claim_bytes={} close_claim_bytes={}",
                claims.total,
                claims.amount.claim.encode_size(),
                claims.close.claim.encode_size(),
            );
        }

        let labels = format!("N={live_accounts} A={changed} B={credited} h={shards}");
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
                        let (vote, sealed) = fixture.seal(input, black_box(&mut rng));
                        elapsed += start.elapsed();
                        black_box(vote);
                        dealing = Some(sealed.into_slices());
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
        for claims in &fixture.claims {
            let total = claims.total;
            c.bench_function(
                &format!(
                    "{}/p={profile_index} op=check-withdrawal-claim action=amount {labels} W={total}",
                    module_path!()
                ),
                |b| {
                    b.iter(|| black_box(check_withdrawal_claim(&claims.amount)));
                },
            );
            c.bench_function(
                &format!(
                    "{}/p={profile_index} op=check-withdrawal-claim action=close {labels} W={total}",
                    module_path!()
                ),
                |b| {
                    b.iter(|| black_box(check_withdrawal_claim(&claims.close)));
                },
            );
        }
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
