use super::*;
use crate::bajillion::{
    admission::seal,
    challenge::{AckWitness, EntryWitness},
    model::settlement as spec,
    payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorAck, VectorSendBody},
    qmdb::account_key,
    state::SettlementOutput,
    transition::{OperatorVariant, Terminal, prepare_close_with_strategy},
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_cryptography::bls12381::primitives::ops::sign_message;
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_parallel::Sequential;
use commonware_utils::test_rng;

const ACCOUNTS: [spec::Account; 3] = [
    spec::Account::Alice,
    spec::Account::Bob,
    spec::Account::Carol,
];
const BATCHES: [spec::Batch; 8] = [
    spec::Batch::B0,
    spec::Batch::B1,
    spec::Batch::B2,
    spec::Batch::B3,
    spec::Batch::Offset,
    spec::Batch::B1C,
    spec::Batch::B2D,
    spec::Batch::OffsetC,
];
fn refinement_config() -> SettlementConfig {
    SettlementConfig::new(
        EpochDeadlinePolicy::new(
            NonZeroU64::new(3).unwrap(),
            NonZeroU64::new(2).unwrap(),
            NonZeroU64::new(2).unwrap(),
        ),
        NonZeroU64::new(2).unwrap(),
        NonZeroU64::new(2).unwrap(),
        NonZeroU64::new(20).unwrap(),
        8,
        NonZeroUsize::new(3).unwrap(),
    )
}

fn refinement_harness() -> Harness {
    harness_with_config(&[10, 5], refinement_config())
}

fn spec_batch(registration: spec::RegistrationId) -> spec::Batch {
    match registration {
        spec::RegistrationId::B0 => spec::Batch::B0,
        spec::RegistrationId::B1 => spec::Batch::B1,
        spec::RegistrationId::B1C => spec::Batch::B1C,
        spec::RegistrationId::B2 => spec::Batch::B2,
        spec::RegistrationId::B3 => spec::Batch::B3,
        spec::RegistrationId::Offset => spec::Batch::Offset,
        spec::RegistrationId::OffsetC => spec::Batch::OffsetC,
    }
}

// Signed epoch activity is the source of both payer debit and recipient credit. Production
// preparation derives balances and settlement outputs from this terminal and the boundaries.
fn refined_payment(
    context: &TestContext,
    operator_ack: &BlsPrivate,
    payer: &SigningKey,
    recipient: &SigningKey,
    amount: u64,
) -> Terminal<VerifyingKey, ShaDigest> {
    let vector = OutVector::new(
        context.payment().epoch(),
        payer.public_key(),
        vec![OutEntry {
            recipient: recipient.public_key(),
            cumulative: amount,
            count: 1,
        }],
    )
    .unwrap();
    let body = VectorSendBody::new(
        context.payment(),
        payer.public_key(),
        1,
        amount,
        vector.root::<Sha256, ShaDigest>().unwrap(),
    );
    let operator_signature = sign_message::<OperatorVariant>(
        operator_ack,
        VECTOR_ACK_AGGREGATE_NAMESPACE,
        body.encode().as_ref(),
    );
    Terminal {
        authorization: SendAuthorization::sign(body, payer),
        vector,
        operator_signature,
    }
}

fn fork_ack(
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    seq: u64,
    amount: u64,
) -> VectorAck<VerifyingKey, ShaDigest> {
    let vector = OutVector::new(
        context.payment().epoch(),
        payer.public_key(),
        vec![OutEntry {
            recipient: SigningKey::from_seed(9_999).public_key(),
            cumulative: amount,
            count: 1,
        }],
    )
    .unwrap();
    let body = VectorSendBody::new(
        context.payment(),
        payer.public_key(),
        seq,
        amount,
        vector.root::<Sha256, ShaDigest>().unwrap(),
    );
    VectorAck::sign_by_authorities(body, payer, operator)
}

struct RegisteredMaterial {
    batch: spec::Batch,
    context: TestContext,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
    extra_openings: Vec<StateOpening<VerifyingKey, ShaDigest>>,
}

struct BatchMaterial {
    context: TestContext,
    withdrawals: TestWithdrawals,
    close: TestClose,
    successor: TestCache,
    id: BatchId<ShaDigest>,
}

struct RefinementDriver {
    fixture: Harness,
    carol: SigningKey,
    now: u8,
    model: spec::SettlementModel,
    state: spec::SettlementState,
    registered: Option<RegisteredMaterial>,
    registrations: Vec<Option<TestContext>>,
    batches: Vec<Option<BatchMaterial>>,
    requests: Vec<Option<SignedWithdrawal<VerifyingKey, ShaDigest>>>,
    terminal_initial: Option<(u64, u64, u64)>,
    visited: u16,
}

impl RefinementDriver {
    fn new() -> Self {
        let fixture = refinement_harness();

        // The spec breaks same-deadline expiry ties by account index while
        // production breaks them by public-key byte order, so the driver keys
        // must sort in account-index order for the two rules to coincide.
        // Carol's key is searched rather than pinned so any harness account
        // set keeps the ordering structurally.
        assert!(fixture.accounts[0].public_key() < fixture.accounts[1].public_key());
        let carol = (0..)
            .map(SigningKey::from_seed)
            .find(|carol| {
                fixture
                    .accounts
                    .iter()
                    .all(|account| account.public_key() < carol.public_key())
            })
            .expect("some seed yields a key above every harness account");
        Self {
            fixture,
            carol,
            now: 0,
            model: spec::SettlementModel::default(),
            state: spec::SettlementState::default(),
            registered: None,
            registrations: (0..8).map(|_| None).collect(),
            batches: (0..8).map(|_| None).collect(),
            requests: (0..6).map(|_| None).collect(),
            terminal_initial: None,
            visited: 0,
        }
    }

    fn signer(&self, account: spec::Account) -> &SigningKey {
        match account {
            spec::Account::Alice => &self.fixture.accounts[0],
            spec::Account::Bob => &self.fixture.accounts[1],
            spec::Account::Carol => &self.carol,
        }
    }

    fn key(&self, account: spec::Account) -> VerifyingKey {
        self.signer(account).public_key()
    }

    fn material(&self, batch: spec::Batch) -> &BatchMaterial {
        self.batches[batch.index()]
            .as_ref()
            .expect("the refined batch has been admitted")
    }

    fn cache(&self, root: spec::Root) -> &TestCache {
        self.available_cache(root)
            .expect("the refined root has an admitted account cache")
    }

    fn finalized_cache(&self) -> &TestCache {
        BATCHES
            .into_iter()
            .filter(|batch| self.state.status[batch.index()] == spec::BatchStatus::Finalized)
            .max_by_key(|batch| batch.candidate().epoch)
            .map_or(&self.fixture.cache, |batch| &self.material(batch).successor)
    }

    fn available_cache(&self, root: spec::Root) -> Option<&TestCache> {
        match root {
            spec::Root::R0 => Some(&self.fixture.cache),
            spec::Root::R1 => self.batches[spec::Batch::B0.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R2 => self.batches[spec::Batch::B1.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R2C => self.batches[spec::Batch::B1C.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R3 => self.batches[spec::Batch::B2.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R3D => self.batches[spec::Batch::B2D.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R4 => self.batches[spec::Batch::B3.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::Offset => self.batches[spec::Batch::Offset.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::OffsetC => self.batches[spec::Batch::OffsetC.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::Empty => None,
        }
    }

    fn canonical_cache(&self, root: spec::Root) -> TestCache {
        if let Some(actual) = self.available_cache(root) {
            return actual.clone();
        }
        let (predecessor, balances) = match root {
            spec::Root::R1 => (spec::Root::R0, [8, 9, 0]),
            spec::Root::R2 => (spec::Root::R1, [7, 9, 1]),
            spec::Root::R3 => (spec::Root::R2, [7, 7, 1]),
            spec::Root::R2C => (spec::Root::R1, [8, 0, 0]),
            spec::Root::R3D => (spec::Root::R2, [15, 1, 1]),
            spec::Root::R4 => (spec::Root::R3, [0, 7, 1]),
            spec::Root::Offset | spec::Root::OffsetC => (spec::Root::R0, [10, 5, 0]),
            spec::Root::R0 | spec::Root::Empty => {
                unreachable!("no successor history for this root")
            }
        };
        // Current roots bind the canonical batch history, including balance-neutral epochs.
        // Replaying each predecessor before its updates makes counterfactual fixtures agree
        // with actual admitted candidates without trusting a map-derived root.
        let liability: u64 = balances.into_iter().sum();
        self.canonical_cache(predecessor).synthetic_next(
            ACCOUNTS
                .into_iter()
                .zip(balances)
                .map(|(account, balance)| {
                    (
                        account_key(&self.key(account)).unwrap(),
                        NonZeroU64::new(balance),
                    )
                })
                .collect(),
            liability,
        )
    }

    fn deposit(&self, id: spec::DepositId) -> (ShaDigest, VerifyingKey, u64) {
        let (tag, account, amount) = match id {
            spec::DepositId::BobTwo => (b"bob-two".as_slice(), spec::Account::Bob, 2),
            spec::DepositId::AliceOne => (b"alice-one".as_slice(), spec::Account::Alice, 1),
            spec::DepositId::BobOne => (b"bob-one".as_slice(), spec::Account::Bob, 1),
        };
        (
            Sha256::hash(&[b"bajillion-refinement-deposit", tag]),
            self.key(account),
            amount,
        )
    }

    fn destination(destination: spec::Destination) -> Bytes {
        match destination {
            spec::Destination::Alice => Bytes::from_static(b"alic"),
            spec::Destination::Bob => Bytes::from_static(b"bob!"),
            spec::Destination::TooLong => Bytes::from_static(b"too-long!"),
        }
    }

    fn signed_withdrawal(
        &self,
        request: spec::WithdrawalRequest,
    ) -> SignedWithdrawal<VerifyingKey, ShaDigest> {
        let deployment = match request.deployment {
            spec::Deployment::Current => self.fixture.deployment,
            spec::Deployment::Other => Sha256::hash(&[b"other-deployment"]),
        };
        let root = self
            .available_cache(request.context_root)
            .map(TestCache::root)
            .unwrap_or_else(|| self.canonical_cache(request.context_root).root());
        let action = match request.action {
            spec::WithdrawalAction::Amount(amount) => {
                WithdrawalAction::Amount(NonZeroU64::new(u64::from(amount)).unwrap())
            }
            spec::WithdrawalAction::Close => WithdrawalAction::Close,
        };
        let signer = self.signer(request.account);
        let signed = SignedWithdrawal::sign(
            deployment,
            root.digest,
            Self::destination(request.destination),
            action,
            u64::from(request.deadline),
            signer,
        );
        if request.signature_valid {
            signed
        } else {
            let wrong = SigningKey::from_seed(9_999);
            let invalid = SignedWithdrawal::sign_body_by_authority(signed.body().clone(), &wrong);
            SignedWithdrawal::from_raw_unchecked(
                signer.public_key(),
                signed.body().clone(),
                invalid.signature().clone(),
            )
        }
    }

    fn registration_material(&self, id: spec::RegistrationId) -> RegisteredMaterial {
        let batch = spec_batch(id);
        let registration = id.registration();
        let cache = self.canonical_cache(registration.predecessor);
        if let Some(actual) = self.available_cache(registration.predecessor) {
            assert_eq!(actual.root(), cache.root());
        }
        let deposits = DepositBatch::new(
            ACCOUNTS
                .into_iter()
                .filter_map(|account| {
                    let amount = registration.deposits[account.index()];
                    (amount != 0)
                        .then(|| DepositRecord::new(self.key(account), u64::from(amount)).unwrap())
                })
                .collect(),
        )
        .unwrap();
        let withdrawals = WithdrawalBatch::new(
            registration
                .withdrawals
                .into_iter()
                .flatten()
                .map(|request| self.signed_withdrawal(request))
                .collect(),
        )
        .unwrap();
        let context = context(
            self.fixture.deployment,
            &self.fixture.operator,
            self.fixture.committee,
            u64::from(registration.epoch),
            &cache,
            &deposits,
            &withdrawals,
            u64::from(registration.admission_deadline),
            u64::from(registration.challenge_deadline),
            self.fixture.chain.registration_floors(),
        );
        // One predecessor-root opening per operator-carried extra, in batch
        // order, mirroring what a production operator submits.
        let pending = self.fixture.chain.pending_withdrawals();
        let extra_openings = withdrawals
            .requests()
            .iter()
            .filter(|request| pending.request_for(request.account()).is_none())
            .filter_map(|request| cache.opening(request.account()).ok())
            .collect();
        RegisteredMaterial {
            batch,
            context,
            deposits,
            withdrawals,
            extra_openings,
        }
    }

    fn withdrawal_opening(
        &self,
        attempt: spec::WithdrawalAttempt,
    ) -> StateOpening<VerifyingKey, ShaDigest> {
        let opening = attempt.opening;
        let source_root = if opening.root == spec::Root::Empty {
            spec::Root::R0
        } else {
            opening.root
        };
        let cache = self.canonical_cache(source_root);
        let account = self.key(opening.account);
        let mut witness = cache.opening(&account).unwrap_or_else(|_| {
            ACCOUNTS
                .into_iter()
                .find_map(|account| cache.opening(&self.key(account)).ok())
                .expect("every nonempty canonical root has a live account")
        });
        let authenticated_balance = witness.balance;
        witness.account = account;
        witness.balance =
            NonZeroU64::new(u64::from(opening.state.balance)).unwrap_or(NonZeroU64::MIN);
        if !opening.authenticated_state
            || !opening.state.active
            || opening.state.balance == 0
            || opening.root == spec::Root::Empty
        {
            witness.balance = NonZeroU64::new(authenticated_balance.get() + 1).unwrap();
        }
        witness
    }

    fn queue_withdrawal(&mut self, attempt: spec::WithdrawalAttempt) -> bool {
        let request = self.signed_withdrawal(attempt.request);
        let opening = self.withdrawal_opening(attempt);
        let result = self.fixture.chain.queue_withdrawal(
            u64::from(self.now),
            request.clone(),
            &opening,
            |_| attempt.destination_eligible,
        );
        if result.is_ok()
            && let spec::WithdrawalKey::Known(id) = attempt.replay_key
        {
            self.requests[id.index()] = Some(request);
        }
        result.is_ok()
    }

    fn register(&mut self, registration: spec::RegistrationId) -> bool {
        let batch = spec_batch(registration);
        let material = self.registration_material(registration);
        let result = self.fixture.chain.register_close(
            u64::from(self.now),
            material.context.clone(),
            material.withdrawals.clone(),
            &material.extra_openings,
            |_| true,
        );
        if result.is_ok() {
            // Record carried requests so the replay-id projection can compute
            // their production ids once admission consumes them.
            for request in material.withdrawals.requests() {
                let attempt = registration
                    .registration()
                    .withdrawals
                    .into_iter()
                    .flatten()
                    .find(|fixture| self.key(fixture.account) == *request.account());
                if let Some(fixture) = attempt
                    && let spec::WithdrawalKey::Known(id) = fixture.replay_key()
                {
                    self.requests[id.index()].get_or_insert_with(|| request.clone());
                }
            }
            self.registrations[batch.index()] = Some(material.context.clone());
            self.registered = Some(material);
        }
        result.is_ok()
    }

    fn admit(&mut self, certified: crate::bajillion::model::certification::CertifiedClose) -> bool {
        let batch = certified.batch();
        let uses_active_registration = self
            .registered
            .as_ref()
            .is_some_and(|registered| registered.batch == spec_batch(batch.registration()));
        let registered = if uses_active_registration {
            self.registered
                .take()
                .expect("the matching registration was observed above")
        } else {
            self.registration_material(batch.registration())
        };
        let cache = self.canonical_cache(batch.candidate().predecessor);
        if let Some(actual) = self.available_cache(batch.candidate().predecessor) {
            assert_eq!(actual.root(), cache.root());
        }
        let terminals = match batch {
            spec::Batch::B0 => vec![refined_payment(
                &registered.context,
                &self.fixture.operator_ack,
                &self.fixture.accounts[0],
                &self.fixture.accounts[1],
                2,
            )],
            spec::Batch::B1 => vec![refined_payment(
                &registered.context,
                &self.fixture.operator_ack,
                &self.fixture.accounts[0],
                &self.carol,
                1,
            )],
            spec::Batch::B2
            | spec::Batch::B3
            | spec::Batch::Offset
            | spec::Batch::B1C
            | spec::Batch::OffsetC => Vec::new(),
            spec::Batch::B2D => vec![refined_payment(
                &registered.context,
                &self.fixture.operator_ack,
                &self.fixture.accounts[1],
                &self.fixture.accounts[0],
                8,
            )],
        };
        let (vote, close, successor) = deterministic::Runner::default().start(|runtime| async {
            let state = cache.reopen(runtime, "refinement-close").await;
            let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &registered.context,
                &registered.deposits,
                &registered.withdrawals,
                terminals,
                &Sequential,
            )
            .await
            .unwrap();
            let (vote, sealed) = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                &self.fixture.signer,
                &state,
                &registered.context,
                &self.fixture.operator_bls,
                &registered.deposits,
                &registered.withdrawals,
                prepared.encoded().clone(),
                &mut test_rng(),
                &Sequential,
            )
            .await
            .unwrap();
            assert_eq!(sealed.close().header, prepared.close().header);
            assert_eq!(sealed.close().roots, prepared.close().roots);
            assert_eq!(
                sealed.close().withdrawal_total,
                prepared.close().withdrawal_total
            );
            let successor_liability = crate::bajillion::transition::checked_successor_liability(
                registered.context.predecessor_liability(),
                registered.deposits.total(),
                sealed.close().withdrawal_total,
            )
            .unwrap();
            let accepted = Accepted::prepared(&sealed);
            let (_, close) = Box::pin(sealed.apply::<_, Sha256>(state)).await.unwrap();
            let successor = cache.extended(accepted, successor_liability);
            (vote, close, successor)
        });
        let certificate = self.fixture.signer.assemble_exact([vote]).unwrap();
        let result = self.fixture.chain.admit(
            u64::from(self.now),
            close.header,
            close.roots,
            close.withdrawal_total,
            certificate,
        );
        match result {
            Ok(id) => {
                assert!(
                    uses_active_registration,
                    "production admitted a close without its modeled registration"
                );
                assert_eq!(
                    successor.root(),
                    self.canonical_cache(batch.candidate().successor).root()
                );
                self.batches[batch.index()] = Some(BatchMaterial {
                    context: registered.context,
                    withdrawals: registered.withdrawals,
                    close,
                    successor,
                    id,
                });
                true
            }
            Err(_) => {
                if uses_active_registration && self.fixture.chain.registered.is_some() {
                    self.registered = Some(registered);
                }
                false
            }
        }
    }

    fn challenge(&mut self, proven: crate::bajillion::model::challenge::ProvenChallenge) -> bool {
        let target = proven.target();
        let material = self.material(target);
        let challenge = match proven.kind() {
            spec::ChallengeKind::HigherDebit => {
                // A retained countersigned endpoint for a payer the close never advanced.
                let payer = &self.fixture.accounts[1];
                let ack = fork_ack(&material.context, &self.fixture.operator, payer, 1, 2);
                let lookup = material.successor.account_lookup(
                    &material.context,
                    &material.close.roots,
                    &payer.public_key(),
                );
                Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(&ack)),
                    payer: Box::new(lookup),
                }
            }
            spec::ChallengeKind::HigherEntry => {
                // A retained alternative vector crediting the virtual recipient above the
                // committed terminal entry on the same edge.
                let payer = &self.fixture.accounts[0];
                let recipient = self.carol.public_key();
                let retained = OutVector::new(
                    material.context.payment().epoch(),
                    payer.public_key(),
                    vec![OutEntry {
                        recipient: recipient.clone(),
                        cumulative: 2,
                        count: 1,
                    }],
                )
                .unwrap();
                let body = VectorSendBody::new(
                    material.context.payment(),
                    payer.public_key(),
                    1,
                    2,
                    retained.root::<Sha256, ShaDigest>().unwrap(),
                );
                let ack = VectorAck::sign_by_authorities(body, payer, &self.fixture.operator);
                let OutTipLookup::Present {
                    cumulative,
                    count,
                    opening,
                } = retained.lookup::<Sha256, ShaDigest>(&recipient).unwrap()
                else {
                    panic!("the retained vector credits the recipient");
                };
                let sender = material.successor.higher_entry_lookup(
                    &material.context,
                    &material.close.roots,
                    &payer.public_key(),
                    &recipient,
                );
                Challenge::HigherAckEntry {
                    entry: Box::new(EntryWitness {
                        ack: AckWitness::from_ack(&ack),
                        recipient,
                        cumulative,
                        count,
                        opening,
                    }),
                    sender: Box::new(sender),
                }
            }
            spec::ChallengeKind::Fork => {
                let left = fork_ack(
                    &material.context,
                    &self.fixture.operator,
                    &self.fixture.accounts[0],
                    1,
                    2,
                );
                let right = fork_ack(
                    &material.context,
                    &self.fixture.operator,
                    &self.fixture.accounts[0],
                    1,
                    3,
                );
                Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(&left)),
                    right: Box::new(AckWitness::from_ack(&right)),
                }
            }
        };
        let batch_id = material.id;
        self.fixture
            .chain
            .challenge(
                u64::from(self.now),
                batch_id,
                &challenge,
            )
            .is_ok_and(|verdict| {
                matches!(verdict, Verdict::Proven(actual) if challenge_kind_matches(actual, proven.kind()))
            })
    }

    fn finalize(&mut self) -> bool {
        let Some(expected) = self.state.pipeline.first().copied() else {
            return self.fixture.chain.finalize(u64::from(self.now)).is_ok();
        };
        self.fixture
            .chain
            .finalize(u64::from(self.now))
            .is_ok_and(|actual| {
                let candidate = expected.candidate();
                actual.batch_id == self.material(expected).id
                    && actual.epoch == u64::from(candidate.epoch)
                    && actual.successor_root == self.material(expected).successor.root()
                    && actual.withdrawal_total
                        == candidate
                            .withdrawal_output
                            .map_or(0, |output| u64::from(output.amount))
            })
    }

    fn claim_withdrawal(&mut self, source: spec::Batch, position: u8, refresh: bool) -> bool {
        let source = self.material(source);
        if source.withdrawals.requests().is_empty() {
            return false;
        }
        let mut claim = source.successor.payout_claim(
            &source.close.roots.withdrawal_outputs,
            source.context.predecessor_logs().payouts.operations,
        );
        assert_eq!(claim.output(), &source.close.withdrawal_outputs()[0]);
        let finalized = self.fixture.chain.finalized_payouts();
        if refresh && claim.position() < finalized.operations {
            claim = self.finalized_cache().refresh(&claim, &finalized);
        }
        let expected = claim.output().clone();
        if claim.position() != u64::from(position) {
            let (output, mut opening) =
                <(WithdrawalOutput, crate::bajillion::logs::Opening<ShaDigest>)>::decode_cfg(
                    claim.encode(),
                    &(RangeCfg::new(..=usize::MAX), ()),
                )
                .unwrap();
            opening.start = u64::from(position);
            claim = WithdrawalClaim::new(output, opening);
        }
        self.fixture
            .chain
            .claim_withdrawal(&claim)
            .is_ok_and(|actual| actual == expected)
    }

    fn apply_production(&mut self, action: spec::SettlementAction) -> bool {
        match action {
            spec::SettlementAction::Observe(at) => {
                if at <= self.now || at > 12 || self.fixture.chain.fault_settled {
                    return false;
                }
                self.fixture.chain.observe_time(u64::from(at));
                self.now = at;
                if self.fixture.chain.registered.is_none() {
                    self.registered = None;
                }
                true
            }
            spec::SettlementAction::RecordDeposit(id) => {
                let (id, account, amount) = self.deposit(id);
                self.fixture
                    .chain
                    .record_deposit(u64::from(self.now), id, account, amount)
                    .is_ok()
            }
            spec::SettlementAction::QueueWithdrawal(attempt) => self.queue_withdrawal(attempt),
            spec::SettlementAction::Register(registration) => self.register(registration),
            spec::SettlementAction::Admit(certified) => self.admit(certified),
            spec::SettlementAction::Challenge(proven) => self.challenge(proven),
            spec::SettlementAction::Finalize => self.finalize(),
            spec::SettlementAction::ClaimWithdrawal {
                refresh,
                source,
                position,
            } => self.claim_withdrawal(source, position, refresh),
            spec::SettlementAction::ClaimDeposit(account) => {
                let index = account.index();
                let expected = match self.state.terminal {
                    spec::Terminal::Dormant => self.state.pending_deposits[index],
                    spec::Terminal::Claiming { .. } => self.state.unfinalized_deposits[index],
                    spec::Terminal::Settled => 0,
                };
                let key = self.key(account);
                self.fixture
                    .chain
                    .claim_pending_deposit(u64::from(self.now), &key)
                    .is_ok_and(|refund| {
                        refund.account == self.key(account) && refund.amount == u64::from(expected)
                    })
            }
            spec::SettlementAction::BeginTerminal => self
                .fixture
                .chain
                .begin_hard_fault_settlement()
                .is_ok_and(|settlement| {
                    let snapshot = (
                        settlement.state_liability,
                        settlement.unfinalized_deposit_total,
                        settlement.custody_balance,
                    );
                    if let Some(expected) = self.terminal_initial {
                        expected == snapshot
                    } else {
                        self.terminal_initial = Some(snapshot);
                        true
                    }
                }),
            spec::SettlementAction::ClaimState(account) => {
                let spec::Terminal::Claiming { frozen_root, .. } = self.state.terminal else {
                    return false;
                };
                let opening = self.cache(frozen_root).opening(&self.key(account));
                opening.is_ok_and(|opening| {
                    self.fixture
                        .chain
                        .claim_hard_fault(&opening)
                        .is_ok_and(|release| {
                            let index = account.index();
                            let balance = self.state.current_state[index].balance;
                            let request = self.state.outstanding_withdrawals[index];
                            let (withdrawal, residual) =
                                request.map_or((0, balance), |request| match request.action {
                                    spec::WithdrawalAction::Amount(amount) if amount <= balance => {
                                        (amount, balance - amount)
                                    }
                                    // An uncovered carried amount degrades at
                                    // the frozen root.
                                    spec::WithdrawalAction::Amount(_) => (0, balance),
                                    spec::WithdrawalAction::Close => (balance, 0),
                                });
                            let expected_withdrawal = request.map(|request| {
                                WithdrawalOutput::from_request(
                                    &self.signed_withdrawal(request),
                                    u64::from(withdrawal),
                                )
                            });
                            release.account == self.key(account)
                                && release.released_custody == u64::from(balance)
                                && release.residual == u64::from(residual)
                                && release.withdrawal == expected_withdrawal
                        })
                })
            }
        }
    }

    fn step(&mut self, action: spec::SettlementAction) {
        self.visited |= action_bit(action);
        let expected = self.model.apply(&self.state, action);
        let accepted = self.apply_production(action);
        assert_eq!(
            accepted,
            expected.is_some(),
            "production acceptance diverged for {action:?}\nabstract: {:#?}",
            self.state
        );
        if let Some(expected) = expected {
            self.state = expected;
        }
        self.assert_refines();
    }

    fn step_at(&mut self, at: u8, action: spec::SettlementAction) {
        assert!(at > self.now);
        self.visited |= action_bit(action);
        let (expected, expected_acceptance) = self.model.call_at(&self.state, at, action);
        self.now = at;
        let accepted = self.apply_production(action);
        if self.fixture.chain.registered.is_none() {
            self.registered = None;
        }
        assert_eq!(
            accepted, expected_acceptance,
            "production timed-call acceptance diverged for {action:?} at {at}\nabstract: {:#?}",
            self.state
        );
        self.state = expected;
        self.assert_refines();
    }

    fn root(&self, root: spec::Root) -> crate::bajillion::qmdb::StateRoot<ShaDigest> {
        self.cache(root).root()
    }

    fn expected_batch(&self, id: BatchId<ShaDigest>) -> spec::Batch {
        BATCHES
            .into_iter()
            .find(|batch| {
                self.batches[batch.index()]
                    .as_ref()
                    .is_some_and(|material| material.id == id)
            })
            .expect("every production batch belongs to the refinement catalog")
    }

    fn outstanding_withdrawal_deadline(&self, account: &VerifyingKey) -> Option<u64> {
        let chain = &self.fixture.chain;
        let Some(claims) = chain.hard_fault_claims.as_ref() else {
            return chain.unfinalized_withdrawal_deadline(account);
        };
        if claims.claimed_accounts.contains(account) {
            return None;
        }
        claims
            .pending_withdrawals
            .get(account)
            .map(|request| request.body().deadline())
            .or_else(|| {
                claims.admitted_withdrawals.iter().find_map(|withdrawals| {
                    withdrawals
                        .get(account, chain.config.max_destination_bytes)
                        .expect("refinement withdrawals were validated at admission")
                        .map(|request| request.body().deadline())
                })
            })
    }

    fn assert_refines(&self) {
        let chain = &self.fixture.chain;
        assert_eq!(self.now, self.state.now);
        assert_eq!(chain.expected_epoch, u64::from(self.state.expected_epoch));
        let finalized_root = if self.state.current_root == spec::Root::Empty {
            assert!(chain.hard_fault_is_settled());
            BATCHES
                .into_iter()
                .filter(|batch| self.state.finalized_batches & (1 << batch.index()) != 0)
                .max_by_key(|batch| batch.candidate().epoch)
                .map_or(spec::Root::R0, |batch| batch.candidate().successor)
        } else {
            self.state.current_root
        };
        assert_eq!(chain.current_state_root, self.root(finalized_root));
        assert_eq!(
            chain.current_liability,
            u64::from(self.state.current_liability)
        );
        assert_eq!(chain.custody_balance, u64::from(self.state.custody));
        assert_eq!(chain.claimable_balance, u64::from(self.state.claimable));
        if self.state.current_root != spec::Root::Empty {
            let cache = self.cache(self.state.current_root);
            assert_eq!(cache.liability(), u64::from(self.state.current_liability));
            for account in ACCOUNTS {
                let expected = self.state.current_state[account.index()];
                let key = self.key(account);
                let actual = cache
                    .lookup(&key)
                    .resolve::<Sha256>(&cache.root(), &account_key(&key).unwrap())
                    .unwrap();
                assert_eq!(actual.is_some(), expected.active);
                if let Some(actual) = actual {
                    assert_eq!(actual.get(), u64::from(expected.balance));
                }
            }
        }
        assert_eq!(
            chain.unfinalized_deposit_total,
            self.state
                .unfinalized_deposits
                .iter()
                .copied()
                .map(u64::from)
                .sum::<u64>()
        );
        assert_eq!(
            chain.registered.as_ref().map(|_| {
                self.registered
                    .as_ref()
                    .expect("the driver mirrors production registration")
                    .batch
                    .registration()
            }),
            self.state.registered
        );
        if let (Some(actual), Some(expected)) = (&chain.registered, &self.registered) {
            assert_eq!(actual.context, expected.context);
            assert_eq!(actual.deposits, expected.deposits);
            assert_eq!(actual.withdrawals, expected.withdrawals);
        }
        assert_eq!(chain.pipeline.len(), self.state.pipeline.len());
        for (actual, expected) in chain.pipeline.iter().zip(&self.state.pipeline) {
            let actual_batch = self.expected_batch(actual.batch.header.batch_id::<Sha256>());
            assert_eq!(&actual_batch, expected);
            let material = self.material(*expected);
            assert_eq!(actual.batch.header, material.close.header);
            assert_eq!(actual.batch.roots, material.close.roots);
            assert_eq!(
                actual.batch.withdrawal_total,
                material.close.withdrawal_total
            );
            assert_eq!(actual.admitted.context, material.context);
            assert_eq!(actual.batch.roots.successor, material.successor.root());
            assert_eq!(
                actual.batch.successor_liability,
                u64::from(
                    expected
                        .candidate()
                        .successor_state
                        .iter()
                        .map(|state| state.balance)
                        .sum::<u16>()
                )
            );
            let expected_status = self.state.status[expected.index()];
            match (&actual.batch.status, expected_status) {
                (BatchStatus::Pending, spec::BatchStatus::Pending) => {}
                (BatchStatus::Challenged(actual), spec::BatchStatus::Challenged(expected)) => {
                    assert!(challenge_kind_matches(*actual, expected));
                }
                (BatchStatus::Invalidated(actual), spec::BatchStatus::Invalidated(expected)) => {
                    assert_eq!(self.expected_batch(*actual), expected);
                }
                pair => panic!("batch status diverged: {pair:?}"),
            }
        }
        for id in [
            spec::DepositId::BobTwo,
            spec::DepositId::AliceOne,
            spec::DepositId::BobOne,
        ] {
            let (actual, _, _) = self.deposit(id);
            assert_eq!(
                chain.consumed_deposit_ids.contains(&actual),
                self.state.consumed_deposits & (1 << id.index()) != 0
            );
        }
        for id in [
            spec::WithdrawalId::Amount,
            spec::WithdrawalId::Close,
            spec::WithdrawalId::CloseAfterFault,
            spec::WithdrawalId::Offset,
            spec::WithdrawalId::Carried,
            spec::WithdrawalId::CarriedOffset,
        ] {
            let expected = self.state.withdrawal_replay_expiries[id.index()].map(u64::from);
            let actual = self.requests[id.index()].as_ref().map(|request| {
                let request_id = request.id::<Sha256>();
                (
                    chain.consumed_withdrawal_ids.contains(&request_id),
                    chain
                        .withdrawal_replay_expiries
                        .contains(&(request.body().deadline(), request_id)),
                )
            });
            assert_eq!(
                actual.map(|(consumed, _)| consumed).unwrap_or(false),
                expected.is_some()
            );
            assert_eq!(
                actual.map(|(_, retained)| retained).unwrap_or(false),
                expected.is_some()
            );
        }
        let actual = chain
            .intervals
            .iter()
            .flat_map(|(&start, &end)| start..end)
            .collect::<Vec<_>>();
        let expected = self
            .state
            .intervals
            .iter()
            .flat_map(|(&start, &end)| u64::from(start)..u64::from(end))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert!(chain.intervals.len() <= expected.len());
        assert_eq!(
            chain.finalized_payouts().operations,
            u64::from(self.state.finalized_payout_operations)
        );
        assert_eq!(chain.finalized_logs(), self.finalized_cache().logs());
        for account in ACCOUNTS {
            let index = account.index();
            let key = self.key(account);
            let expected_deposit = self.state.pending_deposits[index];
            assert_eq!(
                chain
                    .pending_deposits
                    .get(&key)
                    .map(|deposit| deposit.amount),
                (expected_deposit != 0).then_some(u64::from(expected_deposit))
            );
            assert_eq!(
                chain
                    .pending_deposits
                    .get(&key)
                    .map(|deposit| deposit.deadline),
                self.state.deposit_deadlines[index].map(u64::from)
            );
            assert_eq!(
                chain.pending_withdrawals.contains_key(&key),
                self.state.pending_withdrawals[index].is_some()
            );
            if let (Some(actual), Some(expected)) = (
                chain.pending_withdrawals.get(&key),
                self.state.pending_withdrawals[index],
            ) {
                assert_eq!(actual, &self.signed_withdrawal(expected));
            }
            assert_eq!(
                self.outstanding_withdrawal_deadline(&key),
                self.state.outstanding_withdrawals[index]
                    .map(|request| u64::from(request.deadline))
                    .or_else(|| {
                        self.state.registered.and_then(|registration| {
                            registration.registration().withdrawals[index]
                                .map(|request| u64::from(request.deadline))
                        })
                    })
            );
        }
        let expected_deposit_deadlines = ACCOUNTS
            .into_iter()
            .filter_map(|account| {
                self.state.deposit_deadlines[account.index()]
                    .map(|deadline| (u64::from(deadline), self.key(account)))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(chain.pending_deposit_deadlines, expected_deposit_deadlines);
        let expected_withdrawal_deadlines = ACCOUNTS
            .into_iter()
            .filter_map(|account| {
                self.state.pending_withdrawals[account.index()]
                    .map(|request| (u64::from(request.deadline), self.key(account)))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            chain.pending_withdrawal_deadlines,
            expected_withdrawal_deadlines
        );
        assert_eq!(
            chain.admission_fence_epoch,
            self.state.admission_fence_epoch.map(u64::from)
        );
        assert_eq!(
            chain.invalid_from.map(|id| self.expected_batch(id)),
            self.state.invalid_from
        );
        match (&chain.hard_fault, self.state.fault) {
            (None, spec::Fault::Healthy) => {}
            (
                Some(HardFaultReason::ProvenChallenge { batch_id, kind }),
                spec::Fault::ProvenChallenge {
                    batch,
                    kind: expected,
                },
            ) => {
                assert_eq!(self.expected_batch(*batch_id), batch);
                assert!(challenge_kind_matches(*kind, expected));
            }
            (
                Some(HardFaultReason::ExpiredDeposit {
                    account,
                    expired_at,
                }),
                spec::Fault::ExpiredDeposit {
                    account: expected,
                    expired_at: deadline,
                },
            )
            | (
                Some(HardFaultReason::ExpiredWithdrawal {
                    account,
                    expired_at,
                }),
                spec::Fault::ExpiredWithdrawal {
                    account: expected,
                    expired_at: deadline,
                },
            ) => {
                assert_eq!(account, &self.key(expected));
                assert_eq!(*expired_at, u64::from(deadline));
            }
            (
                Some(HardFaultReason::ExpiredRegistration {
                    anchor,
                    epoch,
                    expired_at,
                }),
                spec::Fault::ExpiredRegistration {
                    registration,
                    epoch: expected_epoch,
                    expired_at: expected_deadline,
                    ..
                },
            ) => {
                assert_eq!(
                    anchor,
                    self.registrations[spec_batch(registration).index()]
                        .as_ref()
                        .expect("the expired registration was observed by production")
                        .payment()
                        .anchor()
                );
                assert_eq!(*epoch, u64::from(expected_epoch));
                assert_eq!(*expired_at, u64::from(expected_deadline));
            }
            pair => panic!("hard fault diverged: {pair:?}"),
        }
        match &self.state.terminal {
            spec::Terminal::Dormant => {
                assert!(chain.hard_fault_claims.is_none());
                assert!(!chain.fault_settled);
            }
            spec::Terminal::Claiming {
                frozen_root,
                frozen_state,
                remaining_state,
                remaining_deposits,
            } => {
                let claims = chain
                    .hard_fault_claims
                    .as_ref()
                    .expect("abstract terminal claims require production claims");
                assert_eq!(claims.frozen_state_root, self.root(*frozen_root));
                let initial = self
                    .terminal_initial
                    .expect("production terminal claims retain their initial summary");
                assert_eq!(
                    claims.state_liability,
                    frozen_state
                        .iter()
                        .map(|state| u64::from(state.balance))
                        .sum::<u64>()
                );
                assert_eq!(
                    (claims.state_liability, claims.unfinalized_deposit_total),
                    (initial.0, initial.1)
                );
                assert_eq!(claims.custody_balance, initial.2);
                assert_eq!(
                    claims.remaining_state_liability,
                    u64::from(*remaining_state)
                );

                // The chain counter is the remaining-deposit total for the
                // whole claims phase.
                assert_eq!(
                    chain.unfinalized_deposit_total,
                    u64::from(*remaining_deposits)
                );
                for account in ACCOUNTS {
                    let index = account.index();
                    let key = self.key(account);
                    let expected = self.state.unfinalized_deposits[index];
                    assert_eq!(
                        claims.deposits.get(&key).copied(),
                        (expected != 0).then_some(u64::from(expected))
                    );
                    assert_eq!(
                        claims.claimed_accounts.contains(&key),
                        self.state.consumed_state & (1 << index) != 0
                    );
                }
                assert!(!chain.fault_settled);
            }
            spec::Terminal::Settled => {
                assert!(chain.hard_fault_claims.is_none());
                assert!(chain.fault_settled);
            }
        }
    }
}

fn action_bit(action: spec::SettlementAction) -> u16 {
    let position = match action {
        spec::SettlementAction::Observe(_) => 0,
        spec::SettlementAction::RecordDeposit(_) => 1,
        spec::SettlementAction::QueueWithdrawal(_) => 2,
        spec::SettlementAction::Register(_) => 3,
        spec::SettlementAction::Admit(_) => 4,
        spec::SettlementAction::Challenge(_) => 5,
        spec::SettlementAction::Finalize => 6,
        spec::SettlementAction::ClaimWithdrawal { .. } => 7,
        spec::SettlementAction::ClaimDeposit(_) => 8,
        spec::SettlementAction::BeginTerminal => 9,
        spec::SettlementAction::ClaimState(_) => 10,
    };
    1 << position
}

const ALL_ACTIONS: u16 = (1 << 11) - 1;

fn challenge_kind_matches(actual: ChallengeKind, expected: spec::ChallengeKind) -> bool {
    matches!(
        (actual, expected),
        (
            ChallengeKind::HigherAckDebit,
            spec::ChallengeKind::HigherDebit
        ) | (
            ChallengeKind::HigherAckEntry,
            spec::ChallengeKind::HigherEntry
        ) | (ChallengeKind::AckFork, spec::ChallengeKind::Fork)
    )
}

#[test]
fn production_initial_state_refines_the_stateright_initial_state() {
    RefinementDriver::new().assert_refines();
}

fn admission(batch: spec::Batch) -> spec::SettlementAction {
    spec::SettlementAction::Admit(
        crate::bajillion::model::certification::certify_close(batch.registration(), batch)
            .expect("the modeled close is certified"),
    )
}

fn register_and_admit_refined(driver: &mut RefinementDriver, batch: spec::Batch) {
    driver.step(spec::SettlementAction::Register(batch.registration()));
    driver.step(admission(batch));
}

fn queue_refined(driver: &mut RefinementDriver, id: spec::WithdrawalId) {
    let attempt = spec::SettlementModel::withdrawal_attempt(&driver.state, id);
    driver.step(spec::SettlementAction::QueueWithdrawal(attempt));
}

#[test]
fn active_registration_queue_refines_without_changing_its_boundary() {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B0));
    queue_refined(&mut driver, spec::WithdrawalId::CloseAfterFault);
    assert_eq!(driver.state.registered, Some(spec::RegistrationId::B0));

    driver.step(admission(spec::Batch::B0));
    assert!(driver.state.pending_withdrawals[spec::Account::Alice.index()].is_some());
    assert!(driver.state.outstanding_withdrawals[spec::Account::Alice.index()].is_some());

    // The later request remains staged, so the fixed B1 boundary cannot omit it.
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B1));
}

#[test]
fn registered_account_duplicate_refines_production_rejection() {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    driver.step(spec::SettlementAction::Observe(5));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobOne,
    ));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B1C));

    let mut duplicate =
        spec::SettlementModel::withdrawal_attempt(&driver.state, spec::WithdrawalId::Carried);
    duplicate.request.action = spec::WithdrawalAction::Amount(1);
    duplicate.replay_key = duplicate.request.replay_key();
    driver.step(spec::SettlementAction::QueueWithdrawal(duplicate));
}

#[test]
fn absent_recipient_credit_refines_to_a_virtual_successor_without_a_reserve() {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    register_and_admit_refined(&mut driver, spec::Batch::B1);
    driver.step(spec::SettlementAction::Observe(5));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Observe(7));
    driver.step(spec::SettlementAction::Finalize);

    let carol = driver.state.current_state[spec::Account::Carol.index()];
    assert!(carol.active);
    assert_eq!(carol.balance, 1);
    let material = driver.material(spec::Batch::B1);
    let row = material
        .close
        .rows
        .iter()
        .find(|row| row.account == driver.carol.public_key())
        .expect("the new virtual recipient is committed in the close");
    assert_eq!(row.predecessor, 0);
    assert_eq!(row.successor, 1);
    assert_eq!(row.output, SettlementOutput::None);
    assert_eq!(material.close.withdrawal_total, 0);
    assert!(driver.fixture.chain.intervals.is_empty());
}

fn challenge_refined(driver: &mut RefinementDriver, batch: spec::Batch, kind: spec::ChallengeKind) {
    let proven = crate::bajillion::model::challenge::adjudicated_proven_challenges(batch)
        .into_iter()
        .find(|proven| proven.kind() == kind)
        .expect("the modeled challenge is proven");
    driver.step(spec::SettlementAction::Challenge(proven));
}

fn clean_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.assert_refines();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    register_and_admit_refined(&mut driver, spec::Batch::B1);
    queue_refined(&mut driver, spec::WithdrawalId::Amount);
    register_and_admit_refined(&mut driver, spec::Batch::B2);
    driver.step(spec::SettlementAction::Observe(5));
    driver.step(spec::SettlementAction::Finalize);
    queue_refined(&mut driver, spec::WithdrawalId::Close);
    register_and_admit_refined(&mut driver, spec::Batch::B3);
    driver.step(spec::SettlementAction::Observe(7));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Observe(9));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: false,
        source: spec::Batch::B2,
        position: 3,
    });
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::B2,
        position: 3,
    });
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::B3,
        position: 5,
    });
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::B2,
        position: 3,
    });
    driver
}

#[test]
fn clean_pipeline_and_claims_refine_production_step_by_step() {
    clean_profile();
}

fn rejected_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::BeginTerminal);
    let mut unauthenticated =
        spec::SettlementModel::withdrawal_attempt(&driver.state, spec::WithdrawalId::Amount);
    unauthenticated.opening.authenticated_state = false;
    driver.step(spec::SettlementAction::QueueWithdrawal(unauthenticated));
    let mut wrong_root =
        spec::SettlementModel::withdrawal_attempt(&driver.state, spec::WithdrawalId::Amount);
    wrong_root.opening.root = spec::Root::R1;
    driver.step(spec::SettlementAction::QueueWithdrawal(wrong_root));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B0));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B1));
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B0));
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::AliceOne,
    ));
    driver.step(admission(spec::Batch::Offset));
    driver.step(admission(spec::Batch::B0));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B2));
    queue_refined(&mut driver, spec::WithdrawalId::Amount);
    let duplicate =
        spec::SettlementModel::withdrawal_attempt(&driver.state, spec::WithdrawalId::Amount);
    driver.step(spec::SettlementAction::QueueWithdrawal(duplicate));
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::B0,
        position: 0,
    });
    driver
}

#[test]
fn rejected_edges_stutter_in_both_machines() {
    rejected_profile();
}

fn registration_expiry_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::Observe(1));
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    driver.step(spec::SettlementAction::Observe(2));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B0));
    driver.step(spec::SettlementAction::Observe(3));
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimDeposit(spec::Account::Bob));
    driver.step(spec::SettlementAction::ClaimDeposit(spec::Account::Bob));
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Bob));
    driver
}

fn late_admission_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::Observe(1));
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    driver.step(spec::SettlementAction::Observe(2));
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B0));
    driver.step_at(3, admission(spec::Batch::B0));
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimDeposit(spec::Account::Bob));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Bob));
    driver
}

#[test]
fn registered_deadline_tie_refines_registration_priority_and_recovery() {
    registration_expiry_profile();
}

#[test]
fn late_admission_refines_mutation_on_error() {
    late_admission_profile();
}

fn challenge_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    register_and_admit_refined(&mut driver, spec::Batch::B1);
    queue_refined(&mut driver, spec::WithdrawalId::Amount);
    register_and_admit_refined(&mut driver, spec::Batch::B2);
    challenge_refined(&mut driver, spec::Batch::B1, spec::ChallengeKind::Fork);
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step_at(5, spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Bob));
    driver
}

fn challenge_kind_profile(kind: spec::ChallengeKind) -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    register_and_admit_refined(&mut driver, spec::Batch::B1);
    challenge_refined(&mut driver, spec::Batch::B1, kind);
    driver
}

#[test]
fn challenged_suffix_and_terminal_sender_recovery_refine_production() {
    challenge_profile();
}

#[test]
fn reachable_challenge_capabilities_refine_real_evidence() {
    for kind in [
        spec::ChallengeKind::HigherDebit,
        spec::ChallengeKind::HigherEntry,
        spec::ChallengeKind::Fork,
    ] {
        challenge_kind_profile(kind);
    }
}

fn deposit_fault_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::AliceOne,
    ));
    driver.step_at(
        2,
        spec::SettlementAction::ClaimDeposit(spec::Account::Alice),
    );
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Bob));
    driver
}

#[test]
fn deposit_fault_refund_and_terminal_state_recovery_refine_production() {
    deposit_fault_profile();
}

fn amountless_close_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    queue_refined(&mut driver, spec::WithdrawalId::CloseAfterFault);
    driver.step(spec::SettlementAction::Observe(11));
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Bob));
    driver
}

#[test]
fn amountless_close_fault_recovery_refines_production() {
    amountless_close_profile();
}

// A never-queued request rides B1C's registration, admission consumes its
// replay id, and the claim releases the full carried amount.
fn carried_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    driver.step(spec::SettlementAction::Observe(5));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobOne,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B1C);
    driver.step(spec::SettlementAction::Observe(9));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::B1C,
        position: 2,
    });
    driver
}

#[test]
fn carried_withdrawal_refines_production_step_by_step() {
    carried_profile();
}

// A fault freezes R1 while the carried amount is outstanding, so the terminal
// split degrades: nothing routes to the destination and the whole balance
// stays residual.
fn carried_fault_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    driver.step(spec::SettlementAction::Observe(5));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobOne,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B1C);
    challenge_refined(&mut driver, spec::Batch::B1C, spec::ChallengeKind::Fork);
    driver.step(spec::SettlementAction::BeginTerminal);
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Bob));
    driver.step(spec::SettlementAction::ClaimState(spec::Account::Alice));
    driver.step(spec::SettlementAction::ClaimDeposit(spec::Account::Bob));
    driver
}

#[test]
fn uncovered_carried_amount_refines_terminal_degrade() {
    carried_fault_profile();
}

// Bob's deposit and carried withdrawal settle together without changing his balance.
fn carried_offset_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    driver.step(spec::SettlementAction::Register(
        spec::RegistrationId::OffsetC,
    ));
    driver.step(admission(spec::Batch::OffsetC));
    driver.step(spec::SettlementAction::Observe(2));
    driver.step(spec::SettlementAction::Observe(4));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::OffsetC,
        position: 1,
    });
    driver
}

#[test]
fn carried_offset_inclusion_refines_production() {
    carried_offset_profile();
}

// Bob spends below his queued amount, so certification certifies the degraded
// close: its zero-valued output still occupies a claimable native position.
fn degraded_profile() -> RefinementDriver {
    let mut driver = RefinementDriver::new();
    driver.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut driver, spec::Batch::B0);
    register_and_admit_refined(&mut driver, spec::Batch::B1);
    queue_refined(&mut driver, spec::WithdrawalId::Amount);
    driver.step(spec::SettlementAction::Register(spec::RegistrationId::B2));
    driver.step(admission(spec::Batch::B2D));
    driver.step(spec::SettlementAction::Observe(5));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Observe(6));
    driver.step(spec::SettlementAction::Finalize);
    driver.step(spec::SettlementAction::Observe(7));
    driver.step(spec::SettlementAction::Finalize);
    driver
}

#[test]
fn degraded_amount_refines_production_step_by_step() {
    let mut driver = degraded_profile();
    let material = driver.material(spec::Batch::B2D);
    let row = material
        .close
        .rows
        .iter()
        .find(|row| row.account == driver.key(spec::Account::Bob))
        .expect("the queued withdrawal account is committed in the close");
    assert_eq!(row.predecessor, 9);
    assert_eq!(row.successor, 1);
    assert_eq!(row.output, SettlementOutput::Withdrawal(0));
    assert_eq!(material.close.withdrawal_total, 0);
    assert_eq!(driver.fixture.chain.intervals.len(), 1);
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        refresh: true,
        source: spec::Batch::B2D,
        position: 3,
    });
    assert!(driver.fixture.chain.intervals.is_empty());
    assert_eq!(driver.fixture.chain.claimable_balance(), 0);
}

#[test]
fn refinement_profiles_execute_every_settlement_action_variant() {
    let visited = clean_profile().visited
        | rejected_profile().visited
        | registration_expiry_profile().visited
        | late_admission_profile().visited
        | challenge_profile().visited
        | deposit_fault_profile().visited
        | amountless_close_profile().visited;
    assert_eq!(visited, ALL_ACTIONS);
}

#[test]
fn global_claim_identity_refines_across_equal_output_source_forks() {
    let mut canonical = RefinementDriver::new();
    canonical.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    register_and_admit_refined(&mut canonical, spec::Batch::OffsetC);
    canonical.step(spec::SettlementAction::Observe(2));
    canonical.step(spec::SettlementAction::Observe(4));
    canonical.step(spec::SettlementAction::Finalize);
    let mut other = RefinementDriver::new();
    other.step(spec::SettlementAction::RecordDeposit(
        spec::DepositId::BobTwo,
    ));
    queue_refined(&mut other, spec::WithdrawalId::Offset);
    register_and_admit_refined(&mut other, spec::Batch::Offset);
    let material = other.batches[spec::Batch::Offset.index()].take().unwrap();
    assert_ne!(material.id, canonical.material(spec::Batch::OffsetC).id);
    assert_eq!(
        material.close.roots.withdrawal_outputs,
        canonical
            .material(spec::Batch::OffsetC)
            .close
            .roots
            .withdrawal_outputs
    );
    canonical.batches[spec::Batch::Offset.index()] = Some(material);
    canonical.step(spec::SettlementAction::ClaimWithdrawal {
        source: spec::Batch::Offset,
        position: 1,
        refresh: false,
    });
    assert_eq!(
        canonical.state.claimed_withdrawals[spec::Batch::OffsetC.index()],
        Some(1)
    );
    assert_eq!(
        canonical.state.claimed_withdrawals[spec::Batch::Offset.index()],
        None
    );
    canonical.step(spec::SettlementAction::ClaimWithdrawal {
        source: spec::Batch::OffsetC,
        position: 1,
        refresh: true,
    });
}
