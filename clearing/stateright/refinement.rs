use super::*;
use crate::bajillion::{
    admission::seal, model::settlement as spec, payment::Entry, transition::assemble_slices,
};
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;

const ACCOUNTS: [spec::Account; 3] = [
    spec::Account::Alice,
    spec::Account::Bob,
    spec::Account::Carol,
];
const BATCHES: [spec::Batch; 5] = [
    spec::Batch::B0,
    spec::Batch::B1,
    spec::Batch::B2,
    spec::Batch::B3,
    spec::Batch::Offset,
];
fn refinement_config() -> SettlementConfig {
    SettlementConfig::new(
        NonZeroUsize::new(3).unwrap(),
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
        spec::RegistrationId::B2 => spec::Batch::B2,
        spec::RegistrationId::B3 => spec::Batch::B3,
        spec::RegistrationId::Offset => spec::Batch::Offset,
    }
}

fn successor_cache(cache: &TestCache, close: &TestClose) -> TestCache {
    let changed = close
        .rows
        .iter()
        .map(|row| row.account.clone())
        .collect::<BTreeSet<_>>();
    let mut leaves = cache
        .leaves()
        .iter()
        .filter(|leaf| !changed.contains(&leaf.account))
        .cloned()
        .collect::<Vec<_>>();
    leaves.extend(
        close
            .rows
            .iter()
            .filter(|row| row.successor.active)
            .map(|row| StateLeaf {
                account: row.account.clone(),
                state: row.successor,
            }),
    );
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    StateCache::new::<Sha256>(leaves).unwrap()
}

fn transfer_with_deposit_close(
    cache: &TestCache,
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &SigningKey,
    amount: u64,
    deposits: &TestDeposits,
) -> (TestClose, TestCache) {
    let payment = fork_payment(context, operator, payer, recipient, amount);
    let payer_key = payer.public_key();
    let recipient_key = recipient.public_key();
    let payer_predecessor = cache.opening(&payer_key).unwrap().leaf.state;
    let recipient_predecessor = cache.opening(&recipient_key).unwrap().leaf.state;
    let payer_shards = ShardSet::empty(context.payment().epoch(), payer_key.clone());
    let recipient_shards = ShardSet::new(
        context.payment().epoch(),
        recipient_key.clone(),
        vec![ShardHead::new(0, payment.clone())],
    )
    .unwrap();
    let mut rows = vec![
        (
            AccountRow {
                account: payer_key,
                predecessor: payer_predecessor,
                successor: AccountState {
                    balance: payer_predecessor.balance.checked_sub(amount).unwrap(),
                    cumulative_debit: payer_predecessor
                        .cumulative_debit
                        .checked_add(amount)
                        .unwrap(),
                    ..payer_predecessor
                },
                outgoing: Some(payment),
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            payer_shards,
        ),
        (
            AccountRow {
                account: recipient_key,
                predecessor: recipient_predecessor,
                successor: AccountState {
                    balance: recipient_predecessor
                        .balance
                        .checked_add(deposits.amount_for(&recipient.public_key()))
                        .and_then(|balance| balance.checked_add(amount))
                        .unwrap(),
                    cumulative_credit: recipient_predecessor
                        .cumulative_credit
                        .checked_add(amount)
                        .unwrap(),
                    receipt_count: recipient_predecessor.receipt_count.checked_add(1).unwrap(),
                    ..recipient_predecessor
                },
                outgoing: None,
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            recipient_shards,
        ),
    ];
    rows.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
    let mut prefix = Prefix::default();
    for (row, shards) in &mut rows {
        let (debit, credit, _) = row.checked_deltas().unwrap();
        prefix = prefix
            .checked_extend(Prefix {
                deposit: deposits.amount_for(&row.account),
                debit,
                credit,
                shard_count: shards.heads().len() as u64,
                ..Prefix::default()
            })
            .unwrap();
        row.prefix = prefix;
    }
    let (rows, shards): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
    let close = build_close::<Sha256, _, _>(
        cache,
        context,
        deposits,
        &WithdrawalBatch::empty(),
        rows,
        shards,
    )
    .unwrap();
    let successor = successor_cache(cache, &close);
    assert_eq!(successor.root(), close.roots.successor);
    (close, successor)
}

fn external_payout_refinement_close(
    cache: &TestCache,
    context: &TestContext,
    operator: &SigningKey,
    payer: &SigningKey,
    recipient: &SigningKey,
    amount: u64,
) -> (TestClose, TestCache) {
    let payer_key = payer.public_key();
    let recipient_key = recipient.public_key();
    let payer_predecessor = cache.opening(&payer_key).unwrap().leaf.state;
    let send = SignedSend::sign_next(
        context.payment(),
        payer,
        recipient_key.clone(),
        amount,
        payer_predecessor.cumulative_debit,
    )
    .unwrap();
    let receipt = SignedReceipt::issue_next::<Sha256, _>(
        context.payment(),
        &send,
        &recipient_key,
        0,
        0,
        0,
        operator,
    )
    .unwrap();
    let payment = Payment::new::<Sha256>(context.payment(), send, receipt).unwrap();
    let payer_shards = ShardSet::empty(context.payment().epoch(), payer_key.clone());
    let recipient_shards = ShardSet::new(
        context.payment().epoch(),
        recipient_key.clone(),
        vec![ShardHead::new(0, payment.clone())],
    )
    .unwrap();
    let recipient_successor = AccountState {
        cumulative_credit: amount,
        receipt_count: 1,
        ..AccountState::default()
    };
    let mut rows = vec![
        (
            AccountRow {
                account: payer_key,
                predecessor: payer_predecessor,
                successor: AccountState {
                    balance: payer_predecessor.balance.checked_sub(amount).unwrap(),
                    cumulative_debit: payer_predecessor
                        .cumulative_debit
                        .checked_add(amount)
                        .unwrap(),
                    ..payer_predecessor
                },
                outgoing: Some(payment),
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            payer_shards,
        ),
        (
            AccountRow {
                account: recipient_key,
                predecessor: AccountState::default(),
                successor: recipient_successor,
                outgoing: None,
                output: SettlementOutput::ExternalPayout(amount),
                prefix: Prefix::default(),
            },
            recipient_shards,
        ),
    ];
    rows.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
    let mut prefix = Prefix::default();
    for (row, shards) in &mut rows {
        let (debit, credit, _) = row.checked_deltas().unwrap();
        let payout = if row.predecessor.active { 0 } else { credit };
        prefix = prefix
            .checked_extend(Prefix {
                debit,
                credit,
                payout,
                shard_count: shards.heads().len() as u64,
                ..Prefix::default()
            })
            .unwrap();
        row.prefix = prefix;
    }
    let (rows, shards): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
    let close = build_close::<Sha256, _, _>(
        cache,
        context,
        &DepositBatch::empty(),
        &WithdrawalBatch::empty(),
        rows,
        shards,
    )
    .unwrap();
    let successor = successor_cache(cache, &close);
    assert_eq!(successor.root(), close.roots.successor);
    (close, successor)
}

struct RegisteredMaterial {
    batch: spec::Batch,
    context: TestContext,
    deposits: TestDeposits,
    withdrawals: TestWithdrawals,
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
        Self {
            fixture: refinement_harness(),
            carol: SigningKey::from_seed(12),
            now: 0,
            model: spec::SettlementModel::default(),
            state: spec::SettlementState::default(),
            registered: None,
            registrations: (0..5).map(|_| None).collect(),
            batches: (0..5).map(|_| None).collect(),
            requests: (0..4).map(|_| None).collect(),
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

    fn available_cache(&self, root: spec::Root) -> Option<&TestCache> {
        match root {
            spec::Root::R0 => Some(&self.fixture.cache),
            spec::Root::R1 => self.batches[spec::Batch::B0.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R2 => self.batches[spec::Batch::B1.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R3 => self.batches[spec::Batch::B2.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::R4 => self.batches[spec::Batch::B3.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::Offset => self.batches[spec::Batch::Offset.index()]
                .as_ref()
                .map(|batch| &batch.successor),
            spec::Root::Empty => None,
        }
    }

    fn canonical_cache(&self, root: spec::Root) -> TestCache {
        let states = match root {
            spec::Root::R0 => [
                Some(AccountState {
                    balance: 10,
                    active: true,
                    ..AccountState::default()
                }),
                Some(AccountState {
                    balance: 5,
                    active: true,
                    ..AccountState::default()
                }),
                None,
            ],
            spec::Root::R1 => [
                Some(AccountState {
                    balance: 8,
                    cumulative_debit: 2,
                    active: true,
                    ..AccountState::default()
                }),
                Some(AccountState {
                    balance: 9,
                    cumulative_credit: 2,
                    receipt_count: 1,
                    active: true,
                    ..AccountState::default()
                }),
                None,
            ],
            spec::Root::R2 | spec::Root::R3 => [
                Some(AccountState {
                    balance: 7,
                    cumulative_debit: 3,
                    active: true,
                    ..AccountState::default()
                }),
                Some(AccountState {
                    balance: if root == spec::Root::R2 { 9 } else { 7 },
                    cumulative_credit: 2,
                    receipt_count: 1,
                    active: true,
                    ..AccountState::default()
                }),
                None,
            ],
            spec::Root::R4 => [
                None,
                Some(AccountState {
                    balance: 7,
                    cumulative_credit: 2,
                    receipt_count: 1,
                    active: true,
                    ..AccountState::default()
                }),
                None,
            ],
            spec::Root::Offset => [
                Some(AccountState {
                    balance: 10,
                    active: true,
                    ..AccountState::default()
                }),
                Some(AccountState {
                    balance: 3,
                    active: true,
                    ..AccountState::default()
                }),
                None,
            ],
            spec::Root::Empty => [None, None, None],
        };
        let leaves = ACCOUNTS
            .into_iter()
            .zip(states)
            .filter_map(|(account, state)| {
                state.map(|state| StateLeaf {
                    account: self.key(account),
                    state,
                })
            })
            .collect();
        StateCache::new::<Sha256>(leaves).unwrap()
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
            spec::Destination::Carol => Bytes::from_static(b"carl"),
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
            .map(StateCache::root)
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
        );
        RegisteredMaterial {
            batch,
            context,
            deposits,
            withdrawals,
        }
    }

    fn safety_openings(
        &self,
        attempt: spec::WithdrawalAttempt,
    ) -> Vec<StateOpening<VerifyingKey, ShaDigest>> {
        let expected_count = self.fixture.chain.withdrawal_safety_roots().len();
        let exact_shape = attempt.safety_openings[..expected_count]
            .iter()
            .all(Option::is_some)
            && attempt.safety_openings[expected_count..]
                .iter()
                .all(Option::is_none);
        if !exact_shape {
            return Vec::new();
        }

        attempt.safety_openings[..expected_count]
            .iter()
            .map(|opening| {
                let opening = opening.expect("the exact opening shape was checked");
                let source_root = if opening.root == spec::Root::Empty {
                    spec::Root::R0
                } else {
                    opening.root
                };
                let cache = self.canonical_cache(source_root);
                let account = self.key(opening.account);
                let mut witness = cache.opening(&account).unwrap_or_else(|_| {
                    cache
                        .opening(&cache.leaves()[0].account)
                        .expect("every nonempty canonical root has a leaf")
                });
                witness.leaf.account = account;
                witness.leaf.state.balance = u64::from(opening.state.balance);
                witness.leaf.state.active = opening.state.active;
                if !opening.authenticated_state || opening.root == spec::Root::Empty {
                    witness.leaf.state.cumulative_debit += 1;
                }
                witness
            })
            .collect()
    }

    fn queue_withdrawal(&mut self, attempt: spec::WithdrawalAttempt) -> bool {
        let request = self.signed_withdrawal(attempt.request);
        let openings = self.safety_openings(attempt);
        let result = self.fixture.chain.queue_withdrawal(
            u64::from(self.now),
            request.clone(),
            &openings,
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
            material.deposits.clone(),
            material.withdrawals.clone(),
        );
        if result.is_ok() {
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
            .is_some_and(|registered| registered.batch == batch);
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
        let (close, successor) = match batch {
            spec::Batch::B0 => transfer_with_deposit_close(
                &cache,
                &registered.context,
                &self.fixture.operator,
                &self.fixture.accounts[0],
                &self.fixture.accounts[1],
                2,
                &registered.deposits,
            ),
            spec::Batch::B1 => external_payout_refinement_close(
                &cache,
                &registered.context,
                &self.fixture.operator,
                &self.fixture.accounts[0],
                &self.carol,
                1,
            ),
            spec::Batch::B2 | spec::Batch::B3 | spec::Batch::Offset => boundary_close(
                &cache,
                &registered.context,
                &registered.deposits,
                &registered.withdrawals,
            ),
        };
        let slices = assemble_slices::<Sha256, _, _>(
            &cache,
            &registered.context,
            &registered.deposits,
            &registered.withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        let (vote, sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &self.fixture.signer,
            &registered.context,
            &registered.deposits,
            &registered.withdrawals,
            &close.header,
            &close.roots,
            slices,
            &mut test_rng(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(sealed.header(), &close.header);
        assert_eq!(sealed.roots(), &close.roots);
        let certificate = self.fixture.signer.assemble_exact([vote]).unwrap();
        let terminal = assemble_terminal_proof::<Sha256, _, _>(
            &registered.context,
            &registered.deposits,
            &registered.withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        let result = self.fixture.chain.admit(
            u64::from(self.now),
            close.header,
            close.roots,
            terminal,
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
            spec::ChallengeKind::LatestAcknowledgedSend => {
                let payment = fork_payment(
                    &material.context,
                    &self.fixture.operator,
                    &self.fixture.accounts[1],
                    &self.carol,
                    2,
                );
                let index =
                    ChallengeIndex::new::<Sha256>(&material.context, &material.close).unwrap();
                let payer = index
                    .account_lookup(
                        self.cache(target.candidate().predecessor),
                        &self.fixture.accounts[1].public_key(),
                    )
                    .unwrap();
                Challenge::LatestAcknowledgedSend {
                    payment: Box::new(PaymentWitness::from_payment(&payment)),
                    payer: Box::new(payer),
                }
            }
            spec::ChallengeKind::HigherShardTip => {
                let selected = material
                    .close
                    .rows
                    .iter()
                    .find_map(|row| row.outgoing.clone())
                    .expect("the refined payout close has one outgoing payment");
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    material.context.payment(),
                    selected.send(),
                    selected.recipient(),
                    selected.receipt().body().shard(),
                    selected.receipt().body().cumulative_shard_credit(),
                    selected.receipt().body().index(),
                    &self.fixture.operator,
                )
                .unwrap();
                let payment = Payment::new::<Sha256>(
                    material.context.payment(),
                    selected.send().clone(),
                    receipt,
                )
                .unwrap();
                let index =
                    ChallengeIndex::new::<Sha256>(&material.context, &material.close).unwrap();
                let recipient = payment.recipient().clone();
                let position = material
                    .close
                    .rows
                    .binary_search_by(|row| row.account.cmp(&recipient))
                    .unwrap();
                let recipient = index
                    .higher_shard_tip_lookup::<Sha256>(
                        &recipient,
                        Some(&material.close.shard_sets[position]),
                        payment.receipt().body().shard(),
                    )
                    .unwrap();
                Challenge::HigherShardTip {
                    payment: Box::new(PaymentWitness::from_payment(&payment)),
                    recipient: Box::new(recipient),
                }
            }
            spec::ChallengeKind::InconsistentReceiptRange => {
                // The witness send is a two-entry batch so a refined challenge drives one real
                // multi-entry authorization through witness reconstruction and adjudication.
                let send = SignedSend::sign_next_batch(
                    material.context.payment(),
                    &self.fixture.accounts[1],
                    vec![
                        Entry::new(self.carol.public_key(), 5).unwrap(),
                        Entry::new(self.fixture.accounts[0].public_key(), 1).unwrap(),
                    ],
                    0,
                )
                .unwrap();
                let receipt = SignedReceipt::sign_body_by_authority(
                    ReceiptBody::from_raw_unchecked(
                        *material.context.payment().anchor(),
                        material.context.payment().epoch(),
                        self.carol.public_key(),
                        0,
                        5,
                        send.tx_id::<Sha256>(),
                        4,
                        1,
                    ),
                    &self.fixture.operator,
                );
                let payment =
                    Payment::new::<Sha256>(material.context.payment(), send, receipt).unwrap();
                Challenge::InconsistentReceiptRange {
                    upper: Box::new(PaymentWitness::from_payment(&payment)),
                    lower: RangeLower::ShardStart,
                }
            }
            spec::ChallengeKind::ReceiptFork(spec::ForkRelation::SameSend) => {
                let left = fork_payment(
                    &material.context,
                    &self.fixture.operator,
                    &self.fixture.accounts[1],
                    &self.carol,
                    2,
                );
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    material.context.payment(),
                    left.send(),
                    left.recipient(),
                    1,
                    0,
                    0,
                    &self.fixture.operator,
                )
                .unwrap();
                let right = Payment::new::<Sha256>(
                    material.context.payment(),
                    left.send().clone(),
                    receipt,
                )
                .unwrap();
                Challenge::receipt_fork(&left, &right)
            }
            spec::ChallengeKind::ReceiptFork(spec::ForkRelation::SameIndex) => {
                let left = fork_payment(
                    &material.context,
                    &self.fixture.operator,
                    &self.fixture.accounts[0],
                    &self.carol,
                    2,
                );
                let right = fork_payment(
                    &material.context,
                    &self.fixture.operator,
                    &self.fixture.accounts[1],
                    &self.carol,
                    3,
                );
                Challenge::receipt_fork(&left, &right)
            }
            spec::ChallengeKind::ReceiptFork(spec::ForkRelation::Full) => {
                // A proven Full fork needs two byte-distinct valid signed sends with one body
                // digest. The production test signer is strict and deterministic, so this
                // generic-signature over-approximation has no constructible concrete fixture.
                return false;
            }
        };
        self.fixture
            .chain
            .challenge(
                u64::from(self.now),
                material.id,
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
                    && actual.payout_total
                        == candidate
                            .payout_output
                            .map_or(0, |output| u64::from(output.amount))
            })
    }

    fn claim_withdrawal(&mut self, batch: spec::Batch, source: spec::Batch, position: u8) -> bool {
        let source = self.material(source);
        let account = source.withdrawals.requests().iter().find_map(|request| {
            let claim = assemble_withdrawal_claim::<Sha256, _, _>(
                &source.close,
                &source.withdrawals,
                request.account(),
                &Sequential,
            )
            .ok()?;
            (claim.position() == u32::from(position)).then_some(request.account().clone())
        });
        let Some(account) = account else {
            return false;
        };
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &source.close,
            &source.withdrawals,
            &account,
            &Sequential,
        )
        .unwrap();
        let expected = claim.output().clone();
        let batch_id = self.material(batch).id;
        self.fixture
            .chain
            .claim_withdrawal(batch_id, &claim)
            .is_ok_and(|actual| actual == expected)
    }

    fn claim_payout(&mut self, batch: spec::Batch, source: spec::Batch, position: u8) -> bool {
        let source = self.material(source);
        let claim = assemble_external_payout_claim::<Sha256, _, _>(
            &source.close,
            &self.carol.public_key(),
            &Sequential,
        );
        let Ok(claim) = claim else {
            return false;
        };
        if claim.position() != u32::from(position) {
            return false;
        }
        let expected = source.close.rows.iter().find_map(|row| match row.output {
            SettlementOutput::ExternalPayout(amount) => Some((row.account.clone(), amount)),
            SettlementOutput::None | SettlementOutput::Withdrawal(_) => None,
        });
        let batch_id = self.material(batch).id;
        self.fixture
            .chain
            .claim_external_payout(batch_id, &claim)
            .is_ok_and(|actual| {
                expected.is_some_and(|(recipient, amount)| {
                    actual.recipient == recipient && actual.amount == amount
                })
            })
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
                batch,
                source,
                position,
            } => self.claim_withdrawal(batch, source, position),
            spec::SettlementAction::ClaimPayout {
                batch,
                source,
                position,
            } => self.claim_payout(batch, source, position),
            spec::SettlementAction::ClaimDeposit(account) => {
                let index = account.index();
                let expected = match self.state.terminal {
                    spec::Terminal::Dormant => self.state.pending_deposits[index],
                    spec::Terminal::Claiming { .. } => self.state.unfinalized_deposits[index],
                    spec::Terminal::Settled => 0,
                };
                self.fixture
                    .chain
                    .claim_pending_deposit(u64::from(self.now), &self.key(account))
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
                                    spec::WithdrawalAction::Amount(amount) => {
                                        (amount, balance - amount)
                                    }
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

    fn root(&self, root: spec::Root) -> VectorRoot<ShaDigest> {
        match root {
            spec::Root::Empty => commitment::empty_root::<Sha256>(VectorKind::State),
            _ => self.cache(root).root(),
        }
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
        let position = self
            .cache(match self.state.terminal {
                spec::Terminal::Claiming { frozen_root, .. } => frozen_root,
                spec::Terminal::Dormant | spec::Terminal::Settled => return None,
            })
            .opening(account)
            .ok()
            .map(|opening| opening.proof.position);
        if position.is_some_and(|position| claims.claimed_positions.contains(&position)) {
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
        assert_eq!(chain.current_state_root, self.root(self.state.current_root));
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
                let actual = cache.opening(&self.key(account)).ok();
                assert_eq!(actual.is_some(), expected.active);
                if let Some(actual) = actual {
                    assert_eq!(actual.leaf.state.active, expected.active);
                    assert_eq!(actual.leaf.state.balance, u64::from(expected.balance));
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
            assert_eq!(actual.withdrawals, expected.withdrawals.requests());
        }
        assert_eq!(chain.pipeline.len(), self.state.pipeline.len());
        for (actual, expected) in chain.pipeline.iter().zip(&self.state.pipeline) {
            let actual_batch = self.expected_batch(actual.batch.header.batch_id::<Sha256>());
            assert_eq!(&actual_batch, expected);
            let material = self.material(*expected);
            assert_eq!(actual.batch.header, material.close.header);
            assert_eq!(actual.batch.roots, material.close.roots);
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
        for batch in BATCHES {
            let Some(material) = self.batches[batch.index()].as_ref() else {
                continue;
            };
            let withdrawal = u64::from(self.state.withdrawal_reserve[batch.index()]);
            let payout = u64::from(self.state.payout_reserve[batch.index()]);
            let actual = chain.claimable_batches.get(&material.id);
            assert_eq!(actual.is_some(), withdrawal != 0 || payout != 0);
            if let Some(actual) = actual {
                assert_eq!(actual.change_root, material.close.roots.change);
                assert_eq!(
                    actual.withdrawal_outputs,
                    material.close.roots.withdrawal_outputs
                );
                assert_eq!(actual.withdrawal_remaining, withdrawal);
                assert_eq!(actual.payout_remaining, payout);
                assert_eq!(
                    actual.claimed_withdrawals.iter().next().copied(),
                    self.state.claimed_withdrawals[batch.index()].map(u32::from)
                );
                assert_eq!(
                    actual.claimed_payouts.iter().next().copied(),
                    self.state.claimed_payouts[batch.index()].map(u32::from)
                );
            }
        }
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
                assert_eq!(
                    claims.remaining_deposit_total,
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
                    let opening = self.cache(*frozen_root).opening(&key).ok();
                    assert_eq!(
                        opening.is_some_and(|opening| {
                            claims.claimed_positions.contains(&opening.proof.position)
                        }),
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
        spec::SettlementAction::ClaimPayout { .. } => 8,
        spec::SettlementAction::ClaimDeposit(_) => 9,
        spec::SettlementAction::BeginTerminal => 10,
        spec::SettlementAction::ClaimState(_) => 11,
    };
    1 << position
}

const ALL_ACTIONS: u16 = (1 << 12) - 1;

fn challenge_kind_matches(actual: ChallengeKind, expected: spec::ChallengeKind) -> bool {
    matches!(
        (actual, expected),
        (
            ChallengeKind::LatestAcknowledgedSend,
            spec::ChallengeKind::LatestAcknowledgedSend
        ) | (
            ChallengeKind::HigherShardTip,
            spec::ChallengeKind::HigherShardTip
        ) | (
            ChallengeKind::InconsistentReceiptRange,
            spec::ChallengeKind::InconsistentReceiptRange
        ) | (
            ChallengeKind::ReceiptFork,
            spec::ChallengeKind::ReceiptFork(_)
        )
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
        batch: spec::Batch::B3,
        source: spec::Batch::B2,
        position: 0,
    });
    driver.step(spec::SettlementAction::ClaimPayout {
        batch: spec::Batch::B1,
        source: spec::Batch::B1,
        position: 0,
    });
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        batch: spec::Batch::B2,
        source: spec::Batch::B2,
        position: 0,
    });
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        batch: spec::Batch::B3,
        source: spec::Batch::B3,
        position: 0,
    });
    driver.step(spec::SettlementAction::ClaimPayout {
        batch: spec::Batch::B1,
        source: spec::Batch::B1,
        position: 1,
    });
    driver.step(spec::SettlementAction::ClaimWithdrawal {
        batch: spec::Batch::B2,
        source: spec::Batch::B2,
        position: 0,
    });
    driver.step(spec::SettlementAction::ClaimPayout {
        batch: spec::Batch::B1,
        source: spec::Batch::B1,
        position: 1,
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
    unauthenticated.safety_openings[0]
        .as_mut()
        .unwrap()
        .authenticated_state = false;
    driver.step(spec::SettlementAction::QueueWithdrawal(unauthenticated));
    let mut shifted =
        spec::SettlementModel::withdrawal_attempt(&driver.state, spec::WithdrawalId::Amount);
    shifted.safety_openings[1] = shifted.safety_openings[0].take();
    driver.step(spec::SettlementAction::QueueWithdrawal(shifted));
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
        batch: spec::Batch::B0,
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
    challenge_refined(
        &mut driver,
        spec::Batch::B1,
        spec::ChallengeKind::ReceiptFork(spec::ForkRelation::SameIndex),
    );
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
        spec::ChallengeKind::LatestAcknowledgedSend,
        spec::ChallengeKind::HigherShardTip,
        spec::ChallengeKind::InconsistentReceiptRange,
        spec::ChallengeKind::ReceiptFork(spec::ForkRelation::SameSend),
        spec::ChallengeKind::ReceiptFork(spec::ForkRelation::SameIndex),
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
