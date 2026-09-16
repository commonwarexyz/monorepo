use super::{
    admission_fixtures::{QUORUM, VALIDATORS, Validators},
    fixtures::{
        ActiveProfile, CloseFixture, active_close_fixture, kind_label, profile_key,
        proven_challenges, runner, selected_active_profiles, strategy, terminal_for_entries,
    },
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::bls12381,
    boundary::{SignedWithdrawal, WithdrawalAction},
    challenge::{
        AccountLookup, AckWitness, Challenge, ChallengeKind, Verdict, adjudicate, decode_bounded,
    },
    commitment::{self, VectorKind},
    custody::Epoch,
    logs::{Floors, LogHead, Logs, Opening as LogOpening},
    payment::EntryReceipt,
    posted,
    qmdb::{AccountKey, StateLookup, StateOpening, StateRoot, account_key},
    state::AccountChange,
    transition::{
        Close, CloseContext, OperatorAggregate, WithdrawalClaim, WithdrawalOutput,
        prepare_close_with_strategy, validate_close_with_strategy,
    },
    vector::{OutEntry, OutTipLookup},
};
use commonware_codec::{Decode, DecodeExt, Encode, RangeCfg, varint::UInt};
use commonware_cryptography::{Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_runtime::Runner as _;
use commonware_utils::{Participant, TestRng};
use std::num::NonZeroU64;

const WITHDRAWAL_DESTINATION: &[u8] = b"benchmark-destination";

fn encoded<T: Encode>(value: &T) -> Bytes {
    let bytes = value.encode();
    assert_eq!(bytes.len(), value.encode_size());
    bytes
}

fn field<T: Encode>(wire: &mut Bytes, value: &T) -> usize {
    let expected = encoded(value);
    assert_eq!(wire.split_to(expected.len()), expected);
    expected.len()
}

#[derive(Debug, Default)]
struct DealingBytes {
    row_count: usize,
    account_keys: usize,
    outgoing_flags: usize,
    sequences: usize,
    payer_signatures: usize,
    vector_lengths: usize,
    recipient_indices: usize,
    cumulative_amounts: usize,
    entry_counts: usize,
    operator_aggregate: usize,
}

impl DealingBytes {
    const fn rows(&self) -> usize {
        self.row_count + self.account_keys + self.outgoing_flags + self.sequences
    }

    const fn entries(&self) -> usize {
        self.vector_lengths + self.recipient_indices + self.cumulative_amounts + self.entry_counts
    }

    const fn total(&self) -> usize {
        self.rows() + self.payer_signatures + self.entries() + self.operator_aggregate
    }
}

// Every component is checked against its exact location in the canonical dealing.
fn dealing_bytes(close: &Close<VerifyingKey, Digest>) -> DealingBytes {
    let mut wire = close.encoded().clone();
    let mut sizes = DealingBytes {
        row_count: field(&mut wire, &close.rows.len()),
        ..DealingBytes::default()
    };
    for row in &close.rows {
        sizes.account_keys += field(&mut wire, &row.account);
    }
    for row in &close.rows {
        sizes.outgoing_flags += field(&mut wire, &u8::from(row.outgoing.is_some()));
        if let Some(send) = &row.outgoing {
            sizes.sequences += field(&mut wire, &UInt(send.body().seq()));
            sizes.payer_signatures += field(&mut wire, send.payer_signature());
        }
    }
    for vector in &close.out_vectors {
        sizes.vector_lengths += field(&mut wire, &vector.entries().len());
        for entry in vector.entries() {
            let position = close
                .rows
                .binary_search_by(|row| row.account.cmp(&entry.recipient))
                .expect("every recipient is an activity row");
            sizes.recipient_indices += field(&mut wire, &position);
            sizes.cumulative_amounts += field(&mut wire, &UInt(entry.cumulative));
            sizes.entry_counts += field(&mut wire, &UInt(entry.count));
        }
    }
    let aggregate = Option::<OperatorAggregate>::decode(wire.clone()).expect("aggregate decodes");
    sizes.operator_aggregate = field(&mut wire, &aggregate);
    assert!(wire.is_empty());
    assert_eq!(sizes.total(), close.encoded().len());
    sizes
}

fn challenge_bytes(
    context: &CloseContext<VerifyingKey, Digest>,
    close: &Close<VerifyingKey, Digest>,
    challenge: &Challenge<VerifyingKey, Digest>,
    kind: ChallengeKind,
) -> usize {
    let bytes = encoded(challenge);
    let (witness, lookup) = match challenge {
        Challenge::HigherAckDebit { ack, payer } => {
            (encoded(ack.as_ref()).len(), encoded(payer.as_ref()).len())
        }
        Challenge::HigherAckEntry { entry, sender } => (
            encoded(entry.as_ref()).len(),
            encoded(sender.as_ref()).len(),
        ),
        Challenge::AckFork { left, right } => {
            (encoded(left.as_ref()).len(), encoded(right.as_ref()).len())
        }
    };
    assert_eq!(bytes.len(), encoded(&0_u8).len() + witness + lookup);
    let decoded = decode_bounded::<VerifyingKey, Digest>(bytes.as_ref(), bytes.len())
        .expect("challenge decodes within its actual byte bound");
    assert_eq!(&decoded, challenge);
    assert_eq!(
        adjudicate::<Sha256, _, _>(
            context,
            &close.header,
            &close.roots,
            close.withdrawal_total,
            &decoded
        )
        .expect("challenge verifies"),
        Verdict::Proven(kind),
    );
    bytes.len()
}

fn print_challenges(
    profile: ActiveProfile,
    context: &CloseContext<VerifyingKey, Digest>,
    close: &Close<VerifyingKey, Digest>,
    challenges: [(ChallengeKind, Challenge<VerifyingKey, Digest>); 3],
) {
    for (kind, challenge) in challenges {
        let bytes = challenge_bytes(context, close, &challenge, kind);
        println!(
            "clearing challenge: {} kind={} challenge_bytes={bytes}",
            profile_key(profile),
            kind_label(kind)
        );
    }
}

#[commonware_macros::boxed]
async fn omitted_payer_sizes(
    runtime: commonware_runtime::deterministic::Context,
    profile: ActiveProfile,
) {
    let fixture = active_close_fixture(runtime, profile).await;
    let omitted_ack = fixture.acks.last().expect("profile has senders").clone();
    let omitted_payer = omitted_ack.body().payer().clone();
    assert!(fixture.deposits.is_empty() && fixture.withdrawals.is_empty());
    let terminals = fixture
        .terminals
        .iter()
        .filter(|terminal| {
            terminal.authorization.body().payer() != &omitted_payer
                && terminal
                    .vector
                    .entries()
                    .iter()
                    .all(|entry| entry.recipient != omitted_payer)
        })
        .cloned()
        .collect();
    let CloseFixture {
        state,
        context,
        deposits,
        withdrawals,
        prepared,
        ..
    } = fixture;
    drop(prepared);
    let omitted = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        terminals,
        strategy(),
    )
    .await
    .expect("omitted-payer close prepares");
    let (replica, close) = Box::pin(omitted.apply::<_, Sha256>(state))
        .await
        .expect("omitted-payer close applies");
    let range = close
        .roots
        .activity_range(&context)
        .expect("omitted-payer activity range is valid");
    let epoch = Epoch::at(replica.logs(), context.payment().epoch(), range)
        .await
        .expect("omitted-payer epoch is retained");
    let payer = epoch
        .account_lookup(replica.logs(), &omitted_payer)
        .await
        .expect("omitted payer absence opens");
    assert!(matches!(payer, AccountLookup::Absent(_)));
    let lookup_bytes = encoded(&payer).len();
    let challenge = Challenge::HigherAckDebit {
        ack: Box::new(AckWitness::from_ack(&omitted_ack)),
        payer: Box::new(payer),
    };
    let omitted_bytes =
        challenge_bytes(&context, &close, &challenge, ChallengeKind::HigherAckDebit);
    println!(
        "clearing omitted payer: {} activity_rows={} activity_absence_bytes={} challenge_bytes={omitted_bytes}",
        profile_key(profile),
        close.rows.len(),
        lookup_bytes,
    );
}

fn state_proof_sizes(
    label: &str,
    profile: ActiveProfile,
    root: StateRoot<Digest>,
    opening: StateOpening<VerifyingKey, Digest>,
    present: StateLookup<Digest>,
    absent: StateLookup<Digest>,
    missing: &AccountKey,
) {
    let key = account_key(&opening.account).expect("account key");
    let opening_wire = encoded(&opening);
    let decoded =
        StateOpening::<VerifyingKey, Digest>::decode_cfg(opening_wire.clone(), &opening_wire.len())
            .expect("current opening decodes");
    assert_eq!(decoded, opening);
    assert_eq!(
        decoded
            .verify::<Sha256>(&root)
            .expect("membership verifies"),
        opening.balance
    );
    let membership = encoded(&present);
    let StateLookup::Present(value) = &present else {
        panic!("live account has membership evidence");
    };
    assert_eq!(
        membership.len(),
        encoded(&0_u8).len() + encoded(&value.balance).len() + encoded(&value.proof).len()
    );
    let decoded = StateLookup::<Digest>::decode_cfg(membership.clone(), &membership.len())
        .expect("current membership lookup decodes");
    assert_eq!(decoded, present);
    assert_eq!(
        decoded
            .resolve::<Sha256>(&root, &key)
            .expect("lookup verifies"),
        Some(opening.balance)
    );
    let exclusion = encoded(&absent);
    let StateLookup::Absent(proof) = &absent else {
        panic!("missing account has exclusion evidence");
    };
    let exclusion_proof = encoded(proof).len();
    assert_eq!(exclusion.len(), encoded(&1_u8).len() + exclusion_proof);
    let decoded = StateLookup::<Digest>::decode_cfg(exclusion.clone(), &exclusion.len())
        .expect("current exclusion lookup decodes");
    assert_eq!(decoded, absent);
    assert_eq!(
        decoded
            .resolve::<Sha256>(&root, missing)
            .expect("exclusion verifies"),
        None
    );
    assert_eq!(
        opening_wire.len(),
        encoded(&opening.account).len()
            + encoded(&opening.balance).len()
            + encoded(&opening.proof).len()
    );
    println!(
        "clearing current proofs: {} context={label} family=MMB state_root_bytes={} forced_recovery_opening_bytes={} membership_proof_bytes={} membership_lookup_bytes={} exclusion_proof_bytes={} exclusion_lookup_bytes={}",
        profile_key(profile),
        encoded(&root).len(),
        opening_wire.len(),
        encoded(&opening.proof).len(),
        membership.len(),
        exclusion_proof,
        exclusion.len(),
    );
}

pub(crate) struct WithdrawalClaimFixture {
    pub(crate) root: LogHead<Digest>,
    pub(crate) claim: WithdrawalClaim<Digest>,
    request: SignedWithdrawal<VerifyingKey, Digest>,
}

/// Builds a native Append/Commit payout log with a claim at its middle output.
/// Every filler output has the same destination length as the claimed output.
pub(crate) fn withdrawal_claim_fixture(
    fixture: &CloseFixture,
    total: u32,
    action: WithdrawalAction,
    history_outputs: u32,
) -> WithdrawalClaimFixture {
    let row = &fixture.prepared.close().rows[1];
    let (_, signer) = fixture
        .accounts
        .iter()
        .find(|(account, _)| account == &row.account)
        .expect("withdrawal account is registered");
    let amount = match action {
        WithdrawalAction::Amount(amount) => amount.get(),
        WithdrawalAction::Close => row.successor,
    };
    assert!(amount > 0);
    let request = SignedWithdrawal::sign(
        *fixture.context.deployment(),
        fixture.context.predecessor_root().digest,
        Bytes::from_static(WITHDRAWAL_DESTINATION),
        action,
        100,
        signer,
    );
    request
        .verify_signature()
        .expect("withdrawal request signature verifies");
    let output = WithdrawalOutput::decode_cfg(
        (request.body().destination().clone(), amount).encode(),
        &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
    )
    .expect("withdrawal output decodes");
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
            .expect("filler output decodes")
        })
        .collect::<Vec<_>>();
    let (root, opening) = payout_material(outputs, history_outputs);
    let wire = encoded(&(output.clone(), opening));
    let claim = WithdrawalClaim::<Digest>::decode_cfg(
        wire.clone(),
        &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
    )
    .expect("withdrawal claim decodes");
    assert_eq!(encoded(&claim), wire);
    assert_eq!(
        claim
            .verify::<Sha256>(&root)
            .expect("withdrawal claim verifies"),
        output
    );
    WithdrawalClaimFixture {
        root,
        claim,
        request,
    }
}

fn payout_material(
    outputs: Vec<WithdrawalOutput>,
    history_outputs: u32,
) -> (LogHead<Digest>, LogOpening<Digest>) {
    runner().start(|runtime| async move {
        let cfg = super::fixtures::logs_config(&runtime, "withdrawal-size");
        let mut logs = Logs::<_, Sha256, VerifyingKey, _>::open(runtime, cfg)
            .await
            .expect("native logs open");
        let floors = Floors {
            activity: 0,
            payouts: 0,
        };
        if history_outputs != 0 {
            let filler = WithdrawalOutput::decode_cfg(
                (Bytes::from_static(WITHDRAWAL_DESTINATION), 1_u64).encode(),
                &RangeCfg::exact(WITHDRAWAL_DESTINATION.len()),
            )
            .unwrap();
            let history = logs
                .prepare(
                    logs.head(),
                    commonware_clearing::bajillion::logs::ActivityInput::new(vec![], vec![]),
                    vec![filler; history_outputs as usize],
                    floors,
                )
                .await
                .expect("native historical epoch");
            logs = logs.apply(history).await.expect("apply historical epoch");
        }
        let start = logs.head().payouts.operations;
        let count = outputs.len() as u64;
        let prepared = logs
            .prepare(
                logs.head(),
                commonware_clearing::bajillion::logs::ActivityInput::new(vec![], vec![]),
                outputs,
                floors,
            )
            .await
            .expect("native Append and Commit");
        logs = logs.apply(prepared).await.expect("native batch applies");
        let root = logs.head().payouts;
        assert_eq!(root.operations, start + count + 1);
        let (opening, operations) = logs
            .payout_opening(&root, start + count / 2, NonZeroU64::MIN)
            .await
            .expect("native position opens");
        assert_eq!(
            matches!(
                operations[0],
                commonware_clearing::bajillion::logs::PayoutOperation::Append(_)
            ),
            count != 0
        );
        (root, opening)
    })
}

fn withdrawal_claim_sizes(
    fixture: &CloseFixture,
    total: u32,
    action: WithdrawalAction,
    history_outputs: u32,
) {
    let label = match action {
        WithdrawalAction::Amount(_) => "amount",
        WithdrawalAction::Close => "close",
    };
    let artifact = withdrawal_claim_fixture(fixture, total, action, history_outputs);
    let position = artifact.claim.position();
    let output_bytes = encoded(artifact.claim.output()).len();
    let claim_bytes = encoded(&artifact.claim).len();
    println!(
        "clearing withdrawal claim: {} fixture=native_keyless_mmr history_outputs={history_outputs} operations={} action={label} W={total} position={position} request_bytes={} output_bytes={} opening_bytes={} claim_bytes={} root_bytes={}",
        profile_key(fixture.profile),
        artifact.root.operations,
        encoded(&artifact.request).len(),
        output_bytes,
        claim_bytes - output_bytes,
        claim_bytes,
        encoded(&artifact.root).len(),
    );
}

// The calculator's graph uses first-key senders and last-key recipients when sparse,
// and the next K keys cyclically when every account sends. Sequence numbers are one.
fn calculator_parity() {
    for (live_accounts, cases) in [
        (
            256,
            &[
                (0, 1),
                (1, 1),
                (63, 1),
                (64, 1),
                (65, 1),
                (127, 1),
                (128, 1),
                (129, 1),
                (255, 1),
                (256, 1),
                (256, 127),
                (256, 128),
            ][..],
        ),
        (16_385, &[(8_192, 1), (8_193, 1), (16_385, 1)][..]),
    ] {
        runner().start(|runtime| async move {
            let fixture = active_close_fixture(runtime, ActiveProfile {
                live_accounts, senders: 4, credited_accounts: 4, out_degree: 1,
            }).await;
            for &(senders, degree) in cases {
                let sparse = senders < live_accounts;
                assert!(!sparse || degree == 1);
                let terminals = (0..senders).map(|payer| {
                    let entries = (0..degree).map(|offset| {
                        let recipient = if sparse { live_accounts - senders + payer }
                            else { (payer + offset + 1) % live_accounts };
                        OutEntry {
                            recipient: fixture.accounts[recipient].0.clone(), cumulative: 1, count: 1,
                        }
                    }).collect();
                    terminal_for_entries(&fixture.accounts[payer], &fixture.context,
                        &fixture.operator, 1, entries).0
                }).collect();
                let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                    &fixture.state, &fixture.context, &fixture.deposits, &fixture.withdrawals,
                    terminals, strategy(),
                ).await.expect("calculator close prepares");
                let decoded = posted::decode(prepared.encoded().clone(), &fixture.context)
                    .expect("calculator dealing decodes");
                let validated = validate_close_with_strategy::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                    &fixture.state, &fixture.context, &fixture.operator_bls, &fixture.deposits,
                    &fixture.withdrawals, decoded, &mut TestRng::new(0), strategy(),
                ).await.expect("calculator close validates");
                assert_eq!(prepared.close().header, validated.close().header);
                let close = validated.close();
                assert_eq!(close.rows.len(), (2 * senders).min(live_accounts));
                assert_eq!(close.out_vectors.iter().map(|vector| vector.entries().len()).sum::<usize>(), senders * degree);
                let parts = dealing_bytes(close);
                let graph = if sparse { "sparse_first_last" } else { "cyclic" };
                println!(
                    "clearing calculator parity: graph={graph} N={live_accounts} S={senders} K={degree} E={} A={} rows_bytes={} signatures_bytes={} entries_bytes={} operator_bytes={} dealing_bytes={}",
                    senders * degree, close.rows.len(), parts.rows(), parts.payer_signatures,
                    parts.entries(), parts.operator_aggregate, parts.total(),
                );
            }
        });
    }
}

/// Prints actual encoded artifacts and verifies their proofs for every selected profile.
pub(crate) fn benches(challenges_only: bool) {
    for (_, profile) in selected_active_profiles() {
        runner().start(|runtime| async move {
            let fixture = active_close_fixture(runtime, profile).await;
            let validators = Validators::new(VALIDATORS);
            let close = fixture.prepared.close();
            let parts = dealing_bytes(close);
            let decoded = posted::decode::<VerifyingKey, Digest>(close.encoded().clone(), &fixture.context)
                .expect("complete dealing decodes");
            assert_eq!(decoded.encoded(), close.encoded());
            assert_eq!(validators.committee().members().len(), VALIDATORS);
            let dealings = vec![close.encoded().clone(); VALIDATORS];
            assert!(dealings.iter().all(|wire| wire == close.encoded()));
            for (validator, wire) in dealings.iter().enumerate() {
                println!("clearing validator dealing: {} validator={validator} bytes={}", profile_key(profile), wire.len());
            }
            let egress: usize = dealings.iter().map(Bytes::len).sum();
            assert_eq!(egress, VALIDATORS * parts.total());
            println!("clearing dealing fields: {} {parts:?}", profile_key(profile));

            let certificate = validators.signer(Participant::new(0))
                .assemble_exact(validators.attestations(&close.header))
                .expect("exact quorum certificate assembles");
            assert_eq!(certificate.signers.len(), VALIDATORS);
            assert_eq!(certificate.signers.count(), QUORUM);
            let verifier = bls12381::Scheme::verifier(validators.committee().clone());
            assert!(verifier.verify_exact(&close.header, &certificate));
            assert!(close.header.verify::<Sha256, _>(&fixture.context, &close.roots, close.withdrawal_total));
            let header = encoded(&close.header).len();
            let roots = encoded(&close.roots).len();
            assert_eq!(roots, encoded(&close.roots.change).len() + encoded(&close.roots.row_count).len() + encoded(&close.roots.withdrawal_outputs).len() + encoded(&close.roots.successor).len() + encoded(&close.roots.successor_operations).len() + encoded(&close.roots.successor_sync_boundary).len() + encoded(&close.roots.proposal).len());
            let withdrawal_total_bytes = encoded(&close.withdrawal_total).len();
            let descriptor = encoded(&(close.roots, close.withdrawal_total)).len();
            assert_eq!(descriptor, roots + withdrawal_total_bytes);
            let certificate_bytes = encoded(&certificate).len();
            let external = encoded(&(close.header, certificate.clone())).len();
            assert_eq!(external, 101);
            let package = encoded(&(close.header, close.roots, close.withdrawal_total, certificate)).len();
            assert_eq!(package, header + descriptor + certificate_bytes);

            let ack = &fixture.acks[3];
            let vector = close.out_vectors.iter().find(|vector| vector.payer() == ack.body().payer())
                .expect("receipt payer vector exists");
            let recipient = vector.entries()[0].recipient.clone();
            let OutTipLookup::Present { cumulative, count, opening } = vector.lookup::<Sha256, Digest>(&recipient)
                .expect("receipt entry opens") else { panic!("receipt entry is present") };
            let receipt = EntryReceipt { ack: ack.clone(), recipient, cumulative, count, opening };
            let receipt_wire = encoded(&receipt);
            assert_eq!(receipt_wire.len(), encoded(&receipt.ack).len() + encoded(&receipt.recipient).len()
                + encoded(&receipt.cumulative).len() + encoded(&receipt.count).len() + encoded(&receipt.opening).len());
            let decoded = EntryReceipt::<VerifyingKey, Digest>::decode(receipt_wire.clone()).expect("receipt decodes");
            assert_eq!(decoded, receipt);
            decoded.verify::<Sha256>(fixture.context.payment()).expect("receipt verifies");
            let row = &close.rows[3];
            let send_root = row.outgoing.as_ref().map_or_else(
                || commitment::empty_root::<Sha256>(VectorKind::OutEntry),
                |send| send.body().send_root(),
            );
            let leaf = AccountChange::from_row(row, send_root);
            println!(
                "clearing activity disclosure: {} core_bytes={} value_bytes={} account_change_bytes={}",
                profile_key(profile), encoded(&leaf.value().core()).len(), encoded(&leaf.value()).len(),
                encoded(&leaf).len(),
            );
            println!(
                "clearing sizes: {} E={} rows={} validators={} identical_dealing_bytes={} dealt_egress_bytes={} integrated_commitment_bytes={} root_bundle_bytes={} withdrawal_total_bytes={} descriptor_bytes={} certificate_bytes={} header_certificate_bytes={} header_roots_withdrawal_total_certificate_bytes={} entry_receipt_bytes={}",
                profile_key(profile), profile.edges(), close.rows.len(), VALIDATORS, parts.total(), egress, header, roots, withdrawal_total_bytes, descriptor, certificate_bytes, external, package, receipt_wire.len(),
            );

            if challenges_only {
                let (context, close, _, challenges) =
                    Box::pin(proven_challenges(fixture)).await;
                print_challenges(profile, &context, &close, challenges);
                return;
            }

            for history_outputs in [0, 1024, 65_536] {
                let (head, opening) = payout_material(vec![], history_outputs);
                println!("clearing empty payout epoch: history_outputs={history_outputs} operations={} W=0 commit_position={} commit_opening_bytes={} root_bytes={}", head.operations, opening.start, encoded(&opening).len(), encoded(&head).len());
                for total in [1, u32::try_from(profile.live_accounts).expect("account count fits native log")] {
                    for action in [WithdrawalAction::Amount(NonZeroU64::MIN), WithdrawalAction::Close] {
                        withdrawal_claim_sizes(&fixture, total, action, history_outputs);
                    }
                }
            }

            let account = fixture.accounts[profile.live_accounts / 2].0.clone();
            let key = account_key(&account).expect("account key");
            let missing = account_key(&SigningKey::from_seed(u64::MAX).public_key()).expect("missing account key");
            assert!(fixture.state.state().get(&missing).await.expect("missing balance lookup").is_none());
            let predecessor = fixture.state.state().root();
            let predecessor_operations = fixture.state.state().head().operations();
            state_proof_sizes("predecessor", profile, predecessor,
                fixture.state.state().opening(account.clone()).await.expect("predecessor opening"),
                fixture.state.state().lookup(&key).await.expect("predecessor membership"),
                fixture.state.state().lookup(&missing).await.expect("predecessor exclusion"), &missing);
            let (context, close, state, challenges) =
                Box::pin(proven_challenges(fixture)).await;
            print_challenges(profile, &context, &close, challenges);
            let successor = state.state().root();
            state_proof_sizes("successor_after_apply", profile, successor,
                state.state().opening(account.clone()).await.expect("successor opening"),
                state.state().lookup(&key).await.expect("successor membership"),
                state.state().lookup(&missing).await.expect("successor exclusion"), &missing);
            state_proof_sizes("historical_predecessor_after_apply", profile, predecessor,
                state.state().opening_at(predecessor, predecessor_operations, account).await.expect("historical opening"),
                state.state().lookup_at(predecessor, predecessor_operations, &key).await.expect("historical membership"),
                state.state().lookup_at(predecessor, predecessor_operations, &missing).await.expect("historical exclusion"), &missing);
            assert_eq!(state.state().root(), successor);
            println!("clearing state prefix: {} predecessor_operations={} successor_operations={}", profile_key(profile), predecessor_operations, state.state().head().operations());
        });
        runner().start(|runtime| omitted_payer_sizes(runtime, profile));
    }
    if !challenges_only {
        calculator_parity();
    }
}
