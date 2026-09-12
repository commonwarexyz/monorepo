use super::*;
use crate::bajillion::{
    admission::{self, Committee, bls12381},
    boundary::{WITHDRAWAL_SIGNATURE_NAMESPACE, WithdrawalBody},
    challenge::ChangeAbsence,
    commitment::{self, VectorKind},
    payment::{PaymentContext, VECTOR_ACK_SIGNATURE_NAMESPACE, VECTOR_SEND_SIGNATURE_NAMESPACE},
    state::{AccountChange, AccountRow, SettlementOutput},
    vector::OutTipLookup,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{BatchVerifier, PublicKey, Verifier};
use commonware_cryptography_curve25519::signing::Signature;
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span};
use core::{cmp::Ordering, fmt, ops::Deref};
use rand_core::CryptoRng;

// The cryptographic identity and encoding are unchanged; only Rust's Ord is reversed.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReverseKey(VerifyingKey);
impl Ord for ReverseKey {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.cmp(&self.0)
    }
}
impl PartialOrd for ReverseKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Display for ReverseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl Deref for ReverseKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsRef<[u8]> for ReverseKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl Write for ReverseKey {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}
impl FixedSize for ReverseKey {
    const SIZE: usize = VerifyingKey::SIZE;
}
impl Read for ReverseKey {
    type Cfg = ();
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(VerifyingKey::read(reader)?))
    }
}
impl Span for ReverseKey {}
impl Array for ReverseKey {}
impl Verifier for ReverseKey {
    type Signature = Signature;
    fn verify(&self, namespace: &[u8], message: &[u8], signature: &Signature) -> bool {
        self.0.verify(namespace, message, signature)
    }
}
impl PublicKey for ReverseKey {}

struct ReverseBatch(AckBatchVerifier);
impl BatchVerifier for ReverseBatch {
    type PublicKey = ReverseKey;
    fn new(capacity: usize) -> Self {
        Self(AckBatchVerifier::new(capacity))
    }
    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        key: &ReverseKey,
        signature: &Signature,
    ) -> bool {
        BatchVerifier::add(&mut self.0, namespace, message, &key.0, signature)
    }
    fn verify<R: CryptoRng>(self, rng: &mut R, strategy: &impl Strategy) -> bool {
        BatchVerifier::verify(self.0, rng, strategy)
    }
}

fn accounts() -> Vec<(ReverseKey, SigningKey)> {
    let mut keys = (0..7)
        .map(|seed| {
            let signer = SigningKey::from_seed(seed + 9000);
            (ReverseKey(signer.public_key()), signer)
        })
        .collect::<Vec<_>>();
    keys.sort_unstable_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
    assert!(keys[0].0 > keys[1].0);
    keys
}

#[test]
fn activity_absence_uses_canonical_bytes_even_when_key_ord_is_reversed() {
    let keys = accounts();
    let empty = commitment::empty_root::<Sha256>(VectorKind::OutEntry);
    let guards = [1, 3, 5].map(|index| {
        AccountChange::from_row(
            &AccountRow {
                account: keys[index].0.clone(),
                predecessor: 0,
                successor: 10,
                outgoing: None,
                output: SettlementOutput::None,
            },
            empty,
        )
        .guard::<Sha256>()
    });
    let mut builder = commitment::Builder::<Sha256>::new(VectorKind::Change, 3).unwrap();
    builder.add_values(&guards, &Sequential).unwrap();
    let tree = builder.build(&Sequential).unwrap();
    for position in 0..=guards.len() {
        let start = position.saturating_sub(1);
        let end = (position + 1).min(guards.len());
        let lookup = AccountLookup::Absent(ChangeAbsence {
            predecessor: position.checked_sub(1).map(|i| guards[i].clone()),
            successor: guards.get(position).cloned(),
            opening: tree
                .range_opening(start as u32, (end - start) as u32)
                .unwrap(),
        });
        for present in [1, 3, 5] {
            assert!(
                lookup
                    .resolve::<Sha256>(&tree.root(), &keys[present].0)
                    .is_err(),
                "position {position} must not prove present key {present} absent"
            );
        }
        assert_eq!(
            lookup
                .resolve::<Sha256>(&tree.root(), &keys[position * 2].0)
                .unwrap(),
            (0, None)
        );
    }
}

#[test]
fn recipient_absence_uses_canonical_bytes_even_when_key_ord_is_reversed() {
    let keys = accounts();
    let entries = [1, 3, 5].map(|index| OutEntry {
        recipient: keys[index].0.clone(),
        cumulative: 9,
        count: 1,
    });
    let mut builder = commitment::Builder::<Sha256>::new(VectorKind::OutEntry, 3).unwrap();
    builder.add_values(&entries, &Sequential).unwrap();
    let tree = builder.build(&Sequential).unwrap();
    for position in 0..=entries.len() {
        let start = position.saturating_sub(1);
        let end = (position + 1).min(entries.len());
        let lookup = OutTipLookup::Absent {
            predecessor: position.checked_sub(1).map(|i| entries[i].clone()),
            successor: entries.get(position).cloned(),
            opening: tree
                .range_opening(start as u32, (end - start) as u32)
                .unwrap(),
        };
        for present in [1, 3, 5] {
            assert!(
                lookup
                    .resolve::<Sha256>(&tree.root(), &keys[present].0)
                    .is_err()
            );
        }
        assert_eq!(
            lookup
                .resolve::<Sha256>(&tree.root(), &keys[position * 2].0)
                .unwrap(),
            (0, 0)
        );
    }
}

#[test]
fn outgoing_vectors_follow_bytes_for_construction_decoding_and_lookup() {
    let keys = accounts();
    let entries = [1, 3, 5]
        .map(|index| OutEntry {
            recipient: keys[index].0.clone(),
            cumulative: index as u64,
            count: 1,
        })
        .to_vec();
    let vector = OutVector::new(EPOCH, keys[0].0.clone(), entries.clone()).unwrap();
    assert_eq!(
        OutVector::<ReverseKey>::decode(vector.encode()).unwrap(),
        vector
    );
    let root = vector.root::<Sha256, ShaDigest>().unwrap();
    for (index, (key, _)) in keys.iter().enumerate() {
        let expected = if [1, 3, 5].contains(&index) {
            (index as u64, 1)
        } else {
            (0, 0)
        };
        assert_eq!(
            vector
                .lookup::<Sha256, ShaDigest>(key)
                .unwrap()
                .resolve::<Sha256>(&root, key)
                .unwrap(),
            expected
        );
    }
    let mut descending = entries.clone();
    descending.reverse();
    assert!(OutVector::new(EPOCH, keys[0].0.clone(), descending.clone()).is_err());
    let mut encoded = Vec::new();
    EPOCH.write(&mut encoded);
    keys[0].0.write(&mut encoded);
    descending.write(&mut encoded);
    assert!(OutVector::<ReverseKey>::decode(Bytes::from(encoded)).is_err());
    let duplicate = vec![entries[0].clone(), entries[0].clone()];
    assert!(OutVector::new(EPOCH, keys[0].0.clone(), duplicate).is_err());
}

#[test]
fn boundary_only_close_uses_byte_order_for_withdrawal_positions() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = accounts();
        let cfg = config(&runtime, "reverse-boundary");
        let state = State::<_, Sha256>::init(
            runtime,
            cfg,
            keys.iter()
                .map(|(key, _)| (account_key(key).unwrap(), NonZeroU64::new(100).unwrap()))
                .collect(),
        )
        .await
        .unwrap();
        let deployment = Sha256::hash(&[b"reverse-boundary"]);
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(keys[3].0.clone(), 20).unwrap(),
            DepositRecord::new(keys[2].0.clone(), 7).unwrap(),
            DepositRecord::new(keys[1].0.clone(), 10).unwrap(),
        ])
        .unwrap();
        let requests = [5, 1, 3]
            .map(|index| {
                let body = WithdrawalBody::new(
                    deployment,
                    state.root().digest,
                    Bytes::from(vec![index as u8]),
                    WithdrawalAction::Amount(NonZeroU64::new(index as u64).unwrap()),
                    50,
                );
                let signature = keys[index]
                    .1
                    .sign(WITHDRAWAL_SIGNATURE_NAMESPACE, &body.encode());
                SignedWithdrawal::from_raw_unchecked(keys[index].0.clone(), body, signature)
            })
            .to_vec();
        let withdrawals = WithdrawalBatch::new(requests).unwrap();
        let context = EpochContext::new::<Sha256>(
            deployment,
            EPOCH,
            keys[0].0.clone(),
            &deposits,
            &withdrawals,
            state.liability(),
            60,
            70,
            CloseLimits::protocol_maximum(),
            Sha256::hash(&[b"committee"]),
        )
        .unwrap()
        .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
        .await
        .unwrap();
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(
            deposits
                .records()
                .iter()
                .map(|r| r.account())
                .collect::<Vec<_>>(),
            vec![&keys[1].0, &keys[2].0, &keys[3].0]
        );
        assert_eq!(
            withdrawals
                .requests()
                .iter()
                .map(|r| r.account())
                .collect::<Vec<_>>(),
            vec![&keys[1].0, &keys[3].0, &keys[5].0]
        );
        assert_eq!(
            DepositBatch::<ReverseKey>::decode_cfg(
                deposits.encode(),
                &commonware_codec::RangeCfg::new(..=64)
            )
            .unwrap(),
            deposits
        );
        assert_eq!(
            WithdrawalBatch::<ReverseKey, ShaDigest>::decode_cfg(
                withdrawals.encode(),
                &(
                    commonware_codec::RangeCfg::new(..=64),
                    commonware_codec::RangeCfg::new(..=64)
                )
            )
            .unwrap(),
            withdrawals
        );
        let mut reversed_deposits = deposits.records().to_vec();
        reversed_deposits.reverse();
        assert!(
            DepositBatch::<ReverseKey>::decode_cfg(
                reversed_deposits.encode(),
                &commonware_codec::RangeCfg::new(..=64)
            )
            .is_err()
        );
        assert!(DepositBatch::new(vec![deposits.records()[0].clone(); 2]).is_err());
        let mut reversed_withdrawals = withdrawals.requests().to_vec();
        reversed_withdrawals.reverse();
        assert!(
            WithdrawalBatch::<ReverseKey, ShaDigest>::decode_cfg(
                reversed_withdrawals.encode(),
                &(
                    commonware_codec::RangeCfg::new(..=64),
                    commonware_codec::RangeCfg::new(..=64)
                )
            )
            .is_err()
        );
        assert!(WithdrawalBatch::new(vec![withdrawals.requests()[0].clone(); 2]).is_err());
        assert_eq!(deposits.amount_for(&keys[0].0), 0);
        assert!(withdrawals.request_for(&keys[0].0).is_none());
        for (position, index) in [1, 3, 5].into_iter().enumerate() {
            assert_eq!(
                withdrawals
                    .request_for(&keys[index].0)
                    .unwrap()
                    .body()
                    .destination()
                    .as_ref(),
                &[index as u8]
            );
            let claim = prepared.withdrawal_claim(&keys[index].0).unwrap();
            assert_eq!(claim.position(), position as u32);
            assert_eq!(
                claim
                    .verify::<Sha256>(&prepared.close().roots.withdrawal_outputs)
                    .unwrap()
                    .amount(),
                index as u64
            );
        }
        assert_eq!(deposits.amount_for(&keys[2].0), 7);
        assert_eq!(deposits.amount_for(&keys[1].0), 10);
        assert_eq!(deposits.amount_for(&keys[3].0), 20);
        let operator = compute_public::<crate::bajillion::transition::OperatorVariant>(
            &BlsPrivate::new(Scalar::from(8)),
        );
        let checked = validate_close_with_strategy::<Sha256, _, _, _, _, ReverseBatch, _>(
            &state,
            &context,
            &operator,
            &deposits,
            &withdrawals,
            posted::decode(prepared.encoded().clone(), &context).unwrap(),
            &mut TestRng::new(9),
            &Sequential,
        )
        .await
        .unwrap();
        let retained = Close::decode_evidence::<Sha256>(
            checked.close().encode_evidence(),
            &context,
            &checked.close().header,
        )
        .unwrap();
        let served = crate::bajillion::serve::Index::new(&retained);
        for (position, index) in [1, 3, 5].into_iter().enumerate() {
            assert_eq!(
                served
                    .withdrawal_claim::<Sha256>(&keys[index].0)
                    .unwrap()
                    .position(),
                position as u32
            );
        }
        let (state, _) = checked.apply::<_, Sha256>(state).await.unwrap();
        assert_eq!(
            state
                .get(&account_key(&keys[2].0).unwrap())
                .await
                .unwrap()
                .unwrap()
                .get(),
            107
        );
        assert_eq!(
            state
                .get(&account_key(&keys[1].0).unwrap())
                .await
                .unwrap()
                .unwrap()
                .get(),
            109
        );
        assert_eq!(
            state
                .get(&account_key(&keys[3].0).unwrap())
                .await
                .unwrap()
                .unwrap()
                .get(),
            117
        );
        assert_eq!(
            state
                .get(&account_key(&keys[5].0).unwrap())
                .await
                .unwrap()
                .unwrap()
                .get(),
            95
        );
    });
}

#[test]
fn full_dealing_with_reverse_ord_keys_authenticates_and_serves_every_entry() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = accounts();
        let cfg = config(&runtime, "reverse-full");
        let state = State::<_, Sha256>::init(
            runtime,
            cfg,
            keys.iter()
                .map(|(key, _)| (account_key(key).unwrap(), NonZeroU64::new(100).unwrap()))
                .collect(),
        )
        .await
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let validator_private = BlsPrivate::new(Scalar::from(33));
        let committee = Committee::new(vec![compute_public::<
            crate::bajillion::transition::OperatorVariant,
        >(&validator_private)])
        .unwrap();
        let scheme = bls12381::Scheme::signer(committee.clone(), validator_private).unwrap();
        let context = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"reverse-full"]),
            EPOCH,
            keys[0].0.clone(),
            &deposits,
            &withdrawals,
            state.liability(),
            60,
            70,
            CloseLimits::protocol_maximum(),
            committee.commitment::<Sha256>(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
        .await
        .unwrap();
        let operator_private = BlsPrivate::new(Scalar::from(8));
        let operator =
            compute_public::<crate::bajillion::transition::OperatorVariant>(&operator_private);
        let mut terminals = Vec::new();
        for payer in [1, 5] {
            let vector = OutVector::new(
                EPOCH,
                keys[payer].0.clone(),
                [1, 3, 5]
                    .map(|recipient| OutEntry {
                        recipient: keys[recipient].0.clone(),
                        cumulative: 2,
                        count: 1,
                    })
                    .to_vec(),
            )
            .unwrap();
            let body = VectorSendBody::new(
                context.payment(),
                keys[payer].0.clone(),
                1,
                6,
                vector.root::<Sha256, ShaDigest>().unwrap(),
            );
            terminals.push(Terminal {
                authorization: SendAuthorization::from_raw_unchecked(
                    body.clone(),
                    keys[payer]
                        .1
                        .sign(VECTOR_SEND_SIGNATURE_NAMESPACE, &body.encode()),
                ),
                vector,
                operator_signature: sign_message::<crate::bajillion::transition::OperatorVariant>(
                    &operator_private,
                    VECTOR_ACK_AGGREGATE_NAMESPACE,
                    &body.encode(),
                ),
            });
        }
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &withdrawals,
            terminals,
            &Sequential,
        )
        .await
        .unwrap();
        let (vote, checked) = admission::seal::<Sha256, _, _, _, _, ReverseBatch, _>(
            &scheme,
            &state,
            &context,
            &operator,
            &deposits,
            &withdrawals,
            prepared.encoded().clone(),
            &mut TestRng::new(10),
            &Sequential,
        )
        .await
        .unwrap();
        assert!(scheme.verify_vote(&checked.close().header, &vote));
        let certificate = scheme.assemble_exact([vote]).unwrap();
        assert!(scheme.verify_exact(&checked.close().header, &certificate));
        let retained = Close::decode_evidence::<Sha256>(
            checked.close().encode_evidence(),
            &context,
            &checked.close().header,
        )
        .unwrap();
        let served = crate::bajillion::serve::Index::new(&retained);
        for (index, (key, _)) in keys.iter().enumerate() {
            assert_eq!(
                served
                    .account_lookup::<Sha256>(key)
                    .unwrap()
                    .resolve::<Sha256>(&retained.roots.change, key)
                    .unwrap()
                    .0,
                if [1, 5].contains(&index) { 6 } else { 0 }
            );
            for payer in [1, 5] {
                let lookup = served
                    .higher_entry_lookup::<Sha256>(&keys[payer].0, key)
                    .unwrap();
                let result = lookup
                    .resolve::<Sha256>(&retained.roots.change, &keys[payer].0, key)
                    .unwrap();
                assert_eq!(
                    result,
                    if [1, 3, 5].contains(&index) {
                        (2, 1)
                    } else {
                        (0, 0)
                    }
                );
            }
        }
        let send = retained.rows.last().unwrap().outgoing.as_ref().unwrap();
        let body = send.body();
        let lookup = served.account_lookup::<Sha256>(body.payer()).unwrap();
        let (_, activity) = lookup
            .resolve::<Sha256>(&retained.roots.change, body.payer())
            .unwrap();
        let activity = activity.unwrap();
        assert!(activity.matches_outgoing(context.payment(), body));
        for foreign_context in [
            PaymentContext::new(Sha256::hash(&[b"foreign anchor"]), EPOCH, keys[0].0.clone()),
            PaymentContext::new(*context.payment().anchor(), EPOCH + 1, keys[0].0.clone()),
        ] {
            assert!(!activity.matches_outgoing(&foreign_context, body));
            let foreign_body = VectorSendBody::new(
                &foreign_context,
                body.payer().clone(),
                body.seq(),
                body.cumulative_debit(),
                body.send_root(),
            );
            assert!(!activity.matches_outgoing(context.payment(), &foreign_body));
        }
        let foreign_payer = VectorSendBody::new(
            context.payment(),
            keys[1].0.clone(),
            body.seq(),
            body.cumulative_debit(),
            body.send_root(),
        );
        assert!(!activity.matches_outgoing(context.payment(), &foreign_payer));
        let ack = AckWitness {
            payer: body.payer().clone(),
            seq: body.seq(),
            cumulative_debit: body.cumulative_debit(),
            send_root: body.send_root(),
            payer_signature: send.payer_signature().clone(),
            operator_signature: keys[0]
                .1
                .sign(VECTOR_ACK_SIGNATURE_NAMESPACE, &body.encode()),
        };
        let genuine = Challenge::HigherAckDebit {
            ack: Box::new(ack.clone()),
            payer: Box::new(served.account_lookup::<Sha256>(&keys[5].0).unwrap()),
        };
        assert_eq!(
            adjudicate::<Sha256, _, _>(
                &context,
                &retained.header,
                &retained.roots,
                &retained.amounts,
                &genuine
            )
            .unwrap(),
            Verdict::NoContradiction
        );
        let (leaves, tree) = retained.change_evidence();
        let false_absence = Challenge::HigherAckDebit {
            ack: Box::new(ack),
            payer: Box::new(AccountLookup::Absent(ChangeAbsence {
                predecessor: None,
                successor: Some(leaves[0].guard::<Sha256>()),
                opening: tree.range_opening(0, 1).unwrap(),
            })),
        };
        assert!(matches!(
            adjudicate::<Sha256, _, _>(
                &context,
                &retained.header,
                &retained.roots,
                &retained.amounts,
                &false_absence
            ),
            Err(ChallengeError::LookupOrder)
        ));
        let (state, _) = checked.apply::<_, Sha256>(state).await.unwrap();
        for index in [1, 3, 5] {
            assert_eq!(
                state
                    .get(&account_key(&keys[index].0).unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .get(),
                if index == 3 { 104 } else { 98 }
            );
        }
    });
}
