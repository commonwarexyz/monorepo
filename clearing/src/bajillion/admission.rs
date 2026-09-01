//! Deterministic dealings and exact-quorum header admission.

mod certificate;

#[cfg(test)]
use crate::bajillion::transition::EpochContext;
use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    payment::verify_ack_signatures,
    transition::{
        Assignment, CloseContext, Header, OperatorKey, ProofSlice, RootBundle,
        validate_boundary_roots, validate_slice_after_header,
    },
};
use alloc::vec::Vec;
pub use certificate::{
    COMMITTEE_HASH_NAMESPACE, Committee, Error as AdmissionError, HEADER_NAMESPACE,
    MAX_COMMITTEE_SIZE, bls12381,
};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use rand_core::CryptoRng;

/// One validator attestation over a clearing header.
pub type Vote = bls12381::Vote;

/// Deterministically derives the exact quorum retaining one proof slice.
pub fn slice_holders<H, D>(
    committee: &Committee,
    assignment: &Assignment<D>,
    slice: u16,
) -> Result<Vec<Participant>, AdmissionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    if committee.commitment::<H>() != *assignment.committee() {
        return Err(AdmissionError::CommitteeMismatch);
    }
    if slice >= assignment.slice_count() {
        return Err(AdmissionError::IncompleteAssignment);
    }
    let n = committee.members().len();
    let quorum = committee.quorum();
    let start = usize::from(slice)
        .checked_mul(quorum)
        .ok_or(AdmissionError::IncompleteAssignment)?
        % n;
    let end = start
        .checked_add(quorum)
        .ok_or(AdmissionError::IncompleteAssignment)?;
    let mut holders = Vec::with_capacity(quorum);
    if end <= n {
        holders.extend((start..end).map(Participant::from_usize));
    } else {
        holders.extend((0..end - n).map(Participant::from_usize));
        holders.extend((start..n).map(Participant::from_usize));
    }
    Ok(holders)
}

/// Derives every slice in one validator's dealing.
pub fn assigned_slice_indices<H, D>(
    committee: &Committee,
    assignment: &Assignment<D>,
    validator: Participant,
) -> Result<Vec<u16>, AdmissionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let validator = usize::from(validator);
    let n = committee.members().len();
    if validator >= n {
        return Err(AdmissionError::UnknownValidator);
    }
    if committee.commitment::<H>() != *assignment.committee() {
        return Err(AdmissionError::CommitteeMismatch);
    }
    let quorum = committee.quorum();
    let slice_count = usize::from(assignment.slice_count());
    let capacity = slice_count
        .checked_mul(quorum)
        .and_then(|total| total.checked_add(n - 1))
        .ok_or(AdmissionError::IncompleteAssignment)?
        / n;
    let mut slices = Vec::with_capacity(capacity);
    let mut start = 0_usize;
    for slice in 0..assignment.slice_count() {
        let end = start
            .checked_add(quorum)
            .ok_or(AdmissionError::IncompleteAssignment)?;
        let assigned = if end <= n {
            (start..end).contains(&validator)
        } else {
            validator >= start || validator < end - n
        };
        if assigned {
            slices.push(slice);
        }
        start = if end >= n { end - n } else { end };
    }
    Ok(slices)
}

/// A validator's sealed dealing retained through the challenge deadline.
#[derive(Clone, Debug)]
pub struct SealedDealing<P: PublicKey, D: Digest> {
    validator: Participant,
    header: Header<D>,
    roots: RootBundle<D>,
    slices: Vec<ProofSlice<P, D>>,
}

impl<P: PublicKey, D: Digest> SealedDealing<P, D> {
    /// Validator that sealed and owns this dealing.
    pub const fn validator(&self) -> Participant {
        self.validator
    }

    /// Header signed after the dealing was authenticated.
    pub const fn header(&self) -> &Header<D> {
        &self.header
    }

    /// Root bundle needed to authenticate later challenges and finalization.
    pub const fn roots(&self) -> &RootBundle<D> {
        &self.roots
    }

    /// Canonically ordered proof slices comprising the dealing.
    pub fn slices(&self) -> &[ProofSlice<P, D>] {
        &self.slices
    }

    /// Consumes the sealed dealing and returns its proof slices.
    pub fn into_slices(self) -> Vec<ProofSlice<P, D>> {
        self.slices
    }

    /// Returns one slice for service through the challenge deadline.
    pub fn serve(&self, slice: u16) -> Option<&ProofSlice<P, D>> {
        self.slices
            .binary_search_by_key(&slice, |candidate| candidate.index)
            .ok()
            .map(|position| &self.slices[position])
    }
}

/// Authenticates and takes ownership of one validator's dealing, then signs the header.
///
/// A dealing is the complete, canonically ordered set of proof slices assigned to one validator.
/// `seal` verifies every distinct payer authorization in one randomized aggregate batch and each
/// slice's combined operator countersignature. Applications must make the returned dealing
/// durable before publishing the accompanying vote.
#[allow(clippy::too_many_arguments)]
pub fn seal<H, P, D, B, R>(
    scheme: &bls12381::Scheme,
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
    dealing: Vec<ProofSlice<P, D>>,
    rng: &mut R,
    strategy: &impl Strategy,
) -> Result<(Vote, SealedDealing<P, D>), AdmissionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey + Ord + 'static,
    D: Digest,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    let committee = scheme.committee();
    let validator = scheme.me().ok_or(AdmissionError::SigningUnavailable)?;

    // The dealing must contain exactly the validator's deterministic assignment before any local
    // proof work can be accepted.
    let expected = assigned_slice_indices::<H, D>(committee, context.assignment(), validator)?;
    if dealing
        .iter()
        .map(|slice| slice.index)
        .ne(expected.iter().copied())
    {
        return Err(AdmissionError::IncompleteAssignment);
    }
    if !header.verify::<H, P>(context, roots) {
        return Err(AdmissionError::InvalidSlice);
    }
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)
        .map_err(|_| AdmissionError::InvalidSlice)?;
    strategy
        .try_map_collect_vec(&dealing, |slice| {
            validate_slice_after_header::<H, P, D>(
                context,
                operator,
                deposits,
                withdrawals,
                roots,
                slice,
            )
        })
        .map_err(|_| AdmissionError::InvalidSlice)?;

    // Structural validation makes every authorization reference safe to collect. The complete
    // dealing contributes its distinct payer signatures to one randomized aggregate batch; the
    // operator's acceptance was verified per slice through its combined countersignature.
    let ack_count = dealing
        .iter()
        .map(|slice| {
            slice
                .changes
                .rows
                .iter()
                .filter(|row| row.outgoing.is_some())
                .count()
        })
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or(AdmissionError::InvalidSlice)?;
    if !verify_ack_signatures::<P, D, B, R, _>(
        dealing.iter().flat_map(|slice| {
            slice
                .changes
                .rows
                .iter()
                .filter_map(|row| row.outgoing.as_ref())
        }),
        ack_count,
        rng,
        strategy,
    ) {
        return Err(AdmissionError::InvalidSlice);
    }

    // Return the exact authenticated buffers with the vote so the caller can durably retain the
    // dealing before publishing its attestation.
    let sealed = SealedDealing {
        validator,
        header: *header,
        roots: *roots,
        slices: dealing,
    };
    let vote = scheme.sign(header)?;
    Ok((vote, sealed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        payment::{SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorSendBody},
        state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
        transition::{
            Assignment, CloseLimits, OperatorVariant, PreparedClose, StateCache,
            prepare_close_with_strategy,
        },
        vector::{OutEntry, OutVector, TransposeEntry},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Hasher, Sha256, Signer as _, Verifier,
        bls12381::primitives::{
            group::{Private as ValidatorSigningKey, Scalar},
            ops::{compute_public, sign_message},
            variant::MinSig,
        },
        sha256::Digest as ShaDigest,
    };
    use commonware_cryptography_curve25519::signing::{
        BatchVerifier as PaymentBatchVerifier, SigningKey,
        StrictVerifyingKey as AccountVerifyingKey,
    };
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::test_rng;
    use std::{
        num::NonZeroUsize,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static HASH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ACK_BATCH_CREATIONS: AtomicUsize = AtomicUsize::new(0);
    static ACK_BATCH_VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);
    static ACK_BATCH_ADDS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct CountingSha256(Sha256);

    impl Hasher for CountingSha256 {
        type Digest = ShaDigest;

        fn hash(parts: &[&[u8]]) -> Self::Digest {
            HASH_CALLS.fetch_add(1, Ordering::Relaxed);
            Sha256::hash(parts)
        }

        fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            Sha256::hash_pair(left, right)
        }

        fn update(&mut self, bytes: &[u8]) -> &mut Self {
            self.0.update(bytes);
            self
        }

        fn finalize(self) -> (Self, Self::Digest) {
            let (hasher, digest) = self.0.finalize();
            (Self(hasher), digest)
        }
    }

    #[derive(Clone)]
    struct ValidatorKey {
        signing: ValidatorSigningKey,
    }

    fn validator_keys(count: u64) -> Vec<ValidatorKey> {
        (0..count)
            .map(|index| ValidatorKey {
                signing: ValidatorSigningKey::new(Scalar::from(index + 1)),
            })
            .collect()
    }

    fn committee(keys: &[ValidatorKey]) -> Committee {
        Committee::new(
            keys.iter()
                .map(|key| compute_public::<MinSig>(&key.signing))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn assigned_slice_indices_hashes_committee_once() {
        let keys = validator_keys(100);
        let committee = committee(&keys);
        let assignment = Assignment::new(committee.commitment::<CountingSha256>(), 8).unwrap();
        HASH_CALLS.store(0, Ordering::Relaxed);

        let slices = assigned_slice_indices::<CountingSha256, _>(
            &committee,
            &assignment,
            Participant::new(37),
        )
        .unwrap();

        assert_eq!(slices.len(), 172);
        assert_eq!(HASH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn assignment_arithmetic_matches_cyclic_reference() {
        for validator_count in [1_u64, 4, 7, 10, 100] {
            let keys = validator_keys(validator_count);
            let committee = committee(&keys);
            let count = committee.members().len();
            let quorum = committee.quorum();
            for slice_bits in 0..=8 {
                let assignment =
                    Assignment::new(committee.commitment::<Sha256>(), slice_bits).unwrap();
                let mut inverse = vec![Vec::new(); count];
                for slice in 0..assignment.slice_count() {
                    let start = usize::from(slice) * quorum % count;
                    let mut expected = (0..quorum)
                        .map(|offset| Participant::from_usize((start + offset) % count))
                        .collect::<Vec<_>>();
                    expected.sort_unstable();
                    expected.dedup();

                    let actual =
                        slice_holders::<Sha256, _>(&committee, &assignment, slice).unwrap();
                    assert_eq!(actual, expected);
                    for validator in actual {
                        inverse[usize::from(validator)].push(slice);
                    }
                }
                for (validator, expected) in inverse.into_iter().enumerate() {
                    assert_eq!(
                        assigned_slice_indices::<Sha256, _>(
                            &committee,
                            &assignment,
                            Participant::from_usize(validator),
                        )
                        .unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn every_slice_has_quorum_coverage_and_quorum_intersection() {
        let keys = validator_keys(7);
        let committee = committee(&keys);
        let assignment = Assignment::new(committee.commitment::<Sha256>(), 3).unwrap();
        let faults = committee.faults();
        let quorum = committee.quorum();
        for slice in 0..assignment.slice_count() {
            let holders = slice_holders::<Sha256, _>(&committee, &assignment, slice).unwrap();
            assert_eq!(holders.len(), quorum);
            assert!(holders.windows(2).all(|pair| pair[0] < pair[1]));
            for mask in 0_u16..(1_u16 << committee.members().len()) {
                if mask.count_ones() as usize != quorum {
                    continue;
                }
                let intersection = holders
                    .iter()
                    .filter(|holder| mask & (1_u16 << usize::from(**holder)) != 0)
                    .count();
                assert!(intersection > faults);
            }
        }
        let wrong = Assignment::new(Sha256::hash(&[b"other-committee"]), 3).unwrap();
        assert_eq!(
            slice_holders::<Sha256, _>(&committee, &wrong, 0),
            Err(AdmissionError::CommitteeMismatch)
        );
    }

    #[test]
    fn hundred_validator_assignments_are_balanced() {
        let keys = validator_keys(100);
        let committee = committee(&keys);
        let assignment = Assignment::new(committee.commitment::<Sha256>(), 8).unwrap();
        let counts = (0..committee.members().len())
            .map(|validator| {
                assigned_slice_indices::<Sha256, _>(
                    &committee,
                    &assignment,
                    Participant::from_usize(validator),
                )
                .unwrap()
                .len()
            })
            .collect::<Vec<_>>();
        assert_eq!(counts.iter().min(), Some(&171));
        assert_eq!(counts.iter().max(), Some(&172));
        assert_eq!(counts.iter().sum::<usize>(), 256 * 67);
    }

    struct SealFixture {
        cache: StateCache<AccountVerifyingKey, ShaDigest>,
        context: CloseContext<AccountVerifyingKey, ShaDigest>,
        deposits: DepositBatch<AccountVerifyingKey>,
        withdrawals: WithdrawalBatch<AccountVerifyingKey, ShaDigest>,
        operator_bls: OperatorKey,
        prepared: PreparedClose<AccountVerifyingKey, ShaDigest>,
    }

    /// Builds a close over two accounts where the payer sends twenty units to the recipient,
    /// bound to `committee` with `slice_bits` deterministic slices.
    fn seal_fixture(committee: &Committee, slice_bits: u8, payments: bool) -> SealFixture {
        let operator = SigningKey::from_seed(100);
        let operator_bls_private = ValidatorSigningKey::new(Scalar::from(999));
        let operator_bls = compute_public::<OperatorVariant>(&operator_bls_private);
        let payer = SigningKey::from_seed(101);
        let recipient = SigningKey::from_seed(102);
        let opening = AccountState {
            balance: 100,
            active: true,
            ..AccountState::default()
        };
        let mut leaves = vec![
            StateLeaf {
                account: payer.public_key(),
                state: opening,
            },
            StateLeaf {
                account: recipient.public_key(),
                state: opening,
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let assignment = Assignment::new(committee.commitment::<Sha256>(), slice_bits).unwrap();
        let context = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"deployment"]),
            7,
            operator.public_key(),
            &deposits,
            &withdrawals,
            cache.liability(),
            49,
            50,
            CloseLimits::protocol_maximum(),
            assignment,
        )
        .and_then(|epoch| epoch.bind::<Sha256>(&cache, &deposits, &withdrawals))
        .unwrap();

        let (rows, out_vectors, transpose, signatures) = if payments {
            let epoch = context.payment().epoch();
            let out_vector = OutVector::new(
                epoch,
                payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.public_key(),
                    cumulative: 20,
                    count: 1,
                }],
            )
            .unwrap();
            let body = VectorSendBody::new(
                context.payment(),
                payer.public_key(),
                1,
                20,
                out_vector.root::<Sha256, ShaDigest>().unwrap(),
            );
            let operator_signature = sign_message::<OperatorVariant>(
                &operator_bls_private,
                VECTOR_ACK_AGGREGATE_NAMESPACE,
                body.encode().as_ref(),
            );
            let outgoing = SendAuthorization::sign(body, &payer);
            let transpose = vec![TransposeEntry {
                recipient: recipient.public_key(),
                payer: payer.public_key(),
                cumulative: 20,
                count: 1,
            }];
            let mut rows = vec![
                (
                    AccountRow {
                        account: payer.public_key(),
                        predecessor: opening,
                        successor: AccountState {
                            balance: 80,
                            cumulative_debit: 20,
                            ..opening
                        },
                        outgoing: Some(outgoing),
                        output: SettlementOutput::None,
                        prefix: Prefix::default(),
                    },
                    out_vector,
                    Some(operator_signature),
                ),
                (
                    AccountRow {
                        account: recipient.public_key(),
                        predecessor: opening,
                        successor: AccountState {
                            balance: 120,
                            cumulative_credit: 20,
                            receipt_count: 1,
                            ..opening
                        },
                        outgoing: None,
                        output: SettlementOutput::None,
                        prefix: Prefix::default(),
                    },
                    OutVector::empty(epoch, recipient.public_key()),
                    None,
                ),
            ];
            rows.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
            let mut prefix = Prefix::default();
            for (row, out_vector, _) in &mut rows {
                let (debit, credit, receipts) = row.checked_deltas().unwrap();
                prefix = prefix
                    .checked_extend(Prefix {
                        debit,
                        credit,
                        out_count: u64::try_from(out_vector.entries().len()).unwrap(),
                        in_count: receipts,
                        ..Prefix::default()
                    })
                    .unwrap();
                row.prefix = prefix;
            }
            let mut split_rows = Vec::new();
            let mut split_vectors = Vec::new();
            let mut split_signatures = Vec::new();
            for (row, out_vector, signature) in rows {
                split_rows.push(row);
                split_vectors.push(out_vector);
                split_signatures.push(signature);
            }
            (split_rows, split_vectors, transpose, split_signatures)
        } else {
            (Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        let partials = out_vectors
            .iter()
            .map(OutVector::accumulator)
            .collect::<Vec<_>>();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            out_vectors,
            &partials,
            &signatures,
            transpose,
            &Sequential,
        )
        .unwrap();
        prepared
            .validate::<Sha256, PaymentBatchVerifier, _>(
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                &mut test_rng(),
                &Sequential,
            )
            .unwrap();
        SealFixture {
            cache,
            context,
            deposits,
            withdrawals,
            operator_bls,
            prepared,
        }
    }

    #[test]
    fn validator_seals_only_its_exact_dealing() {
        let validators = validator_keys(4);
        let committee = committee(&validators);
        let fixture = seal_fixture(&committee, 3, false);
        let close = fixture.prepared.close();
        let all = fixture
            .prepared
            .assemble_slices(&fixture.cache, &Sequential)
            .unwrap();
        let scheme =
            bls12381::Scheme::signer(committee.clone(), validators[0].signing.clone()).unwrap();
        let expected = assigned_slice_indices::<Sha256, _>(
            &committee,
            fixture.context.assignment(),
            scheme.me().unwrap(),
        )
        .unwrap();
        let slices = expected
            .iter()
            .map(|slice| all[usize::from(*slice)].clone())
            .collect::<Vec<_>>();
        let mut rng = test_rng();
        let (vote, sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            slices.clone(),
            &mut rng,
            &Sequential,
        )
        .unwrap();
        assert_eq!(sealed.slices(), slices);
        for slice in expected {
            assert_eq!(sealed.serve(slice).map(|slice| slice.index), Some(slice));
        }

        let (parallel_vote, parallel_sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            slices.clone(),
            &mut test_rng(),
            &Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(parallel_vote, vote);
        assert_eq!(parallel_sealed.slices(), sealed.slices());

        assert_eq!(
            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &fixture.context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                &close.header,
                &close.roots,
                slices[..slices.len() - 1].to_vec(),
                &mut rng,
                &Sequential,
            )
            .map(|_| ()),
            Err(AdmissionError::IncompleteAssignment)
        );

        let mut duplicate = slices.clone();
        let last = duplicate.len() - 1;
        duplicate[last] = duplicate[0].clone();
        assert_eq!(
            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &fixture.context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                &close.header,
                &close.roots,
                duplicate,
                &mut rng,
                &Sequential,
            )
            .map(|_| ()),
            Err(AdmissionError::IncompleteAssignment)
        );

        let mut malformed = slices;
        malformed[0].coverage.end.predecessor =
            malformed[0].coverage.end.predecessor.saturating_add(1);
        assert_eq!(
            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &fixture.context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                &close.header,
                &close.roots,
                malformed,
                &mut rng,
                &Sequential,
            )
            .map(|_| ()),
            Err(AdmissionError::InvalidSlice)
        );
    }

    struct ExactAckBatch {
        items: usize,
    }

    impl BatchVerifier for ExactAckBatch {
        type PublicKey = AccountVerifyingKey;

        fn new(capacity: usize) -> Self {
            assert_eq!(capacity, 1);
            ACK_BATCH_CREATIONS.fetch_add(1, Ordering::Relaxed);
            Self { items: 0 }
        }

        fn add(
            &mut self,
            _namespace: &[u8],
            _message: &[u8],
            _public_key: &Self::PublicKey,
            _signature: &<Self::PublicKey as Verifier>::Signature,
        ) -> bool {
            ACK_BATCH_ADDS.fetch_add(1, Ordering::Relaxed);
            self.items += 1;
            true
        }

        fn verify<R: CryptoRng>(self, _rng: &mut R, _strategy: &impl Strategy) -> bool {
            ACK_BATCH_VERIFICATIONS.fetch_add(1, Ordering::Relaxed);
            self.items == 1
        }
    }

    #[test]
    fn seal_authenticates_exact_ack_envelopes() {
        let validators = validator_keys(4);
        let committee = committee(&validators);
        let fixture = seal_fixture(&committee, 0, true);
        let close = fixture.prepared.close();
        let all = fixture
            .prepared
            .assemble_slices(&fixture.cache, &Sequential)
            .unwrap();
        let validator =
            slice_holders::<Sha256, ShaDigest>(&committee, fixture.context.assignment(), 0)
                .unwrap()[0];
        let validator_key = validators
            .iter()
            .find(|key| {
                compute_public::<MinSig>(&key.signing)
                    == committee.members()[usize::from(validator)]
            })
            .unwrap();
        let scheme =
            bls12381::Scheme::signer(committee.clone(), validator_key.signing.clone()).unwrap();
        let strategy = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();

        // A payer signature swap leaves the committed body untouched, so only the randomized
        // aggregate batch can catch it.
        let mut mutated_outgoing = all.clone();
        let row = mutated_outgoing[0]
            .changes
            .rows
            .iter_mut()
            .find(|row| row.outgoing.is_some())
            .unwrap();
        let original = row.outgoing.as_ref().unwrap();
        row.outgoing = Some(SendAuthorization::sign(
            original.body().clone(),
            &SigningKey::from_seed(999),
        ));
        assert_eq!(
            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &fixture.context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                &close.header,
                &close.roots,
                mutated_outgoing,
                &mut test_rng(),
                &strategy,
            )
            .map(|_| ()),
            Err(AdmissionError::InvalidSlice)
        );

        ACK_BATCH_CREATIONS.store(0, Ordering::Relaxed);
        ACK_BATCH_VERIFICATIONS.store(0, Ordering::Relaxed);
        ACK_BATCH_ADDS.store(0, Ordering::Relaxed);
        let (_, sealed) = seal::<Sha256, _, _, ExactAckBatch, _>(
            &scheme,
            &fixture.context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            &close.header,
            &close.roots,
            all,
            &mut test_rng(),
            &strategy,
        )
        .unwrap();
        assert_eq!(sealed.slices().len(), 1);
        assert_eq!(ACK_BATCH_CREATIONS.load(Ordering::Relaxed), 1);
        assert_eq!(ACK_BATCH_VERIFICATIONS.load(Ordering::Relaxed), 1);
        assert_eq!(ACK_BATCH_ADDS.load(Ordering::Relaxed), 1);
    }
}
