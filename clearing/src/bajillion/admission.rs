//! Deterministic dealings and exact-quorum header admission.

mod certificate;

use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    payment::{
        Payment, PaymentContext, RECEIPT_SIGNATURE_NAMESPACE, SEND_SIGNATURE_NAMESPACE,
        SignedReceipt, SignedSend,
    },
    transition::{
        Assignment, CloseContext, Header, ProofSlice, RootBundle, validate_slice_header,
        validate_slice_structure_after_header,
    },
};
use ahash::RandomState;
use alloc::vec::Vec;
pub use certificate::{
    COMMITTEE_HASH_NAMESPACE, Committee, Error as AdmissionError, HEADER_NAMESPACE,
    MAX_COMMITTEE_SIZE, bls12381,
};
use commonware_codec::Encode;
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use hashbrown::HashSet;
use rand_core::CryptoRng;

/// One exact-quorum validator attestation over a clearing header.
pub type Vote = bls12381::Vote;

fn verify_payment_signatures<'a, P, D, B, R, I>(
    context: &PaymentContext<P, D>,
    payments: I,
    capacity: usize,
    rng: &mut R,
    strategy: &impl Strategy,
) -> bool
where
    P: PublicKey + 'a,
    D: Digest + 'a,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
    I: IntoIterator<Item = &'a Payment<P, D>>,
{
    let mut payments = payments.into_iter().peekable();
    if payments.peek().is_none() {
        return true;
    }

    // Randomized hashing bounds collision-amplification from adversarial envelopes. Deduplication
    // still uses exact envelope equality, including the signature, and keeps send and receipt
    // domains separate.
    let hasher = RandomState::with_seeds(
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    );
    let mut unique_sends = HashSet::with_capacity_and_hasher(capacity, hasher.clone());
    let mut unique_receipts = HashSet::with_capacity_and_hasher(capacity, hasher);
    let mut sends = Vec::<&SignedSend<P, D>>::with_capacity(capacity);
    let mut receipts = Vec::<&SignedReceipt<P, D>>::with_capacity(capacity);
    for payment in payments {
        if unique_sends.insert(payment.send()) {
            sends.push(payment.send());
        }
        if unique_receipts.insert(payment.receipt()) {
            receipts.push(payment.receipt());
        }
    }

    let Some(signature_count) = sends.len().checked_add(receipts.len()) else {
        return false;
    };
    drop(unique_sends);
    drop(unique_receipts);

    // Encode independent message bodies through the supplied strategy, then queue every distinct
    // signature into one randomized aggregate verification.
    let mut batch = B::new(signature_count);
    let send_messages =
        strategy.map_collect_vec(sends.iter().copied(), |send| send.body().encode());
    let mut queued = true;
    for (send, message) in sends.into_iter().zip(send_messages) {
        queued &= B::add(
            &mut batch,
            SEND_SIGNATURE_NAMESPACE,
            &message,
            send.body().payer(),
            send.signature(),
        );
    }
    let receipt_messages =
        strategy.map_collect_vec(receipts.iter().copied(), |receipt| receipt.body().encode());
    for (receipt, message) in receipts.into_iter().zip(receipt_messages) {
        queued &= B::add(
            &mut batch,
            RECEIPT_SIGNATURE_NAMESPACE,
            &message,
            context.operator(),
            receipt.signature(),
        );
    }
    queued && batch.verify(rng, strategy)
}

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
pub struct RetainedAssignment<P: PublicKey, D: Digest> {
    validator: Participant,
    header: Header<D>,
    roots: RootBundle<D>,
    slices: Vec<ProofSlice<P, D>>,
}

impl<P: PublicKey, D: Digest> RetainedAssignment<P, D> {
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

    /// Consumes the retained dealing and returns its proof slices.
    pub fn into_slices(self) -> Vec<ProofSlice<P, D>> {
        self.slices
    }

    /// Returns one retained slice for service through the challenge deadline.
    pub fn serve(&self, slice: u16) -> Option<&ProofSlice<P, D>> {
        self.slices
            .binary_search_by_key(&slice, |candidate| candidate.index)
            .ok()
            .and_then(|position| self.slices.get(position))
    }
}

/// Authenticates and takes ownership of one validator's dealing, then signs the header.
///
/// A dealing is the complete, canonically ordered set of proof slices assigned to one validator.
/// `seal` verifies every distinct signed send and receipt in one randomized aggregate batch.
/// Applications must make the returned dealing durable before publishing the accompanying vote.
#[allow(clippy::too_many_arguments)]
pub fn seal<H, P, D, B, R>(
    scheme: &bls12381::Scheme,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
    dealing: Vec<ProofSlice<P, D>>,
    rng: &mut R,
    strategy: &impl Strategy,
) -> Result<(Vote, RetainedAssignment<P, D>), AdmissionError>
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
    if dealing.len() != expected.len()
        || dealing
            .iter()
            .map(|slice| slice.index)
            .ne(expected.iter().copied())
    {
        return Err(AdmissionError::IncompleteAssignment);
    }
    validate_slice_header::<H, P, D>(context, deposits, withdrawals, header, roots)
        .map_err(|_| AdmissionError::InvalidSlice)?;
    strategy
        .try_map_collect_vec(&dealing, |slice| {
            validate_slice_structure_after_header::<H, P, D>(
                context,
                deposits,
                withdrawals,
                roots,
                slice,
            )
        })
        .map_err(|_| AdmissionError::InvalidSlice)?;

    // Structural validation makes every payment reference safe to collect. The complete dealing
    // then contributes all of its distinct signatures to one randomized aggregate batch.
    let payment_count = dealing
        .iter()
        .try_fold(0_usize, |total, slice| {
            let outgoing = slice
                .changes
                .rows
                .iter()
                .filter(|row| row.outgoing.is_some())
                .count();
            let incoming = slice
                .shard_sets
                .iter()
                .map(|shards| shards.heads().len())
                .try_fold(0_usize, usize::checked_add)?;
            total.checked_add(outgoing)?.checked_add(incoming)
        })
        .ok_or(AdmissionError::InvalidSlice)?;
    if !verify_payment_signatures::<P, D, B, R, _>(
        context.payment(),
        dealing.iter().flat_map(|slice| {
            slice
                .changes
                .rows
                .iter()
                .filter_map(|row| row.outgoing.as_ref())
                .chain(
                    slice
                        .shard_sets
                        .iter()
                        .flat_map(|shards| shards.heads().iter().map(|head| &head.payment)),
                )
        }),
        payment_count,
        rng,
        strategy,
    ) {
        return Err(AdmissionError::InvalidSlice);
    }

    // Return the exact authenticated buffers with the vote so the caller can durably retain the
    // dealing before publishing its attestation.
    let retained = RetainedAssignment {
        validator,
        header: *header,
        roots: *roots,
        slices: dealing,
    };
    let vote = scheme.sign(header)?;
    Ok((vote, retained))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        credit::{ShardHead, ShardSet},
        payment::{Payment, SignedReceipt, SignedSend},
        state::{AccountRow, AccountState, Prefix, StateLeaf},
        transition::{
            Assignment, CloseLimits, StateCache, assemble_slices, build_close, validate_close,
        },
    };
    use commonware_cryptography::{
        Hasher, Sha256, Signer as _, Verifier,
        bls12381::primitives::{
            group::{Private as ValidatorSigningKey, Scalar},
            ops::compute_public,
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
    static PAYMENT_BATCH_CREATIONS: AtomicUsize = AtomicUsize::new(0);
    static PAYMENT_BATCH_VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);
    static PAYMENT_BATCH_ADDS: AtomicUsize = AtomicUsize::new(0);

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

    #[test]
    fn validator_seals_only_its_exact_dealing() {
        let validators = validator_keys(4);
        let committee = committee(&validators);
        let operator = SigningKey::from_seed(100);
        let account = SigningKey::from_seed(101).public_key();
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account,
            state: AccountState {
                balance: 3,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let assignment = Assignment::new(committee.commitment::<Sha256>(), 3).unwrap();
        let context = CloseContext::new::<Sha256>(
            Sha256::hash(&[b"deployment"]),
            7,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            49,
            50,
            CloseLimits::protocol_maximum(),
            assignment,
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
        let all = assemble_slices::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        let scheme =
            bls12381::Scheme::signer(committee.clone(), validators[0].signing.clone()).unwrap();
        let expected = assigned_slice_indices::<Sha256, _>(
            &committee,
            context.assignment(),
            scheme.me().unwrap(),
        )
        .unwrap();
        let slices = expected
            .iter()
            .map(|slice| all[usize::from(*slice)].clone())
            .collect::<Vec<_>>();
        let mut rng = test_rng();
        let (vote, retained) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slices.clone(),
            &mut rng,
            &Sequential,
        )
        .unwrap();
        assert_eq!(retained.slices(), slices);
        for slice in expected {
            assert_eq!(retained.serve(slice).map(|slice| slice.index), Some(slice));
        }

        let (parallel_vote, parallel_retained) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
            &scheme,
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            slices.clone(),
            &mut test_rng(),
            &Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(parallel_vote, vote);
        assert_eq!(parallel_retained.slices(), retained.slices());

        assert_eq!(
            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &context,
                &deposits,
                &withdrawals,
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
                &context,
                &deposits,
                &withdrawals,
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
        malformed[0].state_bounds.end = malformed[0].state_bounds.end.saturating_add(1);
        assert_eq!(
            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &context,
                &deposits,
                &withdrawals,
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

    struct ExactPaymentBatch {
        items: usize,
    }

    impl BatchVerifier for ExactPaymentBatch {
        type PublicKey = AccountVerifyingKey;

        fn new(capacity: usize) -> Self {
            assert_eq!(capacity, 2);
            PAYMENT_BATCH_CREATIONS.fetch_add(1, Ordering::Relaxed);
            Self { items: 0 }
        }

        fn add(
            &mut self,
            _namespace: &[u8],
            _message: &[u8],
            _public_key: &Self::PublicKey,
            _signature: &<Self::PublicKey as Verifier>::Signature,
        ) -> bool {
            PAYMENT_BATCH_ADDS.fetch_add(1, Ordering::Relaxed);
            self.items += 1;
            true
        }

        fn verify<R: CryptoRng>(self, _rng: &mut R, _strategy: &impl Strategy) -> bool {
            PAYMENT_BATCH_VERIFICATIONS.fetch_add(1, Ordering::Relaxed);
            self.items == 2
        }
    }

    struct ThreeItemBatch {
        items: usize,
    }

    impl BatchVerifier for ThreeItemBatch {
        type PublicKey = AccountVerifyingKey;

        fn new(capacity: usize) -> Self {
            assert_eq!(capacity, 3);
            Self { items: 0 }
        }

        fn add(
            &mut self,
            _namespace: &[u8],
            _message: &[u8],
            _public_key: &Self::PublicKey,
            _signature: &<Self::PublicKey as Verifier>::Signature,
        ) -> bool {
            self.items += 1;
            true
        }

        fn verify<R: CryptoRng>(self, _rng: &mut R, _strategy: &impl Strategy) -> bool {
            self.items == 3
        }
    }

    #[test]
    fn seal_authenticates_exact_payment_envelopes() {
        let validators = validator_keys(4);
        let committee = committee(&validators);
        let operator = SigningKey::from_seed(100);
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
        let assignment = Assignment::new(committee.commitment::<Sha256>(), 0).unwrap();
        let context = CloseContext::new::<Sha256>(
            Sha256::hash(&[b"batch-deployment"]),
            7,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            49,
            50,
            CloseLimits::protocol_maximum(),
            assignment,
        )
        .unwrap();
        let send = SignedSend::sign_next(context.payment(), &payer, recipient.public_key(), 20, 0)
            .unwrap();
        let receipt =
            SignedReceipt::issue_next::<Sha256, _>(context.payment(), &send, 0, 0, 0, &operator)
                .unwrap();
        let payment = Payment::new::<Sha256>(context.payment(), send, receipt).unwrap();
        let invalid_send = SignedSend::sign_body_by_authority(
            payment.send().body().clone(),
            &SigningKey::from_seed(999),
        );
        let signature_variant =
            Payment::from_parts_unchecked(invalid_send, payment.receipt().clone());
        assert!(verify_payment_signatures::<_, _, ThreeItemBatch, _, _>(
            context.payment(),
            [&payment, &signature_variant],
            2,
            &mut test_rng(),
            &Sequential,
        ));
        assert!(
            !verify_payment_signatures::<_, _, PaymentBatchVerifier, _, _>(
                context.payment(),
                [&payment, &signature_variant],
                2,
                &mut test_rng(),
                &Sequential,
            )
        );
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment.clone())],
        )
        .unwrap();
        let mut rows = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    opening,
                    closing: AccountState {
                        balance: 80,
                        cumulative_debit: 20,
                        ..opening
                    },
                    outgoing: Some(payment),
                    credit_root: payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    opening,
                    closing: AccountState {
                        balance: 120,
                        cumulative_credit: 20,
                        receipt_count: 1,
                        ..opening
                    },
                    outgoing: None,
                    credit_root: recipient_shards.root::<Sha256>().unwrap(),
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
                    debit,
                    credit,
                    shards: u64::try_from(shards.heads().len()).unwrap(),
                    ..Prefix::default()
                })
                .unwrap();
            row.prefix = prefix;
        }
        let (rows, shards): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        let close =
            build_close::<Sha256, _, _>(&cache, &context, &deposits, &withdrawals, rows, shards)
                .unwrap();
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
        let all = assemble_slices::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        let validator =
            slice_holders::<Sha256, ShaDigest>(&committee, context.assignment(), 0).unwrap()[0];
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

        let mut mutated_outgoing = all.clone();
        let row = mutated_outgoing[0]
            .changes
            .rows
            .iter_mut()
            .find(|row| row.outgoing.is_some())
            .unwrap();
        let original = row.outgoing.as_ref().unwrap();
        let invalid_send = SignedSend::sign_body_by_authority(
            original.send().body().clone(),
            &SigningKey::from_seed(999),
        );
        row.outgoing = Some(Payment::from_parts_unchecked(
            invalid_send,
            original.receipt().clone(),
        ));
        assert_eq!(
            seal::<Sha256, _, _, ExactPaymentBatch, _>(
                &scheme,
                &context,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                mutated_outgoing,
                &mut test_rng(),
                &strategy,
            )
            .map(|_| ()),
            Err(AdmissionError::InvalidSlice)
        );

        let mut mutated_incoming = all.clone();
        let shards = mutated_incoming[0]
            .shard_sets
            .iter_mut()
            .find(|shards| !shards.heads().is_empty())
            .unwrap();
        let head = &shards.heads()[0];
        let invalid_send = SignedSend::sign_body_by_authority(
            head.payment.send().body().clone(),
            &SigningKey::from_seed(999),
        );
        let invalid_payment =
            Payment::from_parts_unchecked(invalid_send, head.payment.receipt().clone());
        *shards = ShardSet::new(
            shards.epoch(),
            shards.recipient().clone(),
            vec![ShardHead::new(head.shard, invalid_payment)],
        )
        .unwrap();
        assert_eq!(
            seal::<Sha256, _, _, ExactPaymentBatch, _>(
                &scheme,
                &context,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                mutated_incoming,
                &mut test_rng(),
                &strategy,
            )
            .map(|_| ()),
            Err(AdmissionError::InvalidSlice)
        );

        PAYMENT_BATCH_CREATIONS.store(0, Ordering::Relaxed);
        PAYMENT_BATCH_VERIFICATIONS.store(0, Ordering::Relaxed);
        PAYMENT_BATCH_ADDS.store(0, Ordering::Relaxed);
        let (_, retained) = seal::<Sha256, _, _, ExactPaymentBatch, _>(
            &scheme,
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            all,
            &mut test_rng(),
            &strategy,
        )
        .unwrap();
        assert_eq!(retained.slices().len(), 1);
        assert_eq!(PAYMENT_BATCH_CREATIONS.load(Ordering::Relaxed), 1);
        assert_eq!(PAYMENT_BATCH_VERIFICATIONS.load(Ordering::Relaxed), 1);
        assert_eq!(PAYMENT_BATCH_ADDS.load(Ordering::Relaxed), 2);
    }
}
