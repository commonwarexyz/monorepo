use super::{
    scheme,
    types::{Ack, AckSubject, Chunk},
};
use crate::types::{Epoch, Height, Participant};
use commonware_cryptography::{
    certificate::{Scheme, Verification},
    Digest, PublicKey,
};
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;
use std::collections::{HashMap, HashSet};

/// Key for grouping acks that share the same signing subject.
///
/// Acks with the same chunk and epoch produce identical `AckSubject` values
/// and can be batch-verified together.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct BatchKey<P: PublicKey, D: Digest> {
    chunk: Chunk<P, D>,
    epoch: Epoch,
}

/// Per-subject batch of pending acks.
struct Batch<P: PublicKey, S: Scheme, D: Digest> {
    /// Acks waiting for verification.
    pending: Vec<Ack<P, S, D>>,

    /// Count of acks that have already been verified for this subject.
    verified: usize,

    /// Signers already seen for this subject (pending or verified).
    /// Prevents duplicate acks from the same participant from
    /// accumulating unboundedly.
    seen: HashSet<Participant>,
}

impl<P: PublicKey, S: Scheme, D: Digest> Default for Batch<P, S, D> {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            verified: 0,
            seen: HashSet::new(),
        }
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Batch<P, S, D> {
    /// Returns true if this batch has pending acks ready for verification.
    ///
    /// A batch is ready when it has pending acks AND either:
    /// - The scheme is non-batchable (verify eagerly), OR
    /// - The sum of verified + pending could reach the quorum.
    fn is_ready(&self, quorum: usize) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        if self.verified >= quorum {
            return false;
        }
        if !S::is_batchable() {
            return true;
        }
        self.verified + self.pending.len() >= quorum
    }
}

/// Result of a batch verification round.
pub struct Verified<P: PublicKey, S: Scheme, D: Digest> {
    /// Acks whose signatures were successfully verified.
    pub acks: Vec<Ack<P, S, D>>,

    /// Participant indices whose signatures failed verification.
    pub invalid: Vec<Participant>,
}

/// Buffers acks and batch-verifies their signatures.
///
/// For batchable schemes (ed25519, BLS multisig, BLS threshold), acks are
/// buffered per subject until enough accumulate to potentially reach a quorum,
/// then verified in a single batch call. For non-batchable schemes (secp256r1),
/// verification happens eagerly as acks arrive.
pub struct Verifier<P: PublicKey, S: Scheme, D: Digest> {
    batches: HashMap<BatchKey<P, D>, Batch<P, S, D>>,
    quorum: usize,

    /// Keys of batches that are ready for verification.
    ready: HashSet<BatchKey<P, D>>,
}

impl<P: PublicKey, S: Scheme, D: Digest> Verifier<P, S, D> {
    /// Creates a new `Verifier` with the given quorum size.
    pub fn new(quorum: u32) -> Self {
        Self {
            batches: HashMap::new(),
            quorum: quorum as usize,
            ready: HashSet::new(),
        }
    }

    /// Adds an ack to the pending batch for its subject.
    ///
    /// The ack must have already passed validation (epoch bounds,
    /// sender/signer match, height range). Only signature verification is
    /// deferred.
    ///
    /// If `verified` is true, the ack counts toward the verified total
    /// without being buffered for batch verification.
    ///
    /// Duplicate acks from the same signer and acks for subjects that
    /// have already reached quorum are dropped.
    pub fn add(&mut self, ack: Ack<P, S, D>, verified: bool) {
        let signer = ack.attestation.signer;
        let key = BatchKey {
            chunk: ack.chunk.clone(),
            epoch: ack.epoch,
        };
        let batch = self.batches.entry(key.clone()).or_default();

        // Drop acks for subjects that have already reached quorum.
        if batch.verified >= self.quorum {
            return;
        }

        // Drop duplicate acks from the same signer.
        if !batch.seen.insert(signer) {
            return;
        }

        if verified {
            batch.verified += 1;
        } else {
            batch.pending.push(ack);
        }
        if batch.is_ready(self.quorum) {
            self.ready.insert(key);
        }
    }

    /// Returns true if any batch is ready for verification.
    pub fn ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Batch-verifies all ready batches and returns verified acks and invalid signers.
    ///
    /// Drains pending acks from all ready batches, calls
    /// `scheme.verify_attestations()` on each batch, and returns the results.
    pub fn verify<R>(
        &mut self,
        rng: &mut R,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> Verified<P, S, D>
    where
        R: CryptoRngCore,
        S: scheme::Scheme<P, D>,
    {
        let mut all_acks = Vec::new();
        let mut all_invalid = Vec::new();

        let ready_keys = std::mem::take(&mut self.ready);

        for key in ready_keys {
            let batch = self.batches.get_mut(&key).unwrap();
            let pending = std::mem::take(&mut batch.pending);

            // Separate attestations from acks for batch verification.
            let (acks, attestations): (Vec<_>, Vec<_>) = pending
                .into_iter()
                .map(|ack| {
                    let attestation = ack.attestation.clone();
                    (ack, attestation)
                })
                .unzip();

            let ctx = AckSubject {
                chunk: &key.chunk,
                epoch: key.epoch,
            };

            let Verification { verified, invalid } =
                scheme.verify_attestations::<_, D, _>(rng, ctx, attestations, strategy);

            // Count newly verified.
            batch.verified += verified.len();

            // Map verified attestations back to their acks.
            // Build a set of verified signer indices for quick lookup.
            let verified_signers: HashSet<Participant> =
                verified.iter().map(|a| a.signer).collect();

            for ack in acks {
                if verified_signers.contains(&ack.attestation.signer) {
                    all_acks.push(ack);
                }
            }

            all_invalid.extend(invalid);
        }

        // Remove batches that are fully resolved (verified >= quorum and no pending).
        self.batches
            .retain(|_, batch| !batch.pending.is_empty() || batch.verified < self.quorum);

        Verified {
            acks: all_acks,
            invalid: all_invalid,
        }
    }

    /// Update the quorum size.
    ///
    /// This is used when the validator set changes across epochs.
    pub const fn set_quorum(&mut self, quorum: u32) {
        self.quorum = quorum as usize;
    }

    /// Removes all batches whose epoch falls outside `[min_epoch, max_epoch]`.
    ///
    /// Called when the epoch changes to evict batches that are no longer
    /// within the accepted epoch bounds.
    pub fn prune_epochs(&mut self, min_epoch: Epoch, max_epoch: Epoch) {
        self.batches
            .retain(|key, _| key.epoch >= min_epoch && key.epoch <= max_epoch);
        self.ready
            .retain(|key| key.epoch >= min_epoch && key.epoch <= max_epoch);
    }

    /// Removes all batches for `sequencer` with height below `min_height`.
    ///
    /// Called when the tip advances for a sequencer, since acks for heights
    /// below the tip can no longer contribute to certificate formation.
    pub fn prune_heights(&mut self, sequencer: &P, min_height: Height) {
        self.batches
            .retain(|key, _| key.chunk.sequencer != *sequencer || key.chunk.height >= min_height);
        self.ready
            .retain(|key| key.chunk.sequencer != *sequencer || key.chunk.height >= min_height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordered_broadcast::{
        scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
        types::AckSubject,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1};
    use rand::rngs::StdRng;

    type Sha256Digest = <Sha256 as Hasher>::Digest;

    const NAMESPACE: &[u8] = b"1234";

    fn create_ack<S>(
        scheme: &S,
        chunk: Chunk<PublicKey, Sha256Digest>,
        epoch: Epoch,
    ) -> Ack<PublicKey, S, Sha256Digest>
    where
        S: Scheme<PublicKey, Sha256Digest>,
    {
        let context = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestation = scheme
            .sign::<Sha256Digest>(context)
            .expect("Failed to sign vote");
        Ack::new(chunk, epoch, attestation)
    }

    /// Test that batch verification works for batchable schemes.
    fn batch_verify_batchable<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Add acks one at a time. Not ready until quorum is reachable.
        for i in 0..quorum as usize {
            let ack = create_ack(&fixture.schemes[i], chunk.clone(), epoch);
            verifier.add(ack, false);

            if S::is_batchable() {
                // Should only be ready once we have enough for quorum.
                assert_eq!(verifier.ready(), i + 1 >= quorum as usize);
            } else {
                // Non-batchable: always ready when pending > 0.
                assert!(verifier.ready());
            }
        }

        let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);
        assert_eq!(result.acks.len(), quorum as usize);
        assert!(result.invalid.is_empty());
    }

    #[test]
    fn test_batch_verify() {
        batch_verify_batchable(ed25519::fixture);
        batch_verify_batchable(secp256r1::fixture);
        batch_verify_batchable(bls12381_multisig::fixture::<MinPk, _>);
        batch_verify_batchable(bls12381_multisig::fixture::<MinSig, _>);
        batch_verify_batchable(bls12381_threshold::fixture::<MinPk, _>);
        batch_verify_batchable(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that pre-verified acks count toward quorum readiness.
    fn pre_verified_acks<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Add one as pre-verified (e.g., our own ack).
        let ack = create_ack(&fixture.schemes[0], chunk.clone(), epoch);
        verifier.add(ack, true);

        // Add remaining acks as unverified.
        for i in 1..quorum as usize {
            let ack = create_ack(&fixture.schemes[i], chunk.clone(), epoch);
            verifier.add(ack, false);
        }

        assert!(verifier.ready());
        let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);
        // quorum - 1 because one was pre-verified and not buffered.
        assert_eq!(result.acks.len(), quorum as usize - 1);
        assert!(result.invalid.is_empty());
    }

    #[test]
    fn test_pre_verified_acks() {
        pre_verified_acks(ed25519::fixture);
        pre_verified_acks(secp256r1::fixture);
        pre_verified_acks(bls12381_multisig::fixture::<MinPk, _>);
        pre_verified_acks(bls12381_multisig::fixture::<MinSig, _>);
        pre_verified_acks(bls12381_threshold::fixture::<MinPk, _>);
        pre_verified_acks(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that batches for different subjects are independent.
    fn different_subjects<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk1 = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload1"),
        );
        let chunk2 = Chunk::new(
            fixture.participants[1].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload2"),
        );

        // Add 2 acks for chunk1 and quorum acks for chunk2.
        for i in 0..2 {
            let ack = create_ack(&fixture.schemes[i], chunk1.clone(), epoch);
            verifier.add(ack, false);
        }
        for i in 0..quorum as usize {
            let ack = create_ack(&fixture.schemes[i], chunk2.clone(), epoch);
            verifier.add(ack, false);
        }

        // For batchable schemes, only chunk2 should be ready.
        // For non-batchable, both are ready since they have pending acks.
        assert!(verifier.ready());

        let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);
        if S::is_batchable() {
            // Only chunk2's batch was ready.
            assert_eq!(result.acks.len(), quorum as usize);
            // chunk1 acks still pending.
            let key1 = BatchKey {
                chunk: chunk1,
                epoch,
            };
            assert_eq!(verifier.batches.get(&key1).unwrap().pending.len(), 2);
        } else {
            // Non-batchable: all pending acks were verified.
            assert_eq!(result.acks.len(), 2 + quorum as usize);
        }
        assert!(result.invalid.is_empty());
    }

    #[test]
    fn test_different_subjects() {
        different_subjects(ed25519::fixture);
        different_subjects(secp256r1::fixture);
        different_subjects(bls12381_multisig::fixture::<MinPk, _>);
        different_subjects(bls12381_multisig::fixture::<MinSig, _>);
        different_subjects(bls12381_threshold::fixture::<MinPk, _>);
        different_subjects(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that already-quorum batches stop accepting new verification work.
    fn already_quorum<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Pre-verify enough to reach quorum.
        for i in 0..quorum as usize {
            let ack = create_ack(&fixture.schemes[i], chunk.clone(), epoch);
            verifier.add(ack, true);
        }

        // Add one more unverified.
        let ack = create_ack(&fixture.schemes[quorum as usize], chunk, epoch);
        verifier.add(ack, false);

        // Should not be ready since quorum is already reached.
        assert!(!verifier.ready());
    }

    #[test]
    fn test_already_quorum() {
        already_quorum(ed25519::fixture);
        already_quorum(secp256r1::fixture);
        already_quorum(bls12381_multisig::fixture::<MinPk, _>);
        already_quorum(bls12381_multisig::fixture::<MinSig, _>);
        already_quorum(bls12381_threshold::fixture::<MinPk, _>);
        already_quorum(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that acks arriving while the batch entry still has verified >= quorum
    /// (before cleanup) are dropped by the quorum guard in `add()`.
    fn quorum_guard_drops_late_acks<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 5;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Pre-verify enough to reach quorum.
        for i in 0..quorum as usize {
            let ack = create_ack(&fixture.schemes[i], chunk.clone(), epoch);
            verifier.add(ack, true);
        }

        // Late acks should be dropped by the quorum guard.
        let late_ack = create_ack(&fixture.schemes[quorum as usize], chunk.clone(), epoch);
        verifier.add(late_ack, false);
        assert!(!verifier.ready());

        // The batch entry should have no pending acks.
        let key = BatchKey { chunk, epoch };
        let batch = verifier.batches.get(&key).unwrap();
        assert!(batch.pending.is_empty());
        assert_eq!(batch.verified, quorum as usize);
    }

    #[test]
    fn test_quorum_guard_drops_late_acks() {
        quorum_guard_drops_late_acks(ed25519::fixture);
        quorum_guard_drops_late_acks(secp256r1::fixture);
        quorum_guard_drops_late_acks(bls12381_multisig::fixture::<MinPk, _>);
        quorum_guard_drops_late_acks(bls12381_multisig::fixture::<MinSig, _>);
        quorum_guard_drops_late_acks(bls12381_threshold::fixture::<MinPk, _>);
        quorum_guard_drops_late_acks(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that prune_epochs removes batches outside the given epoch range.
    fn prune_epochs<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Add acks across epochs 5, 10, and 15.
        for epoch_val in [5, 10, 15] {
            let epoch = Epoch::new(epoch_val);
            let ack = create_ack(&fixture.schemes[0], chunk.clone(), epoch);
            verifier.add(ack, false);
        }
        assert_eq!(verifier.batches.len(), 3);

        // Prune to keep only epochs [8, 12].
        verifier.prune_epochs(Epoch::new(8), Epoch::new(12));
        assert_eq!(verifier.batches.len(), 1);

        // Only epoch 10 should remain.
        let key = BatchKey {
            chunk,
            epoch: Epoch::new(10),
        };
        assert!(verifier.batches.contains_key(&key));
    }

    #[test]
    fn test_prune_epochs() {
        prune_epochs(ed25519::fixture);
        prune_epochs(secp256r1::fixture);
        prune_epochs(bls12381_multisig::fixture::<MinPk, _>);
        prune_epochs(bls12381_multisig::fixture::<MinSig, _>);
        prune_epochs(bls12381_threshold::fixture::<MinPk, _>);
        prune_epochs(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that prune_heights removes batches for a sequencer below a given height.
    fn prune_heights<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);

        // Add acks at heights 1, 5, and 10 for sequencer 0.
        for h in [1, 5, 10] {
            let chunk = Chunk::new(
                fixture.participants[0].clone(),
                crate::types::Height::new(h),
                Sha256::hash(b"payload"),
            );
            let ack = create_ack(&fixture.schemes[0], chunk, epoch);
            verifier.add(ack, false);
        }

        // Add an ack at height 1 for sequencer 1 (should not be pruned).
        let other_chunk = Chunk::new(
            fixture.participants[1].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );
        let ack = create_ack(&fixture.schemes[0], other_chunk.clone(), epoch);
        verifier.add(ack, false);

        assert_eq!(verifier.batches.len(), 4);

        // Prune sequencer 0 below height 5 (removes height 1, keeps 5 and 10).
        verifier.prune_heights(&fixture.participants[0], crate::types::Height::new(5));
        assert_eq!(verifier.batches.len(), 3);

        // Height 1 for sequencer 0 should be gone.
        let pruned_key = BatchKey {
            chunk: Chunk::new(
                fixture.participants[0].clone(),
                crate::types::Height::new(1),
                Sha256::hash(b"payload"),
            ),
            epoch,
        };
        assert!(!verifier.batches.contains_key(&pruned_key));

        // Height 1 for sequencer 1 should still exist.
        let kept_key = BatchKey {
            chunk: other_chunk,
            epoch,
        };
        assert!(verifier.batches.contains_key(&kept_key));
    }

    #[test]
    fn test_prune_heights() {
        prune_heights(ed25519::fixture);
        prune_heights(secp256r1::fixture);
        prune_heights(bls12381_multisig::fixture::<MinPk, _>);
        prune_heights(bls12381_multisig::fixture::<MinSig, _>);
        prune_heights(bls12381_threshold::fixture::<MinPk, _>);
        prune_heights(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that invalid signatures are detected and reported.
    fn invalid_signatures<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Create quorum - 1 valid acks.
        for i in 0..quorum as usize - 1 {
            let ack = create_ack(&fixture.schemes[i], chunk.clone(), epoch);
            verifier.add(ack, false);
        }

        // Create one invalid ack: sign over a different chunk, then swap
        // in the real chunk so the signature mismatches.
        let wrong_chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"wrong_payload"),
        );
        let bad_ack = create_ack(&fixture.schemes[quorum as usize - 1], wrong_chunk, epoch);
        let bad_ack = Ack::new(chunk, epoch, bad_ack.attestation);
        verifier.add(bad_ack, false);

        assert!(verifier.ready());
        let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);

        // Valid acks should be verified.
        assert_eq!(result.acks.len(), quorum as usize - 1);

        // The forged ack's signer should appear in invalid.
        assert_eq!(result.invalid.len(), 1);
    }

    #[test]
    fn test_invalid_signatures() {
        invalid_signatures(ed25519::fixture);
        invalid_signatures(secp256r1::fixture);
        invalid_signatures(bls12381_multisig::fixture::<MinPk, _>);
        invalid_signatures(bls12381_multisig::fixture::<MinSig, _>);
        invalid_signatures(bls12381_threshold::fixture::<MinPk, _>);
        invalid_signatures(bls12381_threshold::fixture::<MinSig, _>);
    }

    /// Test that the ready flag is set correctly across add/verify cycles,
    /// including when pre-verified acks tip a batch to readiness.
    fn ready_flag_transitions<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let num_validators = 4;
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, num_validators);
        let quorum = N3f1::quorum(num_validators);

        let mut verifier = Verifier::<PublicKey, S, Sha256Digest>::new(quorum);
        let epoch = Epoch::new(1);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(1),
            Sha256::hash(b"payload"),
        );

        // Initially not ready.
        assert!(!verifier.ready());

        // For non-batchable schemes, verify that a single pending ack
        // is immediately ready, then use a fresh subject for the rest.
        if !S::is_batchable() {
            let ack = create_ack(&fixture.schemes[0], chunk, epoch);
            verifier.add(ack, false);
            assert!(verifier.ready());
            let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);
            assert_eq!(result.acks.len(), 1);
            assert!(!verifier.ready());
        }

        // Use a fresh subject so no signers are already in `seen`.
        let chunk2 = Chunk::new(
            fixture.participants[0].clone(),
            crate::types::Height::new(2),
            Sha256::hash(b"payload2"),
        );

        // Add one pending ack. For batchable schemes, not ready yet.
        let ack = create_ack(&fixture.schemes[0], chunk2.clone(), epoch);
        verifier.add(ack, false);
        if S::is_batchable() {
            assert!(!verifier.ready());
        }

        // Pre-verified acks tip the batch to readiness.
        for i in 1..quorum as usize {
            let ack = create_ack(&fixture.schemes[i], chunk2.clone(), epoch);
            verifier.add(ack, true);
        }
        assert!(verifier.ready());

        // After verify, ready is cleared.
        let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);
        assert!(!result.acks.is_empty());
        assert!(!verifier.ready());

        // Verify on empty is harmless (should not panic or set ready).
        let result = verifier.verify(&mut rng, &fixture.schemes[0], &Sequential);
        assert!(result.acks.is_empty());
        assert!(!verifier.ready());
    }

    #[test]
    fn test_ready_flag_transitions() {
        ready_flag_transitions(ed25519::fixture);
        ready_flag_transitions(secp256r1::fixture);
        ready_flag_transitions(bls12381_multisig::fixture::<MinPk, _>);
        ready_flag_transitions(bls12381_multisig::fixture::<MinSig, _>);
        ready_flag_transitions(bls12381_threshold::fixture::<MinPk, _>);
        ready_flag_transitions(bls12381_threshold::fixture::<MinSig, _>);
    }
}
