use super::types::Node;
use crate::scheme::Scheme;
use commonware_cryptography::{Digest, PublicKey};
use std::collections::{hash_map::Entry, HashMap};

/// Manages the highest-height chunk for each sequencer.
#[derive(Default, Debug)]
pub struct TipManager<C: PublicKey, S: Scheme, D: Digest> {
    // The highest-height chunk for each sequencer.
    // The chunk must have the certificate of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this validator.
    tips: HashMap<C, Node<C, S, D>>,
}

impl<C: PublicKey, S: Scheme, D: Digest> TipManager<C, S, D> {
    /// Creates a new `TipManager`.
    pub fn new() -> Self {
        Self {
            tips: HashMap::new(),
        }
    }

    /// Inserts a new tip. Returns true if the tip is new.
    /// Panics if the new tip is lower-height than the existing tip.
    pub fn put(&mut self, node: &Node<C, S, D>) -> bool {
        match self.tips.entry(node.chunk.sequencer.clone()) {
            Entry::Vacant(e) => {
                e.insert(node.clone());
                true
            }
            Entry::Occupied(mut e) => {
                let old = e.get();
                if old.chunk.height > node.chunk.height {
                    panic!("Attempted to insert a lower-height tip");
                }
                if old.chunk.height == node.chunk.height {
                    assert!(
                        old.chunk.payload == node.chunk.payload,
                        "New tip has the same height but a different payload"
                    );
                    return false;
                }
                e.insert(node.clone());
                true
            }
        }
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &C) -> Option<Node<C, S, D>> {
        self.tips.get(sequencer).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordered_broadcast::{
        mocks::{self, fixtures::Fixture},
        scheme::{
            bls12381_multisig::Scheme as Bls12381MultisigScheme,
            bls12381_threshold::Scheme as Bls12381ThresholdScheme,
            ed25519::Scheme as Ed25519Scheme, OrderedBroadcastScheme,
        },
        types::Chunk,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig, Variant},
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
        Hasher as _, PrivateKeyExt as _, Signer as _,
    };
    use rand::{rngs::StdRng, SeedableRng};

    // Helper to setup Ed25519 test fixture
    fn setup_ed25519_fixture() -> Fixture<Ed25519Scheme> {
        let mut rng = StdRng::seed_from_u64(0);
        mocks::fixtures::ed25519(&mut rng, 4)
    }

    // Helper to setup BLS multisig test fixture
    fn setup_bls_multisig_fixture<V: Variant>() -> Fixture<Bls12381MultisigScheme<PublicKey, V>> {
        let mut rng = StdRng::seed_from_u64(0);
        mocks::fixtures::bls12381_multisig(&mut rng, 4)
    }

    // Helper to setup BLS threshold test fixture
    fn setup_bls_threshold_fixture<V: Variant>() -> Fixture<Bls12381ThresholdScheme<PublicKey, V>> {
        let mut rng = StdRng::seed_from_u64(0);
        mocks::fixtures::bls12381_threshold(&mut rng, 4)
    }

    /// Creates a node for testing with a given scheme.
    fn create_node<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(
        fixture: &Fixture<S>,
        sequencer_idx: usize,
        height: u64,
        payload: &str,
    ) -> Node<PublicKey, S, Sha256Digest> {
        use crate::ordered_broadcast::types::chunk_namespace;
        use commonware_codec::Encode;

        let sequencer = fixture.participants[sequencer_idx].clone();
        let digest = Sha256::hash(payload.as_bytes());
        let chunk = Chunk::new(sequencer, height, digest);

        // Sign the chunk using a deterministic ed25519 key (since Node.signature is P::Signature,
        // which is ed25519::Signature for our PublicKey type)
        let mut rng = StdRng::seed_from_u64(sequencer_idx as u64);
        let private_key = commonware_cryptography::ed25519::PrivateKey::from_rng(&mut rng);
        let namespace = chunk_namespace(b"test");
        let message = chunk.encode();
        let signature = private_key.sign(namespace.as_ref(), &message);

        Node::new(chunk, signature, None)
    }

    /// Generates a deterministic public key for testing using the provided seed.
    fn deterministic_public_key(seed: u64) -> PublicKey {
        let mut rng = StdRng::seed_from_u64(seed);
        commonware_cryptography::ed25519::PrivateKey::from_rng(&mut rng).public_key()
    }

    // Generic test implementations

    fn put_new_tip<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(fixture: &Fixture<S>) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node = create_node(fixture, 0, 1, "payload");
        let key = node.chunk.sequencer.clone();
        assert!(manager.put(&node));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, node.chunk);
        assert_eq!(got.signature, node.signature);
        assert_eq!(got.parent, node.parent);
    }

    fn put_same_height_same_payload<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(
        fixture: &Fixture<S>,
    ) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node = create_node(fixture, 0, 1, "payload");
        let key = node.chunk.sequencer.clone();
        assert!(manager.put(&node));
        assert!(!manager.put(&node));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, node.chunk);
        assert_eq!(got.signature, node.signature);
        assert_eq!(got.parent, node.parent);
    }

    fn put_higher_tip<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(fixture: &Fixture<S>) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(fixture, 0, 1, "payload1");
        let key = node1.chunk.sequencer.clone();
        assert!(manager.put(&node1));
        let node2 = create_node(fixture, 0, 2, "payload2");
        assert!(manager.put(&node2));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, node2.chunk);
        assert_eq!(got.signature, node2.signature);
        assert_eq!(got.parent, node2.parent);
    }

    fn put_lower_tip_panics<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(
        fixture: &Fixture<S>,
    ) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(fixture, 0, 2, "payload");
        assert!(manager.put(&node1));
        let node2 = create_node(fixture, 0, 1, "payload");
        manager.put(&node2); // Should panic
    }

    fn put_same_height_different_payload_panics<
        S: OrderedBroadcastScheme<PublicKey, Sha256Digest>,
    >(
        fixture: &Fixture<S>,
    ) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(fixture, 0, 1, "payload1");
        assert!(manager.put(&node1));
        let node2 = create_node(fixture, 0, 1, "payload2");
        manager.put(&node2); // Should panic
    }

    fn get_nonexistent<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>() {
        let manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let key = deterministic_public_key(6);
        assert!(manager.get(&key).is_none());
    }

    fn multiple_sequencers<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(
        fixture: &Fixture<S>,
    ) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();
        let node1 = create_node(fixture, 0, 1, "payload1");
        let node2 = create_node(fixture, 1, 2, "payload2");
        let key1 = node1.chunk.sequencer.clone();
        let key2 = node2.chunk.sequencer.clone();
        manager.put(&node1);
        manager.put(&node2);

        let got1 = manager.get(&key1).unwrap();
        let got2 = manager.get(&key2).unwrap();
        assert_eq!(got1.chunk, node1.chunk);
        assert_eq!(got2.chunk, node2.chunk);
    }

    fn put_multiple_updates<S: OrderedBroadcastScheme<PublicKey, Sha256Digest>>(
        fixture: &Fixture<S>,
    ) {
        let mut manager = TipManager::<PublicKey, S, Sha256Digest>::new();

        // Insert tip with height 1.
        let node1 = create_node(fixture, 0, 1, "payload1");
        let key = node1.chunk.sequencer.clone();
        manager.put(&node1);
        let got1 = manager.get(&key).unwrap();
        assert_eq!(got1.chunk.height, 1);
        assert_eq!(got1.chunk.payload, node1.chunk.payload);

        // Insert tip with height 2.
        let node2 = create_node(fixture, 0, 2, "payload2");
        manager.put(&node2);
        let got2 = manager.get(&key).unwrap();
        assert_eq!(got2.chunk.height, 2);
        assert_eq!(got2.chunk.payload, node2.chunk.payload);

        // Insert tip with height 3.
        let node3 = create_node(fixture, 0, 3, "payload3");
        manager.put(&node3);
        let got3 = manager.get(&key).unwrap();
        assert_eq!(got3.chunk.height, 3);
        assert_eq!(got3.chunk.payload, node3.chunk.payload);

        // Re-inserting the same tip should return false.
        assert!(!manager.put(&node3));

        // Insert tip with height 4.
        let node4 = create_node(fixture, 0, 4, "payload4");
        manager.put(&node4);
        let got4 = manager.get(&key).unwrap();
        assert_eq!(got4.chunk.height, 4);
        assert_eq!(got4.chunk.payload, node4.chunk.payload);
    }

    // Test entry points for Ed25519

    #[test]
    fn test_put_new_tip_ed25519() {
        put_new_tip(&setup_ed25519_fixture());
    }

    #[test]
    fn test_put_same_height_same_payload_ed25519() {
        put_same_height_same_payload(&setup_ed25519_fixture());
    }

    #[test]
    fn test_put_higher_tip_ed25519() {
        put_higher_tip(&setup_ed25519_fixture());
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics_ed25519() {
        put_lower_tip_panics(&setup_ed25519_fixture());
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics_ed25519() {
        put_same_height_different_payload_panics(&setup_ed25519_fixture());
    }

    #[test]
    fn test_get_nonexistent_ed25519() {
        get_nonexistent::<Ed25519Scheme>();
    }

    #[test]
    fn test_multiple_sequencers_ed25519() {
        multiple_sequencers(&setup_ed25519_fixture());
    }

    #[test]
    fn test_put_multiple_updates_ed25519() {
        put_multiple_updates(&setup_ed25519_fixture());
    }

    // Test entry points for BLS12-381 Multisig MinPk

    #[test]
    fn test_put_new_tip_bls_multisig_min_pk() {
        put_new_tip(&setup_bls_multisig_fixture::<MinPk>());
    }

    #[test]
    fn test_put_same_height_same_payload_bls_multisig_min_pk() {
        put_same_height_same_payload(&setup_bls_multisig_fixture::<MinPk>());
    }

    #[test]
    fn test_put_higher_tip_bls_multisig_min_pk() {
        put_higher_tip(&setup_bls_multisig_fixture::<MinPk>());
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics_bls_multisig_min_pk() {
        put_lower_tip_panics(&setup_bls_multisig_fixture::<MinPk>());
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics_bls_multisig_min_pk() {
        put_same_height_different_payload_panics(&setup_bls_multisig_fixture::<MinPk>());
    }

    #[test]
    fn test_get_nonexistent_bls_multisig_min_pk() {
        get_nonexistent::<Bls12381MultisigScheme<PublicKey, MinPk>>();
    }

    #[test]
    fn test_multiple_sequencers_bls_multisig_min_pk() {
        multiple_sequencers(&setup_bls_multisig_fixture::<MinPk>());
    }

    #[test]
    fn test_put_multiple_updates_bls_multisig_min_pk() {
        put_multiple_updates(&setup_bls_multisig_fixture::<MinPk>());
    }

    // Test entry points for BLS12-381 Multisig MinSig

    #[test]
    fn test_put_new_tip_bls_multisig_min_sig() {
        put_new_tip(&setup_bls_multisig_fixture::<MinSig>());
    }

    #[test]
    fn test_put_same_height_same_payload_bls_multisig_min_sig() {
        put_same_height_same_payload(&setup_bls_multisig_fixture::<MinSig>());
    }

    #[test]
    fn test_put_higher_tip_bls_multisig_min_sig() {
        put_higher_tip(&setup_bls_multisig_fixture::<MinSig>());
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics_bls_multisig_min_sig() {
        put_lower_tip_panics(&setup_bls_multisig_fixture::<MinSig>());
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics_bls_multisig_min_sig() {
        put_same_height_different_payload_panics(&setup_bls_multisig_fixture::<MinSig>());
    }

    #[test]
    fn test_get_nonexistent_bls_multisig_min_sig() {
        get_nonexistent::<Bls12381MultisigScheme<PublicKey, MinSig>>();
    }

    #[test]
    fn test_multiple_sequencers_bls_multisig_min_sig() {
        multiple_sequencers(&setup_bls_multisig_fixture::<MinSig>());
    }

    #[test]
    fn test_put_multiple_updates_bls_multisig_min_sig() {
        put_multiple_updates(&setup_bls_multisig_fixture::<MinSig>());
    }

    // Test entry points for BLS12-381 Threshold MinPk

    #[test]
    fn test_put_new_tip_bls_threshold_min_pk() {
        put_new_tip(&setup_bls_threshold_fixture::<MinPk>());
    }

    #[test]
    fn test_put_same_height_same_payload_bls_threshold_min_pk() {
        put_same_height_same_payload(&setup_bls_threshold_fixture::<MinPk>());
    }

    #[test]
    fn test_put_higher_tip_bls_threshold_min_pk() {
        put_higher_tip(&setup_bls_threshold_fixture::<MinPk>());
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics_bls_threshold_min_pk() {
        put_lower_tip_panics(&setup_bls_threshold_fixture::<MinPk>());
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics_bls_threshold_min_pk() {
        put_same_height_different_payload_panics(&setup_bls_threshold_fixture::<MinPk>());
    }

    #[test]
    fn test_get_nonexistent_bls_threshold_min_pk() {
        get_nonexistent::<Bls12381ThresholdScheme<PublicKey, MinPk>>();
    }

    #[test]
    fn test_multiple_sequencers_bls_threshold_min_pk() {
        multiple_sequencers(&setup_bls_threshold_fixture::<MinPk>());
    }

    #[test]
    fn test_put_multiple_updates_bls_threshold_min_pk() {
        put_multiple_updates(&setup_bls_threshold_fixture::<MinPk>());
    }

    // Test entry points for BLS12-381 Threshold MinSig

    #[test]
    fn test_put_new_tip_bls_threshold_min_sig() {
        put_new_tip(&setup_bls_threshold_fixture::<MinSig>());
    }

    #[test]
    fn test_put_same_height_same_payload_bls_threshold_min_sig() {
        put_same_height_same_payload(&setup_bls_threshold_fixture::<MinSig>());
    }

    #[test]
    fn test_put_higher_tip_bls_threshold_min_sig() {
        put_higher_tip(&setup_bls_threshold_fixture::<MinSig>());
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics_bls_threshold_min_sig() {
        put_lower_tip_panics(&setup_bls_threshold_fixture::<MinSig>());
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics_bls_threshold_min_sig() {
        put_same_height_different_payload_panics(&setup_bls_threshold_fixture::<MinSig>());
    }

    #[test]
    fn test_get_nonexistent_bls_threshold_min_sig() {
        get_nonexistent::<Bls12381ThresholdScheme<PublicKey, MinSig>>();
    }

    #[test]
    fn test_multiple_sequencers_bls_threshold_min_sig() {
        multiple_sequencers(&setup_bls_threshold_fixture::<MinSig>());
    }

    #[test]
    fn test_put_multiple_updates_bls_threshold_min_sig() {
        put_multiple_updates(&setup_bls_threshold_fixture::<MinSig>());
    }
}
