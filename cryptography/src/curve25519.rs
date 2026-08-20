//! Native Curve25519 signing types implementing this crate's signing traits.

use commonware_cryptography_curve25519::signing::BatchVerifier as NativeBatchVerifier;
pub use commonware_cryptography_curve25519::signing::{
    Signature, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

impl crate::PrivateKey for SigningKey {}

impl crate::Signer for SigningKey {
    type Signature = Signature;
    type PublicKey = VerifyingKey;

    fn public_key(&self) -> Self::PublicKey {
        self.strict_verifying_key()
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        Self::sign(self, namespace, msg)
    }
}

impl crate::PublicKey for VerifyingKey {}

impl crate::Verifier for VerifyingKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        Self::verify(self, namespace, msg, sig)
    }
}

impl crate::Signature for Signature {}

/// Batch verifier for strict Curve25519 identity keys.
pub struct BatchVerifier {
    inner: NativeBatchVerifier,
}

impl crate::BatchVerifier for BatchVerifier {
    type PublicKey = VerifyingKey;

    fn new(capacity: usize) -> Self {
        Self {
            inner: NativeBatchVerifier::new(capacity),
        }
    }

    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &<Self::PublicKey as crate::Verifier>::Signature,
    ) -> bool {
        self.inner
            .add(namespace, message, public_key.as_zip215(), signature);
        true
    }

    fn verify<R: CryptoRng>(self, rng: &mut R, strategy: &impl Strategy) -> bool {
        self.inner.verify(rng, strategy)
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchVerifier, Signature, SigningKey, VerifyingKey};
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_FACADE_TRAITS";

    fn assert_trait_compatibility() {
        fn assert_private_key<T>()
        where
            T: crate::PrivateKey + crate::Signer<Signature = Signature, PublicKey = VerifyingKey>,
        {
        }
        fn assert_public_key<T>()
        where
            T: crate::PublicKey + crate::Verifier<Signature = Signature>,
        {
        }
        fn assert_signature<T: crate::Signature>() {}
        fn assert_batch<T: crate::BatchVerifier<PublicKey = VerifyingKey>>() {}

        assert_private_key::<SigningKey>();
        assert_public_key::<VerifyingKey>();
        assert_signature::<Signature>();
        assert_batch::<BatchVerifier>();
    }

    #[test]
    fn traits_codec_and_batch_verification() {
        assert_trait_compatibility();

        let signing_key = <SigningKey as crate::Signer>::from_seed(7);
        let decoded = SigningKey::decode(signing_key.encode()).unwrap();
        let public_key = crate::Signer::public_key(&decoded);
        assert_eq!(
            VerifyingKey::decode(public_key.encode()).unwrap(),
            public_key
        );

        let message = Bytes::from_static(b"message");
        let signature = crate::Signer::sign(&signing_key, NAMESPACE, &message);
        assert_eq!(Signature::decode(signature.encode()).unwrap(), signature);
        assert!(crate::Verifier::verify(
            &public_key,
            NAMESPACE,
            &message,
            &signature,
        ));

        let mut batch = <BatchVerifier as crate::BatchVerifier>::new(1);
        assert!(crate::BatchVerifier::add_owned(
            &mut batch,
            NAMESPACE,
            message,
            &public_key,
            &signature,
        ));
        assert!(crate::BatchVerifier::verify(
            batch,
            &mut test_rng(),
            &Sequential,
        ));
    }

    #[test]
    fn malformed_signatures_and_identity_keys_are_rejected() {
        let signing_key = <SigningKey as crate::Signer>::from_seed(9);
        let public_key = crate::Signer::public_key(&signing_key);
        let message = b"message";
        let signature = crate::Signer::sign(&signing_key, NAMESPACE, message);
        let mut malformed = signature.encode().to_vec();
        malformed[32..].fill(0xff);
        let malformed = Signature::decode(malformed.as_slice()).unwrap();

        let mut batch = <BatchVerifier as crate::BatchVerifier>::new(1);
        assert!(crate::BatchVerifier::add(
            &mut batch,
            NAMESPACE,
            message,
            &public_key,
            &malformed,
        ));
        assert!(!crate::BatchVerifier::verify(
            batch,
            &mut test_rng(),
            &Sequential,
        ));

        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(VerifyingKey::decode(identity.as_slice()).is_err());
        assert!(VerifyingKey::decode([0xff; 32].as_slice()).is_err());
    }
}
