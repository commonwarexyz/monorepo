//! Aggregation operations for BLS12-381 signatures.
//!
//! This module provides functions for aggregating public keys and signatures,
//! as well as verifying aggregate signatures.
//!
//! # Security Considerations
//!
//! Aggregate operations ensure the aggregate is valid, but not that the individual elements are valid.
//! Use [`batch`](super::batch) when you need to ensure each individual signature is valid.

use super::{
    super::{variant::Variant, Error},
    hash_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;

/// An aggregated public key from multiple individual public keys.
///
/// This type is returned by [`combine_public_keys`] and ensures that
/// aggregated public keys are not confused with individual public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey<V: Variant>(V::Public);

impl<V: Variant> PublicKey<V> {
    /// Creates a zero aggregate public key.
    pub fn zero() -> Self {
        Self(V::Public::zero())
    }

    /// Returns the inner public key value.
    pub(crate) const fn inner(&self) -> &V::Public {
        &self.0
    }

    /// Adds another public key to this one.
    pub(crate) fn add(&mut self, other: &V::Public) {
        self.0 += other;
    }
}

impl<V: Variant> Write for PublicKey<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<V: Variant> Read for PublicKey<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(V::Public::read(reader)?))
    }
}

impl<V: Variant> FixedSize for PublicKey<V> {
    const SIZE: usize = V::Public::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for PublicKey<V>
where
    V::Public: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(V::Public::arbitrary(u)?))
    }
}

/// An aggregated signature from multiple individual signatures.
///
/// This type is returned by [`combine_signatures`] and ensures that
/// aggregated signatures are not confused with individual signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature<V: Variant>(V::Signature);

impl<V: Variant> Signature<V> {
    /// Creates a zero aggregate signature.
    pub fn zero() -> Self {
        Self(V::Signature::zero())
    }

    /// Returns the inner signature value.
    pub(crate) const fn inner(&self) -> &V::Signature {
        &self.0
    }

    /// Adds another signature to this one.
    pub(crate) fn add(&mut self, other: &V::Signature) {
        self.0 += other;
    }
}

impl<V: Variant> Write for Signature<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<V: Variant> Read for Signature<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(V::Signature::read(reader)?))
    }
}

impl<V: Variant> FixedSize for Signature<V> {
    const SIZE: usize = V::Signature::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Signature<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(V::Signature::arbitrary(u)?))
    }
}

/// A combined message hash from multiple individual messages.
///
/// This type is returned by [`combine_messages`] and ensures that
/// combined message hashes are not confused with individual message hashes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message<V: Variant>(V::Signature);

impl<V: Variant> Message<V> {
    /// Creates a zero combined message.
    pub fn zero() -> Self {
        Self(V::Signature::zero())
    }

    /// Returns the inner message hash value.
    pub(crate) const fn inner(&self) -> &V::Signature {
        &self.0
    }

    /// Adds another hashed message to this one.
    pub(crate) fn add(&mut self, other: &V::Signature) {
        self.0 += other;
    }

    /// Combines another [Message] into this one.
    pub(crate) fn combine(&mut self, other: &Self) {
        self.0 += &other.0;
    }
}

impl<V: Variant> Write for Message<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<V: Variant> Read for Message<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(V::Signature::read(reader)?))
    }
}

impl<V: Variant> FixedSize for Message<V> {
    const SIZE: usize = V::Signature::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Message<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(V::Signature::arbitrary(u)?))
    }
}

/// Combines multiple public keys into an aggregate public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on all `public_keys`,
/// that each `public_key` is unique, and that the caller has a Proof-of-Possession (PoP)
/// for each `public_key`. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn combine_public_keys<'a, V, I>(public_keys: I) -> PublicKey<V>
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    let mut p = PublicKey::zero();
    for pk in public_keys {
        p.add(pk);
    }
    p
}

/// Combines multiple signatures into an aggregate signature.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature` and
/// that each `signature` is unique. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn combine_signatures<'a, V, I>(signatures: I) -> Signature<V>
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Signature>,
    V::Signature: 'a,
{
    let mut s = Signature::zero();
    for sig in signatures {
        s.add(sig);
    }
    s
}

/// Combines multiple messages into a single message hash.
///
/// # Warning
///
/// It is not safe to provide duplicate messages.
pub fn combine_messages<'a, V, I>(messages: I, strategy: &impl Strategy) -> Message<V>
where
    V: Variant,
    I: IntoIterator<Item = &'a (&'a [u8], &'a [u8])> + Send,
    I::IntoIter: Send,
{
    strategy.fold(
        messages,
        Message::zero,
        |mut sum, (namespace, msg)| {
            let hm = hash_with_namespace::<V>(V::MESSAGE, namespace, msg);
            sum.add(&hm);
            sum
        },
        |mut a, b| {
            a.combine(&b);
            a
        },
    )
}

/// Verifies the aggregate signature over a single message from multiple public keys.
///
/// # Precomputed Aggregate Public Key
///
/// Instead of requiring all public keys that participated in the aggregate signature (and generating
/// the aggregate public key on-demand), this function accepts a precomputed aggregate public key to allow
/// the caller to cache previous constructions and/or perform parallel combination.
///
/// # Warning
///
/// This function assumes the caller has performed a group check and collected a proof-of-possession
/// for all provided `public`. This function assumes a group check was already performed on the
/// `signature`. It is not safe to provide duplicate public keys.
pub fn verify_same_message<V: Variant>(
    public: &PublicKey<V>,
    namespace: &[u8],
    message: &[u8],
    signature: &Signature<V>,
) -> Result<(), Error> {
    let hm = hash_with_namespace::<V>(V::MESSAGE, namespace, message);

    // Verify the signature
    V::verify(public.inner(), &hm, signature.inner())
}

/// Verifies the aggregate signature over multiple messages from a single public key.
///
/// # Precomputed Combined Message
///
/// Instead of requiring all messages that participated in the aggregate signature (and generating
/// the combined message on-demand), this function accepts a precomputed combined message to allow
/// the caller to cache previous constructions and/or perform parallel combination.
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and `signature`.
pub fn verify_same_signer<V: Variant>(
    public: &V::Public,
    message: &Message<V>,
    signature: &Signature<V>,
) -> Result<(), Error> {
    V::verify(public, message.inner(), signature.inner())
}

#[cfg(test)]
mod tests {
    use super::{
        super::{aggregate, keypair, sign_message},
        *,
    };
    use crate::bls12381::primitives::{
        group::{G1_MESSAGE, G2_MESSAGE},
        variant::{MinPk, MinSig},
        Error,
    };
    use blst::BLST_ERROR;
    use commonware_codec::Encode;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{test_rng, union_unique, NZUsize};

    fn blst_aggregate_verify_same_message<'a, V, I>(
        public: I,
        message: &[u8],
        signature: &Signature<V>,
    ) -> Result<(), BLST_ERROR>
    where
        V: Variant,
        I: IntoIterator<Item = &'a V::Public>,
        V::Public: 'a,
    {
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = public
                    .into_iter()
                    .map(|pk| blst::min_sig::PublicKey::from_bytes(&pk.encode()).unwrap())
                    .collect::<Vec<_>>();
                let public = public.iter().collect::<Vec<_>>();
                let signature =
                    blst::min_sig::Signature::from_bytes(&signature.inner().encode()).unwrap();
                match signature.fast_aggregate_verify(true, message, V::MESSAGE, &public) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = public
                    .into_iter()
                    .map(|pk| blst::min_pk::PublicKey::from_bytes(&pk.encode()).unwrap())
                    .collect::<Vec<_>>();
                let public = public.iter().collect::<Vec<_>>();
                let signature =
                    blst::min_pk::Signature::from_bytes(&signature.inner().encode()).unwrap();
                match signature.fast_aggregate_verify(true, message, V::MESSAGE, &public) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn aggregate_verify_same_message_correct<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, public3) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, namespace, message);
        let sig2 = sign_message::<V>(&private2, namespace, message);
        let sig3 = sign_message::<V>(&private3, namespace, message);
        let pks = vec![public1, public2, public3];
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_pk = aggregate::combine_public_keys::<V, _>(&pks);
        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);

        verify_same_message::<V>(&aggregate_pk, namespace, message, &aggregate_sig)
            .expect("Aggregated signature should be valid");

        let payload = union_unique(namespace, message);
        blst_aggregate_verify_same_message::<V, _>(&pks, &payload, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_verify_same_message() {
        aggregate_verify_same_message_correct::<MinPk>();
        aggregate_verify_same_message_correct::<MinSig>();
    }

    fn aggregate_verify_same_message_wrong_public_keys<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, _) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, namespace, message);
        let sig2 = sign_message::<V>(&private2, namespace, message);
        let sig3 = sign_message::<V>(&private3, namespace, message);
        let signatures = vec![sig1, sig2, sig3];

        let (_, public4) = keypair::<_, V>(&mut rng);
        let wrong_pks = vec![public1, public2, public4];
        let wrong_aggregate_pk = aggregate::combine_public_keys::<V, _>(&wrong_pks);
        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);
        let result =
            verify_same_message::<V>(&wrong_aggregate_pk, namespace, message, &aggregate_sig);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_same_message_wrong_public_keys() {
        aggregate_verify_same_message_wrong_public_keys::<MinPk>();
        aggregate_verify_same_message_wrong_public_keys::<MinSig>();
    }

    fn aggregate_verify_same_message_wrong_public_key_count<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, _) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, namespace, message);
        let sig2 = sign_message::<V>(&private2, namespace, message);
        let sig3 = sign_message::<V>(&private3, namespace, message);
        let signatures = vec![sig1, sig2, sig3];

        let wrong_pks = vec![public1, public2];
        let wrong_aggregate_pk = aggregate::combine_public_keys::<V, _>(&wrong_pks);
        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);
        let result =
            verify_same_message::<V>(&wrong_aggregate_pk, namespace, message, &aggregate_sig);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_same_message_wrong_public_key_count() {
        aggregate_verify_same_message_wrong_public_key_count::<MinPk>();
        aggregate_verify_same_message_wrong_public_key_count::<MinSig>();
    }

    fn blst_aggregate_verify_same_signer<'a, V, I>(
        public: &V::Public,
        msgs: I,
        signature: &Signature<V>,
    ) -> Result<(), BLST_ERROR>
    where
        V: Variant,
        I: IntoIterator<Item = &'a [u8]>,
    {
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
                let msgs = msgs.into_iter().collect::<Vec<_>>();
                let pks = vec![&public; msgs.len()];
                let signature =
                    blst::min_sig::Signature::from_bytes(&signature.inner().encode()).unwrap();
                match signature.aggregate_verify(true, &msgs, V::MESSAGE, &pks, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = blst::min_pk::PublicKey::from_bytes(&public.encode()).unwrap();
                let msgs = msgs.into_iter().collect::<Vec<_>>();
                let pks = vec![&public; msgs.len()];
                let signature =
                    blst::min_pk::Signature::from_bytes(&signature.inner().encode()).unwrap();
                match signature.aggregate_verify(true, &msgs, V::MESSAGE, &pks, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn aggregate_verify_same_signer_correct<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let namespace = b"test";
        let messages: Vec<(&[u8], &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let signatures: Vec<_> = messages
            .iter()
            .map(|(namespace, msg)| sign_message::<V>(&private, namespace, msg))
            .collect();

        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);

        let combined_msg = aggregate::combine_messages::<V, _>(&messages, &Sequential);
        aggregate::verify_same_signer::<V>(&public, &combined_msg, &aggregate_sig)
            .expect("Aggregated signature should be valid");

        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        let combined_msg_parallel = aggregate::combine_messages::<V, _>(&messages, &parallel);
        aggregate::verify_same_signer::<V>(&public, &combined_msg_parallel, &aggregate_sig)
            .expect("Aggregated signature should be valid with parallelism");

        let payload_msgs: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| union_unique(ns, msg))
            .collect();
        let payload_refs: Vec<&[u8]> = payload_msgs.iter().map(|p| p.as_ref()).collect();
        blst_aggregate_verify_same_signer::<V, _>(&public, payload_refs, &aggregate_sig)
            .expect("blst should also accept aggregated signature");
    }

    #[test]
    fn test_aggregate_verify_same_signer_correct() {
        aggregate_verify_same_signer_correct::<MinPk>();
        aggregate_verify_same_signer_correct::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PublicKey<MinSig>>,
            CodecConformance<Message<MinSig>>,
            CodecConformance<Signature<MinSig>>,
        }
    }
}
