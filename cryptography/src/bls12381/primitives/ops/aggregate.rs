//! Aggregation operations for BLS12-381 signatures.
//!
//! This module provides functions for aggregating public keys and signatures,
//! as well as verifying aggregate signatures.
//!
//! # Security Considerations
//!
//! Some functions in this module are vulnerable to signature malleability attacks
//! when used incorrectly. See the documentation for each function for details.
//! Use [`batch`](super::batch) instead when you need to ensure each individual signature is valid.

use super::{
    super::{variant::Variant, Error},
    hash_message, hash_message_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::Additive;
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};

/// An aggregated public key from multiple individual public keys.
///
/// This type is returned by [`combine_public_keys`] and ensures that
/// aggregated public keys are not confused with individual public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey<V: Variant>(V::Public);

impl<V: Variant> PublicKey<V> {
    /// Returns the inner public key value.
    pub const fn inner(&self) -> &V::Public {
        &self.0
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
    /// Returns the inner signature value.
    pub const fn inner(&self) -> &V::Signature {
        &self.0
    }

    /// Creates a zero aggregate signature.
    pub fn zero() -> Self {
        Self(V::Signature::zero())
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
    let mut p = V::Public::zero();
    for pk in public_keys {
        p += pk;
    }
    PublicKey(p)
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
    let mut s = V::Signature::zero();
    for sig in signatures {
        s += sig;
    }
    Signature(s)
}

/// Verifies the aggregate signature over a single message from multiple public keys.
///
/// # Warning
///
/// This function assumes the caller has performed a group check and collected a proof-of-possession
/// for all provided `public`. This function assumes a group check was already performed on the
/// `signature`. It is not safe to provide duplicate public keys.
pub fn verify_multiple_public_keys<'a, V, I>(
    public: I,
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &Signature<V>,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    // Aggregate public keys
    //
    // We can take advantage of the bilinearity property of pairings to aggregate public keys
    // that have all signed the same message (as long as all public keys are unique).
    let agg_public = combine_public_keys::<V, _>(public);

    // Compute the hash of the message
    let hm = namespace.map_or_else(
        || hash_message::<V>(V::MESSAGE, message),
        |ns| hash_message_namespace::<V>(V::MESSAGE, ns, message),
    );

    // Verify the signature
    V::verify(agg_public.inner(), &hm, signature.inner())
}

/// Verifies an aggregate signature over multiple unique messages from a single public key.
///
/// Each entry is a tuple of (namespace, message). The signature must be the aggregate
/// of all individual signatures.
///
/// # Warning
///
/// This function is vulnerable to signature malleability when used with signatures
/// that were aggregated from different messages. An attacker can redistribute
/// signature components between messages while keeping the aggregate unchanged.
/// Use [`batch::verify_multiple_messages`](super::batch::verify_multiple_messages) instead when signatures are provided individually.
///
/// This function assumes a group check was already performed on `public` and `signature`.
/// It is not safe to provide an aggregate public key or to provide duplicate messages.
pub fn verify_multiple_messages<'a, V, I>(
    public: &V::Public,
    messages: I,
    signature: &Signature<V>,
    #[cfg_attr(not(feature = "std"), allow(unused_variables))] concurrency: usize,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])> + Send + Sync,
    I::IntoIter: Send + Sync,
{
    #[cfg(not(feature = "std"))]
    let hm_sum = compute_hm_sum::<V, I>(messages);

    #[cfg(feature = "std")]
    let hm_sum = if concurrency == 1 {
        compute_hm_sum::<V, I>(messages)
    } else {
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("Unable to build thread pool");

        pool.install(move || {
            messages
                .into_iter()
                .par_bridge()
                .map(|(namespace, msg)| {
                    namespace.as_ref().map_or_else(
                        || hash_message::<V>(V::MESSAGE, msg),
                        |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
                    )
                })
                .reduce(V::Signature::zero, |mut sum, hm| {
                    sum += &hm;
                    sum
                })
        })
    };

    V::verify(public, &hm_sum, signature.inner())
}

/// Computes the sum over the hash of each message.
fn compute_hm_sum<'a, V, I>(messages: I) -> V::Signature
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])>,
{
    let mut hm_sum = V::Signature::zero();
    for (namespace, msg) in messages {
        let hm = namespace.as_ref().map_or_else(
            || hash_message::<V>(V::MESSAGE, msg),
            |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
        );
        hm_sum += &hm;
    }
    hm_sum
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
    use commonware_utils::{test_rng, union_unique};

    fn blst_aggregate_verify_multiple_public_keys<'a, V, I>(
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

    fn aggregate_verify_multiple_public_keys_correct<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, public3) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let pks = vec![public1, public2, public3];
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);

        verify_multiple_public_keys::<V, _>(&pks, Some(namespace), message, &aggregate_sig)
            .expect("Aggregated signature should be valid");

        let payload = union_unique(namespace, message);
        blst_aggregate_verify_multiple_public_keys::<V, _>(&pks, &payload, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_verify_multiple_public_keys() {
        aggregate_verify_multiple_public_keys_correct::<MinPk>();
        aggregate_verify_multiple_public_keys_correct::<MinSig>();
    }

    fn aggregate_verify_wrong_public_keys<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, _) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);

        let (_, public4) = keypair::<_, V>(&mut rng);
        let wrong_pks = vec![public1, public2, public4];
        let result = verify_multiple_public_keys::<V, _>(
            &wrong_pks,
            Some(namespace),
            message,
            &aggregate_sig,
        );
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_public_keys() {
        aggregate_verify_wrong_public_keys::<MinPk>();
        aggregate_verify_wrong_public_keys::<MinSig>();
    }

    fn aggregate_verify_wrong_public_key_count<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, _) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);

        let wrong_pks = vec![public1, public2];
        let result = verify_multiple_public_keys::<V, _>(
            &wrong_pks,
            Some(namespace),
            message,
            &aggregate_sig,
        );
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_public_key_count() {
        aggregate_verify_wrong_public_key_count::<MinPk>();
        aggregate_verify_wrong_public_key_count::<MinSig>();
    }

    fn blst_aggregate_verify_multiple_messages<'a, V, I>(
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

    fn aggregate_verify_multiple_messages_correct<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let namespace = Some(&b"test"[..]);
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let signatures: Vec<_> = messages
            .iter()
            .map(|(namespace, msg)| sign_message::<V>(&private, *namespace, msg))
            .collect();

        let aggregate_sig = aggregate::combine_signatures::<V, _>(&signatures);

        aggregate::verify_multiple_messages::<V, _>(&public, &messages, &aggregate_sig, 1)
            .expect("Aggregated signature should be valid");

        aggregate::verify_multiple_messages::<V, _>(&public, &messages, &aggregate_sig, 4)
            .expect("Aggregated signature should be valid with parallelism");

        let payload_msgs: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| union_unique(ns.unwrap(), msg))
            .collect();
        let payload_refs: Vec<&[u8]> = payload_msgs.iter().map(|p| p.as_ref()).collect();
        blst_aggregate_verify_multiple_messages::<V, _>(&public, payload_refs, &aggregate_sig)
            .expect("blst should also accept aggregated signature");
    }

    #[test]
    fn test_aggregate_verify_multiple_messages_correct() {
        aggregate_verify_multiple_messages_correct::<MinPk>();
        aggregate_verify_multiple_messages_correct::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PublicKey<MinSig>>,
            CodecConformance<Signature<MinSig>>,
        }
    }
}
