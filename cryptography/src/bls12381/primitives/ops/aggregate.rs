//! Aggregation operations for BLS12-381 signatures.
//!
//! This module provides functions for aggregating public keys and signatures,
//! as well as verifying aggregate signatures.
//!
//! # Security Considerations
//!
//! Combining signatures or verifying an aggregate does not establish that each input signature is
//! valid. Use [`aggregate_signatures`] to verify untrusted signatures before combining them, or
//! [`batch`](super::batch) to verify an existing set individually.
//! Aggregating signatures from multiple public keys over the same message additionally requires a
//! verified proof of possession (PoP) for every public key.

#[stability(ALPHA)]
use super::verify_message;
use super::{
    super::{Error, variant::Variant},
    hash_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_macros::stability;
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
#[stability(ALPHA)]
use hashbrown::HashSet;

#[stability(ALPHA)]
pub(super) type TranscriptEntry<'a, V> = (<V as Variant>::Public, &'a [u8], &'a [u8]);

/// Coalesces public keys attributed to identical `(namespace, message)` pairs.
#[stability(ALPHA)]
pub(super) fn group_entries<'a, V: Variant>(
    mut entries: Vec<TranscriptEntry<'a, V>>,
) -> Vec<TranscriptEntry<'a, V>> {
    entries.sort_unstable_by(|left, right| (left.1, left.2).cmp(&(right.1, right.2)));
    entries.dedup_by(|next, current| {
        if (next.1, next.2) != (current.1, current.2) {
            return false;
        }
        current.0 += &next.0;
        true
    });
    entries
}

#[stability(ALPHA)]
pub(super) fn group_transcript<'a, V: Variant>(
    transcript: impl IntoIterator<Item = TranscriptEntry<'a, V>>,
) -> Result<Vec<TranscriptEntry<'a, V>>, Error> {
    let transcript: Vec<_> = transcript.into_iter().collect();
    if transcript.is_empty() {
        return Err(Error::InvalidSignature);
    }

    let mut publics = HashSet::with_capacity(transcript.len());
    for (public, _, _) in &transcript {
        if public == &V::Public::zero() || !publics.insert(*public) {
            return Err(Error::InvalidSignature);
        }
    }

    let transcript = group_entries::<V>(transcript);
    if transcript
        .iter()
        .any(|(public, _, _)| public == &V::Public::zero())
    {
        return Err(Error::InvalidSignature);
    }
    Ok(transcript)
}

#[stability(ALPHA)]
pub(crate) fn verify_transcript_inner<'a, V: Variant>(
    transcript: impl IntoIterator<Item = TranscriptEntry<'a, V>>,
    signature: &Signature<V>,
    strategy: &impl Strategy,
) -> Result<(), Error> {
    if signature.inner() == &V::Signature::zero() {
        return Err(Error::InvalidSignature);
    }

    let groups = group_transcript::<V>(transcript)?;
    let terms = strategy.map_collect_vec(groups, |(public, namespace, message)| {
        let message = hash_with_namespace::<V>(V::MESSAGE, namespace, message);
        (public, message)
    });
    let (publics, messages): (Vec<_>, Vec<_>) = terms.into_iter().unzip();
    V::verify_pairing_product(&publics, &messages, signature.inner(), strategy)
}

/// An aggregated public key from multiple individual public keys.
///
/// This type is returned by [`combine_public_keys`] and ensures that
/// aggregated public keys are not confused with individual public keys.
///
/// # Security
///
/// Before using this key with [`verify_same_message`], callers must group-check every public key
/// included in it, verify each key's PoP, and ensure the keys are unique. Decoding an aggregate
/// public key does not perform these checks.
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

    /// Returns the aggregated group element.
    #[stability(ALPHA)]
    pub const fn element(&self) -> &V::Signature {
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
/// Every `public_key` must be group-checked and unique, and its proof of possession (PoP) must be
/// verified with [`verify_proof_of_possession`](super::verify_proof_of_possession). Skipping these
/// checks can let an attacker make an invalid aggregate signature verify, including through a
/// rogue-key attack.
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

/// Verifies untrusted signatures individually before combining them.
///
/// Each entry attributes an exact `(namespace, message)` pair and signature to one public key.
/// Public keys must be unique and non-zero, and the input must not be empty.
///
/// # Security
///
/// Every public key must be group-checked and have a verified proof of possession (PoP). This
/// function verifies signatures, but not PoPs. Accepting a public key without a verified PoP can
/// enable rogue-key attacks when the resulting aggregate is verified.
#[stability(ALPHA)]
pub fn aggregate_signatures<'a, V: Variant>(
    entries: impl IntoIterator<Item = (&'a V::Public, &'a [u8], &'a [u8], &'a V::Signature)>,
    strategy: &impl Strategy,
) -> Result<Signature<V>, Error> {
    let entries: Vec<_> = entries.into_iter().collect();
    group_transcript::<V>(
        entries
            .iter()
            .map(|(public, namespace, message, _)| (**public, *namespace, *message)),
    )?;

    strategy.try_map_collect_vec(entries.iter(), |(public, namespace, message, signature)| {
        verify_message::<V>(public, namespace, message, signature)
    })?;

    let signature = combine_signatures::<V, _>(entries.iter().map(|entry| entry.3));
    if signature.inner() == &V::Signature::zero() {
        return Err(Error::InvalidSignature);
    }
    Ok(signature)
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
/// Every public key included in `public` must be unique and group-checked, and its PoP must be
/// verified with [`verify_proof_of_possession`](super::verify_proof_of_possession). This also
/// applies when `public` is decoded or precomputed. The `signature` must be group-checked as well.
/// Accepting a public key without a verified PoP enables rogue-key attacks.
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

/// Verifies an aggregate signature over an exact attributed transcript.
///
/// Each transcript entry contains one public key and its exact `(namespace, message)` pair. Public
/// keys must be unique and non-zero, and the transcript must not be empty. Repeated
/// `(namespace, message)` pairs are allowed and are grouped so each distinct pair requires only one
/// hash and one pairing.
///
/// # Security
///
/// Every public key must be group-checked and have a verified proof of possession (PoP). This
/// function verifies the aggregate equation, but not PoPs. Accepting a public key without a verified
/// PoP enables rogue-key attacks.
#[stability(ALPHA)]
pub fn verify_transcript<'a, V: Variant>(
    transcript: impl IntoIterator<Item = (&'a V::Public, &'a [u8], &'a [u8])>,
    signature: &Signature<V>,
    strategy: &impl Strategy,
) -> Result<(), Error> {
    verify_transcript_inner::<V>(
        transcript
            .into_iter()
            .map(|(public, namespace, message)| (*public, namespace, message)),
        signature,
        strategy,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        super::{aggregate, keypair, sign_message},
        *,
    };
    use crate::bls12381::primitives::{
        Error,
        group::{G1_MESSAGE, G2_MESSAGE},
        variant::{MinPk, MinSig, final_exponentiations, reset_final_exponentiations},
    };
    use blst::BLST_ERROR;
    use commonware_codec::Encode;
    use commonware_math::algebra::CryptoGroup;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, test_rng, union_unique};
    use core::iter::empty;

    type SignedEntry<V> = (
        <V as Variant>::Public,
        &'static [u8],
        &'static [u8],
        <V as Variant>::Signature,
    );

    fn signed_entries<V: Variant>(
        messages: &[(&'static [u8], &'static [u8])],
    ) -> Vec<SignedEntry<V>> {
        let mut rng = test_rng();
        messages
            .iter()
            .map(|&(namespace, message)| {
                let (private, public) = keypair::<_, V>(&mut rng);
                let signature = sign_message::<V>(&private, namespace, message);
                (public, namespace, message, signature)
            })
            .collect()
    }

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

    fn aggregate_transcript_valid<V: Variant>() {
        let entries = signed_entries::<V>(&[
            (b"vote", b"same"),
            (b"finalize", b"other"),
            (b"vote", b"same"),
            (b"vote", b"other"),
        ]);
        let aggregate = aggregate_signatures::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, signature)| {
                    (public, *namespace, *message, signature)
                }),
            &Sequential,
        )
        .expect("individually valid signatures should aggregate");

        verify_transcript::<V>(
            entries
                .iter()
                .rev()
                .map(|(public, namespace, message, _)| (public, *namespace, *message)),
            &aggregate,
            &Sequential,
        )
        .expect("mixed and repeated-message transcript should verify");

        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        verify_transcript::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, _)| (public, *namespace, *message)),
            &aggregate,
            &parallel,
        )
        .expect("transcript should verify in parallel");
    }

    #[test]
    fn test_aggregate_transcript_valid() {
        aggregate_transcript_valid::<MinPk>();
        aggregate_transcript_valid::<MinSig>();
    }

    fn aggregate_transcript_uses_one_final_exponentiation<V: Variant>() {
        let entries = signed_entries::<V>(&[
            (b"vote", b"same"),
            (b"finalize", b"other"),
            (b"vote", b"same"),
            (b"vote", b"other"),
        ]);
        let aggregate = aggregate_signatures::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, signature)| {
                    (public, *namespace, *message, signature)
                }),
            &Sequential,
        )
        .unwrap();

        reset_final_exponentiations();
        verify_transcript::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, _)| (public, *namespace, *message)),
            &aggregate,
            &Sequential,
        )
        .unwrap();
        assert_eq!(final_exponentiations(), 1);

        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        reset_final_exponentiations();
        verify_transcript::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, _)| (public, *namespace, *message)),
            &aggregate,
            &parallel,
        )
        .unwrap();
        assert_eq!(final_exponentiations(), 1);
    }

    #[test]
    fn test_aggregate_transcript_uses_one_final_exponentiation() {
        aggregate_transcript_uses_one_final_exponentiation::<MinPk>();
        aggregate_transcript_uses_one_final_exponentiation::<MinSig>();
    }

    fn aggregate_transcript_rejects_mutation<V: Variant>() {
        let entries = signed_entries::<V>(&[(b"namespace", b"first"), (b"namespace", b"second")]);
        let aggregate = aggregate_signatures::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, signature)| {
                    (public, *namespace, *message, signature)
                }),
            &Sequential,
        )
        .unwrap();
        let mut transcript: Vec<_> = entries
            .iter()
            .map(|(public, namespace, message, _)| (public, *namespace, *message))
            .collect();

        transcript[0].2 = b"mutated";
        assert!(
            verify_transcript::<V>(transcript.iter().copied(), &aggregate, &Sequential).is_err()
        );

        transcript[0].2 = entries[0].2;
        transcript[0].1 = b"mutated";
        assert!(
            verify_transcript::<V>(transcript.iter().copied(), &aggregate, &Sequential).is_err()
        );

        transcript[0].1 = entries[0].1;
        let mut corrupted = aggregate;
        corrupted.add(&V::Signature::generator());
        assert!(
            verify_transcript::<V>(transcript.iter().copied(), &corrupted, &Sequential).is_err()
        );
    }

    #[test]
    fn test_aggregate_transcript_rejects_mutation() {
        aggregate_transcript_rejects_mutation::<MinPk>();
        aggregate_transcript_rejects_mutation::<MinSig>();
    }

    fn aggregate_transcript_rejects_invalid_keys<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let first = sign_message::<V>(&private, b"namespace", b"first");
        let second = sign_message::<V>(&private, b"namespace", b"second");
        let aggregate = combine_signatures::<V, _>([&first, &second]);

        assert!(
            verify_transcript::<V>(
                [
                    (&public, b"namespace".as_slice(), b"first".as_slice()),
                    (&public, b"namespace".as_slice(), b"second".as_slice()),
                ],
                &aggregate,
                &Sequential,
            )
            .is_err()
        );

        let zero = V::Public::zero();
        assert!(
            verify_transcript::<V>(
                [(&zero, b"namespace".as_slice(), b"first".as_slice())],
                &aggregate,
                &Sequential,
            )
            .is_err()
        );
        assert!(
            verify_transcript::<V>(
                empty::<(&V::Public, &[u8], &[u8])>(),
                &aggregate,
                &Sequential,
            )
            .is_err()
        );
        assert!(
            verify_transcript::<V>(
                [(&public, b"namespace".as_slice(), b"first".as_slice())],
                &Signature::zero(),
                &Sequential,
            )
            .is_err()
        );
    }

    #[test]
    fn test_aggregate_transcript_rejects_invalid_keys() {
        aggregate_transcript_rejects_invalid_keys::<MinPk>();
        aggregate_transcript_rejects_invalid_keys::<MinSig>();
    }

    fn aggregate_signatures_rejects_invalid_assembly<V: Variant>() {
        let entries = signed_entries::<V>(&[(b"namespace", b"first"), (b"namespace", b"second")]);
        let raw = combine_signatures::<V, _>([&entries[1].3, &entries[0].3]);
        verify_transcript::<V>(
            entries
                .iter()
                .map(|(public, namespace, message, _)| (public, *namespace, *message)),
            &raw,
            &Sequential,
        )
        .expect("the aggregate equation cannot prove each input was attributed correctly");

        assert!(
            aggregate_signatures::<V>(
                [
                    (&entries[0].0, entries[0].1, entries[0].2, &entries[1].3),
                    (&entries[1].0, entries[1].1, entries[1].2, &entries[0].3),
                ],
                &Sequential,
            )
            .is_err()
        );
        assert!(
            aggregate_signatures::<V>(
                empty::<(&V::Public, &[u8], &[u8], &V::Signature)>(),
                &Sequential,
            )
            .is_err()
        );
    }

    #[test]
    fn test_aggregate_signatures_rejects_invalid_assembly() {
        aggregate_signatures_rejects_invalid_assembly::<MinPk>();
        aggregate_signatures_rejects_invalid_assembly::<MinSig>();
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
