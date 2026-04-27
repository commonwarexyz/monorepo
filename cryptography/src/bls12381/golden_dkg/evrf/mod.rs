mod bandersnatch;

use crate::{
    bls12381::primitives::group::{Scalar, G1},
    transcript::{Summary, Transcript},
    Secret,
};
use bandersnatch::{F, G};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    EncodeFixed, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_math::algebra::{CryptoGroup, HashToGroup, Random};
use commonware_utils::{hex, ordered::Map, Array, Span, TryCollect};
use core::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
use rand_core::CryptoRngCore;
use std::{num::NonZeroU32, sync::LazyLock};
use zeroize::Zeroizing;

const SCHNORR_NS: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BANDERSNATCH_SCHNORR";

const POINT_DST: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_POINT_HASH";

static GOLDEN_BETA: LazyLock<Scalar> =
    LazyLock::new(|| Scalar::map(b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_DKG_BETA", b""));

fn point_hash(pk1: &PublicKey, pk2: &PublicKey, msg: &[u8]) -> (G, G) {
    let msg0 = [pk1, pk2, msg, &[0]].concat();
    let t0 = G::hash_to_group(POINT_DST, &msg0);
    let msg1 = {
        let mut out = msg0;
        out.pop();
        out.push(1);
        out
    };
    let t1 = G::hash_to_group(POINT_DST, &msg1);
    (t0, t1)
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    inner: Secret<F>,
}

impl Random for PrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self {
            inner: Secret::new(F::random(rng)),
        }
    }
}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.inner
            .expose(|x| PublicKey::from_point(G::generator() * x))
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Signature {
        let pk = self.public();
        let mut t = Transcript::new(SCHNORR_NS);
        t.commit(namespace).commit(msg).commit(pk.raw.as_slice());

        // Derive deterministic nonce from secret key + public transcript state
        let k = self.inner.expose(|x| {
            let mut nonce_t = t.fork(b"nonce");
            let x_bytes = Zeroizing::new(x.encode_fixed::<{ F::SIZE }>());
            nonce_t.commit(x_bytes.as_slice());
            F::random(&mut nonce_t.noise(b"k"))
        });

        let k_big = G::generator() * &k;
        let k_big_bytes: [u8; G::SIZE] = k_big.encode_fixed();
        t.commit(k_big_bytes.as_slice());
        let e = F::random(&mut t.noise(b"challenge"));

        // s = k + e * x
        let s = self.inner.expose(|x| e * x + &k);

        let mut raw = [0u8; Signature::SIZE];
        raw[..G::SIZE].copy_from_slice(&k_big_bytes);
        raw[G::SIZE..].copy_from_slice(&s.encode_fixed::<{ F::SIZE }>());
        Signature { raw }
    }
}

impl PrivateKey {
    /// Get the [`PublicKey`] associated with this private key.
    pub fn public(&self) -> PublicKey {
        crate::Signer::public_key(self)
    }

    /// Compute the VRF output between ourselves and the other party, for a given message.
    ///
    /// `SENDER` indicates whether we are the sender (dealer) or receiver. Both
    /// sides derive the same value because the ECDH secret is symmetric, and
    /// `SENDER` ensures `point_hash` receives the keys in a canonical order
    /// (sender first, receiver second).
    ///
    /// Changing the message in any way will produce a completely different output.
    ///
    /// Without knowing either [`PrivateKey`], the output is indistinguishable from
    /// a random value.
    pub(super) fn vrf<const SENDER: bool>(&self, msg: &Summary, other: &PublicKey) -> Scalar {
        let me = self.public();
        let (sender, receiver) = if SENDER { (&me, other) } else { (other, &me) };
        let (t0, t1) = point_hash(sender, receiver, msg);
        let s = self.inner.expose(|x| {
            let raw = other.point.clone() * x;
            raw.clear_cofactor()
        });
        let k = s.x_as_f();
        GOLDEN_BETA.clone() * &(t0 * &k).x_as_scalar() + &(t1 * &k).x_as_scalar()
    }

    /// Compute several [`Self::vrf`] outputs, along with commitments to these outputs.
    ///
    /// We take in several receivers now, and associate each of them with their output.
    ///
    /// We also produce [`VrfCommitments`], which contain commitments.
    ///
    /// # Panics
    ///
    /// Panics if `receivers` contains duplicate public keys.
    pub(super) fn vrf_batch_checked(
        &self,
        msg: &Summary,
        receivers: impl IntoIterator<Item = PublicKey>,
    ) -> (Map<PublicKey, Scalar>, VrfCommitments) {
        let scalars: Map<PublicKey, Scalar> = receivers
            .into_iter()
            .map(|receiver| {
                let s = self.vrf::<true>(msg, &receiver);
                (receiver, s)
            })
            .try_collect()
            .expect("receivers must be unique");
        let commitments: Map<PublicKey, G1> = scalars
            .iter_pairs()
            .map(|(pk, s)| (pk.clone(), G1::generator() * s))
            .try_collect()
            .expect("keys are unique");
        (
            scalars,
            VrfCommitments {
                proof: Proof { key: self.clone() },
                commitments,
            },
        )
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner
            .expose(|x| buf.put_slice(&x.encode_fixed::<{ F::SIZE }>()));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
        let x: F = ReadExt::read(&mut raw.as_slice())?;
        Ok(Self {
            inner: Secret::new(x),
        })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = F::SIZE;
}

/// A Schnorr signature over the Bandersnatch curve.
///
/// Consists of a commitment point K and a scalar response s.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; G::SIZE + F::SIZE],
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        Ok(Self { raw })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = G::SIZE + F::SIZE;
}

impl crate::Signature for Signature {}

impl Span for Signature {}

impl Array for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for Signature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

/// A public key on the Bandersnatch curve, used for signatures and VRF outputs.
///
/// This can be created using [`PrivateKey::public`].
#[derive(Clone)]
pub struct PublicKey {
    raw: [u8; G::SIZE],
    point: G,
}

impl PublicKey {
    fn from_point(point: G) -> Self {
        let raw: [u8; G::SIZE] = point.encode_fixed();
        Self { raw, point }
    }
}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        let k_big: G = match ReadExt::read(&mut &sig.raw[..G::SIZE]) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s: F = match ReadExt::read(&mut &sig.raw[G::SIZE..]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Recompute the challenge
        let mut t = Transcript::new(SCHNORR_NS);
        t.commit(namespace)
            .commit(msg)
            .commit(self.raw.as_slice())
            .commit(sig.raw[..G::SIZE].as_ref());
        let e = F::random(&mut t.noise(b"challenge"));

        // Check: s * G == K + e * X
        let lhs = G::generator() * &s;
        let rhs = k_big + &(self.point.clone() * &e);
        lhs == rhs
    }
}

impl crate::PublicKey for PublicKey {}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let point: G = ReadExt::read(&mut raw.as_slice())?;
        Ok(Self { raw, point })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = G::SIZE;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(self))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(self))
    }
}

/// An insecure "proof" that simply contains the sender's private key.
///
/// This is NOT a real zero-knowledge proof. It reveals the private key,
/// completely breaking the VRF's secrecy property. We use this placeholder
/// so that commitment checking works while the real ZK proof is being developed.
#[derive(Clone)]
struct Proof {
    key: PrivateKey,
}

impl Proof {
    /// Check that each commitment matches the VRF output for the corresponding receiver.
    fn check(&self, msg: &Summary, sender: &PublicKey, commitments: &Map<PublicKey, G1>) -> bool {
        if self.key.public() != *sender {
            return false;
        }
        commitments.iter_pairs().all(|(receiver, commitment)| {
            let expected = G1::generator() * &self.key.vrf::<true>(msg, receiver);
            *commitment == expected
        })
    }
}

impl Write for Proof {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
    }
}

impl Read for Proof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            key: PrivateKey::read(buf)?,
        })
    }
}

impl FixedSize for Proof {
    const SIZE: usize = PrivateKey::SIZE;
}

impl Write for VrfCommitments {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.commitments.write(buf);
    }
}

impl EncodeSize for VrfCommitments {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.commitments.encode_size()
    }
}

impl Read for VrfCommitments {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, max_players: &Self::Cfg) -> Result<Self, CodecError> {
        let proof: Proof = ReadExt::read(buf)?;
        let range = commonware_codec::RangeCfg::new(0..=max_players.get() as usize);
        let commitments = Read::read_cfg(buf, &(range, (), ()))?;
        Ok(Self { proof, commitments })
    }
}

/// Commitments to the output of [`PrivateKey::vrf`] for several receivers.
///
/// These commitments bind the output value for each receiver, without revealing
/// what it is.
#[derive(Clone)]
pub struct VrfCommitments {
    proof: Proof,
    commitments: Map<PublicKey, G1>,
}

impl VrfCommitments {
    /// Shift the commitment for `receiver` by `delta`.
    ///
    /// This exists to allow tests to simulate an adversary who provides
    /// fake mask commitments (exploiting the empty proof).
    #[cfg(any(feature = "arbitrary", test))]
    pub(super) fn perturb(&mut self, receiver: &PublicKey, delta: &G1) {
        if let Some(c) = self.commitments.get_value_mut(receiver) {
            *c += delta;
        }
    }

    /// Extract the VRF output commitments, after checking their integrity.
    ///
    /// For a given message and sender, we can check that the commitments contain
    /// what [`PrivateKey::vrf`] would produce for that receiver.
    pub fn check(self, msg: &Summary, sender: &PublicKey) -> Option<Map<PublicKey, G1>> {
        if !self.proof.check(msg, sender, &self.commitments) {
            return None;
        }
        Some(self.commitments)
    }

    /// Compute [`Self::check`] for an entire batch.
    ///
    /// `rng` is needed to allow to optimize this check, making it potentially
    /// faster than checking each value in isolation.
    ///
    /// A sender will only appear in the output if their output is correct.
    ///
    /// # Panics
    ///
    /// Panics if `outputs` contains duplicate sender public keys.
    pub fn check_batch(
        _rng: &mut impl CryptoRngCore,
        outputs: impl IntoIterator<Item = (PublicKey, Bytes, Self)>,
    ) -> Map<PublicKey, Map<PublicKey, G1>> {
        outputs
            .into_iter()
            .filter_map(|(sender, mut msg, commitments)| {
                let summary: Summary = ReadExt::read(&mut msg).ok()?;
                let checked = commitments.check(&summary, &sender)?;
                Some((sender, checked))
            })
            .try_collect()
            .expect("senders must be unique")
    }
}
