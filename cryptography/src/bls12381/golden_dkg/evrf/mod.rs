mod bandersnatch;

use crate::{
    bls12381::{
        golden_dkg::evrf::bandersnatch::{vrf_batch_checked, vrf_batch_checked_circuit, vrf_recv},
        primitives::group::{Scalar, G1},
    },
    transcript::{Summary, Transcript},
    zk::{
        bulletproofs::circuit::{self, prove, verify},
        pedersen_to_plain,
    },
    Secret,
};
use bandersnatch::{F, G};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Encode, EncodeFixed, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_formatting::hex;
use commonware_math::algebra::{Additive as _, CryptoGroup, Random};
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Map, Array, Span, TryCollect, TryFromIterator};
use core::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
use rand_core::CryptoRngCore;
use std::num::NonZeroU32;
use zeroize::Zeroizing;

const SCHNORR_NS: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BANDERSNATCH_SCHNORR";

const BULLETPROOFS_DST: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_DKG_BULLETPROOFS";

// Linear fit, measured by `vrf_batch_checked_circuit`:
//
//     internal_vars(n) = WIRES_PER_PLAYER * n + WIRES_BASE
//
// (See `bandersnatch::tests::measure_circuit_size_per_receiver` for the
// raw data this fit was derived from.)
//
// TODO: with a hand-tailored scalar-mul gadget the per-receiver constant
// could drop to ~2.5k (Golden paper, eprint 2025/1924), letting us hit a much
// larger receiver count with the same (or smaller) setup.
const WIRES_PER_PLAYER: usize = 8664;
const WIRES_BASE: usize = 3065;

/// `ceil(log2(WIRES_PER_PLAYER * num_players + WIRES_BASE))`.
///
/// Returns the log2 of the smallest power of two that fits the VRF circuit
/// for `num_players` receivers, which is what [`Setup::new`] uses to size
/// the underlying bulletproofs setup.
const fn lg_len_for_players(num_players: u32) -> u8 {
    let internal = WIRES_PER_PLAYER * (num_players as usize) + WIRES_BASE;
    // ceil(log2(internal))
    let mut padded: usize = 1;
    let mut lg: u8 = 0;
    while padded < internal {
        padded <<= 1;
        lg += 1;
    }
    lg
}

/// A bulletproofs setup for the golden DKG eVRF circuit.
///
/// Each setup is created for a specific maximum number of players (passed to
/// [`Setup::new`]). All public DKG operations that consume a setup
/// ([`super::deal`], [`super::observe`], and [`super::play`]) require that the
/// configured number of players fits within this maximum; [`Setup::supports`]
/// is the must-use predicate that callers can query in advance.
///
/// # Cost
///
/// Creating a [`Setup`] is **expensive**: it deterministically hashes
/// roughly `2 * 2^lg_len` curve points, where `lg_len` grows logarithmically
/// with `max_players`. However, it only needs to be done **once**: the same
/// [`Setup`] can be reused across any number of DKG/Reshare rounds, and is
/// intended to be shared by all participants (it is publicly derivable and
/// contains no secrets).
pub struct Setup {
    inner: circuit::Setup<G1>,
    max_players: NonZeroU32,
}

impl Setup {
    /// Build a new [`Setup`] supporting DKG rounds with up to `max_players`
    /// players.
    ///
    /// This is **expensive** (see the type-level docs); generate one setup and
    /// reuse it across all DKG rounds rather than rebuilding it each time.
    pub fn new(max_players: NonZeroU32) -> Self {
        let lg_len = lg_len_for_players(max_players.get());
        // Use the BLS12-381 G1 generator as the value generator so that
        // `value * G1::generator()` (computed by the DKG layer) matches the
        // Pedersen commitments produced by `Witness::claim`.
        let inner = circuit::Setup::hashed(BULLETPROOFS_DST, lg_len, G1::generator());
        Self { inner, max_players }
    }

    /// Return whether this [`Setup`] supports a DKG round with `num_players`
    /// players.
    #[must_use]
    pub const fn supports(&self, num_players: u32) -> bool {
        num_players <= self.max_players.get()
    }

    /// The maximum number of players this setup was constructed for.
    pub(super) const fn max_players(&self) -> NonZeroU32 {
        self.max_players
    }

    pub(super) const fn inner(&self) -> &circuit::Setup<G1> {
        &self.inner
    }
}

impl Write for Setup {
    fn write(&self, buf: &mut impl BufMut) {
        self.max_players.get().write(buf);
        self.inner.write(buf);
    }
}

impl EncodeSize for Setup {
    fn encode_size(&self) -> usize {
        self.max_players.get().encode_size() + self.inner.encode_size()
    }
}

impl Read for Setup {
    /// The exact `max_players` this setup was created for. Decoding fails if
    /// the encoded value does not match.
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, expected_max_players: &Self::Cfg) -> Result<Self, CodecError> {
        let max_players_raw = u32::read(buf)?;
        let max_players = NonZeroU32::new(max_players_raw)
            .ok_or(CodecError::Invalid("Setup", "max_players must be nonzero"))?;
        if max_players != *expected_max_players {
            return Err(CodecError::Invalid("Setup", "max_players mismatch"));
        }
        let lg_len = lg_len_for_players(max_players.get());
        let max_len = 1usize << lg_len;
        let inner = circuit::Setup::<G1>::read_cfg(buf, &(max_len, ()))?;
        if !inner.supports(lg_len) {
            return Err(CodecError::Invalid("Setup", "inner setup too small"));
        }
        Ok(Self { inner, max_players })
    }
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

    /// Compute the VRF output between ourselves (as receiver) and a `sender`, for a given message.
    ///
    /// Both sides derive the same value because the underlying ECDH secret is symmetric.
    ///
    /// Changing the message in any way will produce a completely different output.
    ///
    /// Without knowing either [`PrivateKey`], the output is indistinguishable from
    /// a random value.
    pub(super) fn vrf_recv(&self, msg: &Summary, sender: &PublicKey) -> Scalar {
        self.inner
            .expose(|inner| vrf_recv(msg, sender.point.clone(), inner))
    }

    /// Compute the VRF output for each receiver, along with [`VrfCommitments`]
    /// that bind those outputs and prove they were evaluated correctly.
    ///
    /// # Panics
    ///
    /// Panics if `receivers` contains duplicate public keys.
    pub(super) fn vrf_batch_checked(
        &self,
        rng: &mut impl CryptoRngCore,
        setup: &Setup,
        transcript: &mut Transcript,
        msg: &Summary,
        receivers: impl IntoIterator<Item = PublicKey>,
        strategy: &impl Strategy,
    ) -> (Map<PublicKey, Scalar>, VrfCommitments) {
        let receivers = Map::from_iter_dedup(receivers.into_iter().map(|x| {
            let point = x.point.clone();
            (x, point)
        }));
        let (circuit, witness) = self
            .inner
            .expose(|x| vrf_batch_checked(msg, x, receivers.values()));
        let claim = witness.claim(setup.inner());
        let circuit_proof = prove(
            &mut *rng,
            transcript,
            setup.inner(),
            &circuit,
            &claim,
            &witness,
            strategy,
        )
        .expect("proving should succeed");
        let outputs = Map::try_from_iter(
            receivers
                .into_iter()
                .zip(witness.values())
                .map(|((receiver, _), output)| (receiver, output.clone())),
        )
        .expect("receivers was already deduplicated");
        let commitments = Map::try_from_iter(outputs.keys().iter().cloned().zip(claim.commitments))
            .expect("receivers was already deduplicated");
        let pedersen_to_plain = {
            let setup = pedersen_to_plain::Setup {
                value_generator: *setup.inner().value_generator(),
                blinding_generator: *setup.inner().blinding_generator(),
            };
            let mut out = Vec::new();
            for (receiver, output) in outputs.iter_pairs() {
                let commitment = *commitments
                    .get_value(receiver)
                    .expect("output should have commitment");
                let proof = pedersen_to_plain::prove(
                    &mut *rng,
                    transcript,
                    &setup,
                    &pedersen_to_plain::Claim {
                        plain: commitment,
                        pedersen: commitment,
                    },
                    &pedersen_to_plain::Witness {
                        value: output.clone(),
                        blinding: Scalar::zero(),
                    },
                );
                out.push(proof);
            }
            out
        };
        let proof = Proof {
            circuit_proof,
            pedersen_to_plain,
        };
        (outputs, VrfCommitments { proof, commitments })
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

/// Proves that the VRF was correctly evaluated for each receiver and that the
/// resulting outputs are bound to the accompanying [`VrfCommitments`].
#[derive(Clone)]
struct Proof {
    circuit_proof: circuit::Proof<Scalar, G1>,
    pedersen_to_plain: Vec<pedersen_to_plain::Proof<Scalar, G1>>,
}

impl Write for Proof {
    fn write(&self, buf: &mut impl BufMut) {
        self.circuit_proof.write(buf);
        self.pedersen_to_plain.write(buf);
    }
}

impl EncodeSize for Proof {
    fn encode_size(&self) -> usize {
        self.circuit_proof.encode_size() + self.pedersen_to_plain.encode_size()
    }
}

impl Read for Proof {
    /// `max_players` bounds both the number of `pedersen_to_plain` proofs (one
    /// per receiver, which is checked when validating logs for inclusion in
    /// [`super::observe`] or [`super::play`]) and, via [`lg_len_for_players`],
    /// the number of IPA rounds admissible in the inner circuit proof.
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, max_players: &Self::Cfg) -> Result<Self, CodecError> {
        let max_proof_len = 1usize << lg_len_for_players(max_players.get());
        let circuit_proof =
            circuit::Proof::<Scalar, G1>::read_cfg(buf, &(max_proof_len, ((), ())))?;
        let range = commonware_codec::RangeCfg::new(0..=max_players.get() as usize);
        let pedersen_to_plain =
            Vec::<pedersen_to_plain::Proof<Scalar, G1>>::read_cfg(buf, &(range, ((), ())))?;
        Ok(Self {
            circuit_proof,
            pedersen_to_plain,
        })
    }
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
        let proof = Proof::read_cfg(buf, max_players)?;
        let range = commonware_codec::RangeCfg::new(0..=max_players.get() as usize);
        let commitments = Read::read_cfg(buf, &(range, (), ()))?;
        Ok(Self { proof, commitments })
    }
}

/// Commitments to the output of [`PrivateKey::vrf_recv`] for several receivers.
///
/// These commitments bind the output value for each receiver, without revealing
/// what it is.
#[derive(Clone)]
pub struct VrfCommitments {
    proof: Proof,
    commitments: Map<PublicKey, G1>,
}

impl VrfCommitments {
    /// Shift the commitment for `receiver` by `delta`, producing a tampered
    /// [`VrfCommitments`] that should fail [`Self::check_batch`].
    #[cfg(any(feature = "arbitrary", test))]
    pub(super) fn perturb(&mut self, receiver: &PublicKey, delta: &G1) {
        if let Some(c) = self.commitments.get_value_mut(receiver) {
            *c += delta;
        }
    }

    /// Verify a batch of [`VrfCommitments`] in a single combined check.
    ///
    /// Each entry in `outputs` is a `(sender, msg, commitments)` triple where
    /// `msg` is the same nonce ([`Summary`]) the dealer passed to
    /// [`PrivateKey::vrf_batch_checked`], and `commitments` is what they
    /// produced. `transcript` must match the outer transcript the dealers used
    /// when proving (typically `Transcript::resume(*info.summary())`).
    ///
    /// On success, returns each sender's verified commitments: each entry
    /// in the returned map is a plain group encoding (`G^output`, with no
    /// Pedersen blinding) of the VRF output that sender computed for that
    /// receiver.
    ///
    /// Returns only the commitments which successfully verified. Bad commitments
    /// are simply ommitted from the result.
    ///
    /// # Panics
    ///
    /// Panics if `outputs` contains duplicate sender public keys.
    pub fn check_batch(
        rng: &mut impl CryptoRngCore,
        setup: &Setup,
        transcript: &Transcript,
        outputs: impl IntoIterator<Item = (PublicKey, Bytes, Self)>,
        strategy: &impl Strategy,
    ) -> Map<PublicKey, Map<PublicKey, G1>> {
        // Materialize the batch up front. Each sender's `msg` must parse as a
        // `Summary` (the format the prover passed in); senders whose `msg` is
        // malformed are dropped before we touch the proof system.
        let outputs: Vec<(PublicKey, Bytes, Self)> = outputs
            .into_iter()
            .filter_map(|(sender, msg, commitments)| {
                let mut buf: &[u8] = msg.as_ref();
                let _: Summary = ReadExt::read(&mut buf).ok()?;
                Some((sender, msg, commitments))
            })
            .collect();

        // Build one verification equation per sender; the batched checker
        // sums them (with independent random scalars) into a single MSM and
        // performs a binary-tree fallback to identify any culprits.
        let per_sender = setup.inner().eval_check_batched(
            rng,
            |vs, rng| {
                // Pedersen-to-plain proves and verifies use the value/blinding
                // generators of the bulletproofs setup, so build a matching
                // synthetic-flavored setup once for reuse below.
                let pp_setup = pedersen_to_plain::Setup {
                    value_generator: vs.value_generator().clone(),
                    blinding_generator: vs.blinding_generator().clone(),
                };

                let mut per_sender = Vec::with_capacity(outputs.len());
                for (sender, msg, commitments) in &outputs {
                    // Reconstruct the per-sender circuit. Receivers are taken
                    // from the (sorted) commitment map so they line up with the
                    // order the prover used.
                    let receivers: Vec<G> = commitments
                        .commitments
                        .keys()
                        .iter()
                        .map(|pk| pk.point.clone())
                        .collect();
                    let circuit =
                        vrf_batch_checked_circuit(msg.as_ref(), sender.point.clone(), &receivers);
                    let claim = circuit::Claim {
                        commitments: commitments.commitments.values().to_vec(),
                    };

                    // Per-sender forked transcript matches what the prover used
                    // when calling `circuit::prove` and the chained
                    // `pedersen_to_plain::prove` calls.
                    let mut t = transcript.fork(b"dealer vrf");
                    t.commit(sender.encode());

                    let Some(circuit_synth) = verify(
                        &mut *rng,
                        &mut t,
                        vs,
                        &circuit,
                        &claim,
                        commitments.proof.circuit_proof.clone(),
                        strategy,
                    ) else {
                        // Structural failure for this sender: record `None`
                        // so the batched checker excludes it from any subset
                        // sum without spoiling the rest of the batch.
                        per_sender.push(None);
                        continue;
                    };
                    let mut sender_acc = circuit_synth * &Scalar::random(&mut *rng);

                    // Pedersen-to-plain proofs were appended in the same order
                    // as `commitments.iter_pairs()` on the prover side.
                    for ((_, comm), pp_proof) in commitments
                        .commitments
                        .iter_pairs()
                        .zip(commitments.proof.pedersen_to_plain.iter().cloned())
                    {
                        let pp_claim = pedersen_to_plain::Claim {
                            plain: *comm,
                            pedersen: *comm,
                        };
                        let pp_synth = pedersen_to_plain::verify(
                            &mut *rng, &mut t, &pp_setup, &pp_claim, pp_proof,
                        );
                        sender_acc += &(pp_synth * &Scalar::random(&mut *rng));
                    }
                    per_sender.push(Some(sender_acc));
                }
                Some(per_sender)
            },
            strategy,
        );

        let Some(per_sender) = per_sender else {
            return Map::default();
        };

        outputs
            .into_iter()
            .zip(per_sender)
            .filter_map(|((sender, _, commitments), valid)| {
                valid.then_some((sender, commitments.commitments))
            })
            .try_collect()
            .expect("senders must be unique")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::sync::LazyLock;

    /// Cached setup used by tests in this module. Sized for 3 receivers since
    /// every test in this module uses 3.
    static TEST_SETUP: LazyLock<Setup> = LazyLock::new(|| Setup::new(NonZeroU32::new(3).unwrap()));

    #[test]
    fn vrf_batch_checked_roundtrips_through_check_batch() {
        let mut rng = test_rng();

        let sender_sk = PrivateKey::random(&mut rng);
        let sender_pk = sender_sk.public();
        let receiver_pks: Vec<PublicKey> = (0..3)
            .map(|_| PrivateKey::random(&mut rng).public())
            .collect();

        let nonce = Summary::random(&mut rng);
        let msg = Bytes::copy_from_slice(nonce.as_ref());

        // The outer transcript both sides agree on. The prover forks it the
        // same way `golden_dkg::deal` does, and `check_batch` re-forks it
        // internally per sender.
        let outer_transcript = Transcript::new(b"vrf-batch-checked-test");

        let mut prover_t = outer_transcript.fork(b"dealer vrf");
        prover_t.commit(sender_pk.encode());
        let (_outputs, commitments) = sender_sk.vrf_batch_checked(
            &mut rng,
            &TEST_SETUP,
            &mut prover_t,
            &nonce,
            receiver_pks.iter().cloned(),
            &Sequential,
        );

        let result = VrfCommitments::check_batch(
            &mut rng,
            &TEST_SETUP,
            &outer_transcript,
            std::iter::once((sender_pk.clone(), msg, commitments.clone())),
            &Sequential,
        );

        assert_eq!(result.len(), 1);
        let checked = result
            .get_value(&sender_pk)
            .expect("sender should appear in batch result");
        assert_eq!(checked, &commitments.commitments);
    }

    #[test]
    fn check_batch_rejects_perturbed_commitments() {
        let mut rng = test_rng();

        let sender_sk = PrivateKey::random(&mut rng);
        let sender_pk = sender_sk.public();
        let receiver_pks: Vec<PublicKey> = (0..3)
            .map(|_| PrivateKey::random(&mut rng).public())
            .collect();

        let nonce = Summary::random(&mut rng);
        let msg = Bytes::copy_from_slice(nonce.as_ref());

        let outer_transcript = Transcript::new(b"vrf-batch-checked-test");

        let mut prover_t = outer_transcript.fork(b"dealer vrf");
        prover_t.commit(sender_pk.encode());
        let (_outputs, mut commitments) = sender_sk.vrf_batch_checked(
            &mut rng,
            &TEST_SETUP,
            &mut prover_t,
            &nonce,
            receiver_pks.iter().cloned(),
            &Sequential,
        );

        // Tamper with one commitment so the bulletproofs check should fail.
        commitments.perturb(&receiver_pks[0], &G1::generator());

        let result = VrfCommitments::check_batch(
            &mut rng,
            &TEST_SETUP,
            &outer_transcript,
            std::iter::once((sender_pk, msg, commitments)),
            &Sequential,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn check_batch_falls_back_to_per_sender_on_failure() {
        let mut rng = test_rng();

        // Two independent senders with disjoint commitments.
        let senders: Vec<(PrivateKey, PublicKey)> = (0..2)
            .map(|_| {
                let sk = PrivateKey::random(&mut rng);
                let pk = sk.public();
                (sk, pk)
            })
            .collect();
        let receiver_pks: Vec<PublicKey> = (0..3)
            .map(|_| PrivateKey::random(&mut rng).public())
            .collect();

        let outer_transcript = Transcript::new(b"vrf-batch-checked-test");

        let mut prepared = Vec::new();
        for (sk, pk) in &senders {
            let nonce = Summary::random(&mut rng);
            let msg = Bytes::copy_from_slice(nonce.as_ref());
            let mut prover_t = outer_transcript.fork(b"dealer vrf");
            prover_t.commit(pk.encode());
            let (_outputs, commitments) = sk.vrf_batch_checked(
                &mut rng,
                &TEST_SETUP,
                &mut prover_t,
                &nonce,
                receiver_pks.iter().cloned(),
                &Sequential,
            );
            prepared.push((pk.clone(), msg, commitments));
        }

        // Tamper with the *second* sender's commitments so the batched check
        // fails and we exercise the per-sender fallback path.
        prepared[1].2.perturb(&receiver_pks[0], &G1::generator());

        let result = VrfCommitments::check_batch(
            &mut rng,
            &TEST_SETUP,
            &outer_transcript,
            prepared.iter().cloned(),
            &Sequential,
        );

        // The honest sender should still be present; the perturbed one should not.
        assert_eq!(result.len(), 1);
        let good_pk = &senders[0].1;
        let bad_pk = &senders[1].1;
        assert_eq!(result.get_value(good_pk), Some(&prepared[0].2.commitments));
        assert!(result.get_value(bad_pk).is_none());
    }

    #[test]
    fn setup_codec_roundtrip() {
        let s = Setup::new(NonZeroU32::new(3).unwrap());
        let bytes = s.encode();
        let decoded = Setup::read_cfg(&mut bytes.as_ref(), &NonZeroU32::new(3).unwrap()).unwrap();
        assert_eq!(decoded.max_players(), s.max_players());
        // Re-encode and compare to make sure the roundtrip is bit-exact.
        assert_eq!(decoded.encode(), bytes);
    }
}
