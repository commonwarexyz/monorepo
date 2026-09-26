//! Simple Authenticated Key Exchange (SAKE).
//!
//! This construction is unrelated to [EAP-SAKE] or the [symmetric-key SAKE] protocol.
//!
//! # Construction
//!
//! SAKE is a fixed three-message handshake between a **dialer** and **listener**:
//!
//! 1. [Syn]: The dialer sends a timestamp, an ephemeral X25519 public key, and a signature bound
//!    to the transcript and intended listener.
//! 2. [SynAck]: The listener sends its timestamp, ephemeral X25519 public key, transcript
//!    signature, and key-confirmation tag.
//! 3. [Ack]: The dialer verifies the response and sends the opposite-direction confirmation.
//!
//! The current suite uses X25519 for ephemeral key agreement, BLAKE3 for the transcript and key
//! derivation, a generic [Signer] implementation for identity signatures, and ChaCha20-Poly1305
//! for the resulting directional traffic ciphers.
//!
//! Both public identities are inputs to the core exchange and are incorporated into the transcript
//! with the timestamps, ephemeral keys, and shared secret in a fixed order. Identities are visible,
//! not hidden by the construction. SAKE has no 0-RTT mode or resumption mechanism. Application
//! data can be sent only after the three messages complete.
//!
//! The BLAKE3 transcript first commits the caller-provided application namespace as one packet,
//! then forks it with the fixed `_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE` protocol namespace. Distinct
//! labels derive the listener-to-dialer and dialer-to-listener traffic keys and confirmations.
//! These namespace bytes, transcript order, and labels are protocol constants.
//!
//! # Versions
//!
//! [Version] selects the transcript schema. Both peers must use the same version. A mismatch fails
//! signature verification. The message encodings are identical across versions.
//!
//! - [Version::V0] signs [Syn] over the timestamp, listener identity, and ephemeral key, and
//!   commits the dialer identity only afterwards. With a signature scheme that lets anyone derive a
//!   second public key under which an existing signature verifies, a dialer can complete a
//!   handshake while claiming an identity derived from its signature instead of its own. Whether a
//!   derived identity can match one a listener admits depends on the signature scheme. V0 uses
//!   [transcript::Version::V0], which is sound here because SAKE commits a fixed sequence of
//!   canonical encodings at fixed positions.
//! - [Version::V1] commits both identities before every signature, so each signature covers the
//!   signer's own identity, and uses [transcript::Version::V1].
//!
//! [SendCipher] and [RecvCipher] use independent ChaCha20-Poly1305 keys and 96-bit counter nonces.
//! A successful receive therefore authenticates a message at its expected position in that
//! direction.
//!
//! # Timing
//!
//! Callers provide the accepted timestamp range to limit replay and clock skew. Because this core
//! performs no I/O, callers must separately enforce deadlines around the handshake to bound stalled
//! attempts.
//!
//! [EAP-SAKE]: https://www.rfc-editor.org/rfc/rfc4763
//! [symmetric-key SAKE]: https://eprint.iacr.org/2019/444
use crate::{
    PublicKey, Signature, Signer, Verifier,
    transcript::{self, Summary, Transcript},
};
use commonware_codec::{Buf, Encode, FixedSize, Read, ReadExt, Write};
use core::ops::Range;
use rand_core::CryptoRng;

mod error;
pub use error::Error;

mod key_exchange;
use key_exchange::{EphemeralPublicKey, SecretKey};

mod cipher;
pub use cipher::{RecvCipher, SendCipher, TAG_SIZE};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE";
const LABEL_CIPHER_L2D: &[u8] = b"cipher_l2d";
const LABEL_CIPHER_D2L: &[u8] = b"cipher_d2l";
const LABEL_CONFIRMATION_L2D: &[u8] = b"confirmation_l2d";
const LABEL_CONFIRMATION_D2L: &[u8] = b"confirmation_d2l";

/// Transcript schema used by a SAKE handshake.
///
/// The version is part of the protocol definition: both peers must agree on it out of band.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Version {
    /// Commits the dialer identity after the [Syn] signature.
    ///
    /// A signature scheme that lets anyone derive a second public key for an existing signature
    /// lets a dialer complete a handshake under an identity derived from its [Syn] signature.
    V0,
    /// Commits both identities before every signature and uses injective transcript framing.
    V1,
}

impl Version {
    /// Returns the transcript framing used by this version.
    ///
    /// V0 framing is safe for [Version::V0] because the application namespace is summarized as a
    /// single packet before SAKE commits a fixed sequence of canonical encodings at fixed
    /// positions.
    const fn transcript(self) -> transcript::Version {
        match self {
            Self::V0 => transcript::Version::V0,
            Self::V1 => transcript::Version::V1,
        }
    }

    /// Returns whether a peer's own identity is committed before it signs [Syn].
    const fn binds_identity_before_syn(self) -> bool {
        match self {
            Self::V0 => false,
            Self::V1 => true,
        }
    }
}

/// First handshake message sent by the dialer.
/// Contains dialer's ephemeral key and timestamp signature.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Syn<S: Signature> {
    time_ms: u64,
    epk: EphemeralPublicKey,
    sig: S,
}

impl<S: Signature> FixedSize for Syn<S> {
    const SIZE: usize = u64::SIZE + EphemeralPublicKey::SIZE + S::SIZE;
}

impl<S: Signature + Write> Write for Syn<S> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.time_ms.write(buf);
        self.epk.write(buf);
        self.sig.write(buf);
    }
}

impl<S: Signature + Read> Read for Syn<S> {
    type Cfg = S::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            time_ms: ReadExt::read(buf)?,
            epk: ReadExt::read(buf)?,
            sig: Read::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Signature> arbitrary::Arbitrary<'_> for Syn<S>
where
    S: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            time_ms: u.arbitrary()?,
            epk: u.arbitrary()?,
            sig: u.arbitrary()?,
        })
    }
}

/// Second handshake message sent by the listener.
/// Contains listener's ephemeral key, signature, and confirmation tag.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct SynAck<S: Signature> {
    time_ms: u64,
    epk: EphemeralPublicKey,
    sig: S,
    confirmation: Summary,
}

impl<S: Signature> FixedSize for SynAck<S> {
    const SIZE: usize = u64::SIZE + EphemeralPublicKey::SIZE + S::SIZE + Summary::SIZE;
}

impl<S: Signature + Write> Write for SynAck<S> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.time_ms.write(buf);
        self.epk.write(buf);
        self.sig.write(buf);
        self.confirmation.write(buf);
    }
}

impl<S: Signature + Read> Read for SynAck<S> {
    type Cfg = S::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            time_ms: ReadExt::read(buf)?,
            epk: ReadExt::read(buf)?,
            sig: Read::read_cfg(buf, cfg)?,
            confirmation: ReadExt::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Signature> arbitrary::Arbitrary<'_> for SynAck<S>
where
    S: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            time_ms: u.arbitrary()?,
            epk: u.arbitrary()?,
            sig: u.arbitrary()?,
            confirmation: u.arbitrary()?,
        })
    }
}

/// Third handshake message sent by the dialer.
/// Contains dialer's confirmation tag to complete the handshake.
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(feature = "arbitrary", derive(Debug, arbitrary::Arbitrary))]
pub struct Ack {
    confirmation: Summary,
}

impl FixedSize for Ack {
    const SIZE: usize = Summary::SIZE;
}

impl Write for Ack {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.confirmation.write(buf);
    }
}

impl Read for Ack {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            confirmation: ReadExt::read(buf)?,
        })
    }
}

/// State maintained by the dialer during handshake.
/// Tracks ephemeral secret, peer identity, and protocol transcript.
pub struct DialState<P> {
    esk: SecretKey,
    peer_identity: P,
    transcript: Transcript,
    ok_timestamps: Range<u64>,
}

/// State maintained by the listener during handshake.
/// Tracks expected confirmation and derived ciphers.
pub struct ListenState {
    confirmation: Summary,
    send: SendCipher,
    recv: RecvCipher,
}

/// Handshake context containing timing and identity information.
/// Used by both dialer and listener to initialize handshake state.
pub struct Context<S, P> {
    version: Version,
    transcript: Transcript,
    current_time: u64,
    ok_timestamps: Range<u64>,
    my_identity: S,
    peer_identity: P,
}

impl<S, P> Context<S, P> {
    /// Creates a new handshake context.
    pub fn new(
        namespace: &[u8],
        version: Version,
        current_time_ms: u64,
        ok_timestamps: Range<u64>,
        my_identity: S,
        peer_identity: P,
    ) -> Self {
        let transcript = Transcript::new(namespace, version.transcript()).fork(NAMESPACE);
        Self {
            version,
            transcript,
            current_time: current_time_ms,
            ok_timestamps,
            my_identity,
            peer_identity,
        }
    }
}

/// Initiates a handshake as the dialer.
/// Returns the dialer state and the first message to send.
pub fn dial_start<S: Signer, P: PublicKey>(
    rng: impl CryptoRng,
    ctx: Context<S, P>,
) -> (DialState<P>, Syn<<S as Signer>::Signature>) {
    let Context {
        version,
        current_time,
        ok_timestamps,
        my_identity,
        peer_identity,
        mut transcript,
    } = ctx;
    let esk = SecretKey::new(rng);
    let epk = esk.public();
    let dialer_identity = my_identity.public_key().encode();
    transcript
        .commit(current_time.encode())
        .commit(peer_identity.encode());
    if version.binds_identity_before_syn() {
        transcript.commit(dialer_identity.clone());
    }
    let sig = transcript.commit(epk.encode()).sign(&my_identity);
    if !version.binds_identity_before_syn() {
        transcript.commit(dialer_identity);
    }
    (
        DialState {
            esk,
            peer_identity,
            transcript,
            ok_timestamps,
        },
        Syn {
            time_ms: current_time,
            epk,
            sig,
        },
    )
}

/// Completes a handshake as the dialer.
/// Verifies the listener's response and returns final message and ciphers.
pub fn dial_end<P: PublicKey>(
    state: DialState<P>,
    msg: SynAck<<P as Verifier>::Signature>,
) -> Result<(Ack, SendCipher, RecvCipher), Error> {
    let DialState {
        esk,
        peer_identity,
        mut transcript,
        ok_timestamps,
    } = state;
    if !ok_timestamps.contains(&msg.time_ms) {
        return Err(Error::InvalidTimestamp(msg.time_ms, ok_timestamps));
    }
    if !transcript
        .commit(msg.time_ms.encode())
        .commit(msg.epk.encode())
        .verify(&peer_identity, &msg.sig)
    {
        return Err(Error::HandshakeFailed);
    }
    let Some(shared) = esk.exchange(&msg.epk) else {
        return Err(Error::HandshakeFailed);
    };
    shared
        .secret
        .expose(|secret| transcript.commit(secret.as_ref()));
    let recv = RecvCipher::new(transcript.noise(LABEL_CIPHER_L2D));
    let send = SendCipher::new(transcript.noise(LABEL_CIPHER_D2L));
    let confirmation_l2d = transcript.fork(LABEL_CONFIRMATION_L2D).summarize();
    let confirmation_d2l = transcript.fork(LABEL_CONFIRMATION_D2L).summarize();
    if msg.confirmation != confirmation_l2d {
        return Err(Error::HandshakeFailed);
    }

    Ok((
        Ack {
            confirmation: confirmation_d2l,
        },
        send,
        recv,
    ))
}

/// Processes the first handshake message as the listener.
/// Verifies the dialer's message and returns state and response.
pub fn listen_start<S: Signer, P: PublicKey>(
    rng: impl CryptoRng,
    ctx: Context<S, P>,
    msg: Syn<<P as Verifier>::Signature>,
) -> Result<(ListenState, SynAck<<S as Signer>::Signature>), Error> {
    let Context {
        version,
        current_time,
        my_identity,
        peer_identity,
        ok_timestamps,
        mut transcript,
    } = ctx;
    if !ok_timestamps.contains(&msg.time_ms) {
        return Err(Error::InvalidTimestamp(msg.time_ms, ok_timestamps));
    }
    let dialer_identity = peer_identity.encode();
    transcript
        .commit(msg.time_ms.encode())
        .commit(my_identity.public_key().encode());
    if version.binds_identity_before_syn() {
        transcript.commit(dialer_identity.clone());
    }
    if !transcript
        .commit(msg.epk.encode())
        .verify(&peer_identity, &msg.sig)
    {
        return Err(Error::HandshakeFailed);
    }
    if !version.binds_identity_before_syn() {
        transcript.commit(dialer_identity);
    }
    let esk = SecretKey::new(rng);
    let epk = esk.public();
    let sig = transcript
        .commit(current_time.encode())
        .commit(epk.encode())
        .sign(&my_identity);
    let Some(shared) = esk.exchange(&msg.epk) else {
        return Err(Error::HandshakeFailed);
    };
    shared
        .secret
        .expose(|secret| transcript.commit(secret.as_ref()));
    let send = SendCipher::new(transcript.noise(LABEL_CIPHER_L2D));
    let recv = RecvCipher::new(transcript.noise(LABEL_CIPHER_D2L));
    let confirmation_l2d = transcript.fork(LABEL_CONFIRMATION_L2D).summarize();
    let confirmation_d2l = transcript.fork(LABEL_CONFIRMATION_D2L).summarize();

    Ok((
        ListenState {
            confirmation: confirmation_d2l,
            send,
            recv,
        },
        SynAck {
            time_ms: current_time,
            epk,
            sig,
            confirmation: confirmation_l2d,
        },
    ))
}

/// Completes the handshake as the listener.
/// Verifies the dialer's confirmation and returns established ciphers.
pub fn listen_end(state: ListenState, msg: Ack) -> Result<(SendCipher, RecvCipher), Error> {
    if msg.confirmation != state.confirmation {
        return Err(Error::HandshakeFailed);
    }
    Ok((state.send, state.recv))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Signer, ed25519::PrivateKey, secp256r1::standard};
    use commonware_codec::{Codec, Copying, DecodeExt};
    use commonware_math::algebra::Random;
    use commonware_utils::{test_rng, union_unique};
    use p256::{
        AffinePoint, FieldBytes, ProjectivePoint, Scalar,
        elliptic_curve::{ops::Reduce, sec1::ToSec1Point as _},
    };
    use sha2::{Digest, Sha256};

    const VERSIONS: [Version; 2] = [Version::V0, Version::V1];

    fn test_encode_roundtrip<T: Codec<Cfg = ()> + PartialEq>(value: &T) {
        assert!(value == &<T as DecodeExt<_>>::decode(value.encode()).unwrap());
    }

    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Error> {
        for version in VERSIONS {
            let mut rng = test_rng();
            let dialer_crypto = PrivateKey::random(&mut rng);
            let listener_crypto = PrivateKey::random(&mut rng);

            let (d_state, msg1) = dial_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    version,
                    0,
                    0..1,
                    dialer_crypto.clone(),
                    listener_crypto.public_key(),
                ),
            );
            test_encode_roundtrip(&msg1);
            let (l_state, msg2) = listen_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    version,
                    0,
                    0..1,
                    listener_crypto,
                    dialer_crypto.public_key(),
                ),
                msg1,
            )?;
            test_encode_roundtrip(&msg2);
            let (msg3, mut d_send, mut d_recv) = dial_end(d_state, msg2)?;
            test_encode_roundtrip(&msg3);
            let (mut l_send, mut l_recv) = listen_end(l_state, msg3)?;

            let m1: &'static [u8] = b"message 1";

            let c1 = d_send.send(m1)?;
            let m1_prime = l_recv.recv(&c1)?;
            assert_eq!(m1, &m1_prime);

            let m2: &'static [u8] = b"message 2";
            let c2 = l_send.send(m2)?;
            let m2_prime = d_recv.recv(&c2)?;
            assert_eq!(m2, &m2_prime);
        }

        Ok(())
    }

    #[test]
    fn test_mismatched_namespace_fails() {
        for version in VERSIONS {
            let mut rng = test_rng();
            let dialer_crypto = PrivateKey::random(&mut rng);
            let listener_crypto = PrivateKey::random(&mut rng);

            let (_, msg1) = dial_start(
                &mut rng,
                Context::new(
                    b"namespace_a",
                    version,
                    0,
                    0..1,
                    dialer_crypto.clone(),
                    listener_crypto.public_key(),
                ),
            );

            let result = listen_start(
                &mut rng,
                Context::new(
                    b"namespace_b",
                    version,
                    0,
                    0..1,
                    listener_crypto,
                    dialer_crypto.public_key(),
                ),
                msg1,
            );

            assert!(matches!(result, Err(Error::HandshakeFailed)));
        }
    }

    #[test]
    fn test_mismatched_version_fails() {
        for (dialer_version, listener_version) in
            [(Version::V0, Version::V1), (Version::V1, Version::V0)]
        {
            let mut rng = test_rng();
            let dialer_crypto = PrivateKey::random(&mut rng);
            let listener_crypto = PrivateKey::random(&mut rng);

            let (_, msg1) = dial_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    dialer_version,
                    0,
                    0..1,
                    dialer_crypto.clone(),
                    listener_crypto.public_key(),
                ),
            );

            let result = listen_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    listener_version,
                    0,
                    0..1,
                    listener_crypto,
                    dialer_crypto.public_key(),
                ),
                msg1,
            );

            assert!(matches!(result, Err(Error::HandshakeFailed)));
        }
    }

    #[test]
    fn test_mismatched_dialer_identity_fails() {
        for version in VERSIONS {
            let mut rng = test_rng();
            let dialer_crypto = PrivateKey::random(&mut rng);
            let listener_crypto = PrivateKey::random(&mut rng);
            let impostor_crypto = PrivateKey::random(&mut rng);

            let (_, msg1) = dial_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    version,
                    0,
                    0..1,
                    dialer_crypto,
                    listener_crypto.public_key(),
                ),
            );

            let result = listen_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    version,
                    0,
                    0..1,
                    listener_crypto,
                    impostor_crypto.public_key(),
                ),
                msg1,
            );

            assert!(matches!(result, Err(Error::HandshakeFailed)));
        }
    }

    /// Reconstructs the transcript a listener verifies a [Syn] against, with the dialer identity
    /// included or omitted before the ephemeral key.
    fn syn_transcript<P: PublicKey>(
        version: Version,
        syn: &Syn<P::Signature>,
        listener: &P,
        dialer: Option<&P>,
    ) -> Transcript {
        let mut transcript =
            Transcript::new(b"test_namespace", version.transcript()).fork(NAMESPACE);
        transcript
            .commit(syn.time_ms.encode())
            .commit(listener.encode());
        if let Some(dialer) = dialer {
            transcript.commit(dialer.encode());
        }
        transcript.commit(syn.epk.encode());
        transcript
    }

    #[test]
    fn test_v1_syn_signature_covers_dialer_identity() {
        let mut rng = test_rng();
        let dialer_crypto = PrivateKey::random(&mut rng);
        let listener_crypto = PrivateKey::random(&mut rng);
        let dialer = dialer_crypto.public_key();
        let listener = listener_crypto.public_key();

        let (_, syn) = dial_start(
            &mut rng,
            Context::new(
                b"test_namespace",
                Version::V1,
                0,
                0..1,
                dialer_crypto,
                listener.clone(),
            ),
        );

        // The signature is only valid over a transcript that includes the dialer identity.
        assert!(
            syn_transcript(Version::V1, &syn, &listener, Some(&dialer)).verify(&dialer, &syn.sig)
        );
        assert!(!syn_transcript(Version::V1, &syn, &listener, None).verify(&dialer, &syn.sig));
    }

    #[test]
    fn test_v0_syn_signature_omits_dialer_identity() {
        let mut rng = test_rng();
        let dialer_crypto = PrivateKey::random(&mut rng);
        let listener_crypto = PrivateKey::random(&mut rng);
        let dialer = dialer_crypto.public_key();
        let listener = listener_crypto.public_key();

        let (_, syn) = dial_start(
            &mut rng,
            Context::new(
                b"test_namespace",
                Version::V0,
                0,
                0..1,
                dialer_crypto,
                listener.clone(),
            ),
        );

        assert!(syn_transcript(Version::V0, &syn, &listener, None).verify(&dialer, &syn.sig));
        assert!(
            !syn_transcript(Version::V0, &syn, &listener, Some(&dialer)).verify(&dialer, &syn.sig)
        );
    }

    /// Derives the second public key under which an ECDSA signature over `summary` verifies.
    ///
    /// Replacing the signature's nonce point `R` with `-R` yields `Q' = -Q - 2 e r^-1 G`.
    fn substitute(
        key: &standard::PublicKey,
        summary: &Summary,
        sig: &standard::Signature,
    ) -> standard::PublicKey {
        // Transcript signatures use an empty namespace, so the signed payload is the summary
        // behind a zero-length namespace prefix.
        let payload = union_unique(b"", summary.as_ref());
        let hash: [u8; 32] = Sha256::digest(&payload).into();
        let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(hash));
        let sig = p256::ecdsa::Signature::from_slice(&sig.encode()).unwrap();
        let r: Scalar = *sig.r();
        let r_inv = r.invert().unwrap();
        let q = p256::PublicKey::from_sec1_bytes(&key.encode())
            .unwrap()
            .to_projective();
        let derived: AffinePoint = (-q - ProjectivePoint::GENERATOR * (e * r_inv).double()).into();
        standard::PublicKey::decode(Copying(derived.to_sec1_point(true).as_bytes())).unwrap()
    }

    /// V1 rejects a [Syn] whose signature verifies under a derived identity.
    ///
    /// Some signature schemes let anyone derive a second public key under which an existing
    /// signature verifies. Under V0 the [Syn] signature does not cover the dialer identity, so a
    /// dialer that signs with its own key can complete the handshake while claiming the derived
    /// key. V1 commits the dialer identity before signing, so the claim fails verification.
    #[test]
    fn test_v1_rejects_derived_identity() {
        for version in VERSIONS {
            let mut rng = test_rng();
            let dialer = standard::PrivateKey::random(&mut rng);
            let listener = standard::PrivateKey::random(&mut rng);

            // The dialer signs a Syn with its own key.
            let (state, syn) = dial_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    version,
                    0,
                    0..1,
                    dialer.clone(),
                    listener.public_key(),
                ),
            );

            // It derives a second identity under which that signature verifies and claims it.
            let (dialer_key, listener_key) = (dialer.public_key(), listener.public_key());
            let signed = syn_transcript(
                version,
                &syn,
                &listener_key,
                version.binds_identity_before_syn().then_some(&dialer_key),
            )
            .summarize();
            let derived = substitute(&dialer_key, &signed, &syn.sig);
            assert_ne!(derived, dialer_key);
            assert!(signed.verify(&derived, &syn.sig));
            let mut claimed = syn_transcript(version, &syn, &listener_key, None);
            claimed.commit(derived.encode());
            let result = listen_start(
                &mut rng,
                Context::new(
                    b"test_namespace",
                    version,
                    0,
                    0..1,
                    listener.clone(),
                    derived.clone(),
                ),
                syn,
            );
            if version == Version::V1 {
                assert!(matches!(result, Err(Error::HandshakeFailed)));
                continue;
            }

            // Under V0 the dialer finishes the exchange under the derived identity.
            let (listen_state, syn_ack) = result.unwrap();
            let state = DialState {
                transcript: claimed,
                ..state
            };
            let (ack, mut send, _) = dial_end(state, syn_ack).unwrap();
            let (_, mut recv) = listen_end(listen_state, ack).unwrap();
            assert_eq!(recv.recv(&send.send(b"hello").unwrap()).unwrap(), b"hello");
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Syn<crate::ed25519::Signature>>,
            CodecConformance<SynAck<crate::ed25519::Signature>>,
            CodecConformance<Ack>,
        }
    }
}
