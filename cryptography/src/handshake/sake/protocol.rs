use super::{
    Error,
    key_exchange::{EphemeralPublicKey, SecretKey},
};
use crate::{
    Cipher, PublicKey, Signature, Signer, Verifier,
    transcript::{self, Summary, Transcript},
};
use commonware_codec::{Buf, Encode, FixedSize, Read, ReadExt, Write};
use core::ops::Range;
use rand_core::CryptoRng;

const LABEL_CIPHER_L2D: &[u8] = b"cipher_l2d";
const LABEL_CIPHER_D2L: &[u8] = b"cipher_d2l";
const LABEL_CONFIRMATION_L2D: &[u8] = b"confirmation_l2d";
const LABEL_CONFIRMATION_D2L: &[u8] = b"confirmation_d2l";

/// Transcript schema used by a SAKE handshake.
///
/// The version is part of the protocol definition: both peers must agree on it out of band.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Version {
    /// Commits the dialer identity after the [Syn] signature. If the signature scheme lacks
    /// conservative exclusive ownership (it admits key substitution), a dialer can complete a
    /// handshake under a public key other than its own under which its [Syn] signature also
    /// verifies.
    V0,
    /// Commits both identities before every signature and uses injective transcript framing.
    V1,
}

impl Version {
    /// Returns the protocol namespace forked from the application namespace.
    ///
    /// Each version must produce transcripts that no other version produces. V0 and V1 rely on this
    /// namespace for that, because after [Syn] their transcripts can otherwise commit identical
    /// bytes.
    const fn namespace(self) -> &'static [u8] {
        match self {
            Self::V0 => b"_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE",
            Self::V1 => b"_COMMONWARE_CRYPTOGRAPHY_SAKE",
        }
    }

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
/// Tracks expected confirmation and the transcript that derives the ciphers.
pub struct ListenState {
    confirmation: Summary,
    transcript: Transcript,
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
        let transcript = Transcript::new(namespace, version.transcript());
        Self {
            version,
            transcript,
            current_time: current_time_ms,
            ok_timestamps,
            my_identity,
            peer_identity,
        }
    }

    /// Forks the transcript with the label of a protocol built on SAKE.
    ///
    /// SAKE forks its own protocol namespace after every label added here, so handshakes that
    /// different protocols run with the same application namespace do not share a transcript.
    pub fn fork(mut self, label: &'static [u8]) -> Self {
        self.transcript = self.transcript.fork(label);
        self
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
        transcript,
    } = ctx;
    let mut transcript = transcript.fork(version.namespace());
    let esk = SecretKey::new(rng);
    let epk = esk.public();
    let dialer_identity = my_identity.public_key().encode();
    transcript
        .commit(current_time.encode())
        .commit(peer_identity.encode());

    // V1 commits the dialer identity before signing so the [Syn] signature covers it. V0 commits it
    // after.
    if version.binds_identity_before_syn() {
        transcript.commit(&dialer_identity[..]);
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
/// Verifies the listener's response and returns final message and the send and receive ciphers.
pub fn dial_end<C: Cipher, P: PublicKey>(
    state: DialState<P>,
    msg: SynAck<<P as Verifier>::Signature>,
) -> Result<(Ack, C, C), Error> {
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
    let recv = C::random(transcript.noise(LABEL_CIPHER_L2D));
    let send = C::random(transcript.noise(LABEL_CIPHER_D2L));
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
        transcript,
    } = ctx;
    let mut transcript = transcript.fork(version.namespace());
    if !ok_timestamps.contains(&msg.time_ms) {
        return Err(Error::InvalidTimestamp(msg.time_ms, ok_timestamps));
    }
    let dialer_identity = peer_identity.encode();
    transcript
        .commit(msg.time_ms.encode())
        .commit(my_identity.public_key().encode());

    // Commit the dialer identity where the dialer did: before verifying the [Syn] signature under
    // V1 and after under V0.
    if version.binds_identity_before_syn() {
        transcript.commit(&dialer_identity[..]);
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
    let confirmation_l2d = transcript.fork(LABEL_CONFIRMATION_L2D).summarize();
    let confirmation_d2l = transcript.fork(LABEL_CONFIRMATION_D2L).summarize();

    Ok((
        ListenState {
            confirmation: confirmation_d2l,
            transcript,
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
/// Verifies the dialer's confirmation and returns the send and receive ciphers.
pub fn listen_end<C: Cipher>(state: ListenState, msg: Ack) -> Result<(C, C), Error> {
    if msg.confirmation != state.confirmation {
        return Err(Error::HandshakeFailed);
    }

    // Derive the ciphers only after the dialer proves it holds the same transcript.
    let send = C::random(state.transcript.noise(LABEL_CIPHER_L2D));
    let recv = C::random(state.transcript.noise(LABEL_CIPHER_D2L));
    Ok((send, recv))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{ChaCha20Poly1305, Signer, ed25519::PrivateKey, secp256r1::standard};
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

    /// Seals `msg` with `send` and checks that `recv` opens it.
    fn exchange<C: Cipher>(send: C, recv: C, msg: &[u8]) {
        let mut data = msg.to_vec();
        let (_, tag) = send.seal(&[], &mut data).unwrap();
        recv.open(&[], &mut data, &tag).unwrap();
        assert_eq!(data, msg);
    }

    /// Completes a handshake under each [Version] and exchanges a message in each direction.
    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Error> {
        for version in VERSIONS {
            let mut rng = test_rng();
            let dialer_crypto = PrivateKey::random(&mut rng);
            let listener_crypto = PrivateKey::random(&mut rng);

            // Run the three-message handshake and check each message round-trips through its codec.
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
            let (msg3, d_send, d_recv) = dial_end::<ChaCha20Poly1305, _>(d_state, msg2)?;
            test_encode_roundtrip(&msg3);
            let (l_send, l_recv) = listen_end::<ChaCha20Poly1305>(l_state, msg3)?;

            // Each send cipher pairs with the peer's receive cipher.
            exchange(d_send, l_recv, b"message 1");
            exchange(l_send, d_recv, b"message 2");
        }

        Ok(())
    }

    /// Rejects a [Syn] signed under a different application namespace.
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

    /// Accepts a [Syn] only when the dialer and listener fork the transcript with the same labels.
    #[test]
    fn test_mismatched_fork_fails() {
        let fork = |context: Context<_, _>, label: Option<&'static [u8]>| match label {
            Some(label) => context.fork(label),
            None => context,
        };
        for version in VERSIONS {
            for (dialer_label, listener_label) in [
                (Some(&b"a"[..]), Some(&b"a"[..])),
                (Some(b"a"), Some(b"b")),
                (Some(b"a"), None),
                (None, Some(b"a")),
            ] {
                let mut rng = test_rng();
                let dialer_crypto = PrivateKey::random(&mut rng);
                let listener_crypto = PrivateKey::random(&mut rng);

                let (_, msg1) = dial_start(
                    &mut rng,
                    fork(
                        Context::new(
                            b"namespace",
                            version,
                            0,
                            0..1,
                            dialer_crypto.clone(),
                            listener_crypto.public_key(),
                        ),
                        dialer_label,
                    ),
                );

                let result = listen_start(
                    &mut rng,
                    fork(
                        Context::new(
                            b"namespace",
                            version,
                            0,
                            0..1,
                            listener_crypto,
                            dialer_crypto.public_key(),
                        ),
                        listener_label,
                    ),
                    msg1,
                );

                // Only matching labels produce the transcript the dialer signed.
                if dialer_label == listener_label {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(result, Err(Error::HandshakeFailed)));
                }
            }
        }
    }

    /// Rejects a [Syn] from a dialer running a different [Version].
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

    /// Rejects a [Syn] when the listener expects a different dialer identity.
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
            Transcript::new(b"test_namespace", version.transcript()).fork(version.namespace());
        transcript
            .commit(syn.time_ms.encode())
            .commit(listener.encode());
        if let Some(dialer) = dialer {
            transcript.commit(dialer.encode());
        }
        transcript.commit(syn.epk.encode());
        transcript
    }

    /// Checks that a V1 [Syn] signature covers the dialer identity.
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

    /// Checks that a V0 [Syn] signature omits the dialer identity.
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

        // The signature is only valid over a transcript that omits the dialer identity.
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

            // Rebuild the dialer transcript with the derived identity in its V0 position.
            let mut claimed = syn_transcript(version, &syn, &listener_key, None);
            claimed.commit(derived.encode());
            let result = listen_start(
                &mut rng,
                Context::new(b"test_namespace", version, 0, 0..1, listener, derived),
                syn,
            );

            // V1 fails the [Syn] signature check because the signature covers the real dialer
            // identity.
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
            let (ack, send, _) = dial_end::<ChaCha20Poly1305, _>(state, syn_ack).unwrap();
            let (_, recv) = listen_end::<ChaCha20Poly1305>(listen_state, ack).unwrap();
            exchange(send, recv, b"hello");
        }
    }
}
