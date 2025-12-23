//! This module provides an authenticated key exchange protocol, or handshake.
//!
//! # Design
//!
//! The **dialer** and the **listener** both have a public identity, known to each other in advance.
//! The goal of the handshake is to establish a shared, encrypted, and authenticated communication
//! channel between these two parties. No third party should be able to read messages, or send
//! messates along the channel.
//!
//! A three-message handshake is used to authenticate peers and establish a shared secret. The
//! **dialer** initiates the connection, and the **listener** responds.
//!
//! [Syn] The dialer starts by sending a signed message with their ephemeral key.
//!
//! [SynAck] The listener responds by sending back their ephemeral key, along with a signature over the
//! protocol transcript thus far. They can also derive a shared secret, which they use to generate
//! a confirmation tag, also sent to the dialer.
//!
//! [Ack] The dialer verifies the signed message, then derives the same secret, and uses
//! that to send their own confirmation back to the listener.
//!
//! The listener then verifies this confirmation.
//!
//! The shared secret can then be used to derive to AEAD keys, for the sending data ([SendCipher])
//! and receiving data ([RecvCipher]). These use ChaCha20-Poly1305 as the AEAD. Each direction has
//! a 12 byte counter to used as a nonce, with every call to [SendCipher::send] on one end,
//! or [RecvCipher::recv] on the other end incrementing this counter.
//! Note that this guarantees that messages sent are received in order.
//!
//! # Security Features
//!
//! The protocol includes timestamp validation to protect against replay attacks and clock skew:
//! - Messages with timestamps too old are rejected to prevent replay attacks
//! - Messages with timestamps too far in the future are rejected to safeguard against clock skew
use crate::{
    transcript::{Summary, Transcript},
    PublicKey, Signature, Signer, Verifier,
};
use commonware_codec::{Encode, FixedSize, Read, ReadExt, Write};
use core::ops::Range;
use rand_core::CryptoRngCore;

mod error;
pub use error::Error;

mod key_exchange;
use key_exchange::{EphemeralPublicKey, SecretKey};

mod cipher;
pub use cipher::{RecvCipher, SendCipher, CIPHERTEXT_OVERHEAD};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE";
const LABEL_CIPHER_L2D: &[u8] = b"cipher_l2d";
const LABEL_CIPHER_D2L: &[u8] = b"cipher_d2l";
const LABEL_CONFIRMATION_L2D: &[u8] = b"confirmation_l2d";
const LABEL_CONFIRMATION_D2L: &[u8] = b"confirmation_d2l";

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

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
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

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
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

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
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
    transcript: Transcript,
    current_time: u64,
    ok_timestamps: Range<u64>,
    my_identity: S,
    peer_identity: P,
}

impl<S, P> Context<S, P> {
    /// Creates a new handshake context.
    pub fn new(
        base: &Transcript,
        current_time_ms: u64,
        ok_timestamps: Range<u64>,
        my_identity: S,
        peer_identity: P,
    ) -> Self {
        Self {
            transcript: base.fork(NAMESPACE),
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
    rng: impl CryptoRngCore,
    ctx: Context<S, P>,
) -> (DialState<P>, Syn<<S as Signer>::Signature>) {
    let Context {
        current_time,
        ok_timestamps,
        my_identity,
        peer_identity,
        mut transcript,
    } = ctx;
    let esk = SecretKey::new(rng);
    let epk = esk.public();
    let sig = transcript
        .commit(current_time.encode())
        .commit(peer_identity.encode())
        .commit(epk.encode())
        .sign(&my_identity);
    transcript.commit(my_identity.public_key().encode());
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
    let Some(secret) = esk.exchange(&msg.epk) else {
        return Err(Error::HandshakeFailed);
    };
    transcript.commit(secret.as_ref());
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
    rng: &mut impl CryptoRngCore,
    ctx: Context<S, P>,
    msg: Syn<<P as Verifier>::Signature>,
) -> Result<(ListenState, SynAck<<S as Signer>::Signature>), Error> {
    let Context {
        current_time,
        my_identity,
        peer_identity,
        ok_timestamps,
        mut transcript,
    } = ctx;
    if !ok_timestamps.contains(&msg.time_ms) {
        return Err(Error::InvalidTimestamp(msg.time_ms, ok_timestamps));
    }
    if !transcript
        .commit(msg.time_ms.encode())
        .commit(my_identity.public_key().encode())
        .commit(msg.epk.encode())
        .verify(&peer_identity, &msg.sig)
    {
        return Err(Error::HandshakeFailed);
    }
    let esk = SecretKey::new(rng);
    let epk = esk.public();
    let sig = transcript
        .commit(peer_identity.encode())
        .commit(current_time.encode())
        .commit(epk.encode())
        .sign(&my_identity);
    let Some(secret) = esk.exchange(&msg.epk) else {
        return Err(Error::HandshakeFailed);
    };
    transcript.commit(secret.as_ref());
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
    use crate::{ed25519::PrivateKey, transcript::Transcript, Signer};
    use commonware_codec::{Codec, DecodeExt};
    use commonware_math::algebra::Random;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn test_encode_roundtrip<T: Codec<Cfg = ()> + PartialEq>(value: &T) {
        assert!(value == &<T as DecodeExt<_>>::decode(value.encode()).unwrap());
    }

    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Error> {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let dialer_crypto = PrivateKey::random(&mut rng);
        let listener_crypto = PrivateKey::random(&mut rng);

        let (d_state, msg1) = dial_start(
            &mut rng,
            Context::new(
                &Transcript::new(b"test_namespace"),
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
                &Transcript::new(b"test_namespace"),
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

        Ok(())
    }

    #[test]
    fn test_mismatched_namespace_fails() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let dialer_crypto = PrivateKey::random(&mut rng);
        let listener_crypto = PrivateKey::random(&mut rng);

        let (_, msg1) = dial_start(
            &mut rng,
            Context::new(
                &Transcript::new(b"namespace_a"),
                0,
                0..1,
                dialer_crypto.clone(),
                listener_crypto.public_key(),
            ),
        );

        let result = listen_start(
            &mut rng,
            Context::new(
                &Transcript::new(b"namespace_b"),
                0,
                0..1,
                listener_crypto,
                dialer_crypto.public_key(),
            ),
            msg1,
        );

        assert!(matches!(result, Err(Error::HandshakeFailed)));
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
