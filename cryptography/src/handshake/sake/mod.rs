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
//! derivation, any [Signer](crate::Signer) for identity signatures, and any
//! [Cipher](crate::Cipher) for the two directional traffic ciphers.
//!
//! Both public identities are inputs to the core exchange and are incorporated into the transcript
//! with the timestamps, ephemeral keys, and shared secret in a fixed order. Identities are visible,
//! not hidden by the construction. SAKE has no 0-RTT mode or resumption mechanism. Application
//! data can be sent only after the three messages complete.
//!
//! The BLAKE3 transcript first commits the caller-provided application namespace as one packet. A
//! protocol built on SAKE may then fork it with its own label ([Context::fork]). SAKE then forks it
//! with the protocol namespace of the [Version]: `_COMMONWARE_CRYPTOGRAPHY_SAKE` for [Version::V1]
//! and `_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE` for [Version::V0]. Distinct labels derive the
//! listener-to-dialer and dialer-to-listener traffic keys and confirmations. These namespace bytes,
//! transcript order, and labels are protocol constants.
//!
//! # Versions
//!
//! [Version] selects the transcript schema. Both peers must use the same version. A mismatch fails
//! signature verification. The message encodings are identical across versions.
//!
//! - [Version::V0] signs [Syn] over the timestamp, listener identity, and ephemeral key, and
//!   commits the dialer identity only afterwards. If the signature scheme lacks conservative
//!   exclusive ownership (it admits key substitution), a dialer can complete a handshake under a
//!   public key other than its own under which its [Syn] signature also verifies. Whether such a
//!   key can match one a listener admits depends on the signature scheme. V0 uses
//!   [transcript::Version::V0](crate::transcript::Version::V0), which is sound here because SAKE
//!   commits a fixed sequence of canonical encodings at fixed positions.
//! - [Version::V1] commits both identities before every signature, so each signature covers the
//!   signer's own identity, and uses [transcript::Version::V1](crate::transcript::Version::V1).
//!
//! # Timing
//!
//! Callers provide the accepted timestamp range to limit replay and clock skew. Because this core
//! performs no I/O, callers must separately enforce deadlines around the handshake to bound stalled
//! attempts.
//!
//! [EAP-SAKE]: https://www.rfc-editor.org/rfc/rfc4763
//! [symmetric-key SAKE]: https://eprint.iacr.org/2019/444

mod error;
pub use error::Error;

mod key_exchange;

mod protocol;
pub use protocol::{
    Ack, Context, DialState, ListenState, Syn, SynAck, Version, dial_end, dial_start, listen_end,
    listen_start,
};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
