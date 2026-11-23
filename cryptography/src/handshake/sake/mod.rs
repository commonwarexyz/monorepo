//! Simple Authenticated Key Exchange (SAKE).
//!
//! SAKE establishes a shared secret [Transcript](crate::transcript::Transcript) from signed
//! ephemeral X25519 keys. It uses BLAKE3 and identity signatures from any [Signer](crate::Signer).
//!
//! _This construction is unrelated to [EAP-SAKE] or the [symmetric-key SAKE] protocol._
//!
//! # Protocol
//!
//! Each peer supplies a [Context] with an application namespace, its signer, the expected peer
//! identity, a local timestamp, an accepted peer timestamp range, and a [Version]. Timestamps
//! are in milliseconds. Let `D` and `L` be the public identities, `t_D` and `t_L` their
//! timestamps, and `X` and `Y` their fresh ephemeral public keys.
//!
//! ```text
//! Dialer                                       Listener
//!   |-- Syn(t_D, X, sig_D) ----------------------->|
//!   |<-- SynAck(t_L, Y, sig_L, confirmation_l2d) --|
//!   |-- Ack(confirmation_d2l) -------------------->|
//! ```
//!
//! 1. [dial_start] generates `X` and signs the initial transcript to produce [Syn].
//! 2. [listen_start] checks `t_D` against the accepted range and verifies `sig_D` before
//!    generating `Y` and signing the extended transcript. It rejects a non-contributory X25519
//!    exchange, commits the shared secret, and returns [SynAck] with its key confirmation.
//! 3. [dial_end] checks `t_L`, verifies `sig_L`, and performs the same exchange. It rejects a
//!    non-contributory result or incorrect listener confirmation, then returns [Ack] and the
//!    secret transcript. The dialer must send [Ack] before application data.
//! 4. [listen_end] verifies the dialer's confirmation before returning the same secret
//!    transcript. The listener may then accept application data.
//!
//! # Transcript
//!
//! The transcript commits the application namespace as one packet, then forks it with the
//! version's protocol namespace. V1 then commits a single-byte mode packet containing `1`. V0
//! omits it. Each field below is committed as a separate encoded packet, in order. Signatures
//! authenticate the transcript at the indicated point and are not themselves committed.
//!
//! | Point | V0 fields | V1 fields |
//! |-------|-----------|-----------|
//! | Before `sig_D` | `t_D, L, X` | `t_D, L, D, X` |
//! | Before `sig_L` | `t_D, L, X, D, t_L, Y` | `t_D, L, D, X, t_L, Y` |
//! | Before confirmation | Append the X25519 shared secret | Append the X25519 shared secret |
//!
//! From the final transcript `T`, the confirmations are
//! `T.fork(b"confirmation_l2d").summarize()` and `T.fork(b"confirmation_d2l").summarize()`.
//! Separate labels bind each confirmation to its direction. Successful completion returns `T`
//! for a record protocol to derive its traffic keys.
//!
//! # Versions
//!
//! Both peers must use the same [Version]. Versions have identical message encodings but
//! different signatures and secret transcripts. A mismatch fails signature verification.
//!
//! - [Version::V0] uses `_COMMONWARE_CRYPTOGRAPHY_HANDSHAKE` and
//!   [transcript::Version::V0](crate::transcript::Version::V0). Its fixed packet schema makes
//!   this framing unambiguous. It commits `D` after `sig_D`, so authentication requires a
//!   signature scheme with conservative exclusive ownership: a signature must not also verify
//!   under a substituted public key. Otherwise a dialer can complete the exchange under such
//!   a key if the listener admits it.
//! - [Version::V1] uses `_COMMONWARE_CRYPTOGRAPHY_SAKE` and
//!   [transcript::Version::V1](crate::transcript::Version::V1). Both identities precede every
//!   signature, binding each signer to its declared identity.
//!
//! # Security
//!
//! The listener checks the signed [Syn] before responding. A valid [Syn] can be replayed within
//! the accepted timestamp range. The final confirmation proves possession of this exchange's
//! shared secret. Timestamps alone do not prove fresh participation.
//!
//! Fresh ephemeral secrets provide forward secrecy against later compromise of the identity
//! signing keys, provided the ephemeral secrets and secret transcript state have been erased.
//! Protecting application messages requires a record protocol using keys derived from the
//! transcript.
//!
//! The construction does not hide identities or provide 0-RTT data or resumption. The transcript
//! does not bind a cipher or record format. Peers must agree on them out of band.
//! Callers must enforce a handshake deadline separately from the accepted timestamp range.
//!
//! [EAP-SAKE]: https://www.rfc-editor.org/rfc/rfc4763
//! [symmetric-key SAKE]: https://eprint.iacr.org/2019/444

mod error;
pub use error::Error;

mod exchange;

mod protocol;
pub use protocol::{
    Ack, Context, DialState, ListenState, Syn, SynAck, Version, dial_end, dial_start, listen_end,
    listen_start,
};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
