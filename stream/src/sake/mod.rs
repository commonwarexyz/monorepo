//! Run [Simple Authenticated Key Exchange (SAKE)](commonware_cryptography::handshake::sake) over
//! an ordered byte stream.
//!
//! [Sake] implements [crate::Handshake], returning a confirmed secret transcript. The core SAKE
//! documentation specifies the transcript, authentication checks, and security properties.
//!
//! # Protocol
//!
//! The dialer knows the expected listener identity. It first sends its own public key in a
//! cleartext prelude. The listener passes this unauthenticated claim to its bouncer and proceeds
//! only if accepted, using that identity as the expected peer in SAKE.
//!
//! The peers then exchange SAKE's `Syn`, `SynAck`, and `Ack`. The listener verifies the signed
//! `Syn` before sending `SynAck`. The dialer returns its transcript after sending `Ack`. The
//! listener returns the admitted identity and its transcript only after verifying `Ack`.
//!
//! Verifying `Syn` proves the claim under [Version::V1], which commits both identities before
//! every signature. [Version::V0] signs `Syn` before committing the dialer identity, so it proves
//! the claim only if the signature scheme never lets a signature verify under a public key other
//! than the signer's. With a scheme that admits such key substitution, like ECDSA, a dialer can
//! complete a V0 handshake under a public key other than its own, provided the bouncer admits
//! that key.
//!
//! Every prelude or handshake message has a canonical u32 varint length prefix followed by its
//! encoded bytes. Each frame is bounded by that type's fixed encoded size and decoded exactly.
//! Successful completion leaves subsequent bytes for the record protocol.
//!
//! # Configuration
//!
//! Peers must agree on an application-specific namespace and a SAKE [Version]. Neither is
//! negotiated.
//!
//! Each peer samples its local clock when constructing its SAKE context. The dialer does so
//! before sending `Syn`, and the listener after receiving `Syn`. Peer timestamps must lie in
//! `[now - max_handshake_age, now + synchrony_bound)`, with arithmetic saturated at the u64
//! bounds. The dialer checks `SynAck` against its original window.
//!
//! Callers must enforce a deadline covering the whole attempt, including the bouncer. Discard
//! the connection after handshake failure or cancellation.

mod protocol;
pub use commonware_cryptography::handshake::sake::Version;
pub use protocol::{Error, Sake};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
