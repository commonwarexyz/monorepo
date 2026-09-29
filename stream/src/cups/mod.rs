//! Counter Unidirectional Packet Stream (CUPS).
//!
//! CUPS encrypts and authenticates ordered messages using a separate
//! [Cipher](commonware_cryptography::Cipher) per direction. A packet is one framed message on an
//! ordered byte stream.
//!
//! # Setup
//!
//! [Cups] runs its [handshake](crate::Handshake) to obtain a confirmed secret transcript `T`.
//! [V0](Version::V0) uses `T` unchanged. [V1](Version::V1) replaces `T` with
//! `T.fork(b"_COMMONWARE_STREAM_CUPS")`, then commits a single-byte mode packet containing `1`.
//! `Cipher::random(T.noise(b"cipher_l2d"))` derives the listener-to-dialer cipher, and
//! `Cipher::random(T.noise(b"cipher_d2l"))` derives the reverse direction. CUPS wraps these
//! ciphers in [Sender] and [Receiver] halves.
//!
//! Both peers must configure the same [Version] and cipher out of band. These settings are not
//! included in SAKE signatures or confirmations. The caller sets a plaintext message limit no
//! greater than [Cups::MAX_SIZE].
//!
//! # Records
//!
//! Let `m` be a message of `n` bytes and `t` the cipher's fixed tag size. `seal_i(x)` denotes
//! the ciphertext of `x` followed by its tag at cipher position `i`, with empty associated data.
//! Positions advance independently in each direction and are never transmitted.
//!
//! Each record consists of a header followed by a body:
//!
//! | Version | Header | Body | Positions per record |
//! |---------|--------|------|----------------------|
//! | [V0](Version::V0) | `varint_u32(n + t)` | `seal_i(m)` | 1 |
//! | [V1](Version::V1) | `seal_i(BE32(n))` | `seal_(i+1)(m)` | 2 |
//!
//! V0's length prefix is visible and canonical. The receiver bounds it before requesting the
//! body, then authenticates the body at the expected cipher position. Changing the prefix can
//! change how many bytes it waits for, but cannot make it deliver an unauthenticated message.
//!
//! V1's header is exactly `4 + t` bytes. The receiver authenticates and decrypts it, checks the
//! plaintext length against the message limit, then requests and authenticates the `n + t` byte
//! body. A forged header is rejected before any body is requested. An authenticated peer can still
//! announce an allowed length and stall while sending the body.
//!
//! Empty messages are valid records. Batching preserves each record and its cipher positions.
//! No plaintext is delivered until the complete body authenticates.
//!
//! # Security
//!
//! Cipher positions enforce order: modified, replayed, or reordered records cannot authenticate
//! at the next expected position. After a seal or open failure, that half cannot process further
//! records. Callers must discard the connection after an I/O error or cancellation, as required
//! by [crate::Sender] and [crate::Receiver], and after any receive error.
//!
//! V0 exposes record lengths; V1 encrypts the length field. Transport sizes and timing still
//! reveal traffic patterns. CUPS adds no padding or authenticated end-of-stream marker, so it
//! does not establish whether a closed connection delivered every intended message.
//!
//! CUPS does not evolve keys itself. A cipher may rekey internally. Exhaustion requires a new
//! connection.

mod protocol;
pub use protocol::{Cups, Error, Receiver, Sender, Version};
