//! Counter Unidirectional Packet Stream (CUPS).
//!
//! CUPS protects ordered message records using a separate key and implicit counter for each
//! direction. "Packet" refers to a framed message on an ordered byte stream, not a datagram.
//!
//! # Keys
//!
//! [Cups] implements [crate::Transport]. An [crate::Exchange] agrees on one cipher per direction,
//! and [Cups] turns them into the [Sender] and [Receiver] halves. Both peers must use the same
//! [Version] and cipher. Each version has its own [namespace](crate::Transport::namespace).
//!
//! # Records
//!
//! Each message becomes one record, and batching writes preserves record boundaries. Records are
//! sealed by the [Cipher](commonware_cryptography::Cipher) that [Cups] is instantiated with, which
//! appends a fixed-size tag.
//!
//! - Version 0: a visible u32 varint holding the length of the encrypted payload and its tag,
//!   then the encrypted payload and its tag.
//! - Version 1: a header holding the payload length as an encrypted 4-byte big-endian integer and
//!   its tag, then the encrypted payload and its tag.
//!
//! Each direction uses a fixed session key. A record consumes one position of its cipher in
//! version 0 and two in version 1, first for the header and then for the payload. Positions are
//! never transmitted, so replayed, reordered, or corrupted records fail authentication rather than
//! being reordered for delivery. A cipher that can seal no more messages requires a new
//! connection. After a record fails to seal or open, that half refuses every later record.
//!
//! # Security
//!
//! CUPS protects the confidentiality and integrity of each record. Peer authentication and key
//! freshness come from the handshake. Version 0 exposes record lengths and boundaries in the byte
//! stream. Version 1 removes them from the byte stream, but message sizes and timing remain
//! observable through transport segments. There is no padding, in-session key ratchet, or rekeying.
//! Callers must discard the connection after an I/O error or cancellation, as required by
//! [crate::Sender] and [crate::Receiver].

mod protocol;
pub use protocol::{Cups, Error, Receiver, Sender, Version};
