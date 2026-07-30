//! Native service primitives for the browser P2P example.
//!
//! [`PairingStore`] is the integration seam between WebSocket admission and an
//! authenticated Commonware handshake. Admission reserves an invite and carries the
//! [`PairingReservation`] in its connection metadata. After the handshake authenticates an
//! Ed25519 public key, the owner consumes the reservation and passes the returned
//! [`PeerAdmission`] to the lookup attachment layer. This crate deliberately does not define
//! either the handshake or a lookup attachment API.

mod assets;
mod pairing;

pub use assets::{Asset, EmbeddedAssets};
pub use pairing::{
    Capability, PairingError, PairingInvite, PairingReservation, PairingStore, PeerAdmission,
    PublicKeyBytes, SessionId,
};
