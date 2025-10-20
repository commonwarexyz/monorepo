mod arbiter;
mod contributor;
mod vrf;

pub use arbiter::Arbiter;
pub use contributor::Contributor;
pub use vrf::Vrf;

/// The channel used for DKG messages.
pub const DKG_CHANNEL: u64 = 0;

/// The channel used for VRF messages.
pub const VRF_CHANNEL: u64 = 1;

/// The namespace used for DKG ack signatures.
pub const ACK_NAMESPACE: &[u8] = b"DKG_ACK";

mod wire;
