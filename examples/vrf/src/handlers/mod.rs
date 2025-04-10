mod arbiter;
mod contributor;
mod utils;
mod vrf;

pub use arbiter::Arbiter;
pub use contributor::Contributor;
pub use vrf::Vrf;

/// The channel used for DKG messages.
pub const DKG_CHANNEL: u32 = 0;

/// The channel used for VRF messages.
pub const VRF_CHANNEL: u32 = 1;

mod wire;
