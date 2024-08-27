mod arbiter;
mod contributor;
mod payloads;
mod utils;
mod vrf;

pub use arbiter::Arbiter;
pub use contributor::Contributor;
pub use vrf::Vrf;

pub const DKG_CHANNEL: u32 = 0;
pub const VRF_CHANNEL: u32 = 1;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
