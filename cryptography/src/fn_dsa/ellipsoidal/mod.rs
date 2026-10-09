//! Experimental gamma-6 ellipsoidal Falcon with a distinct wire format.
//!
//! This profile is not standard Falcon or FN-DSA. Its finite key distribution,
//! rejection policy, and numerical implementation require independent security
//! analysis; the estimates in the ellipsoidal-signatures paper do not certify it.

extern crate alloc;

mod api;
mod codec;
mod kgen;
mod sign;
mod transcript;
mod verify;

use api::KeyMaterial;
pub(super) use api::{keygen, sign, signature_is_well_formed};
use transcript::{message_representative_from_hash, public_key_hash};
pub use verify::VerifyingKey;

pub(super) const PUBLIC_KEY_SIZE: usize = 897;
pub(super) const SIGNATURE_SIZE: usize = 512;
pub(super) const PUBLIC_KEY_HEADER: u8 = 0xE1;
pub(super) const SIGNATURE_HEADER: u8 = 0xE2;
