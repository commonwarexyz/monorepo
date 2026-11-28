mod dkg;
pub(crate) mod mocks;
mod reshare;

use commonware_cryptography::bls::sharing::ModeVersion;

pub(crate) const fn max_supported_mode() -> ModeVersion {
    ModeVersion::v1()
}
