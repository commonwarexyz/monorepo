use commonware_cryptography::PublicKey;
use std::time::Duration;

pub struct Config {
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub validators: Vec<PublicKey>,
}
