use std::time::Duration;

pub struct Config {
    pub leader_timeout: Duration,
    pub advance_timeout: Duration,
}
