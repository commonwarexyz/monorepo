use std::env;

pub(crate) const SAMPLES_ENV: &str = "COMMONWARE_CLEARING_SAMPLES";
const DEFAULT_SAMPLES: usize = 3;
const MAX_SAMPLES: usize = 100;

pub(crate) fn samples() -> usize {
    env::var(SAMPLES_ENV)
        .map_or(Ok(DEFAULT_SAMPLES), |value| value.parse())
        .ok()
        .filter(|samples| (1..=MAX_SAMPLES).contains(samples))
        .unwrap_or_else(|| panic!("{SAMPLES_ENV} must be an integer between 1 and {MAX_SAMPLES}"))
}
