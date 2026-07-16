#![no_main]

use commonware_consensus_fuzz::{FuzzInput, SimplexId, StateCoverage, TwinsCampaign, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsCampaign, StateCoverage>(input);
});
