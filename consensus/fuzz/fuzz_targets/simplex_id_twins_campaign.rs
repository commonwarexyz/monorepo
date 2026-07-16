#![no_main]

use commonware_consensus_fuzz::{CodeCoverage, FuzzInput, SimplexId, TwinsCampaign, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsCampaign, CodeCoverage>(input);
});
