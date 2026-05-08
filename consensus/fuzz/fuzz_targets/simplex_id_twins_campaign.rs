#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexId, TwinsCampaign};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsCampaign>(input);
});
