#![no_main]

use commonware_actor_fuzz::{fuzz_coalesce, CoalesceFuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: CoalesceFuzzInput| {
    fuzz_coalesce(input);
});
