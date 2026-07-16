#![no_main]

use commonware_actor_fuzz::{CoalesceFuzzInput, fuzz_coalesce};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: CoalesceFuzzInput| {
    fuzz_coalesce(input);
});
