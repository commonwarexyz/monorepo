#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::types::TermLength;
use commonware_consensus_fuzz::{
    SimplexCertificateMock, fuzz_node,
    simplex_node::{NodeFuzzInput, WithRecovery},
};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU32;

// Dedicated stable-term recovery coverage: every run uses a term length of
// 2-5, so across the corpus the scripted traffic, floors, and the
// unclean-shutdown restart land at varied within-term offsets and recovery
// resumes against term-anchored entry rules. Any single run's durable floor
// is not guaranteed to be mid-term; with most views inside a term at these
// lengths, corpus coverage supplies that case. Rotation (term length one)
// stays covered by the ordinary node targets.
fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(term_length) = u.int_in_range(2u32..=5) else {
        return;
    };
    let Ok(mut input) = NodeFuzzInput::arbitrary(&mut u) else {
        return;
    };
    input.term_length =
        TermLength::new(NonZeroU32::new(term_length).expect("sampled range is non-zero"));
    fuzz_node::<SimplexCertificateMock, WithRecovery>(input);
});
