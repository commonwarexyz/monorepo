#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus_fuzz::{run_quint_tlc_honest_model, FuzzInput};
use libfuzzer_sys::{fuzz_target, Corpus};

// `Corpus::Reject` is returned only when the controlled TLC server reports
// that this input added no new state fingerprints. Every other outcome
// (arbitrary parse failure, pipeline failure, unreachable server, ...)
// returns `Corpus::Keep` so the corpus is only ever pruned by genuine
// "made no progress" verdicts from TLC.
fuzz_target!(|data: &[u8]| -> Corpus {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return Corpus::Reject;
    };
    run_quint_tlc_honest_model(input, data)
});
