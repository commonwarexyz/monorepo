#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz_marshal::marshal::{
        AncestryStreamInput, fuzz_marshal_ancestry_stream,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: AncestryStreamInput| {
        fuzz_marshal_ancestry_stream(input);
    });
}
