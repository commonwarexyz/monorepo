#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{MarshalInlineInput, fuzz_marshal_deferred};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalInlineInput| {
        fuzz_marshal_deferred(input);
    });
}
