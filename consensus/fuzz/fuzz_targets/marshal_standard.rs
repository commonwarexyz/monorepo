#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{fuzz_marshal_standard, MarshalStandardInput};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalStandardInput| {
        fuzz_marshal_standard(input);
    });
}
