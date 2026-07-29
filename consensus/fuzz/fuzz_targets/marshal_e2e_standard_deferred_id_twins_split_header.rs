#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{
        MarshalTwinsInput, fuzz_marshal_standard_deferred_id_twins_split_header,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalTwinsInput| {
        fuzz_marshal_standard_deferred_id_twins_split_header(input);
    });
}
