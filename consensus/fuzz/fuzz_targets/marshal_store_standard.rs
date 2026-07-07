#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{fuzz_marshal_store, MarshalStoreInput};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalStoreInput| {
        fuzz_marshal_store(input);
    });
}
