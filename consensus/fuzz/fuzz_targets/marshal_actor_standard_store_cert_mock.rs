#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{MarshalActorStoreInput, fuzz_marshal_actor_store};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalActorStoreInput| {
        fuzz_marshal_actor_store(input);
    });
}
