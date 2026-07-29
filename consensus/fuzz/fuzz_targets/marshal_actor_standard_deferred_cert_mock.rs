#![no_main]
//! Deferred application adapter over standard Marshal.

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{
        fuzz_marshal_actor_deferred, runner::MarshalActorStandardInput,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalActorStandardInput| {
        fuzz_marshal_actor_deferred(input);
    });
}
