#![no_main]
//! Inline application adapter over standard Marshal.

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::marshal::{
        fuzz_marshal_actor_inline, runner::MarshalActorStandardInput,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalActorStandardInput| {
        fuzz_marshal_actor_inline(input);
    });
}
