#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        SimplexCertificateMock,
        marshal::{MarshalDisrupterInput, fuzz_marshal_standard_disrupter},
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalDisrupterInput| {
        fuzz_marshal_standard_disrupter::<SimplexCertificateMock>(input);
    });
}
