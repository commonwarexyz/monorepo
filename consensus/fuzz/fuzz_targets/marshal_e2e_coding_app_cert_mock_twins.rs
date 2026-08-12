#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        SimplexCertificateMock,
        marshal::{MarshalTwinsInput, fuzz_marshal_coding_twins},
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalTwinsInput| {
        fuzz_marshal_coding_twins::<SimplexCertificateMock>(input);
    });
}
