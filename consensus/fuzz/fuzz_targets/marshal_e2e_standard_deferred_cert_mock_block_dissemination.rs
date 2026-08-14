#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        SimplexCertificateMockByzantineFirstLeader,
        marshal::{MarshalDisrupterInput, fuzz_marshal_standard_block_dissemination},
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalDisrupterInput| {
        fuzz_marshal_standard_block_dissemination::<SimplexCertificateMockByzantineFirstLeader>(
            input,
        );
    });
}
