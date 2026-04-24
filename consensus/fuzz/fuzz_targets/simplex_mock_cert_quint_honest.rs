#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_consensus_fuzz::{
        tracing::run_quint_honest_tracing_for, FuzzInput, SimplexCertificateMock,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        let mut u = Unstructured::new(data);
        let Ok(input) = FuzzInput::arbitrary(&mut u) else {
            return;
        };
        run_quint_honest_tracing_for::<SimplexCertificateMock>(
            "simplex_mock_cert_quint_honest",
            input,
            data,
        );
    });
}

#[cfg(not(feature = "mocks"))]
fn main() {}
