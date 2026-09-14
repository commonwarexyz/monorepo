#![no_main]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use commonware_cryptography::reed_solomon::engine::Avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use commonware_cryptography_fuzz::reed_solomon::{FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fuzz_target!(|input: FuzzInput| {
    if std::arch::is_x86_feature_detected!("avx2") {
        fuzz::<Avx2>(input);
    }
});

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fuzz_target!(|_input: &[u8]| {});
