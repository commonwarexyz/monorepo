//! A runtime feature detection: `sm4` is not enabled statically on the
//! extraction's target, so the answer is a run-time value (refused).
/// Whether the CPU has the SM4 instructions.
pub fn has_sm4() -> bool {
    std::arch::is_aarch64_feature_detected!("sm4")
}
