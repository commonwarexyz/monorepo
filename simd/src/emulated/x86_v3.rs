//! Emulation of the x86-64-v3 (AVX2) common-instruction backend.

/// Emulated x86-64-v3 execution token with 32 byte, eight u32, and four u64 lanes.
///
/// Executes the portable operation path at the native x86-64-v3 vector width without
/// requiring native hardware features.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedX86V3;

super::common::impl_common!(EmulatedX86V3, 32, 8, 4, portable);

#[cfg(test)]
mod tests {
    use super::EmulatedX86V3;

    #[test]
    fn common_contracts() {
        super::super::test_utils::common(EmulatedX86V3);
        super::super::test_utils::basic_common(EmulatedX86V3);
    }
}
