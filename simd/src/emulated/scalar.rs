//! Scalar execution with 64-bit-wide common vectors and four-word registers.

/// Scalar execution token with eight byte, two u32, and one u64 lane.
/// Fixed four-word registers retain four lanes.
///
/// Executes the portable operation path.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedScalar;

super::common::impl_common!(EmulatedScalar, 8, 2, 1, portable);

#[cfg(test)]
mod tests {
    use super::EmulatedScalar;
    #[test]
    fn common_contracts() {
        super::super::test_utils::common(EmulatedScalar);
        super::super::test_utils::basic_common(EmulatedScalar);
    }
}
