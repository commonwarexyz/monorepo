//! Scalar execution with 64-bit-wide common vectors and four-word registers.

/// Scalar execution token with eight byte, two u32, and one u64 lane.
/// Fixed four-word registers retain four lanes.
///
/// Executes the portable operation path.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedScalar;

super::common::impl_common!(EmulatedScalar, 8, 2, 1, false, portable);

#[cfg(test)]
mod tests {
    use super::EmulatedScalar;
    use crate::Simd;

    #[test]
    fn common_contracts() {
        super::super::test_utils::common(EmulatedScalar);
        super::super::test_utils::basic_common(EmulatedScalar);
    }

    #[test]
    fn widening_splits_two_lanes() {
        let simd = EmulatedScalar;
        assert_eq!(
            simd.u32_widen_mul_first([u32::MAX, 5], [3, 7]),
            [3 * u64::from(u32::MAX)]
        );
        assert_eq!(simd.u32_widen_mul_second([u32::MAX, 5], [3, 7]), [35]);
        assert_eq!(simd.u64_narrow_pair([1 << 32 | 7], [9]), [7, 9]);
    }
}
