//! Scalar execution with single-lane common vectors and four-word registers.

/// Scalar execution token with one lane of each common element type.
/// Fixed four-word registers retain four lanes.
///
/// Executes the portable operation path.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedScalar;

super::common::impl_common!(EmulatedScalar, 1, 1, 1, portable);

#[cfg(test)]
mod tests {
    use super::EmulatedScalar;
    #[test]
    fn common_contracts() {
        super::super::test_utils::common(EmulatedScalar);
        super::super::test_utils::basic_common(EmulatedScalar);
    }
}
