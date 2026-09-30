//! A private helper module.
pub(crate) fn helper(x: u32) -> u32 {
    x.wrapping_mul(2)
}

pub(super) const K: u32 = 3;
