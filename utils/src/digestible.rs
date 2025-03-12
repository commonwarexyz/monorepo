use crate::Array;

/// Trait for objects that can be digested into a fixed-size array.
pub trait Digestible<D: Array + Copy>: Clone + Send + Sync + 'static {
    /// Compute the digest of this object.
    fn digest(&self) -> D;
}
