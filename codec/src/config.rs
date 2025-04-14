use std::ops::RangeBounds;

/// Marker trait for types that can be used as configuration during decoding.
///
/// Configuration is primarily used with the [`Read`] trait to pass parameters (like size limits)
/// needed to safely decode untrusted data. Types implementing `Config` must also be
/// `Clone + Send + 'static`.
///
/// Use the unit type `()` if no configuration is required for a specific [`Read`] implementation.
pub trait Config: Copy + Clone + Send + Sync + 'static {}

// Automatically implement `Config` for matching types.
impl<T: Copy + Clone + Send + Sync + 'static> Config for T {}

/// A marker trait for a [`Config`] type that is also a [`RangeBounds<usize>`].
///
/// This is often used to configure length limits for variable-length collections like `Vec<T>` or
/// `Bytes`.
pub trait RangeConfig: Config + RangeBounds<usize> {}

// Automatically implement `RangeConfig` for matching types.
impl<T: Config + RangeBounds<usize>> RangeConfig for T {}

#[derive(Copy, Clone, Debug)]
pub struct Pair<OCfg: Config, ICfg: Config>(pub OCfg, pub ICfg);

impl<C: Config, E: Config + From<()>> From<C> for Pair<C, E> {
    fn from(cfg: C) -> Self {
        Pair(cfg, E::from(()))
    }
}

impl<OCfg: Config, ICfg: Config> From<(OCfg, ICfg)> for Pair<OCfg, ICfg> {
    fn from((outer, inner): (OCfg, ICfg)) -> Self {
        Pair(outer, inner)
    }
}
