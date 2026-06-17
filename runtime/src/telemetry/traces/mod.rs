//! Utility functions for traces

pub mod status;

#[cfg(any(test, feature = "test-utils"))]
pub mod collector;

/// Records an integer as a numeric tracing field.
///
/// `tracing-opentelemetry` serializes `u64` and `Display`/`Debug` span fields as
/// strings, so integers must be recorded as `i64` to stay range-queryable and
/// correctly sorted in TraceQL. Record integer fields as `field = value.traced()`.
pub trait TracedExt {
    /// Returns `self` as an `i64` for use as a tracing field value.
    fn traced(self) -> i64;
}

macro_rules! impl_traced {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl TracedExt for $ty {
                fn traced(self) -> i64 {
                    i64::try_from(self).unwrap_or(i64::MAX)
                }
            }
        )+
    };
}

macro_rules! impl_traced_signed {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl TracedExt for $ty {
                fn traced(self) -> i64 {
                    i64::try_from(self).unwrap_or(if self < 0 {
                        i64::MIN
                    } else {
                        i64::MAX
                    })
                }
            }
        )+
    };
}

impl_traced!(u8, u16, u32, u64, u128, usize);
impl_traced_signed!(i8, i16, i32, i64, i128, isize);
