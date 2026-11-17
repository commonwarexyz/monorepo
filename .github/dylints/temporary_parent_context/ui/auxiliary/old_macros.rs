// compile-flags: --edition=2021

/// Wraps an expression in a block whose span has an edition before 2024.
#[macro_export]
macro_rules! wrap {
    ($e:expr) => {{ $e }};
}
