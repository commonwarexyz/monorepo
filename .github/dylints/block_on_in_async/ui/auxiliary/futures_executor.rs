// edition:2021

// Stands in for `futures-executor` under its crate name, so definition paths match.

mod local_pool {
    pub fn block_on<F: core::future::Future>(_: F) -> F::Output {
        unimplemented!()
    }
}

pub use self::local_pool::block_on;

// Expands to a nested executor in the crate that invokes it.
#[macro_export]
macro_rules! run {
    ($future:expr) => {
        $crate::block_on($future)
    };
}
