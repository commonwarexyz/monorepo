// edition:2021

// Exports a macro that expands to tokio's `select!` in the invoking crate.

#[doc(hidden)]
pub extern crate tokio as __tokio;

#[macro_export]
macro_rules! race {
    ($future:expr) => {
        $crate::__tokio::select! {
            _ = $future => (),
        }
    };
}
