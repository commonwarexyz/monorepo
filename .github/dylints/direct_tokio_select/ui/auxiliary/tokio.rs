// edition:2021

// Stands in for `tokio` under its crate name, so definitions match.

#[doc(hidden)]
pub mod support {
    // Stands in for the output of a branch future.
    pub fn output<F: core::future::IntoFuture>(_: F) -> F::Output {
        unimplemented!()
    }
}

// Like tokio's `select!`, recurses through `$crate::select!` to normalize its
// branches before it expands to the polling code.
#[macro_export]
macro_rules! select {
    (@ { $($p:pat = $f:expr => $h:expr,)* }) => {{
        let mut _pending = true;
        $(
            if _pending {
                _pending = false;
                let $p = $crate::support::output($f);
                $h
            }
        )*
    }};
    (biased; $($t:tt)*) => {
        $crate::select!($($t)*)
    };
    ($($p:pat = $f:expr => $h:expr),* $(,)?) => {
        $crate::select!(@ { $($p = $f => $h,)* })
    };
}
