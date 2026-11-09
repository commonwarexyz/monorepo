// edition:2021

// Stands in for `futures-util` under its crate name, so definition paths match.

pub mod future {
    mod future {
        use core::future::Future;

        pub trait FutureExt: Future {
            fn now_or_never(self) -> Option<Self::Output>
            where
                Self: Sized,
            {
                None
            }
        }

        impl<F: Future + ?Sized> FutureExt for F {}
    }

    pub use self::future::FutureExt;
}
