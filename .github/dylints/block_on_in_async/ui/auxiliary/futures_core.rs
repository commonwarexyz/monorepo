// edition:2021

// Stands in for `futures-core` under its crate name, so definition paths match.

pub mod stream {
    use core::{
        pin::Pin,
        task::{Context, Poll},
    };

    pub trait Stream {
        type Item;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>>;

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
    }
}

pub use self::stream::Stream;
