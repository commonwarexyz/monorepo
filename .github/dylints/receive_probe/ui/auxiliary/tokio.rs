// edition:2021

// Stands in for `tokio` under its crate name, so definition paths match.

// Defines a receiver whose `recv` future never completes.
macro_rules! receiver {
    ($name:ident) => {
        pub struct $name<T>(core::marker::PhantomData<T>);

        impl<T> $name<T> {
            pub fn new() -> Self {
                Self(core::marker::PhantomData)
            }

            pub fn recv(&mut self) -> core::future::Pending<Option<T>> {
                core::future::pending()
            }

            pub fn try_recv(&mut self) -> Result<T, ()> {
                Err(())
            }
        }
    };
}

pub mod sync {
    pub mod mpsc {
        mod bounded {
            receiver!(Receiver);
        }

        mod unbounded {
            receiver!(UnboundedReceiver);
        }

        pub use self::{bounded::Receiver, unbounded::UnboundedReceiver};
    }

    pub mod oneshot {
        use core::{
            future::Future,
            marker::PhantomData,
            pin::Pin,
            task::{Context, Poll},
        };

        pub struct Receiver<T>(PhantomData<T>);

        impl<T> Receiver<T> {
            pub fn new() -> Self {
                Self(PhantomData)
            }

            pub fn try_recv(&mut self) -> Result<T, ()> {
                Err(())
            }
        }

        impl<T> Future for Receiver<T> {
            type Output = Result<T, ()>;

            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Pending
            }
        }
    }

    pub mod watch {
        pub struct Receiver<T>(core::marker::PhantomData<T>);

        impl<T> Receiver<T> {
            pub fn new() -> Self {
                Self(core::marker::PhantomData)
            }

            pub async fn changed(&mut self) -> Result<(), ()> {
                core::future::pending().await
            }

            pub async fn wait_for(&mut self, _: impl FnMut(&T) -> bool) -> Result<(), ()> {
                core::future::pending().await
            }

            pub fn has_changed(&self) -> Result<bool, ()> {
                Ok(false)
            }
        }
    }
}
