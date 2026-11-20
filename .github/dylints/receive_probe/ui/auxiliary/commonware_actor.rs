// edition:2021

// Stands in for `commonware_actor` under its crate name, so definition paths match.

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

pub mod mailbox {
    receiver!(Receiver);
    receiver!(UnreliableReceiver);
}
