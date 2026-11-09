// edition:2021

// Stands in for `commonware_p2p` under its crate name, so definition paths match.

use core::future::Future;

pub trait Receiver {
    fn recv(&mut self) -> impl Future<Output = Result<u8, ()>>;
}

pub mod simulated {
    mod network {
        pub struct Receiver;

        impl Receiver {
            pub fn try_recv(&mut self) -> Result<u8, ()> {
                Err(())
            }
        }

        impl crate::Receiver for Receiver {
            fn recv(&mut self) -> impl core::future::Future<Output = Result<u8, ()>> {
                core::future::pending()
            }
        }
    }

    pub use self::network::Receiver;
}

pub mod authenticated {
    pub struct Receiver;

    impl crate::Receiver for Receiver {
        fn recv(&mut self) -> impl core::future::Future<Output = Result<u8, ()>> {
            core::future::pending()
        }
    }
}
