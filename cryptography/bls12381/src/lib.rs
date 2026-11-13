#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

commonware_macros::stability_scope!(ALPHA {
    extern crate alloc;
});

commonware_macros::stability_mod!(ALPHA, mod core);
commonware_macros::stability_mod!(ALPHA, mod group);
commonware_macros::stability_mod!(ALPHA, mod montgomery);

commonware_macros::stability_scope!(ALPHA {
    #[cfg(feature = "fuzz")]
    pub mod fuzz;
});

commonware_macros::stability_scope!(ALPHA {
    pub use group::{G1, G2, GT, Scalar, multi_pairing, pairing, pairings};
});
