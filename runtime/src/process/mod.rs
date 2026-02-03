//! Process implementations.

#[cfg(not(target_arch = "wasm32"))]
commonware_macros::stability_mod!(BETA, pub mod metered);
