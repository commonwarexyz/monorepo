#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
// The stateful actor's future nests every database's startup, past the default limit of 128.
#![recursion_limit = "256"]

commonware_macros::stability_scope!(ALPHA {
    pub mod dkg;
    pub mod stateful;
    pub mod transfers;

    #[cfg(any(test, feature = "test-utils"))]
    pub mod simulate;
});
