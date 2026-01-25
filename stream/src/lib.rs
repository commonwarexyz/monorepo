//! Exchange messages over arbitrary transport.
//!
//! # Status
//!
//! `commonware-stream` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::ready_scope;

ready_scope!(2 {
    pub mod encrypted;
    pub mod utils;
});
