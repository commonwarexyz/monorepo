//! Exchange messages over arbitrary transport.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#readiness) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::ready_scope;

ready_scope!(GAMMA {
    pub mod encrypted;
    pub mod utils;
});
