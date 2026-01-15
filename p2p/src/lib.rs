//! Communicate with authenticated peers over encrypted connections.
//!
//! # Status
//!
//! See the [readiness page](https://commonware.xyz/readiness.html) for this module's
//! maturity level and stability guarantees.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod authenticated;
mod core;
pub mod simulated;
pub mod types;
pub mod utils;

pub use core::{
    Blocker, Channel, CheckedSender, LimitedSender, Manager, Message, Receiver, Recipients, Sender,
    UnlimitedSender,
};
pub use types::{Address, Ingress};
