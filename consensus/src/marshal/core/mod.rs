//! Marshal core logic. TODO

#![allow(dead_code)]

mod actor;
pub use actor::Actor;

mod cache;

mod mailbox;
pub use mailbox::Mailbox;

mod variant;
pub use variant::{BlockBuffer, Variant};
