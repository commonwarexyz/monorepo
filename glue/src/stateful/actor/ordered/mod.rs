//! The ordered mode's actor: pending state for the executed chain, and its application.

mod actor;
pub use actor::{Config, Stateful};
mod mailbox;
pub use mailbox::Mailbox;
