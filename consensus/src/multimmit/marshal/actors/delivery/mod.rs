//! Delivery: reports committed outputs to the application in output order.
//!
//! Delivery owns the durable acknowledgement cursor. After a crash it redelivers every output
//! after that cursor, so an application acknowledges an output only once it has durably applied
//! it.
//!
//! # Lifecycle
//!
//! 1. The catalog publishes a commit and sends its outputs in a [`DurableBatch`], with bodies it
//!    still holds in memory.
//! 2. Delivery reports each output after its cursor: from the batch when it carries the body,
//!    otherwise read back from custody.
//! 3. The application acknowledges outputs in any order; contiguous acknowledgements coalesce
//!    into one ready prefix.
//! 4. Delivery syncs the ready prefix to its cursor, one sync at a time, and tells the catalog.
//!
//! A floor installation resets the cursor to the new generation and drops the window.
//!
//! The catalog needs delivery's mailbox before delivery exists, and delivery reads committed
//! outputs through the catalog, so [`channel`] creates the mailbox first.

mod acks;
mod actor;
mod batch;
mod cache;
mod cursor;
mod mailbox;
mod metrics;

#[cfg(test)]
mod tests;

pub(crate) use actor::{Actor, Bounds, Config, Error};
pub(crate) use batch::{DeliveryOutput, DurableBatch, HotOutput, body_bytes, descriptor_bytes};
pub(crate) use cursor::{CatalogCut, DeliveryCursor};
#[cfg(test)]
pub(crate) use mailbox::Message;
pub(crate) use mailbox::{Mailbox, Receiver, ResetWaiter, channel};
