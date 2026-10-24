//! Shared sync test harnesses.
//!
//! [`full`] covers databases that retain their operation history, and [`compact`] covers
//! compact databases that retain only a witness for each applied batch.

mod compact;
mod full;

pub(crate) use compact::*;
pub(crate) use full::*;
