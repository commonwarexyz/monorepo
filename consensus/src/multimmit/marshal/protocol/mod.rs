//! Pure synchronization and ordering mechanisms.

pub(super) mod ancestry;
pub(super) mod floor;
pub(super) mod order;
pub(super) mod paths;

#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
