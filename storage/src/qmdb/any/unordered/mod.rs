use crate::qmdb::any::db::Db;

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{Unordered as Operation, update::Unordered as Update};
