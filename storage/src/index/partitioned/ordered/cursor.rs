//! A mutable cursor over a single translated key's values.

/// A [crate::index::Cursor] over a materialized live overlay run.
pub type Cursor<'a, V> = crate::index::storage::RunCursor<'a, V>;
