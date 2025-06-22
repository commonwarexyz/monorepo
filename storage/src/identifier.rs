use commonware_utils::Array;

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, I, K: Array> {
    Index(I),
    Key(&'a K),
}
