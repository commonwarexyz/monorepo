/// `crate::merkle::Error<F>`: the variants the lifted code builds.
#[derive(Debug)]
pub enum Error<F: Family> {
    /// The position does not correspond to a leaf node.
    NonLeaf(super::Position<F>),
    /// The position exceeds the valid range.
    PositionOverflow(super::Position<F>),
    /// The location exceeds the valid range.
    LocationOverflow(super::Location<F>),
}
