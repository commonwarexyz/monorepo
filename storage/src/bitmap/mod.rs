mod authenticated;
pub(crate) use authenticated::partial_chunk_root;
pub use authenticated::{BitMap, Merkleized, Unmerkleized, CleanBitMap, DirtyBitMap, State};
