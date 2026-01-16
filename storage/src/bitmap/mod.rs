mod authenticated;
pub use authenticated::{BitMap, CleanBitMap, DirtyBitMap};
pub(crate) use authenticated::partial_chunk_root;
