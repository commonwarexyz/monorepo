//! A host trait for `lo_hosty` (`codec::Write`).
pub trait Write {
    fn write(&self, buf: &mut Vec<u8>);
}
