use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;

/// Target state to sync to
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target<D: Digest> {
    /// The root digest we're syncing to
    pub root: D,
    /// Lower bound of operations to sync (inclusive)
    pub lower_bound_ops: u64,
    /// Upper bound of operations to sync (inclusive)
    pub upper_bound_ops: u64,
}

impl<D: Digest> Write for Target<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.lower_bound_ops.write(buf);
        self.upper_bound_ops.write(buf);
    }
}

impl<D: Digest> EncodeSize for Target<D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size()
            + self.lower_bound_ops.encode_size()
            + self.upper_bound_ops.encode_size()
    }
}

impl<D: Digest> Read for Target<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let lower_bound_ops = u64::read(buf)?;
        let upper_bound_ops = u64::read(buf)?;
        Ok(Self {
            root,
            lower_bound_ops,
            upper_bound_ops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use std::io::Cursor;

    #[test]
    fn test_sync_target_serialization() {
        let target = Target {
            root: sha256::Digest::from([42; 32]),
            lower_bound_ops: 100,
            upper_bound_ops: 500,
        };

        // Serialize
        let mut buffer = Vec::new();
        target.write(&mut buffer);

        // Verify encoded size matches actual size
        assert_eq!(buffer.len(), target.encode_size());

        // Deserialize
        let mut cursor = Cursor::new(buffer);
        let deserialized = Target::read(&mut cursor).unwrap();

        // Verify
        assert_eq!(target, deserialized);
        assert_eq!(target.root, deserialized.root);
        assert_eq!(target.lower_bound_ops, deserialized.lower_bound_ops);
        assert_eq!(target.upper_bound_ops, deserialized.upper_bound_ops);
    }
}
