//! Shared traits and codecs for QMDB operations.

use crate::merkle::{Family, Location};
use commonware_codec::{
    CodecShared, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
    util::ensure_zeros,
};
use commonware_runtime::{Buf, BufMut};
use core::{fmt::Debug, hash::Hash, ops::Deref};

/// Trait bound for key types used in QMDB operations. Satisfied by both fixed-size keys
/// (`Array` types) and variable-length keys (`Vec<u8>`).
pub trait Key:
    CodecShared + Clone + 'static + Eq + Ord + Hash + AsRef<[u8]> + Deref<Target = [u8]> + Debug
{
}

impl<T> Key for T where
    T: CodecShared + Clone + 'static + Eq + Ord + Hash + AsRef<[u8]> + Deref<Target = [u8]> + Debug
{
}

/// An operation that may be a commit. Commits declare an inactivity floor.
pub trait Committable<F: Family> {
    /// The inactivity floor if this operation is a commit.
    fn floor(&self) -> Option<Location<F>>;

    /// The commit a freshly initialized database holds: no metadata, inactivity floor 0.
    fn initial_commit() -> Self;

    /// If this operation is a commit.
    fn is_commit(&self) -> bool {
        self.floor().is_some()
    }
}

/// An operation that can be applied to a database.
pub trait Operation<F: Family>: Committable<F> {
    /// The key type for this operation.
    type Key: Key;

    /// Returns the key if this operation involves a key, None otherwise.
    fn key(&self) -> Option<&Self::Key>;

    /// Consumes the operation and returns its owned key, if any.
    fn into_key(self) -> Option<Self::Key>;

    /// If this operation updates its key's value.
    fn is_update(&self) -> bool;

    /// If this operation deletes its key's value.
    fn is_delete(&self) -> bool;
}

/// Unpadded size of a fixed-encoded commit operation, context byte included.
pub(crate) const fn commit_fixed_operation_size<V: FixedSize>() -> usize {
    1 + 1 + V::SIZE + u64::SIZE
}

/// Writes a commit's optional metadata and inactivity floor in the fixed encoding.
pub(crate) fn write_commit_fixed<F: Family, V: Write + FixedSize>(
    metadata: &Option<V>,
    floor: Location<F>,
    buf: &mut impl BufMut,
) {
    if let Some(value) = metadata {
        true.write(buf);
        value.write(buf);
    } else {
        buf.put_bytes(0, 1 + V::SIZE);
    }
    buf.put_slice(&floor.as_u64().to_be_bytes());
}

/// Reads a commit's optional metadata and inactivity floor from the fixed encoding.
pub(crate) fn read_commit_fixed<F: Family, V: Read<Cfg = ()> + FixedSize>(
    buf: &mut impl Buf,
) -> Result<(Option<V>, Location<F>), CodecError> {
    let metadata = if bool::read(buf)? {
        Some(V::read(buf)?)
    } else {
        ensure_zeros(buf, V::SIZE)?;
        None
    };
    let floor = Location::new(u64::read(buf)?);
    if !floor.is_valid() {
        return Err(CodecError::Invalid(
            "storage::qmdb::operation::commit",
            "commit floor location overflow",
        ));
    }
    Ok((metadata, floor))
}

/// Encoded size of a variable-encoded commit payload.
pub(crate) fn commit_variable_payload_size<F: Family, V: EncodeSize>(
    metadata: &Option<V>,
    floor: Location<F>,
) -> usize {
    metadata.encode_size() + floor.encode_size()
}

/// Writes a commit's optional metadata and inactivity floor in the variable encoding.
pub(crate) fn write_commit_variable<F: Family, V: Write>(
    metadata: &Option<V>,
    floor: Location<F>,
    buf: &mut impl BufMut,
) {
    metadata.write(buf);
    floor.write(buf);
}

/// Reads a commit's optional metadata and inactivity floor from the variable encoding.
pub(crate) fn read_commit_variable<F: Family, V: Read>(
    buf: &mut impl Buf,
    value_cfg: &V::Cfg,
) -> Result<(Option<V>, Location<F>), CodecError> {
    let metadata = Option::<V>::read_cfg(buf, value_cfg)?;
    let floor = Location::read(buf)?;
    Ok((metadata, floor))
}
