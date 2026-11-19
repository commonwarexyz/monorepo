//! Shared traits and codecs for QMDB operations.

use crate::merkle::{Family, Location};
use commonware_codec::{
    Buf, CodecShared, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
    util::ensure_zeros,
};
use commonware_runtime::BufMut;
use core::{fmt::Debug, hash::Hash};

/// Wire tag for a commit operation. Every database tags its commits alike.
///
/// An encoded operation opens with its tag. One table serves every database, so no tag stands
/// for two kinds of operation.
pub const COMMIT_CONTEXT: u8 = 0;
/// Wire tag for an update operation of an [any](crate::qmdb::any) or
/// [current](crate::qmdb::current) database.
pub const UPDATE_CONTEXT: u8 = 1;
/// Wire tag for a delete operation of an [any](crate::qmdb::any) or
/// [current](crate::qmdb::current) database.
pub const DELETE_CONTEXT: u8 = 2;
/// Wire tag for a set operation of an [immutable](crate::qmdb::immutable) database.
pub const SET_CONTEXT: u8 = 3;
/// Wire tag for an append operation of a [keyless](crate::qmdb::keyless) database.
pub const APPEND_CONTEXT: u8 = 4;

/// A QMDB key, indexed by its `AsRef<[u8]>` bytes.
///
/// For any two keys, `a.cmp(b)` must equal `a.as_ref().cmp(b.as_ref())`. This implies
/// that two keys are equal exactly when their index bytes are equal.
pub trait Key: CodecShared + Clone + 'static + Ord + Hash + AsRef<[u8]> + Debug {}

impl<T> Key for T where T: CodecShared + Clone + 'static + Ord + Hash + AsRef<[u8]> + Debug {}

/// An operation that may be a commit. Commits declare an inactivity floor.
pub trait Committable<F: Family> {
    /// The inactivity floor if this operation is a commit.
    fn inactivity_floor(&self) -> Option<Location<F>>;

    /// The commit a freshly initialized database holds.
    fn initial_commit() -> Self;

    /// If this operation is a commit.
    fn is_commit(&self) -> bool {
        self.inactivity_floor().is_some()
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

    /// If this operation replaces its key's value, making the key's previous location inactive.
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
