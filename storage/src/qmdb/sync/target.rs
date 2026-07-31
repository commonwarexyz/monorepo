use crate::{
    merkle::{Family, Location},
    qmdb::sync::{self, error::EngineError},
};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{non_empty_range, range::NonEmptyRange};

/// Target state to sync to.
///
/// `PartialEq`, `Eq`, and `Clone` are implemented manually to avoid requiring `F` to implement
/// them.
#[derive(Debug)]
pub struct Target<F: Family, D: Digest> {
    /// The ops root the sync engine verifies streaming batches against.
    pub root: D,
    /// Range of operations to sync
    pub range: NonEmptyRange<Location<F>>,
}

impl<F: Family, D: Digest> Target<F, D> {
    /// Create a sync target.
    pub const fn new(root: D, range: NonEmptyRange<Location<F>>) -> Self {
        Self { root, range }
    }

    /// Whether this target advances relative to `from`.
    pub fn advances(&self, from: &Self) -> bool {
        self.range.end().is_valid()
            && self.range.end() > from.range.end()
            && self.range.start() >= from.range.start()
    }
}

impl<F: Family, D: Digest> Clone for Target<F, D> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            range: self.range.clone(),
        }
    }
}

impl<F: Family, D: Digest> PartialEq for Target<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.range == other.range
    }
}

impl<F: Family, D: Digest> Eq for Target<F, D> {}

impl<F: Family, D: Digest> Write for Target<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.range.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for Target<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.range.encode_size()
    }
}

impl<F: Family, D: Digest> Read for Target<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let range = NonEmptyRange::<Location<F>>::read(buf)?;
        if !range.start().is_valid() || !range.end().is_valid() {
            return Err(CodecError::Invalid(
                "storage::qmdb::sync::Target",
                "range bounds out of valid range",
            ));
        }
        Ok(Self { root, range })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for Target<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let root = u.arbitrary()?;
        let max_loc = F::MAX_LEAVES;
        let lower = u.int_in_range(0..=*max_loc - 1)?;
        let upper = u.int_in_range(lower + 1..=*max_loc)?;
        Ok(Self {
            root,
            range: commonware_utils::non_empty_range!(Location::new(lower), Location::new(upper)),
        })
    }
}

/// Target state for syncing to a compact-storage database.
///
/// Compact sync is ordinary [`crate::qmdb::sync::sync`] over a one-operation range. To reach
/// `CompactTarget { root, size: N }`, the client syncs the range `[N - 1, N)`
/// ([`Target::try_from`] performs the conversion). The engine's boundary request fetches the
/// final commit operation, proven at `N`, plus the pinned nodes one operation below it, and
/// verifies all of it against `root` before construction. A full database answers that request
/// from its operation log like any other request. A compact database answers from its witness,
/// refusing requests outside the single state it retains.
///
/// Authenticates only the final committed root and size. There is no lower replay
/// bound because the replayed range is always the single final commit.
#[derive(Debug)]
pub struct CompactTarget<F: Family, D: Digest> {
    /// Authenticated root of the committed compact state.
    pub root: D,
    /// The committed size (total operations) of that state.
    pub size: Location<F>,
}

impl<F: Family, D: Digest> CompactTarget<F, D> {
    /// Create a compact-sync target.
    pub const fn new(root: D, size: Location<F>) -> Self {
        Self { root, size }
    }
}

impl<F: Family, D: Digest> TryFrom<&CompactTarget<F, D>> for Target<F, D> {
    type Error = EngineError<F, D>;

    /// The ranged target that replays the one operation ending at `target`. Fails when
    /// `size` is zero, which no committed state has.
    fn try_from(target: &CompactTarget<F, D>) -> Result<Self, Self::Error> {
        let end = target.size;
        let start = end.checked_sub(1).ok_or(EngineError::InvalidTarget {
            lower_bound_pos: Location::new(0),
            upper_bound_pos: end,
        })?;
        Ok(Self {
            root: target.root,
            range: non_empty_range!(start, end),
        })
    }
}

impl<F: Family, D: Digest> Clone for CompactTarget<F, D> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            size: self.size,
        }
    }
}

impl<F: Family, D: Digest> PartialEq for CompactTarget<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.size == other.size
    }
}

impl<F: Family, D: Digest> Eq for CompactTarget<F, D> {}

impl<F: Family, D: Digest> Write for CompactTarget<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.size.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for CompactTarget<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.size.encode_size()
    }
}

impl<F: Family, D: Digest> Read for CompactTarget<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let size = Location::<F>::read(buf)?;
        if !size.is_valid() || size == 0 {
            return Err(CodecError::Invalid(
                "storage::qmdb::sync::CompactTarget",
                "size must be in 1..=MAX_LEAVES",
            ));
        }
        Ok(Self { root, size })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for CompactTarget<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let root = u.arbitrary()?;
        let size = Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?);
        Ok(Self { root, size })
    }
}

/// Validate a target update against the current target
pub fn validate_update<F, U, D>(
    old_target: &Target<F, D>,
    new_target: &Target<F, D>,
) -> Result<(), sync::Error<F, U, D>>
where
    F: Family,
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    if !new_target.range.end().is_valid() {
        return Err(sync::Error::Engine(EngineError::InvalidTarget {
            lower_bound_pos: new_target.range.start(),
            upper_bound_pos: new_target.range.end(),
        }));
    }

    // Start must not decrease; end must strictly increase. Same end implies same database size implies
    // same root (the operation log is append-only), so retaining the old root under the old
    // size in `retained_roots` requires a distinct end.
    if !new_target.advances(old_target) {
        return Err(sync::Error::Engine(EngineError::SyncTargetMovedBackward {
            old: old_target.clone(),
            new: new_target.clone(),
        }));
    }

    if new_target.root == old_target.root {
        return Err(sync::Error::Engine(EngineError::SyncTargetRootUnchanged));
    }

    Ok(())
}

#[cfg(test)]
// Only `MmrFamily` is exercised here: `Target`'s codec and `validate_update` logic are
// family-agnostic (the family only influences `Location::is_valid` via `F::MAX_LEAVES` and
// the `arbitrary` range picker), so an MMB variant would duplicate coverage without catching
// anything new.
mod tests {
    use super::*;
    use crate::merkle::mmr::Family as MmrFamily;
    use commonware_cryptography::sha256;
    use commonware_utils::non_empty_range;
    use rstest::rstest;
    use std::io::Cursor;

    fn target(root: sha256::Digest, start: u64, end: u64) -> Target<MmrFamily, sha256::Digest> {
        Target::new(
            root,
            non_empty_range!(Location::new(start), Location::new(end)),
        )
    }

    #[test]
    fn test_sync_target_serialization() {
        let target = target(sha256::Digest::from([42; 32]), 100, 500);

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
        assert_eq!(target.range, deserialized.range);
    }

    #[test]
    fn test_sync_target_read_invalid_bounds() {
        // Manually encode root + two Locations with reversed bounds
        let mut buffer = Vec::new();
        sha256::Digest::from([42; 32]).write(&mut buffer);
        Location::<MmrFamily>::new(100).write(&mut buffer); // start
        Location::<MmrFamily>::new(50).write(&mut buffer); // end (< start = invalid)

        let mut cursor = Cursor::new(buffer);
        assert!(matches!(
            Target::<MmrFamily, sha256::Digest>::read(&mut cursor),
            Err(CodecError::Invalid("NonEmptyRange", "start must be < end"))
        ));

        // Manually encode a target with an empty range (start == end)
        let root = sha256::Digest::from([42; 32]);
        let mut buffer = Vec::new();
        root.write(&mut buffer);
        Location::<MmrFamily>::new(100).write(&mut buffer);
        Location::<MmrFamily>::new(100).write(&mut buffer);

        let mut cursor = Cursor::new(buffer);
        assert!(matches!(
            Target::<MmrFamily, sha256::Digest>::read(&mut cursor),
            Err(CodecError::Invalid("NonEmptyRange", "start must be < end"))
        ));
    }

    type TestError = sync::Error<MmrFamily, std::io::Error, sha256::Digest>;

    #[rstest]
    #[case::valid_update(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([1; 32]), 50, 200),
        Ok(())
    )]
    #[case::same_start(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([1; 32]), 0, 200),
        Ok(())
    )]
    #[case::same_end(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([1; 32]), 50, 100),
        Err(TestError::Engine(EngineError::SyncTargetMovedBackward {
            old: target(sha256::Digest::from([0; 32]), 0, 100),
            new: target(sha256::Digest::from([1; 32]), 50, 100),
        }))
    )]
    #[case::moves_backward(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([1; 32]), 0, 50),
        Err(TestError::Engine(EngineError::SyncTargetMovedBackward {
            old: target(sha256::Digest::from([0; 32]), 0, 100),
            new: target(sha256::Digest::from([1; 32]), 0, 50),
        }))
    )]
    #[case::same_root(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([0; 32]), 50, 200),
        Err(TestError::Engine(EngineError::SyncTargetRootUnchanged))
    )]
    fn test_validate_update(
        #[case] old_target: Target<MmrFamily, sha256::Digest>,
        #[case] new_target: Target<MmrFamily, sha256::Digest>,
        #[case] expected: Result<(), TestError>,
    ) {
        let result = validate_update(&old_target, &new_target);
        match (&result, &expected) {
            (Ok(()), Ok(())) => {}
            (Ok(()), Err(expected_err)) => {
                panic!("Expected error {expected_err:?} but got success");
            }
            (Err(actual_err), Ok(())) => {
                panic!("Expected success but got error: {actual_err:?}");
            }
            (Err(actual_err), Err(expected_err)) => match (actual_err, expected_err) {
                (
                    TestError::Engine(EngineError::InvalidTarget {
                        lower_bound_pos: a_lower,
                        upper_bound_pos: a_upper,
                    }),
                    TestError::Engine(EngineError::InvalidTarget {
                        lower_bound_pos: e_lower,
                        upper_bound_pos: e_upper,
                    }),
                ) => {
                    assert_eq!(a_lower, e_lower);
                    assert_eq!(a_upper, e_upper);
                }
                (
                    TestError::Engine(EngineError::SyncTargetMovedBackward { .. }),
                    TestError::Engine(EngineError::SyncTargetMovedBackward { .. }),
                ) => {}
                (
                    TestError::Engine(EngineError::SyncTargetRootUnchanged),
                    TestError::Engine(EngineError::SyncTargetRootUnchanged),
                ) => {}
                _ => panic!("Error type mismatch: got {actual_err:?}, expected {expected_err:?}"),
            },
        }
    }

    #[test]
    fn test_compact_target_decode_rejects_zero_size() {
        use commonware_codec::{DecodeExt as _, Encode as _};
        let unused_root = sha256::Digest::from([42; 32]);
        let encoded = CompactTarget::<MmrFamily, sha256::Digest> {
            root: unused_root,
            size: Location::new(0),
        }
        .encode();

        assert!(CompactTarget::<MmrFamily, sha256::Digest>::decode(encoded).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::merkle::mmb;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Target<MmrFamily, sha256::Digest>>,
            CodecConformance<CompactTarget<MmrFamily, sha256::Digest>>,
            CodecConformance<CompactTarget<mmb::Family, sha256::Digest>>,
        }
    }
}
