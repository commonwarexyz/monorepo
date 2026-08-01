use crate::{
    merkle::{Family, Location},
    qmdb::sync::error::EngineError,
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
    ///
    /// Both targets are assumed to describe valid states of the same append-only QMDB. Because
    /// the root commits to the database size, valid targets at different sizes have distinct
    /// roots.
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
#[derive(Debug)]
pub struct CompactTarget<F: Family, D: Digest> {
    /// Target database root.
    pub root: D,
    /// Target database size.
    pub size: Location<F>,
}

impl<F: Family, D: Digest> TryFrom<&CompactTarget<F, D>> for Target<F, D> {
    type Error = EngineError<F, D>;

    fn try_from(target: &CompactTarget<F, D>) -> Result<Self, Self::Error> {
        let end = target.size;
        let start =
            end.checked_sub(1)
                .filter(|_| end.is_valid())
                .ok_or(EngineError::InvalidTarget {
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

#[cfg(test)]
// The unit tests use `MmrFamily` only. The codec and predicates are family-agnostic (the
// family only influences `Location::is_valid` via `F::MAX_LEAVES` and the `arbitrary` range
// picker), so an MMB variant would duplicate coverage. Codec conformance covers both families.
mod tests {
    use super::*;
    use crate::merkle::mmr::Family as MmrFamily;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::sha256;
    use commonware_utils::non_empty_range;
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

    #[test]
    fn test_compact_target_decode_rejects_zero_size() {
        let unused_root = sha256::Digest::from([42; 32]);
        let encoded = CompactTarget::<MmrFamily, sha256::Digest> {
            root: unused_root,
            size: Location::new(0),
        }
        .encode();

        assert!(CompactTarget::<MmrFamily, sha256::Digest>::decode(encoded).is_err());
    }

    #[test]
    fn test_advances() {
        let current_root = sha256::Digest::from([0; 32]);
        let advanced_root = sha256::Digest::from([1; 32]);
        let current = target(current_root, 10, 100);

        // End strictly increases, start does not decrease.
        assert!(target(advanced_root, 10, 101).advances(&current));
        assert!(target(advanced_root, 50, 200).advances(&current));

        // Same or smaller end does not advance.
        assert!(!target(current_root, 10, 100).advances(&current));
        assert!(!target(current_root, 10, 50).advances(&current));

        // A start moving backward does not advance, even with a larger end.
        assert!(!target(advanced_root, 5, 200).advances(&current));

        // An end outside the location domain does not advance.
        let beyond = target(advanced_root, 10, *MmrFamily::MAX_LEAVES + 1);
        assert!(!beyond.advances(&current));
    }

    #[test]
    fn test_compact_target_serialization() {
        let target = CompactTarget::<MmrFamily, sha256::Digest> {
            root: sha256::Digest::from([42; 32]),
            size: Location::new(100),
        };

        let mut buffer = Vec::new();
        target.write(&mut buffer);
        assert_eq!(buffer.len(), target.encode_size());

        let mut cursor = Cursor::new(buffer);
        let deserialized = CompactTarget::read(&mut cursor).unwrap();
        assert_eq!(target, deserialized);
        assert_eq!(target.root, deserialized.root);
        assert_eq!(target.size, deserialized.size);
    }

    #[test]
    fn test_compact_target_decode_rejects_size_beyond_domain() {
        let mut buffer = Vec::new();
        sha256::Digest::from([42; 32]).write(&mut buffer);
        Location::<MmrFamily>::new(*MmrFamily::MAX_LEAVES + 1).write(&mut buffer);

        let mut cursor = Cursor::new(buffer);
        assert!(matches!(
            CompactTarget::<MmrFamily, sha256::Digest>::read(&mut cursor),
            Err(CodecError::Invalid(_, _))
        ));
    }

    #[test]
    fn test_compact_target_to_ranged() {
        let root = sha256::Digest::from([42; 32]);

        // The derived range replays the one operation ending at the target.
        let compact = CompactTarget::<MmrFamily, _> {
            root,
            size: Location::new(100),
        };
        let ranged = Target::try_from(&compact).unwrap();
        assert_eq!(ranged.root, root);
        assert_eq!(ranged.range.start(), Location::new(99));
        assert_eq!(ranged.range.end(), Location::new(100));

        // A size of one yields [0, 1).
        let genesis = CompactTarget::<MmrFamily, _> {
            root,
            size: Location::new(1),
        };
        let ranged = Target::try_from(&genesis).unwrap();
        assert_eq!(ranged.range.start(), Location::new(0));
        assert_eq!(ranged.range.end(), Location::new(1));

        // A zero size has no operation to replay.
        let empty = CompactTarget::<MmrFamily, _> {
            root,
            size: Location::new(0),
        };
        assert!(matches!(
            Target::try_from(&empty),
            Err(EngineError::InvalidTarget { .. })
        ));

        // A size outside the location domain is rejected.
        let beyond = CompactTarget::<MmrFamily, _> {
            root,
            size: Location::new(*MmrFamily::MAX_LEAVES + 1),
        };
        assert!(matches!(
            Target::try_from(&beyond),
            Err(EngineError::InvalidTarget { .. })
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::merkle::mmb;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Target<MmrFamily, sha256::Digest>>,
            CodecConformance<Target<mmb::Family, sha256::Digest>>,
            CodecConformance<CompactTarget<MmrFamily, sha256::Digest>>,
            CodecConformance<CompactTarget<mmb::Family, sha256::Digest>>,
        }
    }
}
