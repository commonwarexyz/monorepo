use crate::{
    adb::sync::{self, error::EngineError},
    mmr::Location,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use std::ops::Range;

/// Target state to sync to
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target<D: Digest> {
    /// The root digest we're syncing to
    pub root: D,
    /// Range of operations to sync
    pub range: Range<Location>,
}

impl<D: Digest> Write for Target<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        (*self.range.start).write(buf);
        (*self.range.end).write(buf);
    }
}

impl<D: Digest> FixedSize for Target<D> {
    const SIZE: usize = D::SIZE + u64::SIZE + u64::SIZE;
}

impl<D: Digest> Read for Target<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let lower_bound = u64::read(buf)?;
        let upper_bound = u64::read(buf)?;
        if lower_bound >= upper_bound {
            return Err(CodecError::Invalid(
                "storage::adb::sync::Target",
                "lower_bound >= upper_bound",
            ));
        }
        Ok(Self {
            root,
            range: Location::new(lower_bound)..Location::new(upper_bound),
        })
    }
}

/// Validate a target update against the current target
pub fn validate_update<U, D>(
    old_target: &Target<D>,
    new_target: &Target<D>,
) -> Result<(), sync::Error<U, D>>
where
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    if new_target.range.is_empty() {
        return Err(sync::Error::Engine(EngineError::InvalidTarget {
            lower_bound_pos: new_target.range.start,
            upper_bound_pos: new_target.range.end,
        }));
    }

    // Check if sync target moved backward
    if new_target.range.start < old_target.range.start
        || new_target.range.end < old_target.range.end
    {
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
mod tests {
    use super::*;
    use commonware_codec::EncodeSize as _;
    use commonware_cryptography::sha256;
    use std::io::Cursor;
    use test_case::test_case;

    #[test]
    fn test_sync_target_serialization() {
        let target = Target {
            root: sha256::Digest::from([42; 32]),
            range: Location::new(100)..Location::new(500),
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
        assert_eq!(target.range, deserialized.range);
    }

    #[test]
    fn test_sync_target_read_invalid_bounds() {
        let target = Target {
            root: sha256::Digest::from([42; 32]),
            range: Location::new(100)..Location::new(50), // invalid: lower > upper
        };

        let mut buffer = Vec::new();
        target.write(&mut buffer);

        let mut cursor = Cursor::new(buffer);
        assert!(matches!(
            Target::<sha256::Digest>::read(&mut cursor),
            Err(CodecError::Invalid(_, "lower_bound >= upper_bound"))
        ));
    }

    type TestError = sync::Error<std::io::Error, sha256::Digest>;

    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), range: Location::new(0)..Location::new(100) },
        Target { root: sha256::Digest::from([1; 32]), range: Location::new(50)..Location::new(200) },
        Ok(());
        "valid update"
    )]
    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), range: Location::new(0)..Location::new(100) },
        Target { root: sha256::Digest::from([1; 32]), range: Location::new(200)..Location::new(100) },
        Err(TestError::Engine(EngineError::InvalidTarget { lower_bound_pos: Location::new(200), upper_bound_pos: Location::new(100) }));
        "invalid bounds - lower > upper"
    )]
    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), range: Location::new(0)..Location::new(100) },
        Target { root: sha256::Digest::from([1; 32]), range: Location::new(0)..Location::new(50) },
        Err(TestError::Engine(EngineError::SyncTargetMovedBackward {
            old: Target {
                root: sha256::Digest::from([0; 32]),
                range: Location::new(0)..Location::new(100),
            },
            new: Target {
                root: sha256::Digest::from([1; 32]),
                range: Location::new(0)..Location::new(50),
            },
        }));
        "moves backward"
    )]
    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), range: Location::new(0)..Location::new(100) },
        Target { root: sha256::Digest::from([0; 32]), range: Location::new(50)..Location::new(200) },
        Err(TestError::Engine(EngineError::SyncTargetRootUnchanged));
        "same root"
    )]
    fn test_validate_update(
        old_target: Target<sha256::Digest>,
        new_target: Target<sha256::Digest>,
        expected: Result<(), TestError>,
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
}
