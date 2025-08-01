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

/// Errors that can occur during target update validation
#[derive(Debug, thiserror::Error, Clone)]
pub enum TargetUpdateError {
    /// Target bounds are invalid (lower > upper)
    #[error("invalid target bounds: lower_bound {lower_bound} > upper_bound {upper_bound}")]
    InvalidBounds { lower_bound: u64, upper_bound: u64 },
    /// Target moved backward (bounds decreased)
    #[error("sync target moved backward: old bounds [{old_lower}, {old_upper}], new bounds [{new_lower}, {new_upper}]")]
    MovedBackward {
        old_lower: u64,
        old_upper: u64,
        new_lower: u64,
        new_upper: u64,
    },
    /// Target root is unchanged
    #[error("sync target root unchanged")]
    RootUnchanged,
}

/// Validate a target update against the current target
pub fn validate_target_update<D: Digest>(
    old_target: &Target<D>,
    new_target: &Target<D>,
) -> Result<(), TargetUpdateError> {
    if new_target.lower_bound_ops > new_target.upper_bound_ops {
        return Err(TargetUpdateError::InvalidBounds {
            lower_bound: new_target.lower_bound_ops,
            upper_bound: new_target.upper_bound_ops,
        });
    }

    if new_target.lower_bound_ops < old_target.lower_bound_ops
        || new_target.upper_bound_ops < old_target.upper_bound_ops
    {
        return Err(TargetUpdateError::MovedBackward {
            old_lower: old_target.lower_bound_ops,
            old_upper: old_target.upper_bound_ops,
            new_lower: new_target.lower_bound_ops,
            new_upper: new_target.upper_bound_ops,
        });
    }

    if new_target.root == old_target.root {
        return Err(TargetUpdateError::RootUnchanged);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use std::io::Cursor;
    use test_case::test_case;

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

    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        Target { root: sha256::Digest::from([1; 32]), lower_bound_ops: 50, upper_bound_ops: 200 },
        true;
        "valid update"
    )]
    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        Target { root: sha256::Digest::from([1; 32]), lower_bound_ops: 200, upper_bound_ops: 100 },
        false;
        "invalid bounds - lower > upper"
    )]
    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        Target { root: sha256::Digest::from([1; 32]), lower_bound_ops: 0, upper_bound_ops: 50 },
        false;
        "moves backward"
    )]
    #[test_case(
        Target { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        Target { root: sha256::Digest::from([0; 32]), lower_bound_ops: 50, upper_bound_ops: 200 },
        false;
        "same root"
    )]
    fn test_validate_target_update(
        old_target: Target<sha256::Digest>,
        new_target: Target<sha256::Digest>,
        should_succeed: bool,
    ) {
        let result = validate_target_update(&old_target, &new_target);
        if should_succeed {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
}
