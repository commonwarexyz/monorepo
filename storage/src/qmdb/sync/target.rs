use crate::{
    merkle::{Family, Location},
    qmdb::sync::{self, error::EngineError},
};
use commonware_cryptography::Digest;
use commonware_utils::range::NonEmptyRange;
use std::fmt::Debug;

/// Target state to sync to.
pub trait Target: Clone + Debug + Send + Sync + 'static {
    /// Merkle family used by the target range.
    type Family: Family;
    /// Root digest type.
    type Digest: Digest;

    /// Database root expected after sync completes.
    fn root(&self) -> Self::Digest;

    /// Operation root used to verify range proofs.
    fn ops_root(&self) -> Self::Digest;

    /// Range of operations to sync.
    fn range(&self) -> &NonEmptyRange<Location<Self::Family>>;
}

/// Validate a target update against the current target.
pub fn validate_update<T, U>(
    old_target: &T,
    new_target: &T,
) -> Result<(), sync::Error<T::Family, U, T::Digest>>
where
    T: Target,
    U: std::error::Error + Send + 'static,
{
    if !new_target.range().end().is_valid() {
        return Err(sync::Error::Engine(EngineError::InvalidTarget {
            lower_bound_pos: new_target.range().start(),
            upper_bound_pos: new_target.range().end(),
        }));
    }

    // Start must not decrease; end must strictly increase. Same end implies same tree size implies
    // same root (the Merkle structure is append-only), so retaining the old root under the old tree
    // size in `retained_roots` requires a distinct end.
    if new_target.range().start() < old_target.range().start()
        || new_target.range().end() <= old_target.range().end()
    {
        return Err(sync::Error::Engine(EngineError::SyncTargetMovedBackward {
            old_lower_bound_pos: old_target.range().start(),
            old_upper_bound_pos: old_target.range().end(),
            new_lower_bound_pos: new_target.range().start(),
            new_upper_bound_pos: new_target.range().end(),
        }));
    }

    if new_target.ops_root() == old_target.ops_root() {
        return Err(sync::Error::Engine(EngineError::SyncTargetRootUnchanged));
    }

    Ok(())
}

#[cfg(test)]
// Only `MmrFamily` is exercised here: `validate_update` logic is family-agnostic (the family
// only influences `Location::is_valid` via `F::MAX_LEAVES`), so an MMB variant would duplicate
// coverage without catching anything new.
mod tests {
    use super::*;
    use crate::merkle::mmr::Family as MmrFamily;
    use commonware_cryptography::sha256;
    use commonware_utils::non_empty_range;
    use rstest::rstest;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestTarget {
        root: sha256::Digest,
        ops_root: sha256::Digest,
        range: NonEmptyRange<Location<MmrFamily>>,
    }

    impl Target for TestTarget {
        type Family = MmrFamily;
        type Digest = sha256::Digest;

        fn root(&self) -> Self::Digest {
            self.root
        }

        fn ops_root(&self) -> Self::Digest {
            self.ops_root
        }

        fn range(&self) -> &NonEmptyRange<Location<Self::Family>> {
            &self.range
        }
    }

    fn target(ops_root: sha256::Digest, start: u64, end: u64) -> TestTarget {
        TestTarget {
            root: ops_root,
            ops_root,
            range: non_empty_range!(Location::new(start), Location::new(end)),
        }
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
            old_lower_bound_pos: Location::new(0),
            old_upper_bound_pos: Location::new(100),
            new_lower_bound_pos: Location::new(50),
            new_upper_bound_pos: Location::new(100),
        }))
    )]
    #[case::moves_backward(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([1; 32]), 0, 50),
        Err(TestError::Engine(EngineError::SyncTargetMovedBackward {
            old_lower_bound_pos: Location::new(0),
            old_upper_bound_pos: Location::new(100),
            new_lower_bound_pos: Location::new(0),
            new_upper_bound_pos: Location::new(50),
        }))
    )]
    #[case::same_root(
        target(sha256::Digest::from([0; 32]), 0, 100),
        target(sha256::Digest::from([0; 32]), 50, 200),
        Err(TestError::Engine(EngineError::SyncTargetRootUnchanged))
    )]
    fn test_validate_update(
        #[case] old_target: TestTarget,
        #[case] new_target: TestTarget,
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
}
