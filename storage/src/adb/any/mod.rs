//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated
//! with a key.

use crate::{
    adb::{operation::Keyed, Error},
    journal::contiguous::Contiguous,
    mmr::{journaled::Mmr, Location, StandardHasher},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use tracing::warn;

pub mod fixed;
pub mod variable;

/// Discard any uncommitted log operations, then correct any inconsistencies between the MMR and
/// log.
///
/// # Post-conditions
/// - The log will either be empty, or its last operation will be a commit floor operation.
/// - The number of leaves in the MMR will be equal to the number of operations in the log.
pub(crate) async fn align_mmr_and_log<E: Storage + Clock + Metrics, O: Keyed, H: Hasher>(
    mmr: &mut Mmr<E, H>,
    log: &mut impl Contiguous<Item = O>,
    hasher: &mut StandardHasher<H>,
) -> Result<Location, Error>
where
{
    // Back up over / discard any uncommitted operations in the log.
    let mut log_size: Location = log.size().await.into();
    let mut rewind_leaf_num = log_size;
    let mut inactivity_floor_loc = Location::new_unchecked(0);
    while rewind_leaf_num > 0 {
        let op = log.read(rewind_leaf_num.as_u64() - 1).await?;
        if let Some(loc) = op.commit_floor() {
            inactivity_floor_loc = loc;
            break;
        }
        rewind_leaf_num -= 1;
    }
    if rewind_leaf_num != log_size {
        let op_count = log_size - rewind_leaf_num;
        warn!(
            ?log_size,
            ?op_count,
            "rewinding over uncommitted log operations"
        );
        log.rewind(rewind_leaf_num.as_u64()).await?;
        log.sync().await?;
        log_size = rewind_leaf_num;
    }

    // Pop any MMR elements that are ahead of the last log commit point.
    let mut next_mmr_leaf_num = mmr.leaves();
    if next_mmr_leaf_num > log_size {
        let op_count = next_mmr_leaf_num - log_size;
        warn!(?log_size, ?op_count, "popping uncommitted MMR operations");
        mmr.pop(op_count.as_u64() as usize).await?;
        next_mmr_leaf_num = log_size;
    }

    // If the MMR is behind, replay log operations to catch up.
    if next_mmr_leaf_num < log_size {
        let op_count = log_size - next_mmr_leaf_num;
        warn!(
            ?log_size,
            ?op_count,
            "MMR lags behind log, replaying log to catch up"
        );
        while next_mmr_leaf_num < log_size {
            let op = log.read(next_mmr_leaf_num.as_u64()).await?;
            mmr.add_batched(hasher, &op.encode()).await?;
            next_mmr_leaf_num += 1;
        }
        mmr.sync(hasher).await.map_err(Error::Mmr)?;
    }

    // At this point the MMR and log should be consistent.
    assert_eq!(log.size().await, mmr.leaves());

    // The final operation in the log (if any) should be a commit.
    let last_op_loc = log.size().await.checked_sub(1);
    assert!(
        last_op_loc.is_none()
            || log
                .read(last_op_loc.unwrap())
                .await?
                .commit_floor()
                .is_some()
    );

    Ok(inactivity_floor_loc)
}
