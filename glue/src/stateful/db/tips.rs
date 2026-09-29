//! The recent tips a compact database serves.
//!
//! A compact database retains only its latest state, so each snapshot can serve exactly the size
//! it captured. A joiner syncing a compact database next to a slower full one asks for the target
//! the full database settled on, which servers have usually applied past by then. Publishing a
//! compact database's recent tips together keeps those requests answerable.

use commonware_cryptography::Digest;
use commonware_storage::{
    merkle::Family,
    qmdb::{
        compact,
        sync::{Request, Source, source},
    },
};
use std::{collections::VecDeque, sync::Arc};

/// How many of its latest published tips a compact database keeps serving.
pub const RETAINED_TIPS: usize = 128;

/// The latest published tips of a compact database, oldest first.
///
/// As a [`Source`], it serves each request from the tip whose size matches, and otherwise from
/// the latest tip, which refuses the request the way a pruned log would.
pub struct CompactTips<F: Family, Op, D: Digest> {
    tips: Arc<VecDeque<compact::Snapshot<F, Op, D>>>,
}

impl<F: Family, Op, D: Digest> CompactTips<F, Op, D> {
    /// Serve only `tip`.
    pub(crate) fn new(tip: compact::Snapshot<F, Op, D>) -> Self {
        Self {
            tips: Arc::new(VecDeque::from([tip])),
        }
    }

    /// The latest tip.
    pub fn latest(&self) -> &compact::Snapshot<F, Op, D> {
        self.tips.back().expect("compact tips are never empty")
    }

    /// Keep serving the tips in `served` alongside `fresh`'s latest tip, up to
    /// [`RETAINED_TIPS`] in total.
    ///
    /// A `fresh` tip no larger than `served`'s latest is the same state published again, so
    /// `served` is returned as is.
    pub(crate) fn merge(served: &Self, fresh: Self) -> Self {
        let latest = fresh.latest();
        if latest.size() <= served.latest().size() {
            return served.clone();
        }
        let kept = served.tips.len().min(RETAINED_TIPS - 1);
        let mut tips: VecDeque<_> = served
            .tips
            .range(served.tips.len() - kept..)
            .cloned()
            .collect();
        tips.push_back(latest.clone());
        Self {
            tips: Arc::new(tips),
        }
    }
}

impl<F: Family, Op, D: Digest> Clone for CompactTips<F, Op, D> {
    fn clone(&self) -> Self {
        Self {
            tips: self.tips.clone(),
        }
    }
}

impl<F, Op, D> Source for CompactTips<F, Op, D>
where
    F: Family,
    Op: Clone + Send + Sync,
    D: Digest,
{
    type Family = F;
    type Digest = D;
    type Op = Op;
    type Error = <compact::Tip<F, Op, D> as Source>::Error;

    fn serve(&self, request: Request<F>) -> impl Future<Output = source::Result<Self>> + Send {
        let tip = self
            .tips
            .iter()
            .rev()
            .find(|tip| tip.size() == request.size())
            .unwrap_or_else(|| self.latest());
        tip.serve(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::variable::Config as VariableJournalConfig,
        merkle::{Location, mmr},
        qmdb::keyless::fixed,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};

    type Db = fixed::CompactDb<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type Tips = CompactTips<mmr::Family, fixed::Operation<mmr::Family, U64>, sha256::Digest>;

    fn config(context: &deterministic::Context) -> fixed::CompactConfig<Sequential> {
        fixed::CompactConfig {
            strategy: Sequential,
            witness: VariableJournalConfig {
                partition: "compact-tips-witness".into(),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11)),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            commit_codec_config: (),
        }
    }

    async fn commit(db: Db, value: u64) -> Db {
        let floor = db.inactivity_floor_loc();
        let batch = db
            .new_batch()
            .append(U64::new(value))
            .merkleize(&db, None, floor)
            .await
            .unwrap();
        db.apply_batch(batch).await.unwrap().0
    }

    fn boundary(size: Location<mmr::Family>) -> Request<mmr::Family> {
        Request::Boundary {
            size,
            start: size - 1,
        }
    }

    /// Merged tips serve every retained size, drop the oldest past the limit, and ignore a
    /// republished state.
    #[test]
    fn serves_every_retained_tip() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = Db::init(context.child("db"), config(&context), None)
                .await
                .unwrap();
            let mut tips = Tips::new(db.snapshot());
            let first = tips.latest().size();
            for value in 0..RETAINED_TIPS as u64 {
                db = commit(db, value).await;
                tips = Tips::merge(&tips, Tips::new(db.snapshot()));
            }
            assert_eq!(tips.tips.len(), RETAINED_TIPS);

            // The first tip was dropped, and every later one still answers.
            assert!(tips.serve(boundary(first)).await.is_err());
            let oldest = tips.tips.front().unwrap().size();
            assert!(tips.serve(boundary(oldest)).await.is_ok());
            assert!(tips.serve(boundary(tips.latest().size())).await.is_ok());

            // Publishing the same state again changes nothing.
            let again = Tips::merge(&tips, Tips::new(db.snapshot()));
            assert!(Arc::ptr_eq(&again.tips, &tips.tips));

            // A size no tip holds is refused by the latest tip.
            assert!(
                tips.serve(boundary(tips.latest().size() + 1))
                    .await
                    .is_err()
            );
            db.destroy().await.unwrap();
        });
    }
}
