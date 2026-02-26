//! Shared marshal test harnesses and reusable test cases.

mod cases;
mod harnesses;

pub use cases::*;
pub use harnesses::*;

#[cfg(test)]
mod matrix {
    use crate::marshal::tests::{
        self as harness, CodingHarness, StandardMinimmitHarness, StandardSimplexHarness,
        TestHarness, LINK, UNRELIABLE_LINK,
    };
    use commonware_macros::test_traced;
    use paste::paste;

    fn assert_finalize_deterministic<H: TestHarness>(
        seed: u64,
        link: commonware_p2p::simulated::Link,
        quorum_sees_finalization: bool,
    ) {
        let r1 = harness::finalize::<H>(seed, link.clone(), quorum_sees_finalization);
        let r2 = harness::finalize::<H>(seed, link, quorum_sees_finalization);
        assert_eq!(r1, r2);
    }

    macro_rules! run_for_all_harnesses {
        ($base:ident, $test:ident) => {
            paste! {
                #[test_traced("WARN")]
                fn [<$base _standard_simplex>]() {
                    harness::$test::<StandardSimplexHarness>();
                }

                #[test_traced("WARN")]
                fn [<$base _standard_minimmit>]() {
                    harness::$test::<StandardMinimmitHarness>();
                }

                #[test_traced("WARN")]
                fn [<$base _coding>]() {
                    harness::$test::<CodingHarness>();
                }
            }
        };
    }

    macro_rules! run_finalize_for_all_harnesses {
        ($base:ident, $link:expr, $quorum_sees_finalization:expr) => {
            paste! {
                #[test_traced("WARN")]
                fn [<$base _standard_simplex>]() {
                    for seed in 0..5 {
                        assert_finalize_deterministic::<StandardSimplexHarness>(
                            seed,
                            $link,
                            $quorum_sees_finalization,
                        );
                    }
                }

                #[test_traced("WARN")]
                fn [<$base _standard_minimmit>]() {
                    for seed in 0..5 {
                        assert_finalize_deterministic::<StandardMinimmitHarness>(
                            seed,
                            $link,
                            $quorum_sees_finalization,
                        );
                    }
                }

                #[test_traced("WARN")]
                fn [<$base _coding>]() {
                    for seed in 0..5 {
                        assert_finalize_deterministic::<CodingHarness>(
                            seed,
                            $link,
                            $quorum_sees_finalization,
                        );
                    }
                }
            }
        };
    }

    run_finalize_for_all_harnesses!(test_finalize_good_links, LINK, false);
    run_finalize_for_all_harnesses!(test_finalize_bad_links, UNRELIABLE_LINK, false);
    run_finalize_for_all_harnesses!(
        test_finalize_good_links_quorum_sees_finalization,
        LINK,
        true
    );
    run_finalize_for_all_harnesses!(
        test_finalize_bad_links_quorum_sees_finalization,
        UNRELIABLE_LINK,
        true
    );

    run_for_all_harnesses!(test_ack_pipeline_backlog, ack_pipeline_backlog);
    run_for_all_harnesses!(
        test_ack_pipeline_backlog_persists_on_restart,
        ack_pipeline_backlog_persists_on_restart
    );
    run_for_all_harnesses!(test_sync_height_floor, sync_height_floor);
    run_for_all_harnesses!(test_prune_finalized_archives, prune_finalized_archives);
    run_for_all_harnesses!(
        test_reject_stale_block_delivery_after_floor_update,
        reject_stale_block_delivery_after_floor_update
    );
    run_for_all_harnesses!(
        test_subscribe_basic_block_delivery,
        subscribe_basic_block_delivery
    );
    run_for_all_harnesses!(
        test_subscribe_multiple_subscriptions,
        subscribe_multiple_subscriptions
    );
    run_for_all_harnesses!(
        test_subscribe_canceled_subscriptions,
        subscribe_canceled_subscriptions
    );
    run_for_all_harnesses!(
        test_subscribe_blocks_from_different_sources,
        subscribe_blocks_from_different_sources
    );
    run_for_all_harnesses!(
        test_get_info_basic_queries_present_and_missing,
        get_info_basic_queries_present_and_missing
    );
    run_for_all_harnesses!(
        test_get_info_latest_progression_multiple_finalizations,
        get_info_latest_progression_multiple_finalizations
    );
    run_for_all_harnesses!(
        test_get_block_by_height_and_latest,
        get_block_by_height_and_latest
    );
    run_for_all_harnesses!(
        test_get_block_by_commitment_from_sources_and_missing,
        get_block_by_commitment_from_sources_and_missing
    );
    run_for_all_harnesses!(test_get_finalization_by_height, get_finalization_by_height);
    run_for_all_harnesses!(
        test_hint_finalized_triggers_fetch,
        hint_finalized_triggers_fetch
    );
    run_for_all_harnesses!(test_ancestry_stream, ancestry_stream);
    run_for_all_harnesses!(
        test_finalize_same_height_different_views,
        finalize_same_height_different_views
    );
    run_for_all_harnesses!(test_init_processed_height, init_processed_height);
    run_for_all_harnesses!(test_broadcast_caches_block, broadcast_caches_block);
}
