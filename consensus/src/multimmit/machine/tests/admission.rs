//! Admission bounds of the protocol design's adversarial-bounds table: each is enforced before
//! an observed artifact is allocated, so a rejected artifact leaves no store entry behind.
//!
//! | Resource | Bound | Rejection | Witness |
//! |---|---|---|---|
//! | Update tags | `[v - W_back, v + 2]` | `TagWindow` | `tests::pool::updates_are_read_only_within_the_tag_window` |
//! | Pending updates | per sender, whatever chains an update names, other senders unaffected; an update naming every chain that a parked update waits for is admitted past it | `PendingUpdatesFull` | `tests::pool::pending_updates_are_bounded_per_sender`, `tests::pool::a_flooding_sender_cannot_crowd_out_another_senders_header_dependent_update`, `tests::pool::a_senders_latest_vote_naming_every_chain_supersedes_its_parked_updates` |
//! | Buffered headers | tip lead `D + 2N` above the accepted tip | `TipLead` | `tests::chain::buffered_headers_are_bounded_by_the_tip_lead_and_the_branches_per_height`, `tests::chain::one_header_is_accepted_per_height` |
//! | Buffered headers | `pending_branches` per height | `HeightFull` | `tests::chain::buffered_headers_are_bounded_by_the_tip_lead_and_the_branches_per_height` |
//! | Held headers | `n + 1` per height, window above `h*` | refused at insert | `tests::chain::the_header_store_bounds_each_height_and_evicts_unreferenced_headers` |
//! | Off-chain V-QCs | `n` per view, plus parents a stored artifact waits on | `CertificatesFull` | `tests::vqc::a_view_holds_at_most_n_vqcs`, `tests::vqc::a_vqc_a_leader_block_waits_on_is_held_beyond_the_view_bound` |
//! | Leader blocks | window `[v - 1, v + 1]` | `TagWindow` | [`leader_blocks_are_admitted_only_within_one_view_of_the_current_one`], `tests::view::proposals_from_the_wrong_signer_or_outside_the_window_are_refused` |
//! | Leader blocks | signed by the view's leader | `Participant` | `tests::view::proposals_from_the_wrong_signer_or_outside_the_window_are_refused` |
//! | V-QC and L-QC wire | `max_artifact_bytes` | `ArtifactTooLarge` | [`certificates_above_the_artifact_byte_limit_are_rejected_unhashed`] |

use crate::{
    multimmit::{
        config::{Profile, ResourceLimits, Role, Tuning},
        machine::{
            input::{ObservationResult, ObservationStatus, Rejection, StepStatus},
            testing::{
                CapabilitiesExt as _, Drive as _, cohort,
                fixtures::{
                    TestDriver, committee, profile, stage_view_entries, started, started_with,
                    validator,
                },
            },
        },
        types::Artifact,
    },
    types::View,
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::num::NonZeroUsize;

/// Observes `artifacts` and returns each one's admission result, checking that the artifacts
/// cached grow by exactly the scheduled ones and that the verification job holds exactly those.
fn admit(
    driver: &mut TestDriver,
    artifacts: Vec<Artifact<MinPk, Digest>>,
) -> Vec<ObservationResult<Digest>> {
    let cached = driver.inspect().cached_artifacts();
    let step = driver.submit(cohort::<Sha256, _>(artifacts)).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("an observation reports its results");
    };
    let scheduled = results
        .iter()
        .filter(|result| result.status() == ObservationStatus::Scheduled)
        .map(|result| result.id().expect("a scheduled artifact is identified"))
        .collect::<Vec<_>>();
    assert_eq!(
        driver.inspect().cached_artifacts(),
        cached + scheduled.len()
    );
    let verified = if scheduled.is_empty() {
        Vec::new()
    } else {
        step.verify_job()
            .items()
            .iter()
            .map(|item| item.ticket().artifact())
            .collect()
    };
    assert_eq!(verified, scheduled);
    results.clone()
}

/// Returns `profile` with its artifact byte limit lowered to `limit`.
fn limited(profile: &Profile<Digest>, limit: usize) -> Profile<Digest> {
    let resources = profile.resources();
    let nonzero = |value| NonZeroUsize::new(value).unwrap();
    let resources = ResourceLimits::new(
        nonzero(limit),
        nonzero(resources.max_cached_artifacts()),
        nonzero(resources.max_verification_batch()),
        nonzero(resources.max_inflight_verifications()),
        resources.max_future_view_distance(),
        nonzero(resources.max_future_artifacts()),
        nonzero(resources.max_dependency_waiters()),
        nonzero(resources.max_outbox_effects()),
        nonzero(resources.max_forwarded_certificates()),
    );
    Profile::with_limits(
        profile.protocol().clone(),
        profile.role(),
        Tuning::default(),
        resources,
    )
    .unwrap()
}

#[test]
fn certificates_above_the_artifact_byte_limit_are_rejected_unhashed() {
    let committee = committee(300);
    let vqc = Artifact::Vqc(committee.vqc(View::new(1)));
    let lqc = Artifact::Lqc(committee.lqc(View::new(1)));
    let block = Artifact::LeaderBlock(committee.leader_block(View::new(1)));
    let limit = vqc.encoded_len().min(lqc.encoded_len()) - 1;
    assert!(block.encoded_len() <= limit);
    let mut driver = started_with(limited(&profile(&committee, Role::Observer), limit));

    let results = admit(&mut driver, vec![vqc, lqc, block]);
    let rejected = ObservationStatus::Rejected(Rejection::ArtifactTooLarge);
    assert_eq!(
        results
            .iter()
            .map(|result| result.status())
            .collect::<Vec<_>>(),
        vec![rejected, rejected, ObservationStatus::Scheduled]
    );
    assert!(results[..2].iter().all(|result| result.id().is_none()));
}

#[test]
fn leader_blocks_are_admitted_only_within_one_view_of_the_current_one() {
    let committee = committee(301);
    let mut driver = started(&committee, validator(0));
    stage_view_entries(&mut driver, &committee, View::new(5));

    let blocks = (3..=7)
        .map(|view| Artifact::LeaderBlock(committee.leader_block(View::new(view))))
        .collect();
    let window = ObservationStatus::Rejected(Rejection::TagWindow);
    let scheduled = ObservationStatus::Scheduled;
    assert_eq!(
        admit(&mut driver, blocks)
            .iter()
            .map(|result| result.status())
            .collect::<Vec<_>>(),
        vec![window, scheduled, scheduled, scheduled, window]
    );
}
