//! Publication egress: retries until every peer accepts, and retirement once the machine
//! discharges a publication.

use super::harness::{Attachments, Network};
use crate::{
    Viewable as _,
    multimmit::{
        actors::voter::actor::TestEvent,
        machine::{DurableEffect, EffectId, SignRequest},
        mocks::cluster::DATA_CHANNEL,
        types::Artifact,
    },
    types::View,
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, deterministic::Runner};
use std::{collections::BTreeMap, time::Duration};

#[test_traced]
fn a_publication_no_peer_accepted_is_retried_until_delivered() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 31).await;
        // The peer listens but has no link to the node, so the first attempt reaches nobody.
        let (_, mut data) = network.register(1, DATA_CHANNEL).await;
        let attachments = Attachments::paused();
        let _node = network.start(&context, "node", &attachments).await;
        attachments.application.permit_builds(1);
        while attachments.relay.broadcasts().is_empty() {
            context.sleep(Duration::from_millis(10)).await;
        }
        Network::silent(&context, &mut data, Duration::from_millis(500)).await;

        network.link(1).await;
        let block = network.next_block(&context, &mut data).await;
        assert_eq!(block.header().height().get(), 1);
    });
}

/// Returns the view and sequence number of the vote update `effect` publishes, if any.
fn published_update(effect: &DurableEffect<MinPk, Digest>) -> Option<(View, u32)> {
    let DurableEffect::Publish(publication) = effect else {
        return None;
    };
    publication
        .artifacts()
        .iter()
        .find_map(|artifact| match artifact.as_ref() {
            Artifact::Update(update) => Some((update.round().view(), update.seq())),
            _ => None,
        })
}

/// Returns the view and sequence number of the vote update `effect` reserves a signature for, if
/// any.
fn reserved_update(effect: &DurableEffect<MinPk, Digest>) -> Option<(View, u32)> {
    let DurableEffect::Sign(sign) = effect else {
        return None;
    };
    sign.requests().iter().find_map(|request| match request {
        SignRequest::Update(update) => Some((update.content().view(), update.seq())),
        _ => None,
    })
}

#[test_traced]
fn a_vote_update_is_retired_only_once_superseded_twice_or_its_view_closes() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 32).await;
        let attachments = Attachments::paused();
        let _node = network.start(&context, "node", &attachments).await;

        // Each header the node produces moves its own tip, so it keeps sending fresh updates. The
        // application builds one block every 100 ms, spreading the headers over several updates.
        // An update is superseded once a later one of its view is durably reserved.
        let hooks = &attachments.hooks;
        let deadline = context.current() + Duration::from_secs(10);
        let mut next_build = context.current();
        loop {
            if context.current() >= next_build {
                attachments.application.permit_builds(1);
                next_build += Duration::from_millis(100);
            }
            let effects = hooks.effects();
            let updates: BTreeMap<EffectId, (View, u32)> = effects
                .iter()
                .filter_map(|(id, effect)| published_update(effect).map(|update| (*id, update)))
                .collect();
            let reserved = effects
                .values()
                .filter_map(reserved_update)
                .collect::<Vec<_>>();
            let mut retired = false;
            for event in hooks.events() {
                let TestEvent::Retired(ids) = event else {
                    continue;
                };
                for (view, seq) in ids.iter().filter_map(|id| updates.get(id)) {
                    assert!(
                        reserved.iter().any(|(later, next)| {
                            later > view || (later == view && *next >= seq + 2)
                        }),
                        "update {view:?}/{seq} retired before it was superseded twice"
                    );
                    retired = true;
                }
            }
            if retired {
                break;
            }
            assert!(context.current() < deadline, "no vote update was retired");
            context.sleep(Duration::from_millis(50)).await;
        }
    });
}

/// Sums the samples of every series whose name ends with `suffix` and whose labels contain
/// `label`.
fn sum_samples(encoded: &str, suffix: &str, label: &str) -> f64 {
    encoded
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (series, value) = line.rsplit_once(' ')?;
            let (name, labels) = series.split_once('{').unwrap_or((series, ""));
            (name.ends_with(suffix) && labels.contains(label)).then(|| value.parse::<f64>().ok())?
        })
        .sum()
}

#[test_traced]
fn published_traffic_and_voter_service_time_are_attributed_by_kind() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 33).await;
        let (_, mut data) = network.register(1, DATA_CHANNEL).await;
        network.link(1).await;
        let attachments = Attachments::paused();
        let _node = network.start(&context, "node", &attachments).await;
        attachments.application.permit_builds(1);
        network.next_block(&context, &mut data).await;
        // Let the node publish the vote update that endorses its header.
        context.sleep(Duration::from_millis(500)).await;

        let encoded = context.encode();
        for artifact in ["Header", "Update"] {
            let label = format!("artifact=\"{artifact}\"");
            assert!(
                sum_samples(&encoded, "_artifact_transmissions_total", &label) > 0.0,
                "{artifact}"
            );
            assert!(
                sum_samples(&encoded, "_artifact_transmitted_bytes_total", &label) > 0.0,
                "{artifact}"
            );
        }
        assert!(sum_samples(&encoded, "_update_bytes_count", "") > 0.0);
        assert!(sum_samples(&encoded, "_input_processing_count", "kind=\"block_built\"") > 0.0);
        assert!(sum_samples(&encoded, "_work_processing_count", "component=\"producer\"") > 0.0);
        assert!(sum_samples(&encoded, "_input_wait_count", "lane=\"local\"") > 0.0);
    });
}
