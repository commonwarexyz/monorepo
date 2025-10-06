use crate::{
    orchestrator::{EpochCert, EpochTransition},
    types::block::Block,
    NAMESPACE,
};
use commonware_codec::extensions::DecodeRangeExt;
use commonware_consensus::{
    marshal,
    threshold_simplex::types::{Activity, Finalization},
    Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use rand::{seq::SliceRandom, Rng};
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct Config<O: Reporter<Activity = EpochTransition>> {
    pub identity: <MinSig as Variant>::Public,
    pub indexers: Vec<String>,
    pub poll_interval: Duration,
    pub orchestrator: O,
    pub marshal: marshal::Mailbox<MinSig, Block>,
}

/// Poller actor: periodically polls configured indexers for the latest
/// finalizations, validates them against the network identity, and reports
/// next-epoch transitions to the orchestrator.
pub struct Poller<E, O>
where
    E: Clock + Spawner + Metrics + Rng,
    O: Reporter<Activity = EpochTransition>,
{
    context: E,
    identity: <MinSig as Variant>::Public,
    indexers: Vec<String>,
    client: reqwest::Client,
    orchestrator: O,
    marshal: marshal::Mailbox<MinSig, Block>,
    poll_interval: Duration,
}

impl<E, O> Poller<E, O>
where
    E: Clock + Spawner + Metrics + Rng,
    O: Reporter<Activity = EpochTransition> + Clone,
{
    pub fn new(context: E, cfg: Config<O>) -> Self {
        Self {
            context,
            identity: cfg.identity,
            indexers: cfg.indexers,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            orchestrator: cfg.orchestrator,
            marshal: cfg.marshal,
            poll_interval: cfg.poll_interval,
        }
    }

    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
        // Track which next-epochs we've already reported to the orchestrator.
        let mut highest_reported_epoch: u64 = 0;
        let mut rng = self.context.clone();

        // No indexers configured; nothing to do.
        if self.indexers.is_empty() {
            return;
        }

        loop {
            // Sleep between indexer polls.
            debug!("poller: sleeping");
            self.context.sleep(self.poll_interval).await;
            debug!("poller: awake");

            // Pick a random indexer to poll.
            let indexer = self
                .indexers
                .choose(&mut rng)
                .expect("no indexers configured");
            let url = format!("{}/latest", indexer);

            // Poll the indexer for the latest finalizations. Continue if any errors occur.
            let resp = match self.client.get(&url).send().await {
                Ok(resp) => match resp.bytes().await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        warn!(?err, "poller: failed to read response body");
                        continue;
                    }
                },
                Err(err) => {
                    warn!(?err, "poller: latest fetch failed");
                    continue;
                }
            };

            // Decode Vec<Finalization<MinSig, Sha256Digest>> with an upper bound of 2.
            let Ok(finals) =
                <Vec<Finalization<MinSig, Sha256Digest>>>::decode_range(resp.as_ref(), 0..=2)
            else {
                warn!("poller: failed to decode latest finalizations");
                continue;
            };

            // Validate the finalization epochs.
            let cert = match finals.len() {
                0 => continue, // No finalizations found
                1 => EpochCert::Single(finals[0].clone()),
                2 => EpochCert::Double(finals[0].clone(), finals[1].clone()),
                _ => unreachable!(),
            };
            if !cert.verify(NAMESPACE, &self.identity) {
                warn!("poller: finalization failed verification");
                continue;
            }

            // Give to marshal to ensure that it has this finalization.
            for finalization in finals {
                let _ = self
                    .marshal
                    .report(Activity::Finalization(finalization.clone()))
                    .await;
            }

            // The last finalization must be the highest-epoch finalization.
            let epoch = cert.epoch();
            if epoch <= highest_reported_epoch {
                warn!("poller: skipping finalization");
                continue;
            }

            // Report the epoch transition to the orchestrator.
            let seed = cert.seed();
            info!(epoch, ?seed, "poller: reporting epoch transition");
            let mut orchestrator = self.orchestrator.clone();
            orchestrator.report(EpochTransition { epoch, seed }).await;
            highest_reported_epoch = epoch;
        }
    }
}
