use crate::{orchestrator::EpochUpdate, GENESIS_BLOCK, NAMESPACE};
use commonware_codec::extensions::DecodeRangeExt;
use commonware_consensus::threshold_simplex::types::Finalization;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    sha256::Digest as Sha256Digest,
    Committable,
};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use rand::{seq::SliceRandom, Rng};
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// Poller actor: periodically polls configured indexers for the latest
/// finalizations, validates them against the network identity, and reports
/// next-epoch transitions to the orchestrator.
pub struct Poller<E, O>
where
    E: Clock + Spawner + Metrics + Rng,
    O: commonware_consensus::Reporter<Activity = EpochUpdate>,
{
    context: E,
    identity: <MinSig as Variant>::Public,
    indexers: Vec<String>,
    client: reqwest::Client,
    orchestrator: O,
    poll_interval: Duration,
}

impl<E, O> Poller<E, O>
where
    E: Clock + Spawner + Metrics + Rng,
    O: commonware_consensus::Reporter<Activity = EpochUpdate> + Clone,
{
    pub fn new(
        context: E,
        identity: <MinSig as Variant>::Public,
        indexers: Vec<String>,
        orchestrator: O,
    ) -> Self {
        Self {
            context,
            identity,
            indexers,
            client: reqwest::Client::new(),
            orchestrator,
            poll_interval: Duration::from_secs(2),
        }
    }

    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(self) {
        // Track which next-epochs we've already reported to the orchestrator.
        let mut highest_reported_epoch: u64 = 0;
        let mut rng = self.context.clone();

        // No indexers configured; nothing to do.
        if self.indexers.is_empty() {
            return;
        }

        loop {
            // Sleep between indexer polls.
            self.context.sleep(self.poll_interval).await;

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
                    Err(e) => {
                        debug!(url = %url, error = %e, "poller: failed to read response body");
                        continue;
                    }
                },
                Err(e) => {
                    debug!(url = %url, error = %e, "poller: latest fetch failed");
                    continue;
                }
            };

            // Decode Vec<Finalization<MinSig, Sha256Digest>> with an upper bound of 2.
            let Ok(finals) =
                <Vec<Finalization<MinSig, Sha256Digest>>>::decode_range(resp.as_ref(), 0..=2)
            else {
                debug!(url = %url, "poller: failed to decode latest finalizations");
                continue;
            };

            // Validate the finalization epochs.
            match finals.len() {
                0 => {
                    debug!(url = %url, "poller: no finalizations");
                    continue;
                }
                1 => {
                    // If there is only one finalization, it must have the epoch of 0.
                    let f = &finals[0];
                    if f.proposal.round.epoch() != 0 {
                        debug!(url = %url, "poller: finalization has invalid epoch");
                        continue;
                    };
                }
                2 => {
                    // If there are two finalizations, they must have consecutive epochs.
                    let f1 = &finals[0];
                    let f2 = &finals[1];
                    if f1.proposal.round.epoch().checked_add(1).unwrap()
                        != f2.proposal.round.epoch()
                    {
                        debug!(url = %url, "poller: finalizations have invalid epochs");
                        continue;
                    }
                }
                _ => {
                    unreachable!();
                }
            }

            // Verify the finalization signatures.
            for f in finals.iter() {
                if !f.verify(NAMESPACE, &self.identity) {
                    warn!(url = %url, "poller: finalization failed verification");
                    continue;
                }
            }

            // The last finalization must be the highest-epoch finalization.
            let epoch = finals[finals.len() - 1].proposal.round.epoch();
            if epoch <= highest_reported_epoch {
                trace!(url = %url, "poller: skipping finalization");
                continue;
            }

            // Get the seed.
            let seed = match epoch {
                0 => GENESIS_BLOCK.commitment(),
                _ => finals[0].proposal.payload,
            };

            // Report the epoch transition to the orchestrator.
            let next_epoch = epoch + 1;
            info!(next_epoch, "poller: reporting epoch transition");
            let mut orchestrator = self.orchestrator.clone();
            orchestrator
                .report(EpochUpdate {
                    epoch: next_epoch,
                    seed,
                })
                .await;
            highest_reported_epoch = epoch;
        }
    }
}
