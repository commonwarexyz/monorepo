use crate::types::{block::Block, epoch};
use commonware_codec::Encode;
use commonware_consensus::{marshal, threshold_simplex::types::Activity, Block as _, Reporter};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
};
use std::time::Duration;
use tracing::{error, info};

/// Reporter implementation for forwarding finalizations to multiple indexers.
#[derive(Clone)]
pub struct Forwarder {
    marshal: marshal::Mailbox<MinSig, Block>,
    client: reqwest::Client,
    indexers: Vec<String>,
}

impl Forwarder {
    pub fn new(marshal: marshal::Mailbox<MinSig, Block>, indexers: Vec<String>) -> Self {
        Self {
            marshal,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            indexers,
        }
    }
}

impl Reporter for Forwarder {
    type Activity = Activity<MinSig, Sha256Digest>;

    async fn report(&mut self, activity: Self::Activity) {
        let Activity::Finalization(finalization) = activity else {
            return;
        };

        // Best-effort: try to get the block locally from marshal; skip if unavailable
        let rx = self.marshal.get(finalization.proposal.payload).await;
        let Ok(Some(block)) = rx.await else {
            error!(
                "forwarder: failed to get block: {}",
                finalization.proposal.payload
            );
            return;
        };

        // Skip if block height is not the last height in the epoch
        let height = block.height();
        let epoch = finalization.proposal.round.epoch();
        if height != epoch::get_last_height(epoch) {
            return;
        }

        // TODO: remove?
        info!(
            "forwarder: reporting finalization: height: {}, epoch: {}, indexers: {:?}",
            height, epoch, self.indexers
        );

        // Encode (finalization, block) and POST to indexer
        let bytes = (finalization, block).encode().freeze();
        for base in &self.indexers {
            let url = format!("{}/upload", base);
            if let Err(e) = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes.clone())
                .send()
                .await
            {
                error!(
                    "forwarder:failed to post finalization to indexer {}: {}",
                    base, e
                );
            } else {
                info!("forwarder: posted finalization to indexer {}", base);
            }
        }
    }
}
