use crate::types::block::Block;
use commonware_codec::Encode;
use commonware_consensus::{marshal, threshold_simplex::types::Activity, Reporter};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
};
use tracing::error;

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
            client: reqwest::Client::new(),
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

        let commitment = finalization.proposal.payload;

        // Best-effort: try to get the block locally from marshal; skip if unavailable
        let rx = self.marshal.get(commitment).await;
        let Ok(Some(block)) = rx.await else {
            return;
        };

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
                error!("failed to post finalization to indexer {}: {}", base, e);
            };
        }
    }
}
