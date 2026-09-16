//! Proofs reconstructed from retained native QMDB operations at caller-supplied roots.

use super::{Lane, payout};
use crate::chain::query::{Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse};
use anyhow::{Context as _, Result, ensure};
use commonware_clearing::bajillion::{custody::Epoch, qmdb::account_key};
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;

#[cfg(test)]
mod tests;

pub(super) async fn serve<E: StorageContext + Spawner>(
    lanes: &[Lane<E>],
    request: EvidenceRequest,
) -> Result<EvidenceResponse> {
    let Some(lane) = lanes
        .iter()
        .find(|lane| lane.deployment.digest() == &request.deployment)
    else {
        return Ok(EvidenceResponse::Unknown);
    };
    let replica = lane.state.as_ref().context("native owner is unavailable")?;
    ensure!(
        replica.head() == lane.manifest().complete().checkpoint.head,
        "native proof owner is not a complete checkpoint"
    );
    let evidence = match request.lookup {
        EvidenceLookup::State {
            root,
            operations,
            account,
        } => Evidence::State(
            replica
                .state()
                .lookup_at(root, operations, &account_key(&account)?)
                .await?,
        ),
        EvidenceLookup::Payout { head, index } => {
            Evidence::Payout(payout(replica, &head, index).await?)
        }
        EvidenceLookup::Account {
            epoch,
            range,
            account,
        } => Evidence::Account(
            Epoch::at(replica.logs(), epoch, range)
                .await?
                .account_lookup(replica.logs(), &account)
                .await?,
        ),
        EvidenceLookup::CommittedEntry {
            epoch,
            range,
            payer,
            recipient,
        } => Evidence::CommittedEntry(
            Epoch::at(replica.logs(), epoch, range)
                .await?
                .higher_entry_lookup(replica.logs(), &payer, &recipient)
                .await?,
        ),
    };
    Ok(EvidenceResponse::Served(evidence))
}
