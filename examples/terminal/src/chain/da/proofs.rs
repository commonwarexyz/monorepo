//! Proofs reconstructed from original sources in native QMDB operations.

use super::{Lane, payout};
use crate::chain::{
    query::{Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse},
    state::{Record, admitted_key},
    types::Database,
};
use anyhow::{Context as _, Result, ensure};
use commonware_clearing::bajillion::{custody::Epoch, qmdb::account_key, transition::Header};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;

#[cfg(test)]
mod tests;

pub(super) async fn serve<E: StorageContext + Spawner>(
    db: &Database<E>,
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
    match &request.lookup {
        EvidenceLookup::State {
            root,
            operations,
            account,
        } => {
            let lookup = replica
                .state()
                .lookup_at(*root, *operations, &account_key(account)?)
                .await?;
            return Ok(EvidenceResponse::Served(Evidence::State(lookup)));
        }
        EvidenceLookup::Payout { head, index } => {
            return Ok(EvidenceResponse::Served(Evidence::Payout(
                payout(replica, head, *index).await?,
            )));
        }
        _ => {}
    }
    let epoch = request.lookup.epoch().context("missing epoch")?;
    let source = Epoch::load(replica.logs(), epoch).await?;
    ensure!(
        source.context().deployment() == &request.deployment
            && source.context().payment().epoch() == epoch,
        "native source context mismatch"
    );
    let evidence = match request.lookup {
        EvidenceLookup::Source { heads, .. } => {
            Evidence::Source(source.source_proof(replica.logs(), &heads).await?)
        }
        EvidenceLookup::Account { heads, account, .. } => Evidence::Account(
            source
                .account_lookup(replica.logs(), &heads, &account)
                .await?,
        ),
        EvidenceLookup::CommittedEntry {
            heads,
            payer,
            recipient,
            ..
        } => Evidence::CommittedEntry(
            source
                .higher_entry_lookup(replica.logs(), &heads, &payer, &recipient)
                .await?,
        ),
        EvidenceLookup::CloseEvidence { batch_id, .. } => {
            let roots = if let Some(decision) =
                lane.manifest().decision.as_ref().filter(|decision| {
                    lane.manifest().candidate.is_some()
                        && decision.epoch == epoch
                        && decision.header.batch_id::<Sha256>() == batch_id
                }) {
                ensure!(
                    decision.context == *source.context(),
                    "voted source context mismatch"
                );
                decision.roots
            } else {
                let db = db.read().await;
                let Some(Record::Admitted(admitted)) = db
                    .get(&admitted_key(lane.deployment.digest(), epoch))
                    .await?
                else {
                    return Ok(EvidenceResponse::Unsealed);
                };
                ensure!(
                    admitted.batch_id == batch_id,
                    "requested close is not admitted"
                );
                admitted.roots
            };
            let heads = roots.logs();
            let proof = source.source_proof(replica.logs(), &heads).await?;
            let verified = proof.verify::<Sha256, crate::protocol::Key>(&heads)?;
            let mut withdrawal_claims = Vec::with_capacity(verified.withdrawals().len());
            let mut total = 0u64;
            for request in verified.withdrawals().requests() {
                let index = verified
                    .withdrawal_index(request.account())
                    .context("missing native payout index")?;
                let claim = payout(replica, &heads.payouts, index).await?;
                let output = verified.verify_withdrawal::<Sha256>(request, &claim)?;
                total = total
                    .checked_add(output.amount())
                    .context("withdrawal total overflow")?;
                withdrawal_claims.push(claim);
            }
            let header = Header::<Digest>::new::<Sha256, _>(source.context(), &roots, total);
            ensure!(
                header.batch_id::<Sha256>() == batch_id,
                "native source does not match the certified close"
            );
            Evidence::Close {
                header,
                roots,
                context: source.context().clone(),
                withdrawal_claims,
            }
        }
        EvidenceLookup::State { .. } | EvidenceLookup::Payout { .. } => {
            unreachable!("handled without epoch")
        }
    };
    Ok(EvidenceResponse::Served(evidence))
}
