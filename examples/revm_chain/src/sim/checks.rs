use super::{genesis, ConsensusDigest};
use crate::application::Handle;
use crate::consensus;
use futures::{channel::mpsc, StreamExt as _};

pub(super) async fn wait_for_finalized_head(
    finalized_rx: &mut mpsc::UnboundedReceiver<consensus::FinalizationEvent>,
    nodes: usize,
    blocks: u64,
) -> anyhow::Result<ConsensusDigest> {
    let mut counts = vec![0u64; nodes];
    let mut last = vec![None; nodes];
    while counts.iter().any(|count| *count < blocks) {
        let Some((node, digest)) = finalized_rx.next().await else {
            break;
        };
        let idx = node as usize;
        counts[idx] += 1;
        last[idx] = Some(digest);
    }

    let head = last
        .first()
        .and_then(|d| *d)
        .ok_or_else(|| anyhow::anyhow!("missing finalization"))?;
    for (i, d) in last.iter().enumerate() {
        let Some(d) = d else {
            return Err(anyhow::anyhow!("node {i} missing finalization"));
        };
        if *d != head {
            return Err(anyhow::anyhow!("divergent finalized heads"));
        }
    }
    Ok(head)
}

pub(super) async fn assert_all_nodes_converged(
    nodes: &[Handle],
    head: ConsensusDigest,
    genesis: &genesis::GenesisTransfer,
) -> anyhow::Result<crate::StateRoot> {
    let mut state_root = None;
    for node in nodes.iter() {
        let from_balance = node
            .query_balance(head, genesis.from)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing from balance"))?;
        let to_balance = node
            .query_balance(head, genesis.to)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing to balance"))?;
        if from_balance != genesis.expected_from || to_balance != genesis.expected_to {
            return Err(anyhow::anyhow!("unexpected balances"));
        }

        let root = node
            .query_state_root(head)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing state root"))?;
        state_root = match state_root {
            None => Some(root),
            Some(prev) if prev == root => Some(prev),
            Some(_) => return Err(anyhow::anyhow!("divergent state roots")),
        };
    }
    state_root.ok_or_else(|| anyhow::anyhow!("missing state root"))
}
