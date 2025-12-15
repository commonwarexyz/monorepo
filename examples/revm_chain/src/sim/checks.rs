//! Simulation assertions.
//!
//! Waits for finalizations and asserts all nodes converge on:
//! - the same finalized head digest,
//! - the same state commitment, and
//! - the expected balances for the injected transfer.

use super::{demo, ConsensusDigest};
use crate::{application::Handle, consensus};
use alloy_evm::revm::primitives::B256;
use futures::{channel::mpsc, StreamExt as _};

/// Wait until each node has observed `blocks` finalizations and return the common head digest.
pub(super) async fn wait_for_finalized_head(
    finalized_rx: &mut mpsc::UnboundedReceiver<consensus::FinalizationEvent>,
    nodes: usize,
    blocks: u64,
) -> anyhow::Result<ConsensusDigest> {
    if blocks == 0 {
        return Err(anyhow::anyhow!("blocks must be greater than zero"));
    }

    let mut counts = vec![0u64; nodes];
    let mut nth = vec![None; nodes];
    while nth.iter().any(Option::is_none) {
        let Some((node, digest)) = finalized_rx.next().await else {
            break;
        };
        let idx = node as usize;
        if nth[idx].is_some() {
            continue;
        }
        counts[idx] += 1;
        if counts[idx] == blocks {
            nth[idx] = Some(digest);
        }
    }

    let head = nth
        .first()
        .and_then(|d| *d)
        .ok_or_else(|| anyhow::anyhow!("missing finalization"))?;
    for (i, d) in nth.iter().enumerate() {
        let Some(d) = d else {
            return Err(anyhow::anyhow!("node {i} missing finalization"));
        };
        if *d != head {
            return Err(anyhow::anyhow!("divergent finalized heads"));
        }
    }
    Ok(head)
}

/// Query each node's application store at `head` and assert they all agree on the outcome.
pub(super) async fn assert_all_nodes_converged(
    nodes: &[Handle],
    head: ConsensusDigest,
    demo: &demo::DemoTransfer,
) -> anyhow::Result<(crate::StateRoot, B256)> {
    let mut state_root = None;
    let mut seed = None;
    for node in nodes.iter() {
        let from_balance = node
            .query_balance(head, demo.from)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing from balance"))?;
        let to_balance = node
            .query_balance(head, demo.to)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing to balance"))?;
        if from_balance != demo.expected_from || to_balance != demo.expected_to {
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

        let node_seed = node
            .query_seed(head)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing seed"))?;
        seed = match seed {
            None => Some(node_seed),
            Some(prev) if prev == node_seed => Some(prev),
            Some(_) => return Err(anyhow::anyhow!("divergent seeds")),
        };
    }

    let state_root = state_root.ok_or_else(|| anyhow::anyhow!("missing state root"))?;
    let seed = seed.ok_or_else(|| anyhow::anyhow!("missing seed"))?;
    Ok((state_root, seed))
}
