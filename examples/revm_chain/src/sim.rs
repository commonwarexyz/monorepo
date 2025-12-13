use crate::consensus;
use crate::ConsensusDigest;
use alloy_evm::revm::primitives::{Address, Bytes as EvmBytes, U256};
use commonware_consensus::{
    simplex,
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_cryptography::{bls12381::dkg, ed25519, PrivateKeyExt as _, Signer as _};
use commonware_p2p::{simulated, Manager as _, Receiver as _};
use commonware_runtime::{buffer::PoolRef, deterministic, Metrics as _, Runner as _, Spawner as _};
use commonware_utils::{ordered::Set, TryCollect as _, NZU32, NZUsize};
use futures::{channel::mpsc, StreamExt as _};
use governor::Quota;
use rand::{rngs::StdRng, SeedableRng as _};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    pub nodes: usize,
    pub blocks: u64,
    pub seed: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SimOutcome {
    pub head: ConsensusDigest,
    pub state_root: crate::StateRoot,
    pub from_balance: U256,
    pub to_balance: U256,
}

pub fn simulate(cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    let executor = deterministic::Runner::seeded(cfg.seed);
    executor.start(|context| async move {
        let mut rng = StdRng::seed_from_u64(cfg.seed);
        let (participants_vec, schemes) =
            threshold_schemes(&mut rng, cfg.nodes).expect("fixture build");
        let participants: Set<_> = participants_vec
            .iter()
            .cloned()
            .try_collect()
            .expect("participant public keys are unique");

        let (network, mut oracle) = simulated::Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();

        let mut manager = oracle.manager();
        manager.update(0, participants.clone()).await;

        // Fully connect peers with ideal links.
        for a in participants_vec.iter() {
            for b in participants_vec.iter() {
                if a == b {
                    continue;
                }
                oracle
                    .add_link(
                        a.clone(),
                        b.clone(),
                        simulated::Link {
                            latency: Duration::from_millis(5),
                            jitter: Duration::from_millis(0),
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .expect("link should be added");
            }
        }

        const VOTES: u64 = 0;
        const CERTS: u64 = 1;
        const RESOLVER: u64 = 2;
        const BLOCKS: u64 = 3;

        let quota = Quota::per_second(NZU32!(1_000));
        let buffer_pool = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

        let from = Address::from([0x11u8; 20]);
        let to = Address::from([0x22u8; 20]);
        let genesis_alloc = vec![(from, U256::from(1_000_000u64)), (to, U256::ZERO)];
        let genesis_tx = crate::Tx {
            from,
            to,
            value: U256::from(100u64),
            gas_limit: 21_000,
            data: EvmBytes::new(),
        };

        let (finalized_tx, mut finalized_rx) = mpsc::unbounded::<consensus::FinalizationEvent>();
        let mut mailboxes = Vec::with_capacity(cfg.nodes);

        for (i, pk) in participants_vec.iter().cloned().enumerate() {
            let mut control = oracle.control(pk.clone());
            let (vote_sender, vote_receiver) = control.register(VOTES, quota).await.unwrap();
            let (cert_sender, cert_receiver) = control.register(CERTS, quota).await.unwrap();
            let (resolver_sender, resolver_receiver) =
                control.register(RESOLVER, quota).await.unwrap();
            let (block_sender, mut block_receiver) = control.register(BLOCKS, quota).await.unwrap();

            let (application, mailbox, inbox) = consensus::Application::new(
                i as u32,
                consensus::BlockCodecCfg {
                    max_txs: 64,
                    max_calldata_bytes: 1024,
                },
                1024,
                block_sender,
                finalized_tx.clone(),
                genesis_alloc.clone(),
                Some(genesis_tx.clone()),
            );

            let mailbox_for_blocks = mailbox.clone();
            context
                .with_label(&format!("block_receiver_{i}"))
                .spawn(move |_ctx| async move {
                    while let Ok((from, bytes)) = block_receiver.recv().await {
                        mailbox_for_blocks.deliver_block(from, bytes).await;
                    }
                });

            context
                .with_label(&format!("application_{i}"))
                .spawn(move |_ctx| async move {
                    application.run(inbox).await;
                });

            let scheme = schemes[i].clone();
            let blocker = oracle.control(pk.clone());
            let engine = simplex::Engine::new(
                context.with_label(&format!("engine_{i}")),
                simplex::Config {
                    scheme,
                    blocker,
                    automaton: mailbox.clone(),
                    relay: mailbox.clone(),
                    reporter: mailbox.clone(),
                    partition: format!("revm-chain-{i}"),
                    mailbox_size: 1024,
                    epoch: Epoch::zero(),
                    namespace: b"revm-chain-consensus".to_vec(),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    leader_timeout: Duration::from_millis(50),
                    notarization_timeout: Duration::from_millis(100),
                    nullify_retry: Duration::from_millis(200),
                    fetch_timeout: Duration::from_millis(200),
                    activity_timeout: ViewDelta::new(10),
                    skip_timeout: ViewDelta::new(5),
                    fetch_concurrent: 16,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
                    buffer_pool: buffer_pool.clone(),
                },
            );
            engine.start(
                (vote_sender, vote_receiver),
                (cert_sender, cert_receiver),
                (resolver_sender, resolver_receiver),
            );

            mailboxes.push(mailbox);
        }

        let mut counts = vec![0u64; cfg.nodes];
        let mut last = vec![None; cfg.nodes];
        while counts.iter().any(|count| *count < cfg.blocks) {
            let Some((node, digest)) = finalized_rx.next().await else {
                break;
            };
            let idx = node as usize;
            counts[idx] += 1;
            last[idx] = Some(digest);
        }

        let head = last
            .get(0)
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

        let expected_from = U256::from(1_000_000u64 - 100);
        let expected_to = U256::from(100u64);
        let mut state_root = None;
        for mailbox in mailboxes.iter() {
            let from_balance = mailbox
                .query_balance(head, from)
                .await
                .ok_or_else(|| anyhow::anyhow!("missing from balance"))?;
            let to_balance = mailbox
                .query_balance(head, to)
                .await
                .ok_or_else(|| anyhow::anyhow!("missing to balance"))?;
            if from_balance != expected_from || to_balance != expected_to {
                return Err(anyhow::anyhow!("unexpected balances"));
            }

            let root = mailbox
                .query_state_root(head)
                .await
                .ok_or_else(|| anyhow::anyhow!("missing state root"))?;
            state_root = match state_root {
                None => Some(root),
                Some(prev) if prev == root => Some(prev),
                Some(_) => return Err(anyhow::anyhow!("divergent state roots")),
            };
        }

        Ok(SimOutcome {
            head,
            state_root: state_root.expect("state root missing"),
            from_balance: expected_from,
            to_balance: expected_to,
        })
    })
}

fn threshold_schemes(
    rng: &mut StdRng,
    n: usize,
) -> anyhow::Result<(
    Vec<ed25519::PublicKey>,
    Vec<simplex::signing_scheme::bls12381_threshold::Scheme<ed25519::PublicKey, MinSig>>,
)> {
    let participants: Set<ed25519::PublicKey> = (0..n)
        .map(|_| ed25519::PrivateKey::from_rng(rng).public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let (output, shares) = dkg::deal::<MinSig, _>(rng, participants.clone())
        .map_err(|e| anyhow::anyhow!("dkg deal failed: {e:?}"))?;

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let share = shares.get_value(pk).expect("share exists").clone();
        let scheme =
            simplex::signing_scheme::bls12381_threshold::Scheme::signer(
                participants.clone(),
                output.public(),
                share,
            )
            .expect("signer should exist");
        schemes.push(scheme);
    }

    Ok((participants.into(), schemes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sim_smoke() {
        let outcome = simulate(SimConfig {
            nodes: 4,
            blocks: 3,
            seed: 42,
        })
        .unwrap();
        assert_eq!(outcome.from_balance, U256::from(1_000_000u64 - 100));
        assert_eq!(outcome.to_balance, U256::from(100u64));
    }
}
