mod actor;
mod ingress;

use crate::{
    threshold_simplex::{Context, View},
    Automaton, Committer, Relay, ThresholdSupervisor,
};
pub use actor::Actor;
use commonware_cryptography::bls12381::primitives::group;
use commonware_cryptography::Scheme;
use commonware_utils::Array;
pub use ingress::{Mailbox, Message};
use std::time::Duration;

pub struct Config<
    C: Scheme,
    D: Array,
    A: Automaton<Context = Context<D>>,
    R: Relay<Digest = D>,
    F: Committer<Digest = D>,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub crypto: C,
    pub automaton: A,
    pub relay: R,
    pub committer: F,
    pub supervisor: S,

    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: View,
    pub skip_timeout: View,
    pub replay_concurrency: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_simplex::{
        actors::resolver,
        mocks,
        wire::{self, backfiller},
        Prover, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    };
    use bytes::Bytes;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{
                group::{self, Share, Signature},
                poly::{self, Public},
            },
        },
        sha256::Digest,
        Ed25519, Scheme as CryptoScheme, Sha256, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Config as NConfig, Network};
    use commonware_runtime::{
        deterministic::{self, Context as DeterministicContext, Executor},
        Blob, Clock, Metrics, Runner, Spawner, Storage,
    };
    use commonware_storage::journal::variable::{Config as JConfig, Journal};
    use commonware_utils::{quorum, Array};
    use futures::{
        channel::mpsc::{self, UnboundedReceiver},
        StreamExt,
    };
    use prost::Message;
    use std::time::Duration;
    use std::{
        collections::BTreeMap,
        sync::{atomic::AtomicI64, Arc},
    };

    // Mock Committer (no-op)
    #[derive(Clone)]
    struct MockCommitter;
    impl Committer for MockCommitter {
        type Digest = <Sha256 as commonware_cryptography::Hasher>::Digest;
        async fn prepared(&mut self, _proof: Bytes, _payload: Self::Digest) {}
        async fn finalized(&mut self, _proof: Bytes, _payload: Self::Digest) {}
    }

    // Test for late notarization causing a panic
    #[test_traced]
    fn test_late_notarization_panic() {
        let n = 5;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Get participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::<Digest>::new(*pk, &namespace);

            // Initialize voter actor
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let mut participants = BTreeMap::new();
            participants.insert(0, (public.clone(), validators.clone(), shares[0]));
            let supervisor_config = mocks::supervisor::Config {
                prover: prover.clone(),
                participants,
            };
            let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                tracker: done_sender.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let cfg = JConfig {
                partition: "test".to_string(),
            };
            let journal = Journal::init(context.with_label("journal"), cfg)
                .await
                .expect("unable to create journal");

            let cfg = Config {
                crypto: scheme,
                automaton: application.clone(),
                relay: application.clone(),
                committer: MockCommitter,
                supervisor,

                namespace,
                mailbox_size: 10,
                leader_timeout: Duration::from_secs(5),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(5),
                activity_timeout: 10,
                skip_timeout: 10,
                replay_concurrency: 1,
            };
            let (mut actor, mut mailbox) = Actor::new(context.clone(), journal, cfg);

            // Create a dummy backfiller mailbox (not used in this path)
            let (backfiller_sender, backfiller_receiver) = mpsc::channel(1);
            let backfiller = resolver::Mailbox::new(backfiller_sender);

            // Create a dummy network mailbox
            let (voter_sender, voter_receiver) = oracle.register(validator, 0).await.unwrap();

            // Run the actor, expecting it to panic
            actor.start(backfiller, voter_sender, voter_receiver);
        });
    }
}
