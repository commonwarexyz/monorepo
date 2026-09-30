//! Probe tests.

use super::{
    Checkpoint, Config, Mailbox, Probe, Sampled, Source,
    join::{Chain, drive},
    mailbox::Message,
    wire,
};
use bytes::BufMut;
use commonware_actor::mailbox as actor_mailbox;
use commonware_codec::{
    Buf, Decode as _, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Block, Epochable, Heightable, Viewable,
    aggregation::{
        scheme::ed25519,
        types::{Ack, Certificate, Item},
    },
    marshal::{Floors, Ledger},
    types::{Epoch, Height, OutputIndex, View},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher as _, Sha256, Signer as _,
    certificate::mocks::Fixture,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver as _, Recipients, Sender as _,
    simulated::{self, Config as NetworkConfig, Link, Network, Oracle},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Quota, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{
    NZDuration, NZU64, NZUsize, channel::fallible::OneshotExt as _, non_empty, probability,
    sync::Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const CHANNEL: u64 = 0;
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// Blocks per checkpoint: checkpoint `k` certifies the block at height `2k + 1`.
const INTERVAL: u64 = 2;

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_EXECUTOR_PROBE_TEST";

/// An executed block.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
struct Executed {
    height: Height,
    value: u64,
}

impl Write for Executed {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.value.write(buf);
    }
}

impl EncodeSize for Executed {
    fn encode_size(&self) -> usize {
        self.height.encode_size() + self.value.encode_size()
    }
}

impl Read for Executed {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(buf)?,
            value: u64::read(buf)?,
        })
    }
}

impl Digestible for Executed {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[b"executed", &self.encode()])
    }
}

impl Heightable for Executed {
    fn height(&self) -> Height {
        self.height
    }
}

impl Block for Executed {
    fn parent(&self) -> Digest {
        Digest::EMPTY
    }
}

/// A floor finalized at the view of its value, whose certificate verifies unless the value is the
/// largest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
struct Floor(u64);

impl Write for Floor {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for Floor {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for Floor {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(u64::read(buf)?))
    }
}

impl Epochable for Floor {
    fn epoch(&self) -> Epoch {
        Epoch::zero()
    }
}

impl Viewable for Floor {
    fn view(&self) -> View {
        View::new(self.0)
    }
}

type TestCheckpoint = Checkpoint<ed25519::Scheme, Executed, Floor>;
type TestMailbox = Mailbox<ed25519::Scheme, Executed, Floor>;

/// Serves whatever checkpoint the test sets, if any.
#[derive(Clone, Default)]
struct Fixed(Arc<Mutex<Option<TestCheckpoint>>>);

impl Fixed {
    fn set(&self, checkpoint: TestCheckpoint) {
        *self.0.lock() = Some(checkpoint);
    }
}

impl Source for Fixed {
    type Scheme = ed25519::Scheme;
    type Block = Executed;
    type Floor = Floor;

    fn interval(&self) -> NonZeroU64 {
        NZU64!(INTERVAL)
    }

    fn latest(&self) -> Option<Height> {
        self.0
            .lock()
            .as_ref()
            .map(|checkpoint| checkpoint.certificate.item.height)
    }

    async fn newest(&self) -> Option<TestCheckpoint> {
        self.0.lock().clone()
    }
}

/// Validators, each running a probe that serves its own [`Fixed`] checkpoint.
struct Validators {
    schemes: Vec<ed25519::Scheme>,
    participants: Vec<PublicKey>,
    /// A peer of the network that is not a validator.
    outsider: PublicKey,
    oracle: Oracle<PublicKey, deterministic::Context>,
    sources: Vec<Fixed>,
    /// The first validator's probe. The others' mailboxes are dropped, as a node that only
    /// serves drops its own.
    sampler: TestMailbox,
    _probes: Vec<Handle<()>>,
}

impl Validators {
    async fn start(context: &mut deterministic::Context, n: u32) -> Self {
        Self::start_with(context, n, NZUsize!(1024 * 1024)).await
    }

    async fn start_with(
        context: &mut deterministic::Context,
        n: u32,
        max_response_size: NonZeroUsize,
    ) -> Self {
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(context, NAMESPACE, n);
        let outsider = PrivateKey::from_seed(u64::MAX).public_key();
        let peers: Vec<_> = participants
            .iter()
            .cloned()
            .chain([outsider.clone()])
            .collect();
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(peers.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            peers.clone(),
        )
        .await;
        network.start();
        for a in &peers {
            for b in &peers {
                if a != b {
                    oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
                }
            }
        }

        let mut sources = Vec::new();
        let mut sampler = None;
        let mut probes = Vec::new();
        for (index, public_key) in participants.iter().enumerate() {
            let context = context.child("validator").with_attribute("index", index);
            let control = oracle.control(public_key.clone());
            let network = control.register(CHANNEL, QUOTA).await.unwrap();
            let (probe, mailbox) = Probe::new(Config {
                context: context.child("probe"),
                scheme: schemes[index].clone(),
                strategy: Sequential,
                blocker: control,
                block_codec: (),
                floor_codec: (),
                retry_timeout: NZDuration!(Duration::from_millis(100)),
                max_response_size,
                mailbox_size: NZUsize!(16),
            });
            let source = Fixed::default();
            probes.push(probe.start(network, source.clone()));
            sources.push(source);
            sampler.get_or_insert(mailbox);
        }
        Self {
            schemes,
            participants,
            outsider,
            oracle,
            sources,
            sampler: sampler.unwrap(),
            _probes: probes,
        }
    }

    /// Returns checkpoint `checkpoint` of a block with `value`, certified by every validator, with
    /// a floor finalized at view `floor`.
    fn checkpoint(&self, checkpoint: u64, value: u64, floor: Option<u64>) -> TestCheckpoint {
        let block = Executed {
            height: Height::new((checkpoint + 1) * INTERVAL - 1),
            value,
        };
        let item = Item {
            height: Height::new(checkpoint),
            digest: block.digest(),
        };
        let acks = self
            .schemes
            .iter()
            .map(|scheme| Ack::sign(scheme, Epoch::zero(), item.clone()).unwrap())
            .collect::<Vec<_>>();
        TestCheckpoint {
            certificate: Certificate::from_acks(
                &self.schemes[0],
                non_empty![@acks.iter()],
                &Sequential,
            )
            .unwrap(),
            block: Arc::new(block),
            floor: floor.map(Floor),
        }
    }

    /// Returns the validators the first one blocked.
    async fn blocked_by_first(&self) -> Vec<PublicKey> {
        self.oracle
            .blocked()
            .await
            .unwrap()
            .into_iter()
            .filter(|(blocker, _)| *blocker == self.participants[0])
            .map(|(_, blocked)| blocked)
            .collect()
    }
}

#[test]
fn samples_the_newest_checkpoint_among_f_plus_one_validators() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        validators.sources[1].set(validators.checkpoint(1, 10, Some(2)));
        validators.sources[2].set(validators.checkpoint(3, 30, Some(5)));

        // One fault is tolerated, so the two replies decide, the newest checkpoint wins, and the
        // floors are ranked by view.
        let Sampled {
            certificate,
            block,
            floors,
        } = validators.sampler.sample().await.unwrap();
        assert_eq!(certificate.item.height, Height::new(3));
        assert_eq!(block.height, Height::new(7));
        assert_eq!(block.value, 30);
        assert_eq!(floors, vec![Floor(5), Floor(2)]);
        assert!(validators.blocked_by_first().await.is_empty());
    });
}

#[test]
fn a_sample_waits_for_enough_validators() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        validators.sources[1].set(validators.checkpoint(1, 10, None));

        // One reply is not enough, so the sample asks again until a second validator answers.
        let sample = validators.sampler.sample();
        let second = async {
            context.sleep(Duration::from_millis(250)).await;
            validators.sources[3].set(validators.checkpoint(0, 5, None));
        };
        let (sampled, ()) = futures::join!(sample, second);
        let sampled = sampled.unwrap();
        assert_eq!(sampled.certificate.item.height, Height::new(1));
        assert!(sampled.floors.is_empty());
    });
}

#[test]
fn invalid_checkpoints_block_their_senders_and_unverifiable_ones_are_ignored() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 10).await;

        // A block other than the certified one and a block at another height are invalid. A
        // certificate that does not verify may come from a validator set this node does not
        // know.
        let mut misnamed = validators.checkpoint(4, 40, None);
        misnamed.block = Arc::new(Executed {
            height: misnamed.block.height,
            value: 41,
        });
        validators.sources[1].set(misnamed);
        let mut misplaced = validators.checkpoint(4, 40, None);
        misplaced.certificate.item.height = Height::new(5);
        validators.sources[2].set(misplaced);
        let mut forged = validators.checkpoint(4, 41, None);
        let block = validators.checkpoint(4, 40, None).block;
        forged.certificate.item.digest = block.digest();
        forged.block = block;
        validators.sources[3].set(forged);
        for index in 4..7 {
            validators.sources[index].set(validators.checkpoint(2, 20, None));
        }

        // Three faults are tolerated, so the sample waits for a fourth valid reply, and checks
        // every other one meanwhile.
        let sample = validators.sampler.sample();
        let fourth = async {
            context.sleep(Duration::from_millis(250)).await;
            validators.sources[7].set(validators.checkpoint(2, 20, None));
        };
        let (sampled, ()) = futures::join!(sample, fourth);
        assert_eq!(sampled.unwrap().certificate.item.height, Height::new(2));
        let mut blocked = validators.blocked_by_first().await;
        blocked.sort();
        let mut expected = validators.participants[1..3].to_vec();
        expected.sort();
        assert_eq!(blocked, expected);
    });
}

#[test]
fn floors_are_left_for_marshal_to_verify() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        validators.sources[1].set(validators.checkpoint(1, 10, Some(u64::MAX)));
        validators.sources[2].set(validators.checkpoint(1, 10, Some(3)));
        let sampled = validators.sampler.sample().await.unwrap();
        assert_eq!(sampled.floors, vec![Floor(u64::MAX), Floor(3)]);
        assert!(validators.blocked_by_first().await.is_empty());
    });
}

#[test]
fn replies_from_non_validators_are_ignored() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        validators.sources[1].set(validators.checkpoint(1, 10, None));
        let (mut outsider, _) = validators
            .oracle
            .control(validators.outsider.clone())
            .register(CHANNEL, QUOTA)
            .await
            .unwrap();

        // While the sample waits for a second validator, a peer outside the validator set
        // answers with a newer checkpoint, which does not count.
        let sample = validators.sampler.sample();
        let replies = async {
            context.sleep(Duration::from_millis(50)).await;
            let reply = wire::Message::Response(validators.checkpoint(3, 30, None));
            outsider.send(
                Recipients::One(validators.participants[0].clone()),
                reply.encode(),
                false,
            );
            context.sleep(Duration::from_millis(200)).await;
            validators.sources[2].set(validators.checkpoint(1, 10, None));
        };
        let (sampled, ()) = futures::join!(sample, replies);
        assert_eq!(sampled.unwrap().certificate.item.height, Height::new(1));
        assert!(validators.blocked_by_first().await.is_empty());
    });
}

/// Asks the first validator for its checkpoint as a peer outside the validator set, and returns
/// the height of the checkpoint it answers with, if any.
async fn request_as_outsider(
    context: &deterministic::Context,
    validators: &Validators,
    (outsider, receiver): &mut (
        simulated::Sender<PublicKey, deterministic::Context>,
        simulated::Receiver<PublicKey>,
    ),
) -> Option<Height> {
    outsider.send(
        Recipients::One(validators.participants[0].clone()),
        wire::Message::<ed25519::Scheme, Executed, Floor>::Request.encode(),
        false,
    );
    select! {
        message = receiver.recv() => {
            let (_, message) = message.unwrap();
            let codec = wire::Message::<ed25519::Scheme, Executed, Floor>::codec(
                &validators.schemes[0],
                (),
                (),
            );
            match wire::Message::<ed25519::Scheme, Executed, Floor>::decode_cfg(message, &codec)
                .unwrap()
            {
                wire::Message::Response(checkpoint) => Some(checkpoint.certificate.item.height),
                wire::Message::Request => panic!("a validator answers with a response"),
            }
        },
        _ = context.sleep(Duration::from_millis(100)) => None,
    }
}

#[test]
fn requests_are_answered_from_a_response_built_in_the_background() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        let mut outsider = validators
            .oracle
            .control(validators.outsider.clone())
            .register(CHANNEL, QUOTA)
            .await
            .unwrap();

        // Without a certified checkpoint, a node stays silent.
        assert_eq!(
            request_as_outsider(&context, &validators, &mut outsider).await,
            None
        );

        // The first request after a checkpoint is certified starts building its response, which
        // later requests receive, until a newer checkpoint replaces it.
        validators.sources[0].set(validators.checkpoint(1, 10, None));
        assert_eq!(
            request_as_outsider(&context, &validators, &mut outsider).await,
            None
        );
        assert_eq!(
            request_as_outsider(&context, &validators, &mut outsider).await,
            Some(Height::new(1))
        );
        validators.sources[0].set(validators.checkpoint(2, 20, None));
        assert_eq!(
            request_as_outsider(&context, &validators, &mut outsider).await,
            Some(Height::new(1))
        );
        assert_eq!(
            request_as_outsider(&context, &validators, &mut outsider).await,
            Some(Height::new(2))
        );
        assert!(validators.blocked_by_first().await.is_empty());
    });
}

#[test]
fn a_response_above_the_size_limit_is_not_served() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start_with(&mut context, 4, NZUsize!(8)).await;
        let mut outsider = validators
            .oracle
            .control(validators.outsider.clone())
            .register(CHANNEL, QUOTA)
            .await
            .unwrap();
        validators.sources[0].set(validators.checkpoint(1, 10, None));
        for _ in 0..2 {
            assert_eq!(
                request_as_outsider(&context, &validators, &mut outsider).await,
                None
            );
        }
    });
}

#[test]
fn malformed_messages_block_their_senders() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        let (mut outsider, _) = validators
            .oracle
            .control(validators.outsider.clone())
            .register(CHANNEL, QUOTA)
            .await
            .unwrap();
        outsider.send(
            Recipients::One(validators.participants[0].clone()),
            vec![0xFF],
            false,
        );
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            validators.blocked_by_first().await,
            vec![validators.outsider.clone()]
        );
    });
}

#[test]
fn replies_nobody_awaits_are_ignored() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 4).await;
        let (mut outsider, _) = validators
            .oracle
            .control(validators.outsider.clone())
            .register(CHANNEL, QUOTA)
            .await
            .unwrap();

        // Without a sample in progress, even a reply that would be blocked is skipped unread.
        let mut forged = validators.checkpoint(1, 10, None);
        forged.block = Arc::new(Executed {
            height: forged.block.height,
            value: 11,
        });
        outsider.send(
            Recipients::One(validators.participants[0].clone()),
            wire::Message::Response(forged).encode(),
            false,
        );
        context.sleep(Duration::from_millis(100)).await;
        assert!(validators.blocked_by_first().await.is_empty());
    });
}

/// Marshal could not serve a request.
#[derive(Debug, thiserror::Error)]
#[error("marshal is busy")]
struct Busy;

/// An engine marshal that installs the floors a test accepts, recording each attempt.
#[derive(Clone, Default)]
struct Marshal {
    /// The index each accepted floor, by view, resumes after.
    accepts: Arc<Mutex<BTreeMap<u64, u64>>>,
    /// Whether marshal is too busy to install anything.
    busy: Arc<Mutex<bool>>,
    /// The view of every floor offered, in order.
    installs: Arc<Mutex<Vec<u64>>>,
}

impl Ledger for Marshal {
    type Block = Executed;
    type Error = Busy;

    async fn prune(&self, _: OutputIndex) -> Result<(), Busy> {
        Ok(())
    }

    fn ack_window(&self) -> NonZeroUsize {
        NZUsize!(1)
    }
}

impl Floors for Marshal {
    type Floor = Floor;

    async fn floor_at(&self, _: OutputIndex) -> Result<Option<(OutputIndex, Floor)>, Busy> {
        Ok(None)
    }

    async fn install(&self, floor: Floor) -> Result<Option<OutputIndex>, Busy> {
        self.installs.lock().push(floor.0);
        if *self.busy.lock() {
            return Err(Busy);
        }
        Ok(self
            .accepts
            .lock()
            .get(&floor.0)
            .copied()
            .map(OutputIndex::new))
    }
}

/// An executed chain that records the targets it is offered.
#[derive(Clone, Default)]
struct TestChain {
    /// Whether the chain has a state sync target or a base already.
    resumed: bool,
    /// The height of every block offered, in order.
    offered: Arc<Mutex<Vec<u64>>>,
    /// Whether the chain has a base.
    based: Arc<Mutex<bool>>,
    /// Every index marshal never delivers an input after.
    stalled: BTreeSet<u64>,
}

impl Chain<Executed> for TestChain {
    async fn awaits_floor(&self) -> bool {
        !self.resumed && !*self.based.lock()
    }

    async fn has_base(&self) -> bool {
        *self.based.lock()
    }

    async fn resumed_after(&self, index: OutputIndex) -> bool {
        *self.based.lock() || !self.stalled.contains(&index.get())
    }

    async fn sync_to(&self, block: Arc<Executed>) -> bool {
        self.offered.lock().push(block.height.get());
        !*self.based.lock()
    }
}

/// Runs [`drive`] against `samples`, answered in order, then stops the probe.
async fn join_with(
    context: &mut deterministic::Context,
    marshal: &Marshal,
    chain: &TestChain,
    samples: Vec<(u64, Vec<u64>)>,
) -> usize {
    let Fixture { schemes, .. } = ed25519::fixture(context, NAMESPACE, 4);
    let mut samples: VecDeque<_> = samples
        .into_iter()
        .map(|(checkpoint, floors)| {
            let block = Executed {
                height: Height::new((checkpoint + 1) * INTERVAL - 1),
                value: checkpoint,
            };
            let item = Item {
                height: Height::new(checkpoint),
                digest: block.digest(),
            };
            let acks = schemes
                .iter()
                .map(|scheme| Ack::sign(scheme, Epoch::zero(), item.clone()).unwrap())
                .collect::<Vec<_>>();
            Sampled {
                certificate: Certificate::from_acks(
                    &schemes[0],
                    non_empty![@acks.iter()],
                    &Sequential,
                )
                .unwrap(),
                block: Arc::new(block),
                floors: floors.into_iter().map(Floor).collect(),
            }
        })
        .collect();
    let (sender, mut requests) = actor_mailbox::new(context.child("probe"), NZUsize!(16));
    let answered = Arc::new(Mutex::new(0));
    let responder = context.child("responder").spawn({
        let answered = Arc::clone(&answered);
        move |_| async move {
            while let Some(Message::Sample { response }) = requests.recv().await {
                let Some(sampled) = samples.pop_front() else {
                    return;
                };
                *answered.lock() += 1;
                response.send_lossy(sampled);
            }
        }
    });
    drive(
        context.child("join"),
        TestMailbox::new(sender),
        marshal.clone(),
        chain.clone(),
        NZDuration!(Duration::from_millis(10)),
    )
    .await;
    responder.abort();
    *answered.lock()
}

#[test]
fn join_installs_the_newest_floor_marshal_accepts() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let marshal = Marshal::default();
        marshal.accepts.lock().insert(5, 4);
        let chain = TestChain::default();
        join_with(&mut context, &marshal, &chain, vec![(3, vec![9, 5, 2])]).await;
        assert_eq!(*marshal.installs.lock(), vec![9, 5]);
        assert_eq!(*chain.offered.lock(), vec![7]);
    });
}

#[test]
fn join_replaces_a_floor_marshal_does_not_resume_from() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        // Peers pruned what marshal needs after the first floor, so it never resumes from it.
        let marshal = Marshal::default();
        marshal.accepts.lock().insert(5, 4);
        marshal.accepts.lock().insert(9, 16);
        let chain = TestChain {
            stalled: BTreeSet::from([4]),
            ..TestChain::default()
        };
        join_with(
            &mut context,
            &marshal,
            &chain,
            vec![(3, vec![5]), (5, vec![5]), (8, vec![9, 5])],
        )
        .await;
        assert_eq!(*marshal.installs.lock(), vec![5, 9]);
        assert_eq!(*chain.offered.lock(), vec![17]);
    });
}

#[test]
fn join_offers_only_checkpoints_at_or_above_the_floor() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let marshal = Marshal::default();
        marshal.accepts.lock().insert(5, 10);
        let chain = TestChain::default();
        join_with(
            &mut context,
            &marshal,
            &chain,
            vec![(3, vec![5]), (5, vec![5])],
        )
        .await;
        assert_eq!(*marshal.installs.lock(), vec![5]);
        assert_eq!(*chain.offered.lock(), vec![11]);
    });
}

#[test]
fn join_samples_again_until_marshal_installs_a_floor() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        // No sampled validator serves a floor, then marshal is busy, then it installs one.
        let marshal = Marshal::default();
        marshal.accepts.lock().insert(3, 2);
        let chain = TestChain::default();
        let busy = context.child("busy").spawn({
            let marshal = marshal.clone();
            move |context| async move {
                *marshal.busy.lock() = true;
                while marshal.installs.lock().is_empty() {
                    context.sleep(Duration::from_millis(1)).await;
                }
                *marshal.busy.lock() = false;
            }
        });
        join_with(
            &mut context,
            &marshal,
            &chain,
            vec![(1, vec![]), (2, vec![3]), (3, vec![3])],
        )
        .await;
        busy.await.unwrap();
        assert_eq!(*marshal.installs.lock(), vec![3, 3]);
        assert_eq!(*chain.offered.lock(), vec![7]);
    });
}

#[test]
fn join_after_a_restart_keeps_marshal_where_it_is() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let marshal = Marshal::default();
        let chain = TestChain {
            resumed: true,
            ..TestChain::default()
        };
        join_with(
            &mut context,
            &marshal,
            &chain,
            vec![(3, vec![5]), (4, vec![5])],
        )
        .await;
        assert!(marshal.installs.lock().is_empty());
        assert_eq!(*chain.offered.lock(), vec![7, 9]);
    });
}

#[test]
fn join_returns_once_the_chain_has_a_base() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let marshal = Marshal::default();
        let chain = TestChain::default();
        *chain.based.lock() = true;
        let answered = join_with(&mut context, &marshal, &chain, vec![(3, vec![5])]).await;
        assert_eq!(answered, 0);
        assert!(marshal.installs.lock().is_empty());
        assert!(chain.offered.lock().is_empty());
    });
}

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::{super::wire, *};
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<wire::Tag>,
        CodecConformance<wire::Message<ed25519::Scheme, Executed, Floor>> => 128,
    }
}
