//! Probe tests.

use super::{Checkpoint, Config, Mailbox, Probe, Sampled, Source, wire};
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Block, Epochable, Heightable, Viewable,
    aggregation::{
        scheme::ed25519,
        types::{Ack, Certificate, Item},
    },
    types::{Epoch, Height, View},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher as _, Sha256, Signer as _,
    certificate::mocks::Fixture,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_p2p::{
    Recipients, Sender as _,
    simulated::{Config as NetworkConfig, Link, Network, Oracle},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, Handle, Quota, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{NZDuration, NZU64, NZUsize, non_empty, probability, sync::Mutex};
use std::{num::NonZeroU32, sync::Arc, time::Duration};

const CHANNEL: u64 = 0;
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// Blocks per checkpoint: checkpoint `k` certifies the block at height `2k + 1`.
const INTERVAL: u64 = 2;

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

/// Returns whether `floor`'s certificate verifies.
fn verify_floor(floor: &Floor) -> bool {
    floor.0 != u64::MAX
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
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(context, b"probe", n);
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
                floor_verifier: verify_floor,
                strategy: Sequential,
                blocker: control,
                interval: NZU64!(INTERVAL),
                block_codec: (),
                floor_codec: (),
                retry_timeout: NZDuration!(Duration::from_millis(100)),
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
fn invalid_checkpoints_block_their_senders() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let validators = Validators::start(&mut context, 10).await;

        // A block other than the certified one, a floor whose certificate does not verify, a block
        // at another height, and a certificate over another block.
        let mut misnamed = validators.checkpoint(4, 40, None);
        misnamed.block = Arc::new(Executed {
            height: misnamed.block.height,
            value: 41,
        });
        validators.sources[1].set(misnamed);
        validators.sources[2].set(validators.checkpoint(4, 40, Some(u64::MAX)));
        let mut misplaced = validators.checkpoint(4, 40, None);
        misplaced.certificate.item.height = Height::new(5);
        validators.sources[3].set(misplaced);
        let mut forged = validators.checkpoint(4, 41, None);
        let block = validators.checkpoint(4, 40, None).block;
        forged.certificate.item.digest = block.digest();
        forged.block = block;
        validators.sources[4].set(forged);
        for index in 5..8 {
            validators.sources[index].set(validators.checkpoint(2, 20, None));
        }

        // Three faults are tolerated, so the sample waits for a fourth valid reply, and verifies
        // every invalid one meanwhile.
        let sample = validators.sampler.sample();
        let fourth = async {
            context.sleep(Duration::from_millis(250)).await;
            validators.sources[8].set(validators.checkpoint(2, 20, None));
        };
        let (sampled, ()) = futures::join!(sample, fourth);
        assert_eq!(sampled.unwrap().certificate.item.height, Height::new(2));
        let mut blocked = validators.blocked_by_first().await;
        blocked.sort();
        let mut expected = validators.participants[1..5].to_vec();
        expected.sort();
        assert_eq!(blocked, expected);
    });
}

#[test]
fn replies_from_non_validators_block_their_senders() {
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
        assert_eq!(
            validators.blocked_by_first().await,
            vec![validators.outsider.clone()]
        );
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

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::{super::wire, *};
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<wire::Tag>,
        CodecConformance<wire::Message<ed25519::Scheme, Executed, Floor>> => 128,
    }
}
