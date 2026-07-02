#![allow(dead_code)]

use crate::dkg::{
    orchestrator,
    types::{Payload, SchemeInfo},
    Registrar, ReshareBlock, SecretStore,
};
use bytes::{Buf, BufMut};
use commonware_actor::Feedback;
use commonware_codec::{
    varint::UInt, Codec, Decode, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write,
};
use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard, Update},
    simplex::{self, elector::RoundRobin, mocks::scheme, types::Context, Plan},
    types::{Epoch, Height, Round, View, ViewDelta},
    Automaton, Block, CertifiableAutomaton, Heightable, Relay, Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::DealerPrivMsg,
        primitives::{
            group::Share,
            variant::{MinPk, Variant},
        },
    },
    certificate::ConstantProvider,
    ed25519::{PrivateKey, PublicKey},
    sha256::{Digest as Sha256Digest, Sha256},
    transcript::Summary,
    Digest, Digestible, Hasher, PublicKey as CryptoPublicKey, Signer,
};
use commonware_p2p::{
    simulated::{Control, Manager as SimManager},
    utils::mux,
    Message as P2pMessage, Receiver,
};
use commonware_parallel::Sequential;
use commonware_runtime::deterministic;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
    Acknowledgement, NZUsize, NZU16,
};
use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

pub(crate) type TestDigest = Sha256Digest;
pub(crate) type TestPublicKey = PublicKey;
pub(crate) type TestSigner = PrivateKey;
pub(crate) type TestContext = Context<TestDigest, TestPublicKey>;
pub(crate) type TestBlock = MockBlock<TestDigest, TestContext>;
pub(crate) type TestMarshalVariant = Standard<TestBlock>;
pub(crate) type TestBlsVariant = MinPk;
pub(crate) type TestScheme = scheme::Scheme<TestPublicKey>;
pub(crate) type TestProvider = ConstantProvider<TestScheme, Epoch>;
pub(crate) type TestElector = RoundRobin;
pub(crate) type TestStrategy = Sequential;
pub(crate) type TestBlocker = Control<TestPublicKey, deterministic::Context>;
pub(crate) type TestManager = SimManager<TestPublicKey, deterministic::Context>;
pub(crate) type TestMailbox = orchestrator::Mailbox<TestBlock>;
pub(crate) type TestMarshalMailbox = MarshalMailbox<TestScheme, TestMarshalVariant>;
pub(crate) type TestActor = orchestrator::Actor<
    deterministic::Context,
    TestBlocker,
    TestManager,
    TestProvider,
    TestMarshalVariant,
    TestBlsVariant,
    TestSigner,
    MockApplication,
    TestElector,
    TestStrategy,
>;

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_ORCHESTRATOR_TEST";

#[derive(Debug)]
pub(crate) struct FilteredReceiver<R> {
    inner: R,
    filter: Filter,
}

#[derive(Debug)]
enum Filter {
    None,
    All,
    Epochs(Arc<HashSet<u64>>),
}

impl<R> FilteredReceiver<R> {
    pub(crate) const fn pass(inner: R) -> Self {
        Self {
            inner,
            filter: Filter::None,
        }
    }

    pub(crate) const fn drop_all(inner: R) -> Self {
        Self {
            inner,
            filter: Filter::All,
        }
    }

    pub(crate) const fn epochs(inner: R, epochs: Arc<HashSet<u64>>) -> Self {
        Self {
            inner,
            filter: Filter::Epochs(epochs),
        }
    }
}

impl<R: Receiver> Receiver for FilteredReceiver<R> {
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<P2pMessage<Self::PublicKey>, Self::Error> {
        loop {
            let message = self.inner.recv().await?;
            match &self.filter {
                Filter::None => return Ok(message),
                Filter::All => {}
                Filter::Epochs(epochs) => {
                    let (_, bytes) = &message;
                    let (epoch, _) =
                        mux::parse(bytes.clone()).expect("failed to parse mux message");
                    if !epochs.contains(&epoch) {
                        return Ok(message);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct MockBlock<D: Digest, C> {
    context: C,
    parent: D,
    height: Height,
    timestamp: u64,
    payload: Option<EncodedPayload>,
    digest: D,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct EncodedPayload {
    max_participants: NonZeroU32,
    bytes: Vec<u8>,
}

impl EncodedPayload {
    pub(crate) fn new<V: Variant, S: Signer>(
        max_participants: NonZeroU32,
        payload: Payload<V, S>,
    ) -> Self {
        Self {
            max_participants,
            bytes: payload.encode().to_vec(),
        }
    }

    fn decode<V: Variant, S: Signer>(&self) -> Option<Payload<V, S>> {
        Payload::decode_cfg(self.bytes.as_slice(), &self.max_participants).ok()
    }

    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.max_participants.get()).write(writer);
        UInt(u32::try_from(self.bytes.len()).expect("payload too large")).write(writer);
        writer.put_slice(&self.bytes);
    }

    fn read(reader: &mut impl Buf) -> Result<Self, CodecError> {
        let max_participants = NonZeroU32::new(UInt::<u32>::read(reader)?.into()).ok_or(
            CodecError::Invalid("EncodedPayload", "max participants must be non-zero"),
        )?;
        let len: u32 = UInt::read(reader)?.into();
        let len = len as usize;
        if reader.remaining() < len {
            return Err(CodecError::EndOfBuffer);
        }
        let bytes = reader.copy_to_bytes(len).to_vec();
        Ok(Self {
            max_participants,
            bytes,
        })
    }

    fn encode_size(&self) -> usize {
        UInt(self.max_participants.get()).encode_size()
            + UInt(u32::try_from(self.bytes.len()).expect("payload too large")).encode_size()
            + self.bytes.len()
    }
}

impl<D: Digest, C: Codec> MockBlock<D, C> {
    pub(crate) fn new<H: Hasher<Digest = D>>(
        context: C,
        parent: D,
        height: Height,
        timestamp: u64,
    ) -> Self {
        Self::from_parts::<H>(context, parent, height, timestamp, None)
    }

    pub(crate) fn with_payload<H, V, S>(
        self,
        max_participants: NonZeroU32,
        payload: Payload<V, S>,
    ) -> Self
    where
        H: Hasher<Digest = D>,
        V: Variant,
        S: Signer,
    {
        Self::from_parts::<H>(
            self.context,
            self.parent,
            self.height,
            self.timestamp,
            Some(EncodedPayload::new(max_participants, payload)),
        )
    }

    pub(crate) const fn context(&self) -> &C {
        &self.context
    }

    fn from_parts<H: Hasher<Digest = D>>(
        context: C,
        parent: D,
        height: Height,
        timestamp: u64,
        payload: Option<EncodedPayload>,
    ) -> Self {
        let mut hasher = H::new();
        hasher.update(&parent);
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&context.encode());
        hasher.update(&timestamp.to_be_bytes());
        match &payload {
            Some(payload) => {
                hasher.update(&[1]);
                hasher.update(&payload.max_participants.get().to_be_bytes());
                hasher.update(
                    &u32::try_from(payload.bytes.len())
                        .expect("payload too large")
                        .to_be_bytes(),
                );
                hasher.update(&payload.bytes);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        let digest = hasher.finalize();
        Self {
            context,
            parent,
            height,
            timestamp,
            payload,
            digest,
        }
    }
}

impl<D: Digest, C: Write> Write for MockBlock<D, C> {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.payload.is_some().write(writer);
        if let Some(log) = &self.payload {
            log.write(writer);
        }
        self.digest.write(writer);
    }
}

impl<D: Digest, C: Read<Cfg = ()>> Read for MockBlock<D, C> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: C::read(reader)?,
            parent: D::read(reader)?,
            height: Height::read(reader)?,
            timestamp: UInt::read(reader)?.into(),
            payload: if bool::read(reader)? {
                Some(EncodedPayload::read(reader)?)
            } else {
                None
            },
            digest: D::read(reader)?,
        })
    }
}

impl<D: Digest, C: EncodeSize> EncodeSize for MockBlock<D, C> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.payload.is_some().encode_size()
            + self.payload.as_ref().map_or(0, EncodedPayload::encode_size)
            + self.digest.encode_size()
    }
}

impl<D: Digest, C: Clone + Send + Sync + 'static> Digestible for MockBlock<D, C> {
    type Digest = D;

    fn digest(&self) -> D {
        self.digest
    }
}

impl<D: Digest, C: Clone + Send + Sync + 'static> Heightable for MockBlock<D, C> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest, C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> Block for MockBlock<D, C> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<D, C> ReshareBlock for MockBlock<D, C>
where
    D: Digest,
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    type Variant = TestBlsVariant;
    type Signer = TestSigner;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::Signer>> {
        self.payload.as_ref()?.decode()
    }
}

#[derive(Clone, Default)]
pub(crate) struct MockApplication {
    broadcasts: Arc<Mutex<Vec<TestDigest>>>,
    proposals: Arc<Mutex<Vec<TestContext>>>,
}

impl MockApplication {
    pub(crate) fn broadcasts(&self) -> Vec<TestDigest> {
        self.broadcasts.lock().clone()
    }

    pub(crate) fn proposals(&self) -> Vec<TestContext> {
        self.proposals.lock().clone()
    }
}

impl Automaton for MockApplication {
    type Context = TestContext;
    type Digest = TestDigest;

    async fn propose(&mut self, _context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        self.proposals.lock().push(_context);
        sender.send_lossy(Sha256::hash(b"proposal"));
        receiver
    }

    async fn verify(
        &mut self,
        _context: Self::Context,
        _payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send_lossy(true);
        receiver
    }
}

impl CertifiableAutomaton for MockApplication {}

impl Relay for MockApplication {
    type Digest = TestDigest;
    type PublicKey = TestPublicKey;
    type Plan = Plan<TestPublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, _plan: Self::Plan) -> Feedback {
        self.broadcasts.lock().push(payload);
        Feedback::Ok
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConsumerEvent {
    Enter(Epoch),
    Exit(Epoch),
}

#[derive(Clone, Default)]
pub(crate) struct MockConsumer {
    events: Arc<Mutex<Vec<ConsumerEvent>>>,
}

impl MockConsumer {
    pub(crate) fn events(&self) -> Vec<ConsumerEvent> {
        self.events.lock().clone()
    }
}

impl Registrar for MockConsumer {
    type Variant = TestBlsVariant;
    type PublicKey = TestPublicKey;

    async fn register(&self, epoch: Epoch, _info: SchemeInfo<Self::Variant, Self::PublicKey>) {
        self.events.lock().push(ConsumerEvent::Enter(epoch));
    }
}

#[derive(Clone, Default)]
pub(crate) struct MarshalApplication {
    blocks: Arc<Mutex<BTreeMap<Height, TestBlock>>>,
}

impl MarshalApplication {
    pub(crate) fn blocks(&self) -> BTreeMap<Height, TestBlock> {
        self.blocks.lock().clone()
    }
}

impl Reporter for MarshalApplication {
    type Activity = Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, ack) = activity {
            self.blocks.lock().insert(block.height(), block);
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

pub(crate) struct SchemeFixture {
    pub(crate) participants: Vec<TestPublicKey>,
    pub(crate) schemes: Vec<TestScheme>,
    pub(crate) provider: TestProvider,
}

pub(crate) fn scheme_fixture(context: &mut deterministic::Context) -> SchemeFixture {
    scheme_fixture_n(context, 1)
}

pub(crate) fn scheme_fixture_n(context: &mut deterministic::Context, n: u32) -> SchemeFixture {
    let fixture = scheme::fixture(context, NAMESPACE, n);
    let provider = ConstantProvider::new(fixture.schemes[0].clone());
    SchemeFixture {
        participants: fixture.participants,
        schemes: fixture.schemes,
        provider,
    }
}

pub(crate) fn genesis_block(leader: TestPublicKey) -> TestBlock {
    let digest = Sha256::hash(b"");
    let context = TestContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader,
        parent: (View::zero(), digest),
    };
    TestBlock::new::<Sha256>(context, digest, Height::zero(), 0)
}

pub(crate) fn simplex_config() -> orchestrator::SimplexConfig<TestElector> {
    orchestrator::SimplexConfig {
        elector: TestElector::default(),
        mailbox_size: NZUsize!(16),
        replay_buffer: NZUsize!(1024),
        write_buffer: NZUsize!(1024),
        page_cache_page_size: NZU16!(1024),
        page_cache_pages: NZUsize!(8),
        leader_timeout: Duration::from_millis(100),
        certification_timeout: Duration::from_millis(200),
        timeout_retry: Duration::from_millis(500),
        fetch_timeout: Duration::from_millis(100),
        fetch_concurrent: NZUsize!(2),
        activity_timeout: ViewDelta::new(8),
        skip_timeout: ViewDelta::new(2),
        forwarding: simplex::ForwardingPolicy::Disabled,
    }
}

/// In-memory [`SecretStore`] for tests.
///
/// Dealings are keyed by the encoded dealer key so the store works with any
/// [`PublicKey`](CryptoPublicKey). Pruned epochs are recorded for assertions.
#[derive(Clone, Default)]
pub(crate) struct MemorySecretStore {
    inner: Arc<Mutex<MemorySecretStoreInner>>,
}

#[derive(Default)]
struct MemorySecretStoreInner {
    shares: BTreeMap<Epoch, Share>,
    seeds: BTreeMap<Epoch, Summary>,
    dealings: BTreeMap<(Epoch, Vec<u8>), DealerPrivMsg>,
    prunes: Vec<Epoch>,
}

impl MemorySecretStore {
    /// Returns whether a share is held for `epoch`.
    pub(crate) fn has_share(&self, epoch: Epoch) -> bool {
        self.inner.lock().shares.contains_key(&epoch)
    }

    /// Returns the epochs passed to [`SecretStore::prune`], in call order.
    pub(crate) fn prunes(&self) -> Vec<Epoch> {
        self.inner.lock().prunes.clone()
    }

    /// Pre-seeds a share for `epoch`, for tests that install state before the
    /// actor starts.
    pub(crate) fn seed_share(&self, epoch: Epoch, share: Share) {
        self.inner.lock().shares.insert(epoch, share);
    }
}

impl SecretStore for MemorySecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.inner.lock().shares.insert(epoch, share);
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        self.inner.lock().shares.get(&epoch).cloned()
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.inner.lock().seeds.insert(epoch, seed);
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.inner.lock().seeds.get(&epoch).cloned()
    }

    async fn put_dealing<P: CryptoPublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        private: DealerPrivMsg,
    ) {
        self.inner
            .lock()
            .dealings
            .insert((epoch, dealer.encode().to_vec()), private);
    }

    async fn get_dealing<P: CryptoPublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        self.inner
            .lock()
            .dealings
            .get(&(epoch, dealer.encode().to_vec()))
            .cloned()
    }

    async fn prune(&mut self, min: Epoch) {
        let mut inner = self.inner.lock();
        inner.prunes.push(min);
        inner.shares.retain(|epoch, _| *epoch >= min);
        inner.seeds.retain(|epoch, _| *epoch >= min);
        inner.dealings.retain(|(epoch, _), _| *epoch >= min);
    }
}
