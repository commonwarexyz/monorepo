//! Deterministic application and attachment fixtures for attached-actor tests.

use crate::{
    Automaton, Epochable, Heightable, Relay, Reporter,
    multimmit::types::{Activity as MultimmitActivity, ChainId, Context},
    types::Height,
};
use commonware_actor::Feedback;
#[cfg(test)]
use commonware_cryptography::PublicKey;
use commonware_cryptography::{
    Digest, Hasher, Sha256, bls12381::primitives::variant::Variant, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{collections::VecDeque, future::Future, marker::PhantomData, sync::Arc};

/// A peer blocker that accepts every peer.
#[derive(Clone)]
pub struct NoopBlocker;

impl commonware_p2p::Blocker for NoopBlocker {
    type PublicKey = ed25519::PublicKey;

    fn block(&mut self, _: Self::PublicKey) -> Feedback {
        Feedback::Ok
    }
}

/// A peer blocker that records every blocked peer for later assertions.
#[derive(Clone, Default)]
pub struct RecordingBlocker {
    blocked: Arc<Mutex<Vec<ed25519::PublicKey>>>,
}

impl RecordingBlocker {
    /// Returns the peers blocked so far, in block order.
    pub fn blocked(&self) -> Vec<ed25519::PublicKey> {
        self.blocked.lock().clone()
    }
}

impl commonware_p2p::Blocker for RecordingBlocker {
    type PublicKey = ed25519::PublicKey;

    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        self.blocked.lock().push(peer);
        Feedback::Ok
    }
}

/// Observable state of one [`MockApplication`].
#[derive(Default)]
pub struct MockApplicationLog {
    /// Number of proposals requested.
    pub proposed: u64,
    /// Number of bodies built.
    pub built: u64,
    /// Context and commitment returned for each built body.
    pub builds: Vec<(Context<Sha256Digest>, Sha256Digest)>,
    /// Context and commitment supplied to payload verification.
    pub verifications: Vec<(Context<Sha256Digest>, Sha256Digest)>,
}

/// A deterministic application whose commitments bind block context and body bytes.
#[derive(Clone)]
pub struct MockApplication {
    log: Arc<Mutex<MockApplicationLog>>,
    salt: &'static str,
    declined_builds: Arc<Mutex<u64>>,
    build_policy: Arc<Mutex<BuildPolicy>>,
    build_gate: Option<Arc<ApplicationGateState>>,
    verify_gates: Arc<Mutex<VecDeque<VerificationGate>>>,
    verify_gate_chain: Option<ChainId>,
    verify_result: Option<bool>,
}

impl Default for MockApplication {
    fn default() -> Self {
        Self::with_salt("")
    }
}

#[derive(Clone, Copy)]
enum BuildPolicy {
    Continuous,
    Permitted(u64),
}

struct ApplicationGateState {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

struct VerificationGate {
    height: Option<Height>,
    state: Arc<ApplicationGateState>,
}

impl ApplicationGateState {
    fn one_shot() -> (Arc<Self>, MockBuildGate) {
        let (started_sender, started_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel();
        (
            Arc::new(Self {
                started: Mutex::new(Some(started_sender)),
                release: Mutex::new(Some(release_receiver)),
            }),
            MockBuildGate {
                started: Some(started_receiver),
                release: Some(release_sender),
            },
        )
    }
}

/// One-shot control over a mock application's next build or verification result.
pub struct MockBuildGate {
    started: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
}

impl MockBuildGate {
    /// Waits until the application operation starts.
    pub async fn wait_started(&mut self) {
        self.started
            .take()
            .expect("application start is awaited once")
            .await
            .expect("application reports operation start");
    }

    /// Releases the pending application result.
    pub fn release(&mut self) {
        self.release
            .take()
            .expect("application operation is released once")
            .send(())
            .expect("application still awaits release");
    }

    /// Waits until cancellation drops the pending application operation.
    pub async fn wait_cancelled(&mut self) {
        let mut release = self
            .release
            .take()
            .expect("application cancellation is checked once");
        release.closed().await;
        assert!(
            release.send(()).is_err(),
            "application operation remains live",
        );
    }
}

impl MockApplication {
    pub(crate) fn block_digest(context: Context<Sha256Digest>, payload: &[u8]) -> Sha256Digest {
        let epoch = context.epoch().get().to_be_bytes();
        let chain = context.chain().get().to_be_bytes();
        let height = context.height().get().to_be_bytes();
        Sha256::hash(&[
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_MOCK_APPLICATION_BLOCK",
            &epoch,
            &chain,
            &height,
            context.parent().as_ref(),
            payload,
        ])
    }

    /// Creates an application.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an application whose built bodies embed `salt`.
    ///
    /// Two applications with different salts build conflicting bodies from identical work, which
    /// twin tests use to force producer equivocation.
    pub fn with_salt(salt: &'static str) -> Self {
        Self {
            log: Arc::new(Mutex::new(MockApplicationLog::default())),
            salt,
            declined_builds: Arc::new(Mutex::new(0)),
            build_policy: Arc::new(Mutex::new(BuildPolicy::Continuous)),
            build_gate: None,
            verify_gates: Arc::new(Mutex::new(VecDeque::new())),
            verify_gate_chain: None,
            verify_result: Some(true),
        }
    }

    /// Creates an application that declines the first `count` proposal requests.
    pub fn with_declined_builds(count: u64) -> Self {
        let application = Self::new();
        *application.declined_builds.lock() = count;
        application
    }

    /// Closes proposal requests until another production policy is selected.
    pub fn pause_building(&self) {
        *self.build_policy.lock() = BuildPolicy::Permitted(0);
    }

    /// Builds every proposal requested by the protocol.
    pub fn produce_continuously(&self) {
        *self.build_policy.lock() = BuildPolicy::Continuous;
    }

    /// Allows exactly `count` subsequent proposal requests to build a body.
    pub fn permit_builds(&self, count: u64) {
        *self.build_policy.lock() = BuildPolicy::Permitted(count);
    }

    /// Creates an application whose first build remains pending until the returned gate opens.
    pub fn with_gated_build() -> (Self, MockBuildGate) {
        let mut application = Self::new();
        let (gate_state, gate) = ApplicationGateState::one_shot();
        application.build_gate = Some(gate_state);
        (application, gate)
    }

    /// Creates an application whose first verification remains pending until the gate opens.
    pub fn with_gated_verify() -> (Self, MockBuildGate) {
        Self::with_gated_verification_result(Some(true))
    }

    /// Creates an application whose first verification on `chain` remains pending.
    pub fn with_gated_verify_chain(chain: ChainId) -> (Self, MockBuildGate) {
        let (application, mut gates) = Self::with_gated_verify_chain_count(chain, 1);
        (application, gates.pop().expect("one gate was requested"))
    }

    /// Creates an application whose next `count` verifications on `chain` remain pending.
    pub fn with_gated_verify_chain_count(
        chain: ChainId,
        count: usize,
    ) -> (Self, Vec<MockBuildGate>) {
        let (mut application, gates) =
            Self::with_gated_verifications(Some(true), (0..count).map(|_| None));
        application.verify_gate_chain = Some(chain);
        (application, gates)
    }

    /// Creates an application with one pending verification for each chain height.
    pub fn with_gated_verify_heights(
        chain: ChainId,
        heights: impl IntoIterator<Item = Height>,
    ) -> (Self, Vec<MockBuildGate>) {
        let (mut application, gates) =
            Self::with_gated_verifications(Some(true), heights.into_iter().map(Some));
        application.verify_gate_chain = Some(chain);
        (application, gates)
    }

    /// Creates an application whose first fixed verification result is gated.
    pub fn with_gated_verification_result(result: Option<bool>) -> (Self, MockBuildGate) {
        let (application, mut gates) = Self::with_gated_verifications(result, [None]);
        (application, gates.pop().expect("one gate was requested"))
    }

    fn with_gated_verifications(
        result: Option<bool>,
        heights: impl IntoIterator<Item = Option<Height>>,
    ) -> (Self, Vec<MockBuildGate>) {
        let mut application = Self::new();
        let mut gates = Vec::new();
        let mut states = application.verify_gates.lock();
        for height in heights {
            let (state, gate) = ApplicationGateState::one_shot();
            states.push_back(VerificationGate { height, state });
            gates.push(gate);
        }
        drop(states);
        application.verify_result = result;
        (application, gates)
    }

    /// Creates an application with one fixed verification response.
    pub fn with_verification_result(result: Option<bool>) -> Self {
        Self {
            verify_result: result,
            ..Self::new()
        }
    }

    /// Returns the shared observable log.
    pub fn log(&self) -> Arc<Mutex<MockApplicationLog>> {
        Arc::clone(&self.log)
    }
}

impl Automaton for MockApplication {
    type Context = Context<Sha256Digest>;
    type Digest = Sha256Digest;

    #[expect(
        clippy::async_yields_async,
        reason = "the Automaton contract returns a receiver for separately cancelable application work"
    )]
    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        let log = Arc::clone(&self.log);
        let salt = self.salt;
        let declined_builds = Arc::clone(&self.declined_builds);
        let build_policy = Arc::clone(&self.build_policy);
        let gate = self.build_gate.take();
        async move {
            let (sender, receiver) = oneshot::channel();
            {
                let mut log = log.lock();
                log.proposed += 1;
            }
            if let Some(gate) = gate {
                if let Some(started) = gate.started.lock().take() {
                    let _ = started.send(());
                }
                let release = gate.release.lock().take();
                if let Some(release) = release {
                    let _ = release.await;
                }
            }
            {
                let mut declined_builds = declined_builds.lock();
                if *declined_builds > 0 {
                    *declined_builds -= 1;
                    drop(sender);
                    return receiver;
                }
            }
            {
                let mut build_policy = build_policy.lock();
                match *build_policy {
                    BuildPolicy::Continuous => {}
                    BuildPolicy::Permitted(0) => {
                        drop(sender);
                        return receiver;
                    }
                    BuildPolicy::Permitted(remaining) => {
                        *build_policy = BuildPolicy::Permitted(remaining - 1);
                    }
                }
            }
            let commitment = {
                let mut log = log.lock();
                log.built += 1;
                let payload = format!("mock payload {salt}{}", log.built);
                let commitment = Self::block_digest(context, payload.as_bytes());
                log.builds.push((context, commitment));
                commitment
            };
            let _ = sender.send(commitment);
            receiver
        }
    }

    #[expect(
        clippy::async_yields_async,
        reason = "the Automaton contract returns a receiver for separately cancelable application work"
    )]
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        let log = Arc::clone(&self.log);
        let gate = if self
            .verify_gate_chain
            .is_none_or(|chain| chain == context.chain())
        {
            let mut gates = self.verify_gates.lock();
            gates
                .iter()
                .position(|gate| gate.height.is_none_or(|height| height == context.height()))
                .and_then(|index| gates.remove(index))
                .map(|gate| gate.state)
        } else {
            None
        };
        let result = self.verify_result;
        async move {
            let (sender, receiver) = oneshot::channel();
            log.lock().verifications.push((context, payload));
            if let Some(gate) = gate {
                if let Some(started) = gate.started.lock().take() {
                    let _ = started.send(());
                }
                let release = gate.release.lock().take();
                if let Some(release) = release {
                    let _ = release.await;
                }
            }
            if let Some(result) = result {
                let _ = sender.send(result);
            }
            receiver
        }
    }
}

impl Relay for MockApplication {
    type Digest = Sha256Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = ();

    fn broadcast(&mut self, _payload: Self::Digest, (): Self::Plan) -> Feedback {
        Feedback::Ok
    }
}

#[cfg(test)]
struct RecordingRelayState<D: Digest> {
    scripted: VecDeque<Feedback>,
    fallback: Feedback,
    broadcasts: Vec<(D, Feedback)>,
}

/// Configurable block relay that records every canonical digest and returned response.
#[cfg(test)]
pub struct RecordingRelay<D: Digest, P: PublicKey> {
    state: Arc<Mutex<RecordingRelayState<D>>>,
    _marker: PhantomData<fn() -> P>,
}

#[cfg(test)]
impl<D: Digest, P: PublicKey> Clone for RecordingRelay<D, P> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
impl<D: Digest, P: PublicKey> RecordingRelay<D, P> {
    /// Creates a relay that always returns `feedback`.
    pub fn with_feedback(feedback: Feedback) -> Self {
        Self::scripted([], feedback)
    }

    /// Creates a relay that returns `scripted` responses, then `fallback`.
    pub fn scripted(scripted: impl IntoIterator<Item = Feedback>, fallback: Feedback) -> Self {
        Self {
            state: Arc::new(Mutex::new(RecordingRelayState {
                scripted: scripted.into_iter().collect(),
                fallback,
                broadcasts: Vec::new(),
            })),
            _marker: PhantomData,
        }
    }

    /// Returns the canonical digests and responses observed so far, in call order.
    pub fn broadcasts(&self) -> Vec<(D, Feedback)> {
        self.state.lock().broadcasts.clone()
    }
}

#[cfg(test)]
impl<D: Digest, P: PublicKey> Default for RecordingRelay<D, P> {
    fn default() -> Self {
        Self::with_feedback(Feedback::Ok)
    }
}

#[cfg(test)]
impl<D: Digest, P: PublicKey> Relay for RecordingRelay<D, P> {
    type Digest = D;
    type PublicKey = P;
    type Plan = ();

    fn broadcast(&mut self, payload: Self::Digest, (): Self::Plan) -> Feedback {
        tracing::debug!("test relay received payload");
        let mut state = self.state.lock();
        let feedback = state.scripted.pop_front().unwrap_or(state.fallback);
        state.broadcasts.push((payload, feedback));
        feedback
    }
}

#[cfg(test)]
struct RecordingReporterState<V: Variant, D: Digest> {
    feedback: Feedback,
    activities: Vec<MultimmitActivity<V, D>>,
}

/// Configurable reporter that records every submitted activity.
#[cfg(test)]
pub struct RecordingReporter<V: Variant, D: Digest> {
    state: Arc<Mutex<RecordingReporterState<V, D>>>,
}

#[cfg(test)]
impl<V: Variant, D: Digest> Clone for RecordingReporter<V, D> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> RecordingReporter<V, D> {
    /// Creates a reporter that returns `feedback` for every submitted activity.
    pub fn with_feedback(feedback: Feedback) -> Self {
        Self {
            state: Arc::new(Mutex::new(RecordingReporterState {
                feedback,
                activities: Vec::new(),
            })),
        }
    }

    /// Returns the activities observed so far, in call order.
    pub fn activities(&self) -> Vec<MultimmitActivity<V, D>> {
        self.state.lock().activities.clone()
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> Default for RecordingReporter<V, D> {
    fn default() -> Self {
        Self::with_feedback(Feedback::Ok)
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> Reporter for RecordingReporter<V, D> {
    type Activity = MultimmitActivity<V, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        tracing::debug!("test reporter received activity");
        let mut state = self.state.lock();
        state.activities.push(activity);
        state.feedback
    }
}

/// Reporter fixture that discards authenticated Multimmit activity.
#[derive(Clone)]
pub struct NoopReporter<V, D> {
    _marker: PhantomData<fn() -> (V, D)>,
}

impl<V, D> Default for NoopReporter<V, D> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<V, D> Reporter for NoopReporter<V, D>
where
    V: Variant,
    D: Digest,
{
    type Activity = MultimmitActivity<V, D>;

    fn report(&mut self, _activity: Self::Activity) -> Feedback {
        Feedback::Ok
    }
}
