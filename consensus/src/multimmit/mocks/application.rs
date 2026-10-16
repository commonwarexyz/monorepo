//! A scriptable mock application, plus a discarding reporter and a recording blocker.

use crate::{
    Automaton, Epochable, Heightable, Relay, Reporter,
    multimmit::types::{Activity as MultimmitActivity, Context},
    types::Height,
};
use commonware_actor::Feedback;
use commonware_cryptography::{
    Digest, Hasher, Sha256, bls12381::primitives::variant::Variant, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_utils::{
    NZUsize,
    channel::{oneshot, ring},
    sync::Mutex,
};
use std::{
    collections::VecDeque,
    future::Future,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Namespace for the commitments [`MockApplication`] builds.
const BLOCK_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MOCK_APPLICATION_BLOCK";

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

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        let (_, receiver) = ring::channel(NZUsize!(1));
        receiver
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
    /// Context and commitment of each verification request, in request order.
    pub verifications: Vec<(Context<Sha256Digest>, Sha256Digest)>,
}

/// Which proposal requests build a body.
#[derive(Clone, Copy)]
enum BuildPolicy {
    /// Build every request.
    Continuous,
    /// Build the next `n` requests, then decline.
    Permitted(u64),
}

impl BuildPolicy {
    /// Returns whether the next request builds, advancing the policy.
    const fn permit(&mut self) -> bool {
        match *self {
            Self::Continuous => true,
            Self::Permitted(0) => false,
            Self::Permitted(remaining) => {
                *self = Self::Permitted(remaining - 1);
                true
            }
        }
    }
}

/// State shared by a [`MockGate`] and the application operation it holds.
struct GateState {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
    active: AtomicBool,
}

impl GateState {
    /// Reports that the held operation started, then waits until its gate releases or drops.
    async fn pass(&self) {
        if let Some(started) = self.started.lock().take() {
            let _ = started.send(());
        }
        let release = self.release.lock().take();
        if let Some(release) = release {
            let _ = release.await;
        }
    }
}

/// A pending verification gate, optionally limited to one chain height.
struct VerificationGate {
    height: Option<Height>,
    state: Arc<GateState>,
}

/// The application's mutable controls, shared by every clone.
struct Control {
    build_policy: BuildPolicy,
    build_delay: Duration,
    verify_gates: VecDeque<VerificationGate>,
}

/// One-shot control over a mock application's next verification result.
pub struct MockGate {
    started: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
    state: Arc<GateState>,
}

impl MockGate {
    fn new() -> Self {
        let (started_sender, started) = oneshot::channel();
        let (release, release_receiver) = oneshot::channel();
        Self {
            started: Some(started),
            release: Some(release),
            state: Arc::new(GateState {
                started: Mutex::new(Some(started_sender)),
                release: Mutex::new(Some(release_receiver)),
                active: AtomicBool::new(true),
            }),
        }
    }

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

impl Drop for MockGate {
    fn drop(&mut self) {
        self.state.active.store(false, Ordering::Release);
    }
}

/// A deterministic application whose commitments bind block context and body bytes.
#[derive(Clone)]
pub struct MockApplication {
    log: Arc<Mutex<MockApplicationLog>>,
    control: Arc<Mutex<Control>>,
    salt: &'static str,
    verify_result: Option<bool>,
}

impl Default for MockApplication {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Builds a [`MockApplication`].
pub struct MockApplicationBuilder {
    salt: &'static str,
    verify_result: Option<bool>,
}

impl MockApplicationBuilder {
    /// Embeds `salt` in every built body.
    ///
    /// Two applications with different salts build conflicting bodies from identical work, which
    /// forces two engines signing as one producer to equivocate.
    pub const fn salt(mut self, salt: &'static str) -> Self {
        self.salt = salt;
        self
    }

    /// Answers every verification with `result`, or never answers when `None`.
    pub const fn verify_result(mut self, result: Option<bool>) -> Self {
        self.verify_result = result;
        self
    }

    /// Creates the application.
    pub fn build(self) -> MockApplication {
        MockApplication {
            log: Arc::new(Mutex::new(MockApplicationLog::default())),
            control: Arc::new(Mutex::new(Control {
                build_policy: BuildPolicy::Continuous,
                build_delay: Duration::ZERO,
                verify_gates: VecDeque::new(),
            })),
            salt: self.salt,
            verify_result: self.verify_result,
        }
    }
}

impl MockApplication {
    /// Returns the commitment this application builds for `payload` in `context`.
    ///
    /// The digest binds every context field, so the same payload at another chain height yields
    /// a different commitment.
    pub(crate) fn block_digest(context: Context<Sha256Digest>, payload: &[u8]) -> Sha256Digest {
        let epoch = context.epoch().get().to_be_bytes();
        let chain = context.chain().get().to_be_bytes();
        let height = context.height().get().to_be_bytes();
        Sha256::hash(&[
            BLOCK_NAMESPACE,
            &epoch,
            &chain,
            &height,
            context.parent().as_ref(),
            payload,
        ])
    }

    /// Creates an application that builds every requested block and accepts every
    /// verification.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a builder whose defaults match [`Self::new`].
    pub const fn builder() -> MockApplicationBuilder {
        MockApplicationBuilder {
            salt: "",
            verify_result: Some(true),
        }
    }

    /// Closes proposal requests until another production policy is selected.
    pub fn pause_building(&self) {
        self.control.lock().build_policy = BuildPolicy::Permitted(0);
    }

    /// Builds every proposal requested by the protocol.
    pub fn produce_continuously(&self) {
        self.control.lock().build_policy = BuildPolicy::Continuous;
    }

    /// Allows exactly `count` subsequent proposal requests to build a body.
    pub fn permit_builds(&self, count: u64) {
        self.control.lock().build_policy = BuildPolicy::Permitted(count);
    }

    /// Makes every later build take `delay` before its body is returned.
    ///
    /// Only a runtime-backed wrapper such as the cluster application waits; the bare mock answers
    /// at once.
    pub fn delay_builds(&self, delay: Duration) {
        self.control.lock().build_delay = delay;
    }

    /// Returns how long each build takes.
    pub fn build_delay(&self) -> Duration {
        self.control.lock().build_delay
    }

    /// Holds the next verification until the returned gate is released or dropped.
    pub fn gate_verification(&self) -> MockGate {
        self.gate_verification_slots([None])
            .pop()
            .expect("one gate was requested")
    }

    /// Holds one verification per listed height until its gate is released or dropped.
    pub fn gate_verification_heights(
        &self,
        heights: impl IntoIterator<Item = Height>,
    ) -> Vec<MockGate> {
        self.gate_verification_slots(heights.into_iter().map(Some))
    }

    fn gate_verification_slots(
        &self,
        heights: impl IntoIterator<Item = Option<Height>>,
    ) -> Vec<MockGate> {
        let mut control = self.control.lock();
        heights
            .into_iter()
            .map(|height| {
                let gate = MockGate::new();
                control.verify_gates.push_back(VerificationGate {
                    height,
                    state: Arc::clone(&gate.state),
                });
                gate
            })
            .collect()
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
        let control = Arc::clone(&self.control);
        let salt = self.salt;
        async move {
            let (sender, receiver) = oneshot::channel();
            log.lock().proposed += 1;
            if !control.lock().build_policy.permit() {
                drop(sender);
                return receiver;
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
        self.log.lock().verifications.push((context, payload));
        let gate = {
            let mut control = self.control.lock();
            control
                .verify_gates
                .retain(|gate| gate.state.active.load(Ordering::Acquire));
            let index = control
                .verify_gates
                .iter()
                .take_while(|gate| gate.height.is_some_and(|height| height != context.height()))
                .count();
            control.verify_gates.remove(index).map(|gate| gate.state)
        };
        let result = self.verify_result;
        async move {
            let (sender, receiver) = oneshot::channel();
            if let Some(gate) = gate {
                gate.pass().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_policy_spends_permits_then_declines() {
        let mut policy = BuildPolicy::Permitted(1);
        assert!(policy.permit());
        assert!(!policy.permit());
        assert!(!policy.permit());
        let mut policy = BuildPolicy::Continuous;
        assert!(policy.permit());
        assert!(policy.permit());
    }
}
