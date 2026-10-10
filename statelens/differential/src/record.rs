//! Recording wrappers that stamp the victim's observables through the helper.
//!
//! Each wrapper forwards every call and reply unchanged and at once, and, when
//! it carries a [`Recorder`], stamps the entry it records with the helper's
//! `stamp` as it records it. The recorder keeps the latest value per
//! `(observable, key)` with its stamp, so a prefix reads an `exact` witness
//! item back exactly as the entry line printed it. Without a recorder a
//! wrapper is transparent (side A installs the same wrappers; nothing watches
//! there, so `stamp` returns position 0 and prints nothing).
//!
//! Keys name the card's entities: the replica (`B=1`), a view (`v=1`, or the
//! alias a prefix registers, such as `w`), a digest (`d=<hex>`, or an alias
//! such as `p`, `c` or `m`) and a height (`h=2`).

use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{
        Update,
        core::Buffer,
        resolver::handler::{Annotation, Key},
        standard::Standard,
    },
    types::Round,
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::{B, PublicKeyOf},
    scenarios::{
        harness::{BufferSend, RecordingBuffer},
        recording_resolver::RecordingResolver,
    },
};
use commonware_cryptography::{Digestible as _, sha256::Digest as Sha256Digest};
use commonware_p2p::Recipients;
use commonware_resolver::{Fetch, Resolver, TargetedResolver};
use commonware_utils::{channel::oneshot, sync::Mutex, vec::NonEmptyVec};
use statelens_differential_shim::target_states::{Stamp, stamp};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// One recorded entry: what `stamp` printed, kept for an `exact` witness item.
#[derive(Clone, Debug)]
pub struct Entry {
    pub observable: String,
    pub key: String,
    pub value: String,
    pub stamp: Stamp,
}

impl Entry {
    /// The entry as a `Witness::exact` item.
    pub fn read(&self) -> (&str, &str, &str, Option<Stamp>) {
        (&self.observable, &self.key, &self.value, Some(self.stamp))
    }
}

struct Inner {
    /// The latest entry per `(observable, key)`.
    entries: BTreeMap<(String, String), Entry>,
    /// Entity names of digests other than the default `d`.
    digests: BTreeMap<String, &'static str>,
    /// Entity names of views other than the default `v`.
    views: BTreeMap<u64, &'static str>,
    /// Per-digest local-wait registrations.
    waits: BTreeMap<String, usize>,
}

/// The recorder of one replica's observables, shared by its wrappers and the
/// prefix.
#[derive(Clone)]
pub struct Recorder {
    replica: &'static str,
    inner: Arc<Mutex<Inner>>,
}

impl Recorder {
    /// A recorder whose keys start with `replica`, such as `B=1`.
    pub fn new(replica: &'static str) -> Self {
        Self {
            replica,
            inner: Arc::new(Mutex::new(Inner {
                entries: BTreeMap::new(),
                digests: BTreeMap::new(),
                views: BTreeMap::new(),
                waits: BTreeMap::new(),
            })),
        }
    }

    /// The replica key, `B=1`.
    pub fn replica(&self) -> &'static str {
        self.replica
    }

    /// Names `digest` by the card entity `name` in every later key.
    pub fn alias_digest(&self, digest: Sha256Digest, name: &'static str) {
        self.inner.lock().digests.insert(digest.to_string(), name);
    }

    /// Names view `view` by the card entity `name` in every later key.
    pub fn alias_view(&self, view: u64, name: &'static str) {
        self.inner.lock().views.insert(view, name);
    }

    /// The key part of a digest, `d=<hex>` or its alias.
    pub fn digest_key(&self, digest: Sha256Digest) -> String {
        let hex = digest.to_string();
        let name = self.inner.lock().digests.get(&hex).copied().unwrap_or("d");
        format!("{name}={hex}")
    }

    /// The key part of a view, `v=<view>` or its alias.
    pub fn view_key(&self, view: u64) -> String {
        let name = self.inner.lock().views.get(&view).copied().unwrap_or("v");
        format!("{name}={view}")
    }

    /// Records `observable[key]=value`: stamps it as it records it, and returns
    /// the entry as recorded.
    pub fn record(&self, observable: &str, key: &str, value: &str) -> Entry {
        let entry = Entry {
            observable: observable.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            stamp: stamp(observable, key, value),
        };
        self.inner
            .lock()
            .entries
            .insert((entry.observable.clone(), entry.key.clone()), entry.clone());
        entry
    }

    /// Records a reply the prefix received, keyed by the replica and `rest`
    /// (`,v=1,d=<hex>`).
    pub fn reply(&self, observable: &str, rest: &str, value: &str) -> Entry {
        let key = format!("{}{}", self.replica, rest);
        self.record(observable, &key, value)
    }

    /// The latest entry of `observable[key]`, if any.
    pub fn entry(&self, observable: &str, key: &str) -> Option<Entry> {
        self.inner
            .lock()
            .entries
            .get(&(observable.to_string(), key.to_string()))
            .cloned()
    }

    /// The latest entry of `observable[<replica>rest]`, if any.
    pub fn replica_entry(&self, observable: &str, rest: &str) -> Option<Entry> {
        self.entry(observable, &format!("{}{}", self.replica, rest))
    }

    /// The latest entry of `observable[<replica>rest]` when its value is `value`.
    pub fn replica_exact(&self, observable: &str, rest: &str, value: &str) -> Option<Entry> {
        self.replica_entry(observable, rest)
            .filter(|entry| entry.value == value)
    }

    /// The latest entry of `observable[<replica>rest]` when its value is a
    /// count other than `0`.
    pub fn replica_nonzero(&self, observable: &str, rest: &str) -> Option<Entry> {
        self.replica_entry(observable, rest)
            .filter(|entry| entry.value != "0")
    }

    /// One more local wait for `digest`: its registration count.
    fn wait(&self, digest: Sha256Digest) -> usize {
        let mut inner = self.inner.lock();
        let count = inner.waits.entry(digest.to_string()).or_insert(0);
        *count += 1;
        *count
    }
}

/// `RecordingResolver` with stamps: `fetch[B=1,v=1]=active|retained`,
/// `fetch_count[B=1]=n` and `targeted[B=1]=n`.
pub struct StampingResolver<P: Simplex> {
    inner: RecordingResolver<P>,
    recorder: Option<Recorder>,
}

impl<P: Simplex> Clone for StampingResolver<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            recorder: self.recorder.clone(),
        }
    }
}

impl<P: Simplex> StampingResolver<P> {
    /// Wraps `inner`; with a recorder, stamps the initial counts.
    pub fn new(inner: RecordingResolver<P>, recorder: Option<Recorder>) -> Self {
        if let Some(recorder) = &recorder {
            recorder.record("fetch_count", recorder.replica(), "0");
            recorder.record("targeted", recorder.replica(), "0");
        }
        Self { inner, recorder }
    }

    fn fetch_key(recorder: &Recorder, key: &Key<Sha256Digest>) -> String {
        let rest = match key {
            Key::Block(digest) => recorder.digest_key(*digest),
            Key::Finalized { height } => format!("h={}", height.get()),
            Key::Notarized { round } => recorder.view_key(round.view().get()),
        };
        format!("{},{rest}", recorder.replica())
    }

    fn note_fetches(&self, keys: &[Key<Sha256Digest>]) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        for key in keys {
            recorder.record("fetch", &Self::fetch_key(recorder, key), "active");
        }
        let count = self.inner.fetches().len().to_string();
        recorder.record("fetch_count", recorder.replica(), &count);
    }

    fn note_targeted(&self) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        let count = self.inner.targeted().len().to_string();
        recorder.record("targeted", recorder.replica(), &count);
    }
}

impl<P: Simplex> Resolver for StampingResolver<P> {
    type Key = Key<Sha256Digest>;
    type Subscriber = Annotation;

    fn fetch<F>(&mut self, fetch: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let fetch = fetch.into();
        let key = fetch.key;
        let feedback = self.inner.fetch(fetch);
        if feedback.accepted() {
            self.note_fetches(&[key]);
        }
        feedback
    }

    fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let fetches: Vec<Fetch<Self::Key, Self::Subscriber>> =
            fetches.into_iter().map(Into::into).collect();
        let keys: Vec<Key<Sha256Digest>> = fetches.iter().map(|fetch| fetch.key).collect();
        let feedback = self.inner.fetch_all(fetches);
        if feedback.accepted() {
            self.note_fetches(&keys);
        }
        feedback
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        let before = self.inner.active_fetches();
        let feedback = self.inner.retain(predicate);
        if let Some(recorder) = &self.recorder {
            let after: Vec<String> = self
                .inner
                .active_fetches()
                .iter()
                .map(|(key, annotation)| format!("{key:?}/{annotation:?}"))
                .collect();
            for (key, annotation) in &before {
                if !after.contains(&format!("{key:?}/{annotation:?}")) {
                    recorder.record("fetch", &Self::fetch_key(recorder, key), "retained");
                }
            }
        }
        feedback
    }
}

impl<P: Simplex> TargetedResolver for StampingResolver<P> {
    type PublicKey = PublicKeyOf<P>;

    fn fetch_targeted(
        &mut self,
        fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        let feedback = self.inner.fetch_targeted(fetch, targets);
        if feedback.accepted() {
            self.note_targeted();
        }
        feedback
    }

    fn fetch_all_targeted<F>(&mut self, fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let feedback = self.inner.fetch_all_targeted(fetches);
        if feedback.accepted() {
            self.note_targeted();
        }
        feedback
    }
}

/// `RecordingBuffer` with stamps: `subscriptions[B=1]=n`,
/// `subscription[B=1,d=<hex>]=n` and `sends[B=1]=n`.
pub struct StampingBuffer<P: Simplex> {
    inner: RecordingBuffer<P>,
    recorder: Option<Recorder>,
    sends: Arc<Mutex<Vec<BufferSend<P>>>>,
    subscriptions: Arc<AtomicUsize>,
}

impl<P: Simplex> Clone for StampingBuffer<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            recorder: self.recorder.clone(),
            sends: self.sends.clone(),
            subscriptions: self.subscriptions.clone(),
        }
    }
}

impl<P: Simplex> StampingBuffer<P> {
    /// Wraps `inner`, which shares `sends` and `subscriptions`; with a
    /// recorder, stamps the initial counts.
    pub fn new(
        inner: RecordingBuffer<P>,
        recorder: Option<Recorder>,
        sends: Arc<Mutex<Vec<BufferSend<P>>>>,
        subscriptions: Arc<AtomicUsize>,
    ) -> Self {
        if let Some(recorder) = &recorder {
            recorder.record("subscriptions", recorder.replica(), "0");
            recorder.record("sends", recorder.replica(), "0");
        }
        Self {
            inner,
            recorder,
            sends,
            subscriptions,
        }
    }

    fn note_subscription(&self, digest: Sha256Digest) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        let total = self.subscriptions.load(Ordering::Relaxed).to_string();
        recorder.record("subscriptions", recorder.replica(), &total);
        let key = format!("{},{}", recorder.replica(), recorder.digest_key(digest));
        let count = recorder.wait(digest).to_string();
        recorder.record("subscription", &key, &count);
    }
}

impl<P: Simplex> Buffer<Standard<B<P>>> for StampingBuffer<P> {
    type PublicKey = PublicKeyOf<P>;

    async fn find_by_digest(&self, digest: Sha256Digest) -> Option<Arc<B<P>>> {
        self.inner.find_by_digest(digest).await
    }

    async fn find_by_commitment(&self, commitment: Sha256Digest) -> Option<Arc<B<P>>> {
        self.inner.find_by_commitment(commitment).await
    }

    fn subscribe_by_digest(&self, digest: Sha256Digest) -> Option<oneshot::Receiver<Arc<B<P>>>> {
        let receiver = self.inner.subscribe_by_digest(digest);
        self.note_subscription(digest);
        receiver
    }

    fn subscribe_by_commitment(
        &self,
        commitment: Sha256Digest,
    ) -> Option<oneshot::Receiver<Arc<B<P>>>> {
        let receiver = self.inner.subscribe_by_commitment(commitment);
        self.note_subscription(commitment);
        receiver
    }

    fn send(&self, round: Round, block: Arc<B<P>>, recipients: Recipients<PublicKeyOf<P>>) {
        self.inner.send(round, block, recipients);
        if let Some(recorder) = &self.recorder {
            let count = self.sends.lock().len().to_string();
            recorder.record("sends", recorder.replica(), &count);
        }
    }
}

/// The reporter the marshal actor reports to, with stamps:
/// `tip[B=1,h=<h>,d=<hex>]=v<view>` and `delivered[B=1,h=<h>,d=<hex>]=block`.
pub struct StampingReporter<R> {
    inner: R,
    recorder: Option<Recorder>,
}

impl<R: Clone> Clone for StampingReporter<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            recorder: self.recorder.clone(),
        }
    }
}

impl<R> StampingReporter<R> {
    /// Wraps `inner`.
    pub fn new(inner: R, recorder: Option<Recorder>) -> Self {
        Self { inner, recorder }
    }
}

impl<R, Bk> Reporter for StampingReporter<R>
where
    R: Reporter<Activity = Update<Bk>>,
    Bk: commonware_consensus::Block<Digest = Sha256Digest>,
{
    type Activity = Update<Bk>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Some(recorder) = &self.recorder {
            match &activity {
                Update::Tip(round, height, digest) => {
                    let key = format!(
                        "{},h={},{}",
                        recorder.replica(),
                        height.get(),
                        recorder.digest_key(*digest)
                    );
                    recorder.record("tip", &key, &format!("v{}", round.view().get()));
                }
                Update::Block(block, _) => {
                    let key = format!(
                        "{},h={},{}",
                        recorder.replica(),
                        block.height().get(),
                        recorder.digest_key(block.digest())
                    );
                    recorder.record("delivered", &key, "block");
                }
            }
        }
        self.inner.report(activity)
    }
}
