//! ByzzFuzz process-fault injector. Drives Algorithm 1's *replace* half:
//! per [`Intercept`] pushed by the byzantine forwarders it decodes the
//! *actual* intercepted message, applies the strategy mutator (votes are
//! re-signed with the byzantine keys; certs / resolver are byte-mutated),
//! and emits the result via cloned senders that bypass the forwarder.
//!
//! One mutation per intercepted byzantine message -- faithful to
//! `m' = mutate(m, seed)` rather than synthesizing fresh adversarial
//! messages. The mutator RNG is keyed only by the per-fault `seed`, so
//! given the same intercepted message, observed-value pool, and seed the
//! produced fault is identical.

use crate::{
    byzzfuzz::{
        intercept::{Intercept, InterceptChannel},
        log,
    },
    strategy::Strategy,
    EPOCH,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    simplex::{
        scheme::Scheme,
        types::{Finalize, Notarize, Nullify, Vote},
    },
    types::{Epoch, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_runtime::{Clock, Handle, IoBuf, Spawner};
use commonware_utils::channel::mpsc::UnboundedReceiver;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::sync::Arc;

/// The injector byte-mutates certificate / resolver bytes (no decode) and
/// re-signs votes via [`Notarize::sign`] / [`Finalize::sign`] /
/// [`Nullify::sign`]; it has no codec dependency on `S::Certificate::Cfg`,
/// so unlike the forwarders it does not require `Cfg: Default`.
pub struct ByzzFuzzInjector<S, St, E>
where
    S: Scheme<Sha256Digest>,
    St: Strategy + 'static,
    E: Clock + Spawner + CryptoRngCore,
{
    context: E,
    scheme: S,
    strategy: Arc<St>,
}

impl<S, St, E> ByzzFuzzInjector<S, St, E>
where
    S: Scheme<Sha256Digest>,
    St: Strategy + 'static,
    E: Clock + Spawner + CryptoRngCore,
{
    pub fn new(context: E, scheme: S, strategy: St) -> Self {
        Self {
            context,
            scheme,
            strategy: Arc::new(strategy),
        }
    }

    /// Spawn the injector loop. Runs until `intercept_rx` closes (when all
    /// forwarder-held senders are dropped at end-of-run).
    pub fn start<VS, CS, RS>(
        self,
        vote_sender: VS,
        cert_sender: CS,
        resolver_sender: RS,
        intercept_rx: UnboundedReceiver<Intercept<S::PublicKey>>,
    ) -> Handle<()>
    where
        VS: commonware_p2p::Sender<PublicKey = S::PublicKey> + 'static,
        CS: commonware_p2p::Sender<PublicKey = S::PublicKey> + 'static,
        RS: commonware_p2p::Sender<PublicKey = S::PublicKey> + 'static,
    {
        let context = self.context.clone();
        context.spawn(move |_| self.run(vote_sender, cert_sender, resolver_sender, intercept_rx))
    }

    async fn run<VS, CS, RS>(
        self,
        mut vote_sender: VS,
        mut cert_sender: CS,
        mut resolver_sender: RS,
        mut intercept_rx: UnboundedReceiver<Intercept<S::PublicKey>>,
    ) where
        VS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
        CS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
        RS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
    {
        while let Some(item) = intercept_rx.recv().await {
            self.handle(
                &mut vote_sender,
                &mut cert_sender,
                &mut resolver_sender,
                item,
            )
            .await;
        }
    }

    async fn handle<VS, CS, RS>(
        &self,
        vote_sender: &mut VS,
        cert_sender: &mut CS,
        resolver_sender: &mut RS,
        item: Intercept<S::PublicKey>,
    ) where
        VS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
        CS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
        RS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
    {
        if item.omit {
            log::push(format!(
                "byzzfuzz: omit channel={:?} view={} targets_n={} seed={}",
                item.channel,
                item.view,
                item.targets.len(),
                item.fault_seed,
            ));
            return;
        }
        // Per-fault deterministic RNG keyed only by `seed`.
        let mut rng = StdRng::seed_from_u64(item.fault_seed);
        match item.channel {
            InterceptChannel::Vote => {
                let Ok(vote) = Vote::<S, Sha256Digest>::decode(IoBuf::from(item.bytes.clone()))
                else {
                    log::push(format!(
                        "byzzfuzz: skip view={} reason=undecodable_vote seed={}",
                        item.view, item.fault_seed,
                    ));
                    return;
                };
                let Some((variant, bytes)) = self.mutate_vote(vote, &mut rng) else {
                    return;
                };
                log::push(format!(
                    "byzzfuzz: replace channel=Vote view={} variant={} targets_n={} seed={}",
                    item.view,
                    variant,
                    item.targets.len(),
                    item.fault_seed,
                ));
                let _ = vote_sender
                    .send(commonware_p2p::Recipients::Some(item.targets), bytes, true)
                    .await;
            }
            InterceptChannel::Cert => {
                let mutated = self
                    .strategy
                    .mutate_certificate_bytes(&mut rng, &item.bytes);
                log::push(format!(
                    "byzzfuzz: replace channel=Cert view={} targets_n={} seed={} bytes={}",
                    item.view,
                    item.targets.len(),
                    item.fault_seed,
                    mutated.len(),
                ));
                let _ = cert_sender
                    .send(
                        commonware_p2p::Recipients::Some(item.targets),
                        mutated,
                        true,
                    )
                    .await;
            }
            InterceptChannel::Resolver => {
                let mutated = self.strategy.mutate_resolver_bytes(&mut rng, &item.bytes);
                log::push(format!(
                    "byzzfuzz: replace channel=Resolver view={} targets_n={} seed={} bytes={}",
                    item.view,
                    item.targets.len(),
                    item.fault_seed,
                    mutated.len(),
                ));
                let _ = resolver_sender
                    .send(
                        commonware_p2p::Recipients::Some(item.targets),
                        mutated,
                        true,
                    )
                    .await;
            }
        }
    }

    /// True per-message mutate: take the actual decoded `Vote`, run the
    /// strategy mutator over its proposal/view, and re-sign with the
    /// byzantine keys. Preserves message *type* (Notarize stays Notarize,
    /// etc.) so the receiver experiences mutation of the intercepted message
    /// rather than a synthetic injection.
    fn mutate_vote(
        &self,
        vote: Vote<S, Sha256Digest>,
        rng: &mut StdRng,
    ) -> Option<(&'static str, Vec<u8>)> {
        let view = vote.view().get();
        match vote {
            Vote::Notarize(n) => {
                let proposal =
                    self.strategy
                        .mutate_proposal(rng, &n.proposal, view, view, view, view);
                let signed = Notarize::sign(&self.scheme, proposal)?;
                Some((
                    "Notarize",
                    Vote::<S, Sha256Digest>::Notarize(signed).encode().to_vec(),
                ))
            }
            Vote::Finalize(f) => {
                let proposal =
                    self.strategy
                        .mutate_proposal(rng, &f.proposal, view, view, view, view);
                let signed = Finalize::sign(&self.scheme, proposal)?;
                Some((
                    "Finalize",
                    Vote::<S, Sha256Digest>::Finalize(signed).encode().to_vec(),
                ))
            }
            Vote::Nullify(_) => {
                let nullify_view = self
                    .strategy
                    .mutate_nullify_view(rng, view, view, view, view);
                let round = Round::new(Epoch::new(EPOCH), View::new(nullify_view));
                let signed = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round)?;
                Some((
                    "Nullify",
                    Vote::<S, Sha256Digest>::Nullify(signed).encode().to_vec(),
                ))
            }
        }
    }
}
