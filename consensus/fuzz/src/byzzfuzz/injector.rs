//! ByzzFuzz process-fault injector.
//!
//! - **Vote**: decode the *actual* intercepted vote, apply the strategy
//!   mutator semantically, re-sign under the byzantine keys, and emit
//!   the result via the cloned vote sender (bypasses the forwarder).
//! - **Certificate / Resolver**: omit-only. The forwarder has already
//!   dropped the original to the targeted recipients; the injector emits
//!   nothing. A single byzantine node cannot forge a valid quorum
//!   certificate or a meaningful recovery response, so byte mutation on
//!   those channels would be parser-fuzzing rather than consensus-semantic
//!   byzantine behavior. Omission + partition faults already cover
//!   delayed/missing certificate and recovery traffic.
//!
//! Vote mutation is deterministic: the per-fault RNG is keyed only by the
//! `seed`, so given the same intercepted message, observed-value pool,
//! and seed the produced fault is identical.

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

/// Re-signs votes via [`Notarize::sign`] / [`Finalize::sign`] /
/// [`Nullify::sign`]; cert and resolver process faults are omit-only so
/// no certificate-codec dependency is required.
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
    /// forwarder-held senders are dropped at end-of-run). Only the vote
    /// sender is needed -- cert / resolver process faults are omit-only.
    pub fn start<VS>(
        self,
        vote_sender: VS,
        intercept_rx: UnboundedReceiver<Intercept<S::PublicKey>>,
    ) -> Handle<()>
    where
        VS: commonware_p2p::Sender<PublicKey = S::PublicKey> + 'static,
    {
        let context = self.context.clone();
        context.spawn(move |_| self.run(vote_sender, intercept_rx))
    }

    async fn run<VS>(
        self,
        mut vote_sender: VS,
        mut intercept_rx: UnboundedReceiver<Intercept<S::PublicKey>>,
    ) where
        VS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
    {
        while let Some(item) = intercept_rx.recv().await {
            self.handle(&mut vote_sender, item).await;
        }
    }

    async fn handle<VS>(&self, vote_sender: &mut VS, item: Intercept<S::PublicKey>)
    where
        VS: commonware_p2p::Sender<PublicKey = S::PublicKey>,
    {
        // Cert and resolver process faults are omit-only: a single byzantine
        // node cannot forge a valid quorum certificate or a meaningful
        // recovery response, so byte mutation on those channels would be
        // parser-fuzzing rather than consensus-semantic byzantine behavior.
        // The forwarder's drop has already removed the original from the
        // targeted recipients; the injector emits nothing.
        let omit_only_channel = matches!(
            item.channel,
            InterceptChannel::Cert | InterceptChannel::Resolver
        );
        if item.omit || omit_only_channel {
            // `reason` records the *dominant* cause (channel policy beats
            // schedule); `scheduled_omit` preserves the schedule's flag so
            // a Cert/Resolver intercept with `scheduled_omit=true` still
            // shows both facts in the trace.
            let reason = if omit_only_channel {
                "omit_only_channel"
            } else {
                "scheduled_omit"
            };
            log::push(format!(
                "byzzfuzz: omit channel={:?} view={} targets_n={} seed={} scheduled_omit={} reason={reason}",
                item.channel,
                item.view,
                item.targets.len(),
                item.fault_seed,
                item.omit,
            ));
            return;
        }
        // Per-fault deterministic RNG keyed only by `seed`.
        let mut rng = StdRng::seed_from_u64(item.fault_seed);
        // Vote is the only channel with content mutation: a byzantine
        // signer can sign conflicting votes, so semantic mutation +
        // re-signing under the byzantine keys is meaningful.
        let Ok(vote) = Vote::<S, Sha256Digest>::decode(IoBuf::from(item.bytes.clone())) else {
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
                let mut nullify_view = self
                    .strategy
                    .mutate_nullify_view(rng, view, view, view, view);
                // Identity guard: a Nullify mutation that returns the same
                // view re-signs identical content -- a no-op for the
                // receiver. Force a nearby different view.
                if nullify_view == view {
                    nullify_view = view.saturating_add(1);
                    if nullify_view == view {
                        nullify_view = view.saturating_sub(1);
                    }
                }
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
