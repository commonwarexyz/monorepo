use super::service::Service;
use crate::{
    dkg::{
        ReshareBlock,
        network::Manager,
        probe::{ActorArtifact, ActorInfo, Artifact, Bootstrap, mailbox::Message, wire},
        types::Payload,
    },
    stateful::probe::sample::Sample,
};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Buf, Encode as _, Read};
use commonware_consensus::{
    Epochable, Heightable,
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::{Signer, bls12381::dkg::feldman_desmedt::SignedDealerLog};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, telemetry::metrics::Counter};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::collections::VecDeque;
use tracing::{debug, warn};

/// Dealer log type carried by a variant's application blocks.
type WindowLog<V> = SignedDealerLog<
    <<V as Variant>::ApplicationBlock as ReshareBlock>::Variant,
    <<V as Variant>::ApplicationBlock as ReshareBlock>::Signer,
>;

/// A peer whose boundary finalization reply verified.
struct Candidate<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    peer: S::PublicKey,
    finalization: Finalization<S, V::Commitment>,
}

/// Fetch of the floor block and, for a floor in the late phase of its epoch,
/// the inclusion-window blocks below it.
struct Walk<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    /// Authenticated boundary finalization of the floor's epoch (`None` for
    /// epoch zero).
    finalization: Option<Finalization<S, V::Commitment>>,
    /// Public information for the floor's epoch.
    info: ActorInfo<S, V>,
    /// Peers asked for blocks in turn. A peer that answers keeps serving; one
    /// that does not moves to the back.
    responders: VecDeque<S::PublicKey>,
    in_flight: Option<S::PublicKey>,
    /// Commitment of the block requested next: the floor, then each parent.
    next: V::Commitment,
    /// Height the next block must have, known once the floor block is
    /// authenticated.
    height: Option<Height>,
    /// Dealer logs of the floor's ancestors, newest first.
    logs: Vec<WindowLog<V>>,
    /// Requests that timed out since the last block arrived.
    stalled: usize,
}

enum Stage<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    /// Collecting verified boundary responders and fetching the boundary block
    /// at `height` from one of them.
    Boundary {
        height: Height,
        in_flight: Option<Candidate<S, V>>,
        candidates: VecDeque<Candidate<S, V>>,
    },
    /// Fetching the floor block and the inclusion window below it.
    Window(Box<Walk<S, V>>),
}

pub(super) struct Pending<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    floor: Finalization<S, V::Commitment>,
    stage: Stage<S, V>,
}

/// Discovery phase of the probe actor (see the
/// [module docs](crate::dkg::probe#protocol)).
pub(super) struct Discovery<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) manager: M,
    pub(super) bootstrap: Bootstrap<S::PublicKey, <V::ApplicationBlock as ReshareBlock>::Directory>,
    pub(super) floor: Option<Finalization<S, V::Commitment>>,
    pub(super) verifier: S,
    pub(super) genesis: ActorInfo<S, V>,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    pub(super) retry_timeout: NonZeroDuration,
    pub(super) window_blocks: Counter,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) sample: Sample<S, V::Commitment>,
    pub(super) subscribers: Vec<oneshot::Sender<ActorArtifact<S, V>>>,
    pub(super) pending: Option<Pending<S, V>>,
}

impl<E, M, S, V, T, B> Discovery<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runs discovery until shutdown or until it can hand off to [`Service`].
    pub(super) async fn run<BSE, BRE>(
        mut self,
        mut boundary_sender: BSE,
        mut boundary_receiver: BRE,
    ) where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        let mut marshal = None;
        let mut deadline = self.context.current() + self.retry_timeout.get();

        select_loop! {
            self.context,
            on_start => {
                self.subscribers
                    .retain(|subscriber| !subscriber.is_closed());
                if marshal.is_some() && self.subscribers.is_empty() {
                    break;
                }

                // Arm the retry timer only while actively discovering.
                let retry = if self.artifact.is_none() && !self.subscribers.is_empty() {
                    Either::Left(self.context.sleep_until(deadline))
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return;
            } => match message {
                Message::Subscribe { response } => {
                    match self.subscribe(response, &mut boundary_sender) {
                        Ok(true) => {
                            deadline = self.context.current() + self.retry_timeout.get();
                        }
                        Ok(false) => {}
                        Err(error) => {
                            warn!(
                                epoch = %self.bootstrap.epoch,
                                %error,
                                "failed to activate bootstrap peer set, shutting down",
                            );
                            return;
                        }
                    }
                }
                Message::Attach { marshal: attached } => {
                    marshal = Some(attached);
                }
            },
            Ok((peer, message)) = boundary_receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
                if self.handle_boundary_response(peer, message, &mut boundary_sender).await {
                    deadline = self.context.current() + self.retry_timeout.get();
                }
            },
            _ = retry => {
                if self.pending.is_some() {
                    self.retry_pending(&mut boundary_sender);
                } else if self.sample.floor().is_none() {
                    debug!(reason = "deadline elapsed", "re-soliciting latest finalizations");
                    self.request_latest(&mut boundary_sender);
                }
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }

        Service {
            context: self.context,
            mailbox: self.mailbox,
            marshal: marshal.expect("serving requires attached marshal"),
            blocker: self.blocker,
            epocher: self.epocher,
            artifact: self.artifact,
        }
        .run(boundary_sender, boundary_receiver)
        .await;
    }

    /// Handles a subscriber and returns whether it started a solicitation.
    ///
    /// Answers the subscriber immediately if the artifact is known. Returns an
    /// error if the bootstrap snapshot cannot be activated.
    fn subscribe(
        &mut self,
        response: oneshot::Sender<ActorArtifact<S, V>>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> Result<bool, M::Error> {
        if let Some(artifact) = &self.artifact {
            response.send_lossy(artifact.clone());
            return Ok(false);
        }
        let solicit = self.subscribers.is_empty() && self.sample.floor().is_none();
        self.subscribers.push(response);
        if solicit {
            // Activate the snapshot only when soliciting: a node that never
            // bootstraps must not claim a peer-set ID above the epochs its
            // orchestrator still enters. A later orchestrator activation of this
            // epoch has identical contents.
            self.manager.track(
                self.bootstrap.epoch,
                self.bootstrap.participants.tracked_peers(),
                &self.bootstrap.directory,
            )?;
            self.request_latest(boundary_sender);
        }
        Ok(solicit)
    }

    /// Clears collected replies and solicits the snapshot dealers' latest
    /// finalizations.
    fn request_latest(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        self.sample.reset();
        boundary_sender.send(
            Recipients::Some(
                self.bootstrap
                    .participants
                    .dealers
                    .iter()
                    .cloned()
                    .collect(),
            ),
            wire::Message::<S, V>::LatestRequest.encode(),
            false,
        );
    }

    /// Requests the boundary finalization of `epoch` from all peers.
    fn request_boundary_finalization(
        epoch: Epoch,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        boundary_sender.send(
            Recipients::All,
            wire::Message::<S, V>::BoundaryRequest(epoch).encode(),
            false,
        );
    }

    /// Handles a probe response and returns whether it sent a new request.
    async fn handle_boundary_response(
        &mut self,
        peer: S::PublicKey,
        message: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let response = match wire::read_response::<S, V, _>(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(Some(response)) => response,
            Ok(None) => return false,
            Err(err) => {
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    ?err,
                    "invalid bootstrap boundary response"
                );
                return false;
            }
        };

        match response {
            wire::Response::Latest(finalization) => {
                self.handle_latest(peer, finalization, boundary_sender)
            }
            wire::Response::Boundary(finalization) => {
                if self.pending.is_none() {
                    return false;
                }
                self.handle_boundary_finalization(peer, finalization, boundary_sender)
            }
            wire::Response::Block { epoch, body } => {
                if self.pending.is_none() {
                    return false;
                }
                self.handle_boundary_block(peer, epoch, body, boundary_sender)
                    .await
            }
            wire::Response::Ancestor { commitment, body } => {
                if self.pending.is_none() {
                    return false;
                }
                self.handle_ancestor(peer, commitment, body, boundary_sender)
                    .await
            }
        }
    }

    /// Records a latest-finalization reply that passes the discovery rules (see
    /// the [module docs](crate::dkg::probe#protocol)) and returns whether a
    /// boundary request was sent.
    fn handle_latest(
        &mut self,
        peer: S::PublicKey,
        finalization: Finalization<S, V::Commitment>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        // Once the floor is selected or the peer has contributed this request
        // round, further replies are ignored without verification.
        if !self.sample.awaits(&peer) {
            return false;
        }
        if self
            .bootstrap
            .participants
            .dealers
            .position(&peer)
            .is_none()
        {
            commonware_p2p::block!(self.blocker, peer, "latest finalization from non-member");
            return false;
        }
        if finalization.epoch() < self.sample.minimum_epoch() {
            debug!(
                epoch = %finalization.epoch(),
                minimum_epoch = %self.sample.minimum_epoch(),
                "ignoring latest finalization below minimum epoch"
            );
            return false;
        }
        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid latest finalization");
            return false;
        }
        if self.subscribers.is_empty() {
            self.sample.reset();
            return false;
        }
        self.sample.record(peer, finalization);
        self.select(boundary_sender)
    }

    /// Selects the floor once `f + 1` distinct dealers have replied: the highest
    /// reply, or the persisted floor when that is at a later round. Then begins
    /// the boundary fetch for the floor's epoch, or the window walk for a floor
    /// in epoch zero.
    ///
    /// Returns whether a request was sent.
    fn select(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) -> bool {
        // Every recorded reply was verified under the all-epoch verifier.
        let Some(sampled) = self
            .sample
            .select(self.bootstrap.participants.dealers.len(), |_| true)
        else {
            return false;
        };

        // A persisted floor is what marshal resumes from, so the window must
        // describe it rather than an older sampled floor of the same epoch.
        let floor = match &self.floor {
            Some(persisted) if persisted.round() > sampled.round() => persisted.clone(),
            _ => sampled,
        };
        let target = floor.epoch();
        debug!(round = ?floor.round(), "selected state-sync floor");

        if target.is_zero() {
            // Epoch zero is anchored by genesis and has no boundary block, so
            // the snapshot's dealers serve the walk.
            let responders = self
                .bootstrap
                .participants
                .dealers
                .iter()
                .cloned()
                .collect();
            return self.start_walk(
                floor,
                None,
                self.genesis.clone(),
                responders,
                boundary_sender,
            );
        }

        let Some(height) = target.previous().and_then(|epoch| self.epocher.last(epoch)) else {
            // Unreachable without a forged quorum: re-sample rather than wedge.
            warn!(epoch = %target, "sampled floor epoch has no boundary height");
            self.sample.reset();
            return false;
        };
        Self::request_boundary_finalization(target, boundary_sender);
        self.pending = Some(Pending {
            floor,
            stage: Stage::Boundary {
                height,
                in_flight: None,
                candidates: VecDeque::new(),
            },
        });
        true
    }

    fn handle_boundary_finalization(
        &mut self,
        peer: S::PublicKey,
        finalization: Finalization<S, V::Commitment>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let mut pending = self.pending.take().expect("pending checked by caller");

        let Some(expected_finalization_epoch) = pending.floor.epoch().previous() else {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return false;
        };

        let response_finalization_epoch = finalization.epoch();
        if response_finalization_epoch < expected_finalization_epoch {
            debug!(
                response_finalization_epoch = %response_finalization_epoch,
                pending_epoch = %pending.floor.epoch(),
                "ignoring stale bootstrap boundary response"
            );
            self.pending = Some(pending);
            return false;
        }

        if response_finalization_epoch != expected_finalization_epoch {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return false;
        }

        let duplicate = match &pending.stage {
            Stage::Boundary {
                in_flight,
                candidates,
                ..
            } => {
                in_flight
                    .as_ref()
                    .is_some_and(|candidate| candidate.peer == peer)
                    || candidates.iter().any(|candidate| candidate.peer == peer)
            }
            Stage::Window(walk) => {
                walk.in_flight.as_ref() == Some(&peer) || walk.responders.contains(&peer)
            }
        };
        if duplicate {
            self.pending = Some(pending);
            return false;
        }

        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return false;
        }

        let requested = match &mut pending.stage {
            Stage::Boundary {
                in_flight,
                candidates,
                ..
            } => {
                candidates.push_back(Candidate { peer, finalization });
                let requested = in_flight.is_none();
                if requested {
                    Self::request_next_block(&mut pending, boundary_sender);
                }
                requested
            }
            // A responder verified after the walk began joins its rotation and
            // serves right away if no request is outstanding.
            Stage::Window(walk) => {
                walk.responders.push_back(peer);
                walk.in_flight.is_none() && Self::request_ancestor(walk, boundary_sender)
            }
        };
        self.pending = Some(pending);
        requested
    }

    async fn handle_boundary_block(
        &mut self,
        peer: S::PublicKey,
        epoch: Epoch,
        body: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let mut pending = self.pending.take().expect("pending checked by caller");
        let Stage::Boundary {
            height, in_flight, ..
        } = &mut pending.stage
        else {
            self.pending = Some(pending);
            return false;
        };
        let height = *height;
        let Some(candidate) = in_flight.take() else {
            self.pending = Some(pending);
            return false;
        };
        if candidate.peer != peer || pending.floor.epoch() != epoch {
            *in_flight = Some(candidate);
            self.pending = Some(pending);
            return false;
        }

        let commitment = candidate.finalization.proposal.payload;
        let block =
            match wire::read_block::<V>(body, commitment, &self.block_codec_config, &self.strategy)
                .await
            {
                Ok(block) => block,
                Err(err) => {
                    commonware_p2p::block!(
                        self.blocker,
                        peer,
                        ?err,
                        "invalid bootstrap boundary block"
                    );
                    Self::request_next_block(&mut pending, boundary_sender);
                    self.pending = Some(pending);
                    return true;
                }
            };

        let Some(info) = Self::boundary_info(&pending, height, block) else {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary block");
            Self::request_next_block(&mut pending, boundary_sender);
            self.pending = Some(pending);
            return true;
        };

        // The responder that served the boundary block serves the walk first,
        // followed by the other verified responders.
        let Stage::Boundary { candidates, .. } = pending.stage else {
            unreachable!("stage checked above");
        };
        let responders = std::iter::once(peer)
            .chain(candidates.into_iter().map(|candidate| candidate.peer))
            .collect();
        self.start_walk(
            pending.floor,
            Some(candidate.finalization),
            info,
            responders,
            boundary_sender,
        )
    }

    /// Begins fetching the floor block from `responders` and returns `true`.
    fn start_walk(
        &mut self,
        floor: Finalization<S, V::Commitment>,
        finalization: Option<Finalization<S, V::Commitment>>,
        info: ActorInfo<S, V>,
        responders: VecDeque<S::PublicKey>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let mut walk = Walk {
            finalization,
            info,
            responders,
            in_flight: None,
            next: floor.proposal.payload,
            height: None,
            logs: Vec::new(),
            stalled: 0,
        };
        Self::request_ancestor(&mut walk, boundary_sender);
        self.pending = Some(Pending {
            floor,
            stage: Stage::Window(Box::new(walk)),
        });
        true
    }

    /// Handles a block requested by commitment and returns whether it sent a
    /// new request.
    async fn handle_ancestor(
        &mut self,
        peer: S::PublicKey,
        commitment: V::Commitment,
        body: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let mut pending = self.pending.take().expect("pending checked by caller");
        let Stage::Window(walk) = &mut pending.stage else {
            self.pending = Some(pending);
            return false;
        };
        if walk.in_flight.as_ref() != Some(&peer) || walk.next != commitment {
            self.pending = Some(pending);
            return false;
        }
        walk.in_flight = None;

        // The commitment authenticates the block, so its height and parent
        // link are the chain's own. The floor block's height decides whether a
        // window exists; each ancestor must sit one below its child. The floor
        // block itself is delivered by marshal, so only its ancestors from the
        // midpoint on are part of the window.
        let epoch = pending.floor.epoch();
        let midpoint = self
            .epocher
            .midpoint(epoch)
            .expect("epocher must know epoch midpoint");
        let done =
            match wire::read_block::<V>(body, commitment, &self.block_codec_config, &self.strategy)
                .await
            {
                Ok(block)
                    if walk
                        .height
                        .is_none_or(|expected| block.height() == expected) =>
                {
                    let height = block.height();
                    let parent = V::parent_commitment(&block);
                    let done = if walk.height.is_some() {
                        self.window_blocks.inc();
                        if let Some(Payload::DealerLog(log)) =
                            V::into_shared(block).inner().payload()
                        {
                            walk.logs.push(log);
                        }
                        height <= midpoint
                    } else {
                        let Some(bounds) = self
                            .epocher
                            .containing(height)
                            .filter(|bounds| bounds.epoch() == epoch)
                        else {
                            return self.skip_responder(pending, peer, boundary_sender);
                        };
                        bounds.phase() != EpochPhase::Late
                    };
                    walk.next = parent;
                    walk.height = height.previous();
                    walk.stalled = 0;
                    done
                }
                Ok(_) => return self.skip_responder(pending, peer, boundary_sender),
                Err(err) => {
                    debug!(?err, "inclusion window block failed to decode");
                    return self.skip_responder(pending, peer, boundary_sender);
                }
            };

        walk.responders.push_front(peer);
        if !done {
            Self::request_ancestor(walk, boundary_sender);
            self.pending = Some(pending);
            return true;
        }

        let Stage::Window(walk) = pending.stage else {
            unreachable!("stage checked above");
        };
        let Walk {
            finalization,
            info,
            mut logs,
            ..
        } = *walk;
        logs.reverse();
        debug!(
            %epoch,
            floor = ?pending.floor.proposal.payload,
            logs = logs.len(),
            "inclusion window fetched"
        );
        self.resolve(Artifact {
            finalization,
            info,
            floor: pending.floor,
            window: logs,
        });
        false
    }

    /// Blocks `peer` for answering a window request with the wrong block, drops
    /// it from the rotation, and asks the next responder, recruiting more when
    /// none remain. Returns whether a request was sent.
    fn skip_responder(
        &mut self,
        mut pending: Pending<S, V>,
        peer: S::PublicKey,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let Stage::Window(walk) = &mut pending.stage else {
            unreachable!("window responders belong to the window stage");
        };
        commonware_p2p::block!(self.blocker, peer, "invalid inclusion window block");
        let sent = Self::request_ancestor(walk, boundary_sender)
            || self.recruit_responders(&mut pending, boundary_sender);
        self.pending = Some(pending);
        sent
    }

    /// Abandons the outstanding request and asks the next responder. A walk
    /// that cycled through its whole rotation without a block also recruits
    /// responders beyond it.
    fn retry_pending(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        let mut pending = self
            .pending
            .take()
            .expect("retry requires pending discovery");
        match &mut pending.stage {
            Stage::Boundary { in_flight, .. } => {
                *in_flight = None;
                Self::request_next_block(&mut pending, boundary_sender);
            }
            Stage::Window(walk) => {
                if let Some(peer) = walk.in_flight.take() {
                    walk.responders.push_back(peer);
                }
                walk.stalled += 1;
                if walk.stalled >= walk.responders.len() {
                    warn!(
                        epoch = %pending.floor.epoch(),
                        commitment = ?walk.next,
                        "no responder served the inclusion window block, recruiting more"
                    );
                    walk.stalled = 0;
                    self.recruit_responders(&mut pending, boundary_sender);
                }
                if let Stage::Window(walk) = &mut pending.stage
                    && walk.in_flight.is_none()
                {
                    Self::request_ancestor(walk, boundary_sender);
                }
            }
        }
        self.pending = Some(pending);
    }

    /// Looks for walk responders beyond the current rotation: the snapshot's
    /// dealers for an epoch-zero floor, otherwise every peer that answers a new
    /// boundary request, which [`Self::handle_boundary_finalization`] admits
    /// into the walk. Returns whether a request was sent.
    fn recruit_responders(
        &mut self,
        pending: &mut Pending<S, V>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let epoch = pending.floor.epoch();
        let Stage::Window(walk) = &mut pending.stage else {
            unreachable!("only a window walk recruits responders");
        };
        if !epoch.is_zero() {
            Self::request_boundary_finalization(epoch, boundary_sender);
            return true;
        }
        let known = |dealer: &S::PublicKey| {
            walk.in_flight.as_ref() == Some(dealer) || walk.responders.contains(dealer)
        };
        let dealers = self
            .bootstrap
            .participants
            .dealers
            .iter()
            .filter(|dealer| !known(dealer))
            .cloned()
            .collect::<Vec<_>>();
        walk.responders.extend(dealers);
        walk.in_flight.is_none() && Self::request_ancestor(walk, boundary_sender)
    }

    /// Requests the boundary block from the next verified responder, or
    /// re-solicits responders when none remain.
    fn request_next_block(
        pending: &mut Pending<S, V>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        let epoch = pending.floor.epoch();
        let Stage::Boundary {
            in_flight,
            candidates,
            ..
        } = &mut pending.stage
        else {
            unreachable!("boundary requests belong to the boundary stage");
        };
        let Some(candidate) = candidates.pop_front() else {
            debug!(%epoch, "requesting boundary finalizations");
            Self::request_boundary_finalization(epoch, boundary_sender);
            return;
        };

        let commitment = candidate.finalization.proposal.payload;
        debug!(%epoch, ?commitment, peer = ?candidate.peer, "requesting boundary block");
        boundary_sender.send(
            Recipients::One(candidate.peer.clone()),
            wire::Message::<S, V>::BlockRequest(epoch).encode(),
            false,
        );
        *in_flight = Some(candidate);
    }

    /// Requests the walk's next block from the responder at the front of the
    /// rotation.
    /// Requests the next window block from the rotation's first responder.
    /// Returns whether a responder was available.
    fn request_ancestor(
        walk: &mut Walk<S, V>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let Some(peer) = walk.responders.pop_front() else {
            return false;
        };
        debug!(
            commitment = ?walk.next,
            height = ?walk.height,
            ?peer,
            "requesting inclusion window block"
        );
        boundary_sender.send(
            Recipients::One(peer.clone()),
            wire::Message::<S, V>::AncestorRequest(walk.next).encode(),
            false,
        );
        walk.in_flight = Some(peer);
        true
    }

    /// Returns the epoch info carried by an authenticated boundary block at
    /// `height` for the floor's epoch.
    fn boundary_info(
        pending: &Pending<S, V>,
        height: Height,
        block: V::Block,
    ) -> Option<ActorInfo<S, V>> {
        if block.height() != height {
            return None;
        }

        let block = V::into_shared(block);
        let Some(Payload::EpochInfo(info)) = block.inner().payload() else {
            return None;
        };
        if info.epoch != pending.floor.epoch() {
            return None;
        }
        Some(info)
    }

    fn resolve(&mut self, artifact: ActorArtifact<S, V>) {
        self.pending = None;
        self.subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(artifact.clone());
        });
        self.artifact = Some(artifact);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks;
    use bytes::{BufMut, Bytes};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
    use commonware_coding::ReedSolomon;
    use commonware_consensus::{
        Block as ConsensusBlock, CertifiableBlock, Heightable,
        marshal::coding::{
            Coding,
            types::{CodedBlock, coding_config_for_participants},
        },
        simplex::{
            scheme::bls12381_threshold::vrf::Scheme as ThresholdScheme,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Height, Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest as _, Digested, Digestible, Hasher, bls12381::primitives::variant::MinPk,
        sha256::Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::non_empty;
    use std::{sync::Arc, time::Duration};

    const THRESHOLD_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_DISCOVERY_TEST";

    type TestCommitment = Commitment<CodingBlock, ReedSolomon<Sha256>, Sha256>;
    type CodingContext =
        commonware_consensus::simplex::types::Context<TestCommitment, mocks::TestPublicKey>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CodingBlock(mocks::MockBlock<mocks::TestDigest, CodingContext>);

    impl CodingBlock {
        fn new<H: Hasher<Digest = mocks::TestDigest>>(
            context: CodingContext,
            parent: mocks::TestDigest,
            height: Height,
            timestamp: u64,
        ) -> Self {
            Self(mocks::MockBlock::new::<H>(
                context, parent, height, timestamp,
            ))
        }
    }

    impl Write for CodingBlock {
        fn write(&self, writer: &mut impl BufMut) {
            self.0.write(writer);
        }
    }

    impl Read for CodingBlock {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
            mocks::MockBlock::read_cfg(reader, cfg).map(Self)
        }
    }

    impl EncodeSize for CodingBlock {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Digestible for CodingBlock {
        type Digest = mocks::TestDigest;

        fn digest(&self) -> Self::Digest {
            self.0.digest()
        }
    }

    impl Heightable for CodingBlock {
        fn height(&self) -> Height {
            self.0.height()
        }
    }

    impl ConsensusBlock for CodingBlock {
        fn parent(&self) -> Self::Digest {
            self.0.parent()
        }
    }

    impl CertifiableBlock for CodingBlock {
        type Context = CodingContext;

        fn context(&self) -> Self::Context {
            self.0.context().clone()
        }
    }

    type TestCodingVariant = Coding<CodingBlock, ReedSolomon<Sha256>, Sha256, mocks::TestPublicKey>;
    type TestThresholdScheme = ThresholdScheme<mocks::TestPublicKey, MinPk>;

    fn finalization<S, D>(proposal: Proposal<D>, schemes: &[S]) -> Finalization<S, D>
    where
        D: commonware_cryptography::Digest,
        S: commonware_consensus::simplex::scheme::Scheme<D>,
    {
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
            .expect("finalization quorum")
    }

    fn decode_finalization_response<S, V>(
        message: Bytes,
        verifier: &S,
    ) -> Finalization<S, V::Commitment>
    where
        S: Scheme<V::Commitment>,
        V: Variant,
    {
        match wire::read_response::<S, V, _>(message, &verifier.certificate_codec_config())
            .expect("response decoded")
            .expect("response tag")
        {
            wire::Response::Boundary(finalization) => finalization,
            wire::Response::Block { .. }
            | wire::Response::Latest(_)
            | wire::Response::Ancestor { .. } => {
                panic!("expected finalization response")
            }
        }
    }

    fn split_block_response<S, V>(message: Bytes, verifier: &S) -> (Epoch, Bytes)
    where
        S: Scheme<V::Commitment>,
        V: Variant,
    {
        match wire::read_response::<S, V, _>(message, &verifier.certificate_codec_config())
            .expect("response decoded")
            .expect("response tag")
        {
            wire::Response::Block { epoch, body } => (epoch, body),
            wire::Response::Boundary(_)
            | wire::Response::Latest(_)
            | wire::Response::Ancestor { .. } => {
                panic!("expected block response")
            }
        }
    }

    fn threshold_fixture(
        context: &mut deterministic::Context,
    ) -> commonware_cryptography::certificate::mocks::Fixture<TestThresholdScheme> {
        commonware_consensus::simplex::scheme::bls12381_threshold::vrf::fixture::<MinPk, _>(
            context,
            THRESHOLD_NAMESPACE,
            4,
        )
    }

    async fn coding_block(
        leader: mocks::TestPublicKey,
        participants: u16,
    ) -> Arc<CodedBlock<CodingBlock, ReedSolomon<Sha256>, Sha256>> {
        let parent = Sha256::hash(&[b"parent"]);
        let context = CodingContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader,
            parent: (
                View::zero(),
                Commitment::from((
                    mocks::TestDigest::EMPTY,
                    mocks::TestDigest::EMPTY,
                    mocks::TestDigest::EMPTY,
                    coding_config_for_participants(participants),
                )),
            ),
        };
        let block = CodingBlock::new::<Sha256>(context, parent, Height::new(1), 0);
        Arc::new(
            CodedBlock::encode(
                Digested::precomputed(block.clone(), block.digest()),
                coding_config_for_participants(participants),
                &Sequential,
            )
            .await,
        )
    }

    #[test]
    fn invalid_coding_finalization_is_rejected_before_block_request() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = threshold_fixture(&mut context);
            let verifier = TestThresholdScheme::certificate_verifier(
                THRESHOLD_NAMESPACE,
                *fixture.verifier.identity(),
            );
            let block = coding_block(
                fixture.participants[0].clone(),
                fixture
                    .participants
                    .len()
                    .try_into()
                    .expect("participant count fits u16"),
            )
            .await;
            let payload = TestCodingVariant::commitment(&block);
            let mut finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    payload,
                ),
                &fixture.schemes,
            );
            finalization.proposal.payload = Commitment::from((
                Sha256::hash(&[b"tampered block"]),
                Sha256::hash(&[b"tampered root"]),
                Sha256::hash(&[b"tampered context"]),
                coding_config_for_participants(
                    fixture
                        .participants
                        .len()
                        .try_into()
                        .expect("participant count fits u16"),
                ),
            ));
            let message = wire::Message::<TestThresholdScheme, TestCodingVariant>::BoundaryResponse(
                finalization,
            )
            .encode();
            let finalization = decode_finalization_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(message, &verifier);
            let authenticated = finalization.verify(&mut context, &verifier, &Sequential);

            assert!(!authenticated);
        });
    }

    #[test]
    fn valid_standard_block_decodes_after_finalization_authentication() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let block = mocks::genesis_block(fixture.participants[0].clone());
            let finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    block.digest(),
                ),
                &fixture.schemes,
            );
            let finalization_message = wire::Message::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >::BoundaryResponse(finalization)
            .encode();
            let finalization = decode_finalization_response::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >(finalization_message, &fixture.schemes[0]);
            let authenticated = finalization.verify(&mut context, &fixture.schemes[0], &Sequential);
            assert!(authenticated);
            let commitment = finalization.proposal.payload;
            let block_message =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::zero(),
                    block: Digested::precomputed(block.clone(), block.digest()),
                }
                .encode();
            let (epoch, body) = split_block_response::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >(block_message, &fixture.schemes[0]);
            assert_eq!(epoch, Epoch::zero());
            let decoded =
                wire::read_block::<mocks::TestMarshalVariant>(body, commitment, &(), &Sequential)
                    .await
                    .expect("standard block authenticated");

            assert_eq!(decoded.inner(), &block);
        });
    }

    #[test]
    fn valid_coding_block_decodes_after_finalization_authentication() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let block = coding_block(
                fixture.participants[0].clone(),
                fixture
                    .participants
                    .len()
                    .try_into()
                    .expect("participant count fits u16"),
            )
            .await;
            let payload = TestCodingVariant::commitment(&block);
            let finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    payload,
                ),
                &fixture.schemes,
            );
            let finalization_message =
                wire::Message::<mocks::TestScheme, TestCodingVariant>::BoundaryResponse(
                    finalization,
                )
                .encode();
            let finalization = decode_finalization_response::<mocks::TestScheme, TestCodingVariant>(
                finalization_message,
                &fixture.schemes[0],
            );
            let authenticated = finalization.verify(&mut context, &fixture.schemes[0], &Sequential);
            assert!(authenticated);
            let block_message =
                wire::Message::<mocks::TestScheme, TestCodingVariant>::BlockResponse {
                    epoch: Epoch::zero(),
                    block,
                }
                .encode();
            let (epoch, body) = split_block_response::<mocks::TestScheme, TestCodingVariant>(
                block_message,
                &fixture.schemes[0],
            );
            assert_eq!(epoch, Epoch::zero());
            let commitment = finalization.proposal.payload;
            let decoded = wire::read_block::<TestCodingVariant>(body, commitment, &(), &Sequential)
                .await
                .expect("coding block authenticated");

            assert_eq!(decoded.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&decoded), payload);

            // The finalized payload fixes the root, so the probe decodes without re-encoding.
            assert!(decoded.shard(0).is_none());
        });
    }

    #[test]
    fn valid_coding_block_decodes_with_certificate_verifier() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = threshold_fixture(&mut context);
            let verifier = TestThresholdScheme::certificate_verifier(
                THRESHOLD_NAMESPACE,
                *fixture.verifier.identity(),
            );
            let block = coding_block(
                fixture.participants[0].clone(),
                fixture
                    .participants
                    .len()
                    .try_into()
                    .expect("participant count fits u16"),
            )
            .await;
            let payload = TestCodingVariant::commitment(&block);
            let finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    payload,
                ),
                &fixture.schemes,
            );
            let finalization_message = wire::Message::<
                TestThresholdScheme,
                TestCodingVariant,
            >::BoundaryResponse(finalization)
            .encode();
            let finalization = decode_finalization_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(finalization_message, &verifier);
            let authenticated = finalization.verify(&mut context, &verifier, &Sequential);
            assert!(authenticated);
            let block_message = wire::Message::<
                TestThresholdScheme,
                TestCodingVariant,
            >::BlockResponse {
                epoch: Epoch::zero(),
                block,
            }
            .encode();
            let (epoch, body) = split_block_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(block_message, &verifier);
            assert_eq!(epoch, Epoch::zero());
            let commitment = finalization.proposal.payload;
            let decoded = wire::read_block::<TestCodingVariant>(body, commitment, &(), &Sequential)
                .await
                .expect("coding block authenticated");

            assert_eq!(decoded.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&decoded), payload);

            // The finalized payload fixes the root, so the probe decodes without re-encoding.
            assert!(decoded.shard(0).is_none());
        });
    }
}
