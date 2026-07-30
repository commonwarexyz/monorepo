//! Lookup adapter for explicitly attached connections.

#[stability(ALPHA)]
pub use crate::authenticated::{
    admission::{
        ExactPeerAdmission, InboundAdmission as PeerAdmission, Rejection as Rejected,
        UnrestrictedAdmission,
    },
    attachment::{Attachments, Error},
};
use crate::{
    PeerEndpoint,
    authenticated::{
        Mailbox,
        admission::InboundAdmission,
        attachment::{self, Direction, Protocol},
        lookup::actors::{spawner, tracker},
    },
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_macros::stability;
use commonware_runtime::{
    BufferPooler, Clock, Connection, ConnectionInfo, Handle, Metrics, Scheduler,
};
use commonware_stream::encrypted::Config as StreamConfig;
use rand_core::CryptoRng;
use std::num::{NonZeroU32, NonZeroUsize};

type SpawnerMailbox<N, P, E> =
    Mailbox<spawner::Message<<N as Connection>::Sink, <N as Connection>::Stream, P, E>>;

struct LookupProtocol<N: Connection, P: PublicKey, E: PeerEndpoint> {
    tracker: tracker::Mailbox<P, E>,
    spawner: SpawnerMailbox<N, P, E>,
    attached: bool,
}

impl<N: Connection, P: PublicKey, E: PeerEndpoint> Clone for LookupProtocol<N, P, E> {
    fn clone(&self) -> Self {
        Self {
            tracker: self.tracker.clone(),
            spawner: self.spawner.clone(),
            attached: self.attached,
        }
    }
}

impl<N: Connection, P: PublicKey, E: PeerEndpoint> Protocol<P, N> for LookupProtocol<N, P, E> {
    type Reservation = tracker::Reservation<P, E>;

    async fn acceptable(
        &self,
        peer: P,
        _direction: &Direction,
        _info: &ConnectionInfo<N::Origin>,
    ) -> bool {
        self.attached || self.tracker.acceptable(peer).await
    }

    async fn reserve(
        &self,
        peer: P,
        direction: &Direction,
        _info: &ConnectionInfo<N::Origin>,
    ) -> Option<Self::Reservation> {
        if self.attached {
            return self
                .tracker
                .attach(peer, matches!(direction, Direction::Inbound))
                .await;
        }
        match direction {
            Direction::Inbound => self.tracker.listen(peer).await,
            Direction::Outbound => None,
        }
    }

    fn spawn(
        &self,
        connection: (
            commonware_stream::encrypted::Sender<N::Sink>,
            commonware_stream::encrypted::Receiver<N::Stream>,
        ),
        reservation: Self::Reservation,
    ) -> bool {
        let mut spawner = self.spawner.clone();
        spawner.spawn(connection, reservation).accepted()
    }
}

pub struct Actor<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: InboundAdmission<C::PublicKey, N::Origin>,
> {
    inner: attachment::Actor<E, C, N, A>,
}

impl<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: InboundAdmission<C::PublicKey, N::Origin>,
> Actor<E, C, N, A>
{
    pub fn new(
        context: E,
        stream_cfg: StreamConfig<C>,
        admission: A,
        mailbox_size: NonZeroUsize,
        max_concurrent_handshakes: NonZeroU32,
    ) -> (
        Self,
        crate::authenticated::attachment::Attachments<N, C::PublicKey, A>,
    ) {
        let (inner, attachments) = attachment::Actor::new(
            context,
            stream_cfg,
            admission,
            mailbox_size,
            max_concurrent_handshakes,
        );
        (Self { inner }, attachments)
    }

    #[stability(ALPHA)]
    pub fn start<Ep: PeerEndpoint>(
        self,
        tracker: tracker::Mailbox<C::PublicKey, Ep>,
        spawner: SpawnerMailbox<N, C::PublicKey, Ep>,
    ) -> Handle<()> {
        self.inner.start(LookupProtocol {
            tracker,
            spawner,
            attached: true,
        })
    }

    /// Starts an inbound listener attachment engine that only reserves tracked peers.
    pub(crate) fn start_listener<Ep: PeerEndpoint>(
        self,
        tracker: tracker::Mailbox<C::PublicKey, Ep>,
        spawner: SpawnerMailbox<N, C::PublicKey, Ep>,
    ) -> Handle<()> {
        self.inner.start(LookupProtocol {
            tracker,
            spawner,
            attached: false,
        })
    }
}
