//! Egress functionality for broadcasting votes and certificates.

use crate::minimmit::{
    metrics::Outbound,
    types::{Certificate, Notarize, Nullify, Vote},
};
use commonware_codec::Encode;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::{Recipients, Sender};
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::marker::PhantomData;

/// Wraps senders with vote/certificate encoding and metrics.
pub struct Egress<S, D, V, C>
where
    S: Scheme,
    D: Digest,
    V: Sender,
    C: Sender,
{
    vote_sender: V,
    certificate_sender: C,
    outbound_messages: Family<Outbound, Counter>,
    _marker: PhantomData<(S, D)>,
}

impl<S, D, V, C> Egress<S, D, V, C>
where
    S: Scheme,
    D: Digest,
    V: Sender,
    C: Sender,
{
    pub fn new(
        vote_sender: V,
        certificate_sender: C,
        outbound_messages: Family<Outbound, Counter>,
    ) -> Self {
        Self {
            vote_sender,
            certificate_sender,
            outbound_messages,
            _marker: PhantomData,
        }
    }

    /// Broadcast a notarize vote to all peers.
    pub async fn broadcast_notarize(&mut self, notarize: Notarize<S, D>) {
        self.outbound_messages
            .get_or_create(Outbound::notarize())
            .inc();
        self.vote_sender
            .send(
                Recipients::All,
                Vote::<S, D>::Notarize(notarize).encode(),
                true,
            )
            .await
            .ok();
    }

    /// Broadcast a nullify vote to all peers.
    pub async fn broadcast_nullify(&mut self, nullify: Nullify<S>) {
        self.outbound_messages
            .get_or_create(Outbound::nullify())
            .inc();
        self.vote_sender
            .send(
                Recipients::All,
                Vote::<S, D>::Nullify(nullify).encode(),
                true,
            )
            .await
            .ok();
    }

    /// Broadcast a certificate to all peers.
    pub async fn broadcast_certificate(&mut self, certificate: Certificate<S, D>) {
        let metric = match &certificate {
            Certificate::MNotarization(_) => Outbound::m_notarization(),
            Certificate::Nullification(_) => Outbound::nullification(),
            Certificate::Finalization(_) => Outbound::finalization(),
        };
        self.outbound_messages.get_or_create(metric).inc();
        self.certificate_sender
            .send(Recipients::All, certificate.encode(), true)
            .await
            .ok();
    }
}
