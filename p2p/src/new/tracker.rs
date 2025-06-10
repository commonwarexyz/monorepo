use std::{collections::BTreeMap, time::Duration};

use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::Clock;
use commonware_utils::SystemTimeExt as _;

use crate::{authenticated::is_global, new::peer_info::PeerInfo};

struct Config<E: Signer + Clock> {
    context: E,

    /// The namespace used to sign and verify [PeerInfo] messages.
    ip_namespace: Vec<u8>,

    /// Whether to allow private IPs.
    allow_private_ips: bool,

    /// The time bound for synchrony. Messages with timestamps greater than this far into the
    /// future will be considered malformed.
    synchrony_bound: Duration,

    /// The maximum number of peers in a set.
    max_peer_set_size: usize,

    /// The maximum number of [`types::PeerInfo`] allowable in a single message.
    peer_gossip_max_count: usize,
}

pub(super) struct Tracker<P: PublicKey, E: Signer<PublicKey = P, Signature = P::Signature> + Clock>
{
    cfg: Config<E>,
    /// The current known information about each peer.
    peers: BTreeMap<P, PeerInfo<P>>,
}

impl<P: PublicKey, E: Signer<PublicKey = P, Signature = P::Signature> + Clock> Tracker<P, E> {
    /// Create a new tracker.
    pub fn new(cfg: Config<E>) -> Self {
        Self {
            cfg,
            peers: BTreeMap::new(),
        }
    }
}

impl<P: PublicKey, E: Signer<PublicKey = P, Signature = P::Signature> + Clock> Tracker<P, E> {
    fn validate(&mut self, infos: &Vec<PeerInfo<P>>) -> Result<(), Error> {
        // Ensure there aren't too many peers sent
        if infos.len() > self.cfg.peer_gossip_max_count {
            return Err(Error::TooManyPeers(infos.len()));
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        let my_public_key = self.cfg.context.public_key();
        for info in infos {
            // Check if IP is allowed
            if !self.cfg.allow_private_ips && !is_global(info.socket.ip()) {
                return Err(Error::PrivateIPsNotAllowed(info.socket.ip()));
            }

            // Check if peer is us
            if info.public_key == my_public_key {
                return Err(Error::ReceivedSelf);
            }

            // If any timestamp is too far into the future, disconnect from the peer
            if Duration::from_millis(info.timestamp)
                > self.cfg.context.current().epoch() + self.cfg.synchrony_bound
            {
                return Err(Error::SynchronyBound);
            }

            // If any signature is invalid, disconnect from the peer
            if !info.verify(&self.cfg.ip_namespace) {
                return Err(Error::InvalidSignature);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
enum Error {
    TooManyPeers(usize),
    PrivateIPsNotAllowed(std::net::IpAddr),
    ReceivedSelf,
    SynchronyBound,
    InvalidSignature,
}
