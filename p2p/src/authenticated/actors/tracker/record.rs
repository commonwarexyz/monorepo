use crate::authenticated::types::PeerInfo;
use commonware_cryptography::PublicKey;
use std::net::SocketAddr;
use tracing::trace;

// /// Represents information known about a peer's address.
// #[derive(Clone, Debug)]
// pub enum Address<C: PublicKey> {
//     /// Peer address is not yet known.
//     /// Can be upgraded to `Discovered`.
//     Unknown,

//     /// Peer is the local node.
//     Myself(PeerInfo<C>),

//     /// Address is provided during initialization.
//     /// Can be upgraded to `Discovered`.
//     Bootstrapper(SocketAddr),

//     /// Discovered this peer's address from other peers.
//     ///
//     /// The `usize` indicates the number of times dialing this record has failed.
//     Known(PeerInfo<C>, usize),

//     /// Peer is blocked.
//     /// We don't care to track its information.
//     Blocked,
// }

/// Represents the connection status of a peer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Status {
    /// Initial state. The peer is not yet connected.
    /// Will be upgraded to [`Status::Reserved`] when a reservation is made.
    Inert,

    /// The peer connection is reserved by an actor that is attempting to establish a connection.
    /// Will either be upgraded to [`Status::Connected`] or downgraded to [`Status::Inert`].
    Reserved,

    /// The peer is connected.
    /// Must return to [`Status::Inert`] after the connection is closed.
    Connected,
}

pub enum Record<C: PublicKey> {
    /// We don't know this peer's address.
    Unknown { sets: usize },

    /// The peer is myself.
    Myself { info: PeerInfo<C>, sets: usize },

    /// The peer is a bootstrapper with a known address.
    Bootstrapper { peer: SocketAddr, sets: usize },

    /// The peer is known and has been discovered.
    Known {
        info: PeerInfo<C>,
        status: Status,
        sets: usize,
        dial_fails: usize,
    },

    /// The peer is blocked.
    Blocked { sets: usize },
}

// /// Represents a record of a peer's address and associated information.
// #[derive(Clone, Debug)]
// pub struct Record<C: PublicKey> {
//     /// Address state of the peer.
//     address: Address<C>,

//     /// Connection status of the peer.
//     status: Status,

//     /// Number of peer sets this peer is part of.
//     sets: usize,
// }

impl<C: PublicKey> Record<C> {
    /// Create a new record with an unknown address.
    pub fn unknown() -> Self {
        Self::Unknown { sets: 0 }
    }

    /// Create a new record with the local node's information.
    pub fn myself(info: PeerInfo<C>) -> Self {
        Self::Myself { info, sets: 0 }
    }

    /// Create a new record with a bootstrapper address.
    pub fn bootstrapper(peer: SocketAddr) -> Self {
        Self::Bootstrapper { peer, sets: 0 }
    }

    /// Attempt to update the [`PeerInfo`] of a discovered peer.
    ///
    /// Returns true if the update was successful.
    pub fn update(&mut self, info: PeerInfo<C>) -> bool {
        match self {
            Self::Blocked { .. } | Self::Myself { .. } => false,
            Self::Unknown { sets } => {
                *self = Self::Known {
                    info,
                    status: Status::Inert,
                    sets: *sets,
                    dial_fails: 0,
                };
                true
            }
            Self::Bootstrapper { sets, .. } => {
                *self = Self::Known {
                    info,
                    status: Status::Inert,
                    sets: *sets,
                    dial_fails: 0,
                };
                true
            }
            Self::Known {
                info: existing_info,
                status: _,
                sets,
                dial_fails,
            } => {
                // Ensure the new info is more recent.
                let existing_ts = existing_info.timestamp;
                let incoming_ts = info.timestamp;
                if existing_ts >= incoming_ts {
                    let peer = info.public_key;
                    trace!(
                        ?peer,
                        ?existing_ts,
                        ?incoming_ts,
                        "peer discovery not updated"
                    );
                    return false;
                }

                // Transition from Known to Known.
                *self = Self::Known {
                    info,
                    status: Status::Inert,
                    sets: *sets,
                    dial_fails: *dial_fails,
                };
                true
            }
        }
        // match &self.address {
        //     Address::Myself(_) => false,
        //     Address::Blocked => false,
        //     Address::Unknown | Address::Bootstrapper(_) => {
        //         self.address = Address::Known(info, 0);
        //         true
        //     }
        //     Address::Known(prev, _) => {
        //         // Ensure the new info is more recent.
        //         let existing_ts = prev.timestamp;
        //         let incoming_ts = info.timestamp;
        //         if existing_ts >= incoming_ts {
        //             let peer = info.public_key;
        //             trace!(
        //                 ?peer,
        //                 ?existing_ts,
        //                 ?incoming_ts,
        //                 "peer discovery not updated"
        //             );
        //             return false;
        //         }
        //         self.address = Address::Known(info, 0);
        //         true
        //     }
        // }
    }

    /// Attempt to mark the peer as blocked.
    ///
    /// Returns `true` if the peer was newly blocked.
    /// Returns `false` if the peer was already blocked or is the local node (unblockable).
    pub fn block(&mut self) -> bool {
        let sets = match self {
            Self::Blocked { .. } | Self::Myself { .. } => {
                return false;
            }
            Self::Unknown { sets } => sets,
            Self::Bootstrapper { peer: _, sets } => sets,
            Self::Known { info: _, sets, .. } => sets,
        };
        *self = Self::Blocked { sets: *sets };
        true
    }

    /// Increase the count of peer sets this peer is part of.
    pub fn increment(&mut self) {
        let sets = match self {
            Self::Unknown { sets } => sets,
            Self::Myself { sets, .. } => sets,
            Self::Bootstrapper { sets, .. } => sets,
            Self::Known { sets, .. } => sets,
            Self::Blocked { sets } => sets,
        };
        *sets = sets.wrapping_add(1);
    }

    /// Decrease the count of peer sets this peer is part of.
    ///
    /// Returns `true` if the record can be deleted. That is:
    /// - The count reaches zero
    /// - The peer is not a bootstrapper or the local node
    pub fn decrement(&mut self) {
        let sets = match self {
            Self::Unknown { sets } => sets,
            Self::Myself { sets, .. } => sets,
            Self::Bootstrapper { sets, .. } => sets,
            Self::Known { sets, .. } => sets,
            Self::Blocked { sets } => sets,
        };
        *sets = sets.wrapping_sub(1);
    }

    /// Attempt to reserve the peer for connection.
    ///
    /// Returns `true` if the reservation was successful, `false` otherwise.
    pub fn reserve(&mut self) -> bool {
        match self {
            Self::Blocked { .. } | Self::Myself { .. } => false,
            Self::Unknown { .. } => {
                // Cannot reserve an unknown peer.
                false
            }
            Self::Bootstrapper { .. } => {
                // Bootstrapper can be reserved.
                // *self = true
                todo!()
            }
            Self::Known { status, .. } => {
                if *status == Status::Inert {
                    *status = Status::Reserved;
                    true
                } else {
                    false
                }
            }
        }

        // if matches!(self.address, Address::Blocked | Address::Myself(_)) {
        //     return false;
        // }
        // if matches!(self.status, Status::Inert) {
        //     self.status = Status::Reserved;
        //     return true;
        // }
        // false
    }

    /// Marks the peer as connected.
    ///
    /// The peer must have the status [`Status::Reserved`].
    // TODO danlaine: refactor code to remove unreachable!() calls.
    pub fn connect(&mut self) {
        match self {
            Record::Unknown { .. } => unreachable!("Cannot connect an unknown peer"),
            Record::Myself { .. } => unreachable!("Cannot connect to myself"),
            Record::Blocked { .. } => {
                unreachable!("Cannot connect a blocked peer");
            }
            Record::Known { status, .. } if status != &Status::Reserved => {
                unreachable!("Cannot connect a peer that is not reserved")
            }
            Record::Bootstrapper { .. } => {
                unreachable!("Cannot connect a bootstrapper");
            }
            Record::Known { status, .. } => {
                assert!(
                    *status == Status::Reserved,
                    "Cannot connect a peer that is not reserved"
                );
                *status = Status::Connected;
            }
        }
        // assert!(matches!(self.status, Status::Reserved));
        // self.status = Status::Connected;
    }

    /// Releases any reservation on the peer.
    pub fn release(&mut self) {
        match self {
            Record::Unknown { .. } => unreachable!("Cannot release an unknown peer"),
            Record::Myself { .. } => unreachable!("Cannot release to myself"),
            Record::Blocked { .. } => {
                unreachable!("Cannot release a blocked peer");
            }
            Record::Known { status, .. } if status != &Status::Reserved => {
                unreachable!("Cannot release a peer that is not reserved")
            }
            Record::Bootstrapper { .. } => {
                unreachable!("Cannot release a bootstrapper peer");
            }
            Record::Known { status, .. } => {
                *status = Status::Connected;
            }
        }
        // assert!(self.status != Status::Inert, "Cannot release an Inert peer");
        // self.status = Status::Inert;
    }

    /// Indicate that there was a dial failure for this peer using the given `socket`, which is
    /// checked against the existing record to ensure that we correctly attribute the failure.
    pub fn dial_failure(&mut self, socket: SocketAddr) {
        match self {
            Record::Known {
                info, dial_fails, ..
            } => {
                if info.socket == socket {
                    // TODO danlaine: do we need this address check?
                    *dial_fails += 1;
                }
            }
            _ => {} // TODO danlaine: should we error here?
        }
        // if let Address::Known(info, fails) = &mut self.address {
        //     if info.socket == socket {
        //         *fails += 1;
        //     }
        // }
    }

    /// Indicate that a dial succeeded for this peer.
    ///
    /// Due to race conditions, it's possible that we connected using a socket that is now ejected
    /// from the record. However, in this case, the record would already have the `fails` set to 0,
    /// so we can avoid checking against the socket.
    pub fn dial_success(&mut self) {
        match self {
            Record::Known { dial_fails, .. } => {
                *dial_fails = 0;
            }
            _ => {} // TODO danlaine: should we error here?
        }
        // if let Address::Known(_, fails) = &mut self.address {
        //     *fails = 0;
        // }
    }

    // ---------- Getters ----------

    /// Returns `true` if the record is blocked.
    pub fn blocked(&self) -> bool {
        matches!(self, Record::Blocked { .. })
    }

    /// Returns `true` if the record is dialable.
    ///
    /// A record is dialable if:
    /// - We have the socket address of the peer
    /// - It is not ourselves
    /// - We are not already connected
    pub fn dialable(&self) -> bool {
        match self {
            Record::Unknown { .. } | Record::Blocked { .. } | Record::Myself { .. } => false,
            Record::Bootstrapper { .. } => true,
            Record::Known { status, .. } if status == &Status::Connected => false,
            Record::Known { .. } => true,
        }
        // self.status == Status::Inert
        //     && matches!(
        //         self.address,
        //         Address::Bootstrapper(_) | Address::Known(_, _)
        //     )
    }

    /// Return the socket of the peer, if known.
    pub fn socket(&self) -> Option<SocketAddr> {
        match self {
            Record::Unknown { .. } | Record::Blocked { .. } => None,
            Record::Myself { info, .. } => Some(info.socket),
            Record::Bootstrapper { peer, sets: _ } => Some(*peer),
            Record::Known { info, .. } => Some(info.socket),
        }
        // match &self {
        //     Address::Unknown => None,
        //     Address::Myself(info) => Some(info.socket),
        //     Address::Bootstrapper(socket) => Some(*socket),
        //     Address::Known(info, _) => Some(info.socket),
        //     Address::Blocked => None,
        // }
    }

    /// Get the peer information if it is sharable. The information is considered sharable if it is
    /// known and we are connected to the peer.
    pub fn sharable(&self) -> Option<PeerInfo<C>> {
        match self {
            Record::Unknown { .. } | Record::Blocked { .. } | Record::Bootstrapper { .. } => None,
            Record::Myself { info, .. } => Some(info.clone()),
            Record::Known {
                info,
                status: Status::Connected,
                ..
            } => Some(info.clone()),
            Record::Known { .. } => None,
        }
        // match &self.address {
        //     Address::Unknown => None,
        //     Address::Myself(info) => Some(info),
        //     Address::Bootstrapper(_) => None,
        //     Address::Known(info, _) => (self.status == Status::Connected).then_some(info),
        //     Address::Blocked => None,
        // }
        // .cloned()
    }

    /// Returns `true` if the peer is reserved (or connected).
    /// This is used to determine if we should attempt to reserve the peer again.
    pub fn reserved(&self) -> bool {
        match self {
            Record::Known { status, .. } => {
                return matches!(status, Status::Reserved | Status::Connected)
            }
            _ => false,
        }
    }

    /// Returns `true` if we want to ask for updated peer information for this peer.
    ///
    /// - Returns `false` for `Myself` and `Blocked` addresses.
    /// - Returns `true` for addresses for which we don't have peer info.
    /// - Returns true for addresses for which we do have peer info if-and-only-if we have failed to
    ///   dial at least `min_fails` times.
    pub fn want(&self, min_fails: usize) -> bool {
        match self {
            Record::Myself { .. } | Record::Blocked { .. } => false,
            Record::Unknown { .. } | Record::Bootstrapper { .. } => true,
            Record::Known { status, sets, .. } => {
                // We want to ask for updated peer info if we are not connected and
                // have failed dialing it at least `min_fails` times.
                // TODO danlaine: replace sets with record_min_fails.
                *status != Status::Connected && sets >= &min_fails
            }
        }
        // Ignore how many sets the peer is part of.
        // If the peer is not in any sets, this function is not called anyway.

        // Return true if we either:
        // - Don't have signed peer info
        // - Are not connected to the peer and have failed dialing it
        // match self.address {
        //     Address::Myself(_) | Address::Blocked => false,
        //     Address::Unknown | Address::Bootstrapper(_) => true,
        //     Address::Known(_, fails) => self.status != Status::Connected && fails >= min_fails,
        // }
    }

    /// Returns `true` if the record can safely be deleted.
    pub fn deletable(&self) -> bool {
        match self {
            Record::Myself { .. } | Record::Bootstrapper { .. } => false,
            Record::Unknown { sets } => *sets == 0,
            Record::Blocked { sets } => *sets == 0,
            Record::Known { status, sets, .. } => *sets == 0 && status == &Status::Inert,
        }
        // self.sets == 0 && !self.persistent() && matches!(self.status, Status::Inert)
    }

    /// Returns `true` if the record is allowed to be used for connection.
    pub fn allowed(&self) -> bool {
        match self {
            Record::Myself { .. } | Record::Blocked { .. } => false,
            Record::Bootstrapper { .. } => true,
            Record::Unknown { sets } => *sets > 0,
            Record::Known { sets, .. } => *sets > 0,
        }
        // match self.address {
        //     Address::Blocked | Address::Myself(_) => false,
        //     Address::Bootstrapper(_) | Address::Unknown | Address::Known(_, _) => {
        //         self.sets > 0 || self.persistent()
        //     }
        // }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::authenticated::types::PeerInfo;
//     use commonware_codec::Encode;
//     use commonware_cryptography::{secp256r1, PrivateKeyExt};
//     use std::net::SocketAddr;

//     // Helper function to create signed peer info for testing
//     fn create_peer_info<S>(
//         signer_seed: u64,
//         socket: SocketAddr,
//         timestamp: u64,
//     ) -> PeerInfo<S::PublicKey>
//     where
//         S: PrivateKeyExt,
//     {
//         let signer = S::from_seed(signer_seed);
//         let signature = signer.sign(None, &(socket, timestamp).encode());
//         PeerInfo {
//             socket,
//             timestamp,
//             public_key: signer.public_key(),
//             signature,
//         }
//     }

//     // Common test sockets
//     fn test_socket() -> SocketAddr {
//         SocketAddr::from(([127, 0, 0, 1], 8080))
//     }
//     fn test_socket2() -> SocketAddr {
//         SocketAddr::from(([127, 0, 0, 1], 8081))
//     }

//     // Helper function to compare the contents of two PeerInfo instances
//     fn peer_info_contents_are_equal<S: PublicKey>(
//         actual: &PeerInfo<S>,
//         expected: &PeerInfo<S>,
//     ) -> bool {
//         actual.socket == expected.socket
//             && actual.timestamp == expected.timestamp
//             && actual.public_key == expected.public_key
//             && actual.signature == expected.signature
//     }

//     // Helper function to compare an Option<&PeerInfo<S>> with a &PeerInfo<S>
//     fn compare_optional_peer_info<S: PublicKey>(
//         actual_opt: Option<&PeerInfo<S>>,
//         expected: &PeerInfo<S>,
//     ) -> bool {
//         actual_opt.is_some_and(|actual| peer_info_contents_are_equal(actual, expected))
//     }

//     #[test]
//     fn test_unknown_initial_state() {
//         let record = Record::<secp256r1::PublicKey>::unknown();
//         assert!(matches!(record.address, Address::Unknown));
//         assert_eq!(record.status, Status::Inert);
//         assert_eq!(record.sets, 0);
//         assert!(!record.persistent());
//         assert_eq!(record.socket(), None);
//         assert!(record.sharable().is_none());
//         assert!(!record.blocked());
//         assert!(!record.reserved());
//         assert!(record.want(0), "Should want info for unknown peer");
//         assert!(record.deletable());
//         assert!(!record.allowed());
//     }

//     #[test]
//     fn test_myself_initial_state() {
//         let my_info = create_peer_info::<secp256r1::PrivateKey>(0, test_socket(), 100);
//         let record = Record::<secp256r1::PublicKey>::myself(my_info.clone());
//         assert!(
//             matches!(&record.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
//         );
//         assert_eq!(record.status, Status::Inert);
//         assert_eq!(record.sets, 0);
//         assert!(record.persistent());
//         assert_eq!(record.socket(), Some(my_info.socket),);
//         assert!(compare_optional_peer_info(
//             record.sharable().as_ref(),
//             &my_info
//         ));
//         assert!(!record.blocked());
//         assert!(!record.reserved());
//         assert!(!record.want(0), "Should not want info for myself");
//         assert!(!record.deletable());
//         assert!(!record.allowed());
//     }

//     #[test]
//     fn test_bootstrapper_initial_state() {
//         let socket = test_socket();
//         let record = Record::<secp256r1::PublicKey>::bootstrapper(socket);
//         assert!(matches!(record.address, Address::Bootstrapper(s) if s == socket));
//         assert_eq!(record.status, Status::Inert);
//         assert_eq!(record.sets, 0);
//         assert!(record.persistent());
//         assert_eq!(record.socket(), Some(socket));
//         assert!(record.sharable().is_none());
//         assert!(!record.blocked());
//         assert!(!record.reserved());
//         assert!(record.want(0), "Should want info for bootstrapper");
//         assert!(!record.deletable());
//         assert!(record.allowed());
//     }

//     #[test]
//     fn test_unknown_to_discovered() {
//         let socket = test_socket();
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(1, socket, 1000);

//         assert!(record.update(peer_info.clone()));
//         assert_eq!(record.socket(), Some(socket));
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info)),
//             "Address should be Discovered with 0 failures"
//         );
//         assert!(record.sharable().is_none(), "Info not sharable yet");
//         assert!(!record.persistent());
//     }

//     #[test]
//     fn test_bootstrapper_to_discovered() {
//         let socket = test_socket();
//         let mut record = Record::<secp256r1::PublicKey>::bootstrapper(socket);
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(2, socket, 1000);

//         assert!(record.persistent(), "Should start as persistent");
//         assert!(record.update(peer_info.clone()));
//         assert_eq!(record.socket(), Some(socket));
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info)),
//             "Address should be Discovered with 0 failures"
//         );
//         assert!(record.sharable().is_none());
//         assert!(record.persistent(), "Should remain persistent after update");
//     }

//     #[test]
//     fn test_discovered_update_newer_timestamp() {
//         let socket = test_socket();
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         let peer_info_old = create_peer_info::<secp256r1::PrivateKey>(3, socket, 1000);
//         let peer_info_new = create_peer_info::<secp256r1::PrivateKey>(3, socket, 2000);

//         assert!(record.update(peer_info_old.clone()));
//         assert!(record.update(peer_info_new.clone()));

//         assert_eq!(record.socket(), Some(socket));
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info_new)),
//             "Address should contain newer info"
//         );
//     }

//     #[test]
//     fn test_discovered_no_update_older_or_equal_timestamp() {
//         let socket = test_socket();
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         let peer_info_current = create_peer_info::<secp256r1::PrivateKey>(5, socket, 1000);
//         let peer_info_older = create_peer_info::<secp256r1::PrivateKey>(5, socket, 500);
//         let peer_info_equal = create_peer_info::<secp256r1::PrivateKey>(5, socket, 1000);

//         assert!(record.update(peer_info_current.clone()));

//         assert!(!record.update(peer_info_older));
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info_current)),
//             "Address should not update with older info"
//         );

//         assert!(!record.update(peer_info_equal));
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info_current)),
//             "Address should not update with equal timestamp info"
//         );
//     }

//     #[test]
//     fn test_update_myself_and_blocked() {
//         let my_info = create_peer_info::<secp256r1::PrivateKey>(0, test_socket(), 100);
//         let mut record_myself = Record::myself(my_info.clone());
//         let other_info = create_peer_info::<secp256r1::PrivateKey>(1, test_socket2(), 200);
//         let newer_my_info = create_peer_info::<secp256r1::PrivateKey>(0, test_socket(), 300);

//         // Cannot update Myself record with other info or newer self info
//         assert!(!record_myself.update(other_info.clone()));
//         assert!(!record_myself.update(newer_my_info.clone()));
//         assert!(
//             matches!(&record_myself.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info)),
//             "Myself record should remain unchanged"
//         );

//         // Cannot update a Blocked record
//         let mut record_blocked = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_blocked.block());
//         assert!(!record_blocked.update(other_info));
//         assert!(matches!(record_blocked.address, Address::Blocked));
//     }

//     #[test]
//     fn test_update_with_different_public_key() {
//         // While unlikely in normal operation (update uses PeerInfo tied to a specific record),
//         // the `update` method itself doesn't check the public key matches.
//         let socket = test_socket();
//         let mut record = Record::<secp256r1::PublicKey>::unknown();

//         let peer_info_pk1_ts1000 = create_peer_info::<secp256r1::PrivateKey>(10, socket, 1000);
//         let peer_info_pk2_ts2000 = create_peer_info::<secp256r1::PrivateKey>(11, socket, 2000);

//         assert!(record.update(peer_info_pk1_ts1000.clone()));
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info_pk1_ts1000))
//         );

//         // Update should succeed based on newer timestamp, even if PK differs (though context matters)
//         assert!(
//             record.update(peer_info_pk2_ts2000.clone()),
//             "Update should succeed based on newer timestamp"
//         );
//         assert!(
//             matches!(&record.address, Address::Known(info, 0) if peer_info_contents_are_equal(info, &peer_info_pk2_ts2000))
//         );
//     }

//     #[test]
//     fn test_increment_decrement_and_deletable() {
//         // Test Unknown (not persistent)
//         let mut record_unknown = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_unknown.deletable());
//         record_unknown.increment(); // sets = 1
//         assert!(!record_unknown.deletable());
//         record_unknown.decrement(); // sets = 0
//         assert!(record_unknown.deletable());

//         // Test Discovered (not persistent)
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(7, test_socket(), 1000);
//         let mut record_disc = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_disc.update(peer_info));
//         assert!(record_disc.deletable());
//         record_disc.increment(); // sets = 1
//         assert!(!record_disc.deletable());
//         record_disc.decrement(); // sets = 0
//         assert!(record_disc.deletable());

//         // Test Bootstrapper (persistent)
//         let mut record_boot = Record::<secp256r1::PublicKey>::bootstrapper(test_socket());
//         assert!(!record_boot.deletable()); // Persistent
//         record_boot.increment(); // sets = 1
//         assert!(!record_boot.deletable());
//         record_boot.decrement(); // sets = 0
//         assert!(!record_boot.deletable()); // Still persistent

//         // Test Myself (persistent)
//         let my_info = create_peer_info::<secp256r1::PrivateKey>(0, test_socket(), 100);
//         let mut record_myself = Record::myself(my_info);
//         assert!(!record_myself.deletable()); // Persistent
//         record_myself.increment(); // sets = 1
//         assert!(!record_myself.deletable());
//         record_myself.decrement(); // sets = 0
//         assert!(!record_myself.deletable()); // Still persistent
//     }

//     #[test]
//     #[should_panic]
//     fn test_decrement_panics_at_zero() {
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         assert_eq!(record.sets, 0);
//         record.decrement(); // Panics
//     }

//     #[test]
//     fn test_block_behavior_and_persistence() {
//         let sample_peer_info = create_peer_info::<secp256r1::PrivateKey>(20, test_socket(), 1000);

//         // Block an Unknown record
//         let mut record_unknown = Record::<secp256r1::PublicKey>::unknown();
//         assert!(!record_unknown.persistent());
//         assert!(record_unknown.block()); // Newly blocked
//         assert!(record_unknown.blocked());
//         assert!(matches!(record_unknown.address, Address::Blocked));
//         assert_eq!(record_unknown.status, Status::Inert);
//         assert!(
//             !record_unknown.persistent(),
//             "Blocking sets persistent=false"
//         );
//         assert!(!record_unknown.block()); // Already blocked

//         // Block a Bootstrapper record (initially persistent)
//         let mut record_boot = Record::<secp256r1::PublicKey>::bootstrapper(test_socket());
//         assert!(record_boot.persistent());
//         assert!(record_boot.block());
//         assert!(record_boot.blocked());
//         assert!(matches!(record_boot.address, Address::Blocked));
//         assert!(!record_boot.persistent(), "Blocking sets persistent=false");

//         // Block a Discovered record (initially not persistent)
//         let mut record_disc = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_disc.update(sample_peer_info.clone()));
//         assert!(!record_disc.persistent());
//         assert!(record_disc.block());
//         assert!(record_disc.blocked());
//         assert!(matches!(record_disc.address, Address::Blocked));
//         assert!(!record_disc.persistent());

//         // Block a Discovered record that came from a Bootstrapper (initially persistent)
//         let mut record_disc_from_boot = Record::<secp256r1::PublicKey>::bootstrapper(test_socket());
//         assert!(record_disc_from_boot.update(sample_peer_info.clone()));
//         assert!(record_disc_from_boot.persistent());
//         assert!(record_disc_from_boot.block());
//         assert!(record_disc_from_boot.blocked());
//         assert!(matches!(record_disc_from_boot.address, Address::Blocked));
//         assert!(
//             !record_disc_from_boot.persistent(),
//             "Blocking sets persistent=false"
//         );

//         // Check status remains unchanged when blocking
//         let mut record_reserved = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_reserved.update(sample_peer_info.clone()));
//         assert!(record_reserved.reserve());
//         assert!(record_reserved.block());
//         assert_eq!(record_reserved.status, Status::Reserved);

//         let mut record_connected = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_connected.update(sample_peer_info.clone()));
//         assert!(record_connected.reserve());
//         record_connected.connect();
//         assert!(record_connected.block());
//         assert_eq!(record_connected.status, Status::Connected);
//     }

//     #[test]
//     fn test_block_myself_and_already_blocked() {
//         let my_info = create_peer_info::<secp256r1::PrivateKey>(0, test_socket(), 100);
//         let mut record_myself = Record::myself(my_info.clone());
//         assert!(!record_myself.block(), "Cannot block myself");
//         assert!(
//             matches!(&record_myself.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
//         );

//         let mut record_to_be_blocked = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_to_be_blocked.block());
//         assert!(
//             !record_to_be_blocked.block(),
//             "Cannot block already blocked peer"
//         );
//         assert!(matches!(record_to_be_blocked.address, Address::Blocked));
//     }

//     #[test]
//     fn test_status_transitions_reserve_connect_release() {
//         let mut record = Record::<secp256r1::PublicKey>::unknown();

//         assert_eq!(record.status, Status::Inert);
//         assert!(record.reserve());
//         assert_eq!(record.status, Status::Reserved);
//         assert!(record.reserved());

//         assert!(!record.reserve(), "Cannot re-reserve when Reserved");
//         assert_eq!(record.status, Status::Reserved);

//         record.connect();
//         assert_eq!(record.status, Status::Connected);
//         assert!(record.reserved()); // reserved() is true for Connected too

//         assert!(!record.reserve(), "Cannot reserve when Connected");
//         assert_eq!(record.status, Status::Connected);

//         record.release(); // Release from Connected
//         assert_eq!(record.status, Status::Inert);
//         assert!(!record.reserved());

//         assert!(record.reserve()); // Reserve again
//         assert_eq!(record.status, Status::Reserved);
//         record.release(); // Release from Reserved
//         assert_eq!(record.status, Status::Inert);
//     }

//     #[test]
//     #[should_panic]
//     fn test_connect_when_not_reserved_panics_from_inert() {
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         record.connect(); // Should panic
//     }

//     #[test]
//     #[should_panic]
//     fn test_connect_when_connected_panics() {
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record.reserve());
//         record.connect();
//         record.connect(); // Should panic
//     }

//     #[test]
//     #[should_panic]
//     fn test_release_when_inert_panics() {
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         record.release(); // Should panic
//     }

//     #[test]
//     fn test_sharable_logic() {
//         let socket = test_socket();
//         let peer_info_data = create_peer_info::<secp256r1::PrivateKey>(12, socket, 100);

//         // Unknown: Not sharable
//         let record_unknown = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_unknown.sharable().is_none());

//         // Myself: Sharable
//         let record_myself = Record::myself(peer_info_data.clone());
//         assert!(compare_optional_peer_info(
//             record_myself.sharable().as_ref(),
//             &peer_info_data
//         ));

//         // Bootstrapper (no PeerInfo yet): Not sharable
//         let record_boot = Record::<secp256r1::PublicKey>::bootstrapper(socket);
//         assert!(record_boot.sharable().is_none());

//         // Blocked: Not sharable
//         let mut record_blocked = Record::<secp256r1::PublicKey>::unknown();
//         record_blocked.block();
//         assert!(record_blocked.sharable().is_none());

//         // Discovered but not Active: Not sharable
//         let mut record_disc = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_disc.update(peer_info_data.clone()));
//         assert!(record_disc.sharable().is_none()); // Status Inert
//         assert!(record_disc.reserve());
//         assert!(record_disc.sharable().is_none()); // Status Reserved

//         // Discovered and Active: Sharable
//         record_disc.connect();
//         assert!(compare_optional_peer_info(
//             record_disc.sharable().as_ref(),
//             &peer_info_data
//         ));

//         // Released after Active: Not sharable
//         record_disc.release();
//         assert!(record_disc.sharable().is_none());
//     }

//     #[test]
//     fn test_reserved_status_check() {
//         let mut record = Record::<secp256r1::PublicKey>::unknown();
//         assert!(!record.reserved()); // Inert
//         assert!(record.reserve());
//         assert!(record.reserved()); // Reserved
//         record.connect();
//         assert!(record.reserved()); // Active
//         record.release();
//         assert!(!record.reserved()); // Inert again
//     }

//     #[test]
//     fn test_dial_failure_and_dial_success() {
//         let socket = test_socket();
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(18, socket, 1000);
//         let mut record = Record::<secp256r1::PublicKey>::unknown();

//         // Cannot fail dial before discovered
//         record.dial_failure(socket);
//         assert!(matches!(record.address, Address::Unknown));

//         // Discover
//         assert!(record.update(peer_info.clone()));
//         assert!(matches!(&record.address, Address::Known(_, 0)));

//         // Fail dial 1
//         record.dial_failure(socket);
//         assert!(matches!(&record.address, Address::Known(_, 1)));

//         // Fail dial 2
//         record.dial_failure(socket);
//         assert!(matches!(&record.address, Address::Known(_, 2)));

//         // Fail dial for wrong socket
//         record.dial_failure(test_socket2());
//         assert!(
//             matches!(&record.address, Address::Known(_, 2)),
//             "Failure count should not change for wrong socket"
//         );

//         // Success resets failures
//         record.dial_success();
//         assert!(
//             matches!(&record.address, Address::Known(_, 0)),
//             "Failures should reset"
//         );

//         // Fail dial again
//         record.dial_failure(socket);
//         assert!(matches!(&record.address, Address::Known(_, 1)));
//     }

//     #[test]
//     fn test_want_logic_with_min_fails() {
//         let socket = test_socket();
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(13, socket, 100);
//         let min_fails = 2;

//         // Unknown and Bootstrapper always want info
//         assert!(Record::<secp256r1::PublicKey>::unknown().want(min_fails));
//         assert!(Record::<secp256r1::PublicKey>::bootstrapper(socket).want(min_fails));

//         // Myself and Blocked never want info
//         assert!(!Record::myself(peer_info.clone()).want(min_fails));
//         let mut blocked = Record::<secp256r1::PublicKey>::unknown();
//         blocked.block();
//         assert!(!blocked.want(min_fails));

//         let mut record_disc = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_disc.update(peer_info.clone()));

//         // Status Inert
//         assert!(
//             !record_disc.want(min_fails),
//             "Should not want when fails=0 < min_fails"
//         );
//         record_disc.dial_failure(socket); // fails = 1
//         assert!(
//             !record_disc.want(min_fails),
//             "Should not want when fails=1 < min_fails"
//         );
//         record_disc.dial_failure(socket); // fails = 2
//         assert!(
//             record_disc.want(min_fails),
//             "Should want when fails=2 >= min_fails"
//         );

//         // Status Reserved
//         assert!(record_disc.reserve());
//         assert!(
//             record_disc.want(min_fails),
//             "Should still want when Reserved and fails >= min_fails"
//         );

//         // Status Active
//         record_disc.connect();
//         assert!(!record_disc.want(min_fails), "Should not want when Active");

//         // Status Inert again (after release)
//         record_disc.release();
//         assert!(record_disc.want(min_fails));

//         // Reset failures
//         record_disc.dial_success(); // Reset failures
//         assert!(
//             !record_disc.want(min_fails),
//             "Should not want when Inert and fails=0"
//         );
//         record_disc.dial_failure(socket); // fails = 1
//         assert!(!record_disc.want(min_fails));
//         record_disc.dial_failure(socket); // fails = 2
//         assert!(record_disc.want(min_fails));
//     }

//     #[test]
//     fn test_deletable_logic_detailed() {
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(14, test_socket(), 100);

//         // Persistent records are never deletable regardless of sets count
//         assert!(!Record::myself(peer_info.clone()).deletable());
//         assert!(!Record::<secp256r1::PublicKey>::bootstrapper(test_socket()).deletable());
//         let mut record_pers = Record::<secp256r1::PublicKey>::bootstrapper(test_socket());
//         assert!(record_pers.update(peer_info.clone()));
//         assert!(!record_pers.deletable());

//         // Non-persistent records depend on sets count and status
//         let mut record = Record::<secp256r1::PublicKey>::unknown(); // Not persistent
//         assert_eq!(record.sets, 0);
//         assert_eq!(record.status, Status::Inert);
//         assert!(record.deletable()); // sets = 0, !persistent, Inert

//         record.increment(); // sets = 1
//         assert!(!record.deletable()); // sets != 0

//         assert!(record.reserve()); // status = Reserved
//         assert!(!record.deletable()); // status != Inert

//         record.connect(); // status = Active
//         assert!(!record.deletable()); // status != Inert

//         record.release(); // status = Inert
//         assert!(!record.deletable()); // sets != 0

//         record.decrement(); // sets = 0
//         assert!(record.deletable()); // sets = 0, !persistent, Inert

//         // Blocking makes a record non-persistent, but deletability still depends on sets/status
//         let mut record_blocked = Record::<secp256r1::PublicKey>::bootstrapper(test_socket());
//         assert!(record_blocked.persistent());
//         record_blocked.increment(); // sets = 1
//         assert!(record_blocked.block());
//         assert!(!record_blocked.persistent());
//         assert!(!record_blocked.deletable()); // sets = 1
//         record_blocked.decrement(); // sets = 0
//         assert!(record_blocked.deletable()); // sets = 0, !persistent, Inert
//     }

//     #[test]
//     fn test_allowed_logic_detailed() {
//         let peer_info = create_peer_info::<secp256r1::PrivateKey>(16, test_socket(), 100);

//         // Blocked and Myself are never allowed
//         let mut record_blocked = Record::<secp256r1::PublicKey>::unknown();
//         record_blocked.block();
//         assert!(!record_blocked.allowed());
//         assert!(!Record::myself(peer_info.clone()).allowed());

//         // Persistent records (Bootstrapper, Myself before blocking) are allowed even with sets=0
//         assert!(Record::<secp256r1::PublicKey>::bootstrapper(test_socket()).allowed());
//         let mut record_pers = Record::<secp256r1::PublicKey>::bootstrapper(test_socket());
//         assert!(record_pers.update(peer_info.clone()));
//         assert!(record_pers.allowed());

//         // Non-persistent records (Unknown, Discovered) require sets > 0
//         let mut record_unknown = Record::<secp256r1::PublicKey>::unknown();
//         assert!(!record_unknown.allowed()); // sets = 0, !persistent
//         record_unknown.increment(); // sets = 1
//         assert!(record_unknown.allowed()); // sets > 0
//         record_unknown.decrement(); // sets = 0
//         assert!(!record_unknown.allowed());

//         let mut record_disc = Record::<secp256r1::PublicKey>::unknown();
//         assert!(record_disc.update(peer_info.clone()));
//         assert!(!record_disc.allowed()); // sets = 0, !persistent
//         record_disc.increment(); // sets = 1
//         assert!(record_disc.allowed()); // sets > 0
//     }
// }
