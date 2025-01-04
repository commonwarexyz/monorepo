//! Participants in a DKG/Resharing procedure that hold a share of the secret.
//!
//! # Tracking Invalidity
//!
//! Unlike the arbiter, the contributor does not track invalidity and requires
//! the arbiter to notify it of such things. This prevents the case where
//! a malicious contributor disqualifies itself on one contributor before
//! said contributors can inform the arbiter of the issue. This could prevent
//! an honest contributor from recognizing a commitment as valid (that all other
//! contributors have agreed upon).
//!
//! # Warning
//!
//! It is up to the developer to authorize interaction with the contributor. This is purposely
//! not provided by the contributor because this authorization function is highly dependent on
//! the context in which the contributor is being used.

use crate::bls12381::{
    dkg::{ops, Error},
    primitives::{group::Share, poly},
};
use crate::PublicKey;
use commonware_utils::quorum;
use std::collections::{HashMap, HashSet};

/// Dealer output of a DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    pub active: Vec<u32>,
    pub inactive: Vec<u32>,
}

/// Track acks from recipients.
pub struct P0 {
    threshold: u32,
    players: HashMap<PublicKey, u32>,

    acks: HashSet<u32>,
}

impl P0 {
    /// Create a new dealer for a DKG/Resharing procedure.
    pub fn new(
        share: Option<Share>,
        mut players: Vec<PublicKey>,
    ) -> (Self, poly::Public, Vec<Share>) {
        // Order players
        players.sort();
        let players_ordered = players
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();

        // Generate shares and commitment
        let players_len = players.len() as u32;
        let threshold = quorum(players_len).expect("insufficient players");
        let (commitment, shares) = ops::generate_shares(share, players_len, threshold);
        (
            Self {
                threshold,
                players: players_ordered,
                acks: HashSet::new(),
            },
            commitment,
            shares,
        )
    }

    /// Track ack from a player.
    ///
    /// TODO: signature should be over commitment (otherwise will get rejected by arbiter).
    pub fn ack(&mut self, player: PublicKey) -> Result<(), Error> {
        // Ensure player is valid
        let idx = match self.players.get(&player) {
            Some(player) => *player,
            None => return Err(Error::PlayerInvalid),
        };

        // Store ack
        match self.acks.insert(idx) {
            true => Ok(()),
            false => Err(Error::DuplicateAck),
        }
    }

    /// Return whether an ack has been received from a player.
    pub fn has(&self, player: PublicKey) -> bool {
        let Some(idx) = self.players.get(&player) else {
            return false;
        };
        self.acks.contains(idx)
    }

    /// Return the count of acks.
    pub fn count(&self) -> usize {
        self.acks.len()
    }

    /// If there exist at least `2f + 1` acks, finalize.
    pub fn finalize(self) -> Option<Output> {
        // Ensure there are enough commitments to proceed
        if self.acks.len() < self.threshold as usize {
            return None;
        }

        // Return the list of players and players that weren't active
        let mut active = Vec::new();
        let mut inactive = Vec::new();
        for (_, player) in self.players.into_iter() {
            if self.acks.contains(&player) {
                active.push(player);
            } else {
                inactive.push(player);
            }
        }
        Some(Output { active, inactive })
    }
}
