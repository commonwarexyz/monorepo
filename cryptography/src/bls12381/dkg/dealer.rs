//! Participants in a DKG/Resharing procedure that distribute dealings
//! to players and collect their acknowledgements.

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
    /// List of active players.
    pub active: Vec<u32>,

    /// List of inactive players (that we need to send
    /// a reveal for).
    pub inactive: Vec<u32>,
}

/// Track acknowledgements from players.
pub struct Dealer {
    threshold: u32,
    players: HashMap<PublicKey, u32>,

    acks: HashSet<u32>,
}

impl Dealer {
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

    /// Track acknowledgement from a player.
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
        active.sort();
        inactive.sort();
        Some(Output { active, inactive })
    }
}
