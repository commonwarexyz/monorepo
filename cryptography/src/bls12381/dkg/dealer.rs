//! Participants in a DKG/Resharing procedure that distribute dealings
//! to players and collect their acknowledgements.

use crate::{
    bls12381::{
        dkg::{ops::generate_shares, Error},
        primitives::{group::Share, poly, variant::Variant},
    },
    PublicKey,
};
use commonware_utils::{quorum, set::Ordered};
use rand_core::CryptoRngCore;
use std::{collections::HashSet, marker::PhantomData};

/// Dealer output of a DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    /// List of active players.
    pub active: Ordered<u32>,

    /// List of inactive players (that we need to send
    /// a reveal for).
    pub inactive: Ordered<u32>,
}

/// Track acknowledgements from players.
pub struct Dealer<P: PublicKey, V: Variant> {
    threshold: u32,
    players: Ordered<P>,

    acks: HashSet<u32>,

    _phantom: PhantomData<V>,
}

impl<P: PublicKey, V: Variant> Dealer<P, V> {
    /// Create a new dealer for a DKG/Resharing procedure.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        share: Option<Share>,
        players: Ordered<P>,
    ) -> (Self, poly::Public<V>, Ordered<Share>) {
        // Generate shares and commitment
        let players_len = players.len() as u32;
        let threshold = quorum(players_len);
        let (commitment, shares) = generate_shares::<_, V>(rng, share, players_len, threshold);
        (
            Self {
                threshold,
                players,
                acks: HashSet::new(),

                _phantom: PhantomData,
            },
            commitment,
            shares.into_iter().collect(),
        )
    }

    /// Track acknowledgement from a player.
    pub fn ack(&mut self, player: P) -> Result<(), Error> {
        // Ensure player is valid
        let idx = match self.players.position(&player) {
            Some(player) => player,
            None => return Err(Error::PlayerInvalid),
        };

        // Store ack
        match self.acks.insert(idx as u32) {
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
        for player in 0..self.players.len() as u32 {
            if self.acks.contains(&player) {
                active.push(player);
            } else {
                inactive.push(player);
            }
        }
        Some(Output {
            active: Ordered::from_iter(active),
            inactive: Ordered::from_iter(inactive),
        })
    }
}
