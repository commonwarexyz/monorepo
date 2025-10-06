//! Orchestrator of the DKG/Resharing procedure.
//!
//! # Deployment Options
//!
//! ## Recommended: All Participants Run the Arbiter
//!
//! Each participant should run its own instance of the arbiter over a replicated log (deterministic
//! order of events across all dealers) of commitments, acknowledgements, and reveals.
//! All correct participants, when given the same log, will arrive at the same result (will recover
//! the same group polynomial and a share that can generate partial signatures over it). Using a
//! replicated log allows us to provide both reliable broadcast (all honest dealers see all messages from
//! all other honest dealers) and to enforce a "timeout" (using log index).
//!
//! ## Alternative: Trusted Process
//!
//! It is possible to run the arbiter as a standalone process that dealers
//! must trust to track commitments, acknowledgements, and reveals and then notify
//! all parties which commitments and shares to use to generate the group public key and shares.
//!
//! _For an example of this approach, refer to <https://docs.rs/commonware-vrf>._
//!
//! # Disqualification on Attributable Faults
//!
//! Submitting duplicate and/or unnecessary information (i.e. a dealer submitting the same commitment twice
//! or submitting an acknowledgement for a disqualified dealer) will throw an error but not disqualify the
//! dealer. It may not be possible for dealers to know the latest state of the arbiter when submitting
//! information and penalizing them for this is not helpful.
//!
//! Submitting invalid information (invalid commitment) qualifies as an attributable fault that disqualifies a
//! dealer from a round of DKG/Resharing. A developer can additionally handle such a fault as they see
//! fit (may warrant additional punishment).
//!
//! # Warning
//!
//! It is up to the developer to authorize interaction with the arbiter. This is purposely
//! not provided by the arbiter because this authorization function is highly dependent on
//! the context in which the dealer is being used.

use crate::{
    bls12381::{
        dkg::{
            ops::{construct_public, recover_public, verify_commitment, verify_share},
            Error,
        },
        primitives::{group::Share, poly, variant::Variant},
    },
    PublicKey,
};
use commonware_utils::{max_faults, quorum};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Output of the DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output<V: Variant> {
    /// The group polynomial output by the DKG/Resharing procedure.
    pub public: poly::Public<V>,

    /// `2f + 1` commitments used to derive group polynomial.
    pub commitments: HashMap<u32, poly::Public<V>>,

    /// Reveals published by dealers of selected commitments.
    pub reveals: HashMap<u32, Vec<Share>>,
}

/// Gather commitments, acknowledgements, and reveals from all dealers.
pub struct Arbiter<P: PublicKey, V: Variant> {
    previous: Option<poly::Public<V>>,
    dealer_threshold: u32,
    player_threshold: u32,
    concurrency: usize,

    dealers: HashMap<P, u32>,
    players: Vec<P>,

    #[allow(clippy::type_complexity)]
    commitments: BTreeMap<u32, (poly::Public<V>, Vec<u32>, Vec<Share>)>,
    disqualified: HashSet<P>,
}

impl<P: PublicKey, V: Variant> Arbiter<P, V> {
    /// Create a new arbiter for a DKG/Resharing procedure.
    pub fn new(
        previous: Option<poly::Public<V>>,
        mut dealers: Vec<P>,
        mut players: Vec<P>,
        concurrency: usize,
    ) -> Self {
        dealers.sort();
        let dealers = dealers
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect::<HashMap<P, _>>();
        players.sort();
        Self {
            dealer_threshold: quorum(dealers.len() as u32),
            player_threshold: quorum(players.len() as u32),
            previous,
            concurrency,

            dealers,
            players,

            commitments: BTreeMap::new(),
            disqualified: HashSet::new(),
        }
    }

    /// Disqualify a participant from the DKG for external reason (i.e. sending invalid messages).
    pub fn disqualify(&mut self, participant: P) {
        self.disqualified.insert(participant);
    }

    /// Verify and track a commitment, acknowledgements, and reveals collected by a dealer.
    pub fn commitment(
        &mut self,
        dealer: P,
        commitment: poly::Public<V>,
        acks: Vec<u32>,
        reveals: Vec<Share>,
    ) -> Result<(), Error> {
        // Check if dealer is disqualified
        //
        // If disqualified, ignore future messages to avoid unnecessary processing.
        if self.disqualified.contains(&dealer) {
            return Err(Error::DealerDisqualified);
        }

        // Find the index of the dealer
        let idx = match self.dealers.get(&dealer) {
            Some(idx) => *idx,
            None => return Err(Error::DealerInvalid),
        };

        // Check if commitment already exists
        if self.commitments.contains_key(&idx) {
            return Err(Error::DuplicateCommitment);
        }

        // Verify the commitment is valid
        if let Err(e) = verify_commitment::<V>(
            self.previous.as_ref(),
            &commitment,
            idx,
            self.player_threshold,
        ) {
            self.disqualified.insert(dealer);
            return Err(e);
        }

        // Ensure acks valid range and >= threshold
        let players_len = self.players.len() as u32;
        let mut active = HashSet::new();
        for ack in &acks {
            // Ensure index is valid
            if *ack >= players_len {
                self.disqualified.insert(dealer);
                return Err(Error::PlayerInvalid);
            }

            // Ensure index not already active
            if !active.insert(ack) {
                self.disqualified.insert(dealer);
                return Err(Error::AlreadyActive);
            }
        }

        // Ensure reveals less than max_faults and for players not yet ack'd
        let reveals_len = reveals.len();
        let max_faults = max_faults(players_len) as usize;
        if reveals_len > max_faults {
            self.disqualified.insert(dealer);
            return Err(Error::TooManyReveals);
        }

        // Check reveals
        for share in &reveals {
            // Ensure index is valid
            if share.index >= players_len {
                self.disqualified.insert(dealer);
                return Err(Error::PlayerInvalid);
            }

            // Ensure index not already active
            if !active.insert(&share.index) {
                self.disqualified.insert(dealer);
                return Err(Error::AlreadyActive);
            }

            // Verify share
            verify_share::<V>(&commitment, share.index, share)?;
        }

        // Active must be equal to number of players
        if active.len() != players_len as usize {
            self.disqualified.insert(dealer);
            return Err(Error::IncorrectActive);
        }

        // Record acks and reveals
        self.commitments.insert(idx, (commitment, acks, reveals));
        Ok(())
    }

    /// Returns whether or not we are ready to finalize.
    pub fn ready(&self) -> bool {
        self.commitments.len() >= self.dealer_threshold as usize
    }

    /// Recover the group polynomial and return `2f + 1` commitments and reveals from dealers.
    ///
    /// Return the disqualified dealers.
    pub fn finalize(mut self) -> (Result<Output<V>, Error>, HashSet<P>) {
        // Drop commitments from disqualified dealers
        for disqualified in self.disqualified.iter() {
            let idx = self.dealers.get(disqualified).unwrap();
            self.commitments.remove(idx);
        }

        // Add any dealers we haven't heard from to disqualified
        for (dealer, idx) in &self.dealers {
            if self.commitments.contains_key(idx) {
                continue;
            }
            self.disqualified.insert(dealer.clone());
        }

        // Ensure we have enough commitments to proceed
        let dealer_threshold = self.dealer_threshold as usize;
        if self.commitments.len() < dealer_threshold {
            return (Err(Error::InsufficientDealings), self.disqualified);
        }

        // If there exist more than `2f + 1` commitments, take the first `2f + 1`
        // sorted by dealer index.
        let selected = self
            .commitments
            .into_iter()
            .take(dealer_threshold)
            .collect::<Vec<_>>();

        // Recover group
        let public = match self.previous {
            Some(previous) => {
                let mut commitments = BTreeMap::new();
                for (dealer_idx, (commitment, _, _)) in &selected {
                    commitments.insert(*dealer_idx, commitment.clone());
                }
                match recover_public::<V>(
                    &previous,
                    commitments,
                    self.player_threshold,
                    self.concurrency,
                ) {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
            None => {
                let mut commitments = Vec::new();
                for (_, (commitment, _, _)) in &selected {
                    commitments.push(commitment.clone());
                }
                match construct_public::<V>(commitments, self.player_threshold) {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
        };

        // Generate output
        let mut commitments = HashMap::new();
        let mut reveals = HashMap::new();
        for (dealer_idx, (commitment, _, shares)) in selected {
            commitments.insert(dealer_idx, commitment);
            if shares.is_empty() {
                continue;
            }
            reveals.insert(dealer_idx, shares);
        }
        let output = Output {
            public,
            commitments,
            reveals,
        };

        // Return output
        (Ok(output), self.disqualified)
    }
}
