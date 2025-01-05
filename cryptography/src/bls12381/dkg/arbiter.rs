//! Orchestrator of the DKG/Resharing procedure.
//!
//! # Deployment Options
//!
//! ## Recommended: All Contributors Run the Arbiter
//!
//! Each contributor should run its own instance of the arbiter over a replicated log (deterministic
//! order of events across all contributors) of commitments, acknowledgements, and complaints.
//! All correct contributors, when given the same log, will arrive at the same result (will recover
//! the same group polynomial and a share that can generate partial signatures over it). Using a
//! replicated log allows us to provide both reliable broadcast (all honest contributors see all messages from
//! all other honest contributors) and to enforce a "timeout" (using log index) for each phase of DKG/Resharing.
//!
//! ## Trusted Alternative: Standalone Process
//!
//! It is possible to run the arbiter as a standalone process that contributors
//! must trust to track commitments, acknowledgements, and complaints and then notify
//! all parties which commitments and shares to use to generate the group public key and shares.
//!
//! _For an example of this approach, refer to <https://docs.rs/commonware-vrf>._
//!
//! # Disqualification on Attributable Faults
//!
//! Submitting duplicate and/or unnecessary information (i.e. a dealer submitting the same commitment twice
//! or submitting an acknowledgement for a disqualified dealer) will throw an error but not disqualify the
//! contributor. It may not be possible for contributors to know the latest state of the arbiter when submitting
//! information and penalizing them for this is not helpful (i.e. an acknowledgement may be inflight when another
//! contributor submits a valid complaint).
//!
//! Submitting invalid information (invalid commitment) qualifies as an attributable fault that disqualifies a
//! dealer/recipient from a round of DKG/Resharing. A developer can additionally handle such a fault as they see
//! fit (may warrant additional punishment).
//!
//! # Warning
//!
//! It is up to the developer to authorize interaction with the arbiter. This is purposely
//! not provided by the Arbiter because this authorization function is highly dependent on
//! the context in which the contributor is being used.

use crate::bls12381::{
    dkg::{ops, Error},
    primitives::{group::Share, poly},
};
use crate::PublicKey;
use commonware_utils::{max_faults, quorum};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Output of the DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    pub public: poly::Public,
    pub commitments: HashMap<u32, poly::Public>,
    pub reveals: HashMap<u32, Vec<Share>>,
}

/// Gather commitments from all contributors.
pub struct P0 {
    previous: Option<poly::Public>,
    dealer_threshold: u32,
    recipient_threshold: u32,
    concurrency: usize,

    dealers: HashMap<PublicKey, u32>,

    recipients: Vec<PublicKey>,

    commitments: BTreeMap<u32, (poly::Public, Vec<u32>, Vec<Share>)>,
    reveals: BTreeMap<usize, Vec<u32>>,
    disqualified: HashSet<PublicKey>,
}

impl P0 {
    /// Create a new arbiter for a DKG/Resharing procedure.
    pub fn new(
        previous: Option<poly::Public>,
        mut dealers: Vec<PublicKey>,
        mut recipients: Vec<PublicKey>,
        concurrency: usize,
    ) -> Self {
        dealers.sort();
        let dealers_ordered = dealers
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();
        recipients.sort();
        Self {
            dealer_threshold: quorum(dealers.len() as u32).expect("insufficient dealers"),
            recipient_threshold: quorum(recipients.len() as u32).expect("insufficient recipients"),
            previous,
            concurrency,

            dealers: dealers_ordered,

            recipients,

            commitments: BTreeMap::new(),
            reveals: BTreeMap::new(),
            disqualified: HashSet::new(),
        }
    }

    /// Disqualify a participant from the DKG for external reason (i.e. sending invalid messages).
    pub fn disqualify(&mut self, participant: PublicKey) {
        self.disqualified.insert(participant);
    }

    /// Verify and track a commitment from a dealer.
    pub fn commitment(
        &mut self,
        dealer: PublicKey,
        commitment: poly::Public,
        acks: Vec<u32>,
        reveals: Vec<Share>,
    ) -> Result<(), Error> {
        // Check if contributor is disqualified
        //
        // If disqualified, ignore future messages to avoid unnecessary processing.
        if self.disqualified.contains(&dealer) {
            return Err(Error::ContributorDisqualified);
        }

        // Find the index of the contributor
        let idx = match self.dealers.get(&dealer) {
            Some(idx) => *idx,
            None => return Err(Error::ContributorInvalid),
        };

        // Check if commitment already exists
        if self.commitments.contains_key(&idx) {
            return Err(Error::DuplicateCommitment);
        }

        // Verify the commitment is valid
        if let Err(e) = ops::verify_commitment(
            self.previous.as_ref(),
            idx,
            &commitment,
            self.recipient_threshold,
        ) {
            self.disqualified.insert(dealer);
            return Err(e);
        }

        // Ensure acks valid range and >= threshold
        let recipients_len = self.recipients.len() as u32;
        let mut active = HashSet::new();
        for ack in &acks {
            if *ack >= recipients_len {
                self.disqualified.insert(dealer);
                return Err(Error::PlayerInvalid);
            }
            active.insert(ack);
        }

        // Ensure reveals less than max_faults and for recipients not yet ack'd
        let reveals_len = reveals.len();
        let max_faults = max_faults(recipients_len).unwrap() as usize;
        if reveals_len > max_faults {
            self.disqualified.insert(dealer);
            return Err(Error::TooManyReveals);
        }

        // Check reveals
        for share in &reveals {
            if share.index >= recipients_len {
                self.disqualified.insert(dealer);
                return Err(Error::PlayerInvalid);
            }
            if active.contains(&share.index) {
                self.disqualified.insert(dealer);
                return Err(Error::PlayerInvalid);
            }

            // Verify share
            ops::verify_share(
                self.previous.as_ref(),
                idx,
                &commitment,
                self.recipient_threshold,
                share.index,
                share,
            )?;

            // Record active
            active.insert(&share.index);
        }

        // Record acks and reveals
        self.commitments.insert(idx, (commitment, acks, reveals));
        self.reveals.entry(reveals_len).or_default().push(idx);
        Ok(())
    }

    /// If we are prepared, proceed to `P1`.
    ///
    /// Return the disqualified contributors.
    pub fn finalize(mut self) -> (Result<Output, Error>, HashSet<PublicKey>) {
        // Drop commitments from disqualified contributors
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
        if self.commitments.len() < self.dealer_threshold as usize {
            return (Err(Error::InsufficientDealings), self.disqualified);
        }

        // Select best `2f + 1` commitments (sorted by fewest reveals)
        let mut selected = Vec::new();
        for (_, dealers) in self.reveals.iter() {
            for dealer_idx in dealers {
                if let Some(commitment) = self.commitments.get(dealer_idx) {
                    selected.push((*dealer_idx, commitment));
                    if selected.len() == self.dealer_threshold as usize {
                        break;
                    }
                }
            }
            if selected.len() == self.dealer_threshold as usize {
                break;
            }
        }

        // Recover group
        let public = match self.previous {
            Some(previous) => {
                let mut commitments = BTreeMap::new();
                for (dealer_idx, (commitment, _, _)) in &selected {
                    commitments.insert(*dealer_idx, commitment.clone());
                }
                match ops::recover_public(
                    &previous,
                    commitments,
                    self.recipient_threshold,
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
                match ops::construct_public(commitments, self.recipient_threshold) {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
        };

        // Generate output
        let mut commitments = HashMap::new();
        let mut reveals = HashMap::new();
        for (dealer_idx, (commitment, _, shares)) in selected {
            commitments.insert(dealer_idx, commitment.clone());
            if shares.is_empty() {
                continue;
            }
            reveals.insert(dealer_idx, shares.clone());
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
