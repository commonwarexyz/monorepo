//! Orchestrator of the DKG/Resharing procedure.
//!
//! # Deployment Options
//!
//! ## Recommended: All Contributors Run the Arbiter
//!
//! Each contributor should run its own instance of the arbiter over a replicated
//! log (deterministic order of events across all contributors) of commitments,
//! acknowledgements, and complaints. All correct contributors, when given
//! the same log, will arrive at the same result (will recover the same group polynomial
//! and a share that can generate partial signatures over it). Using a replicated log allows
//! us to provide both reliable broadcast (all honest contributors see all messages from
//! all other honest contributors) and to enforce a "timeout" (using log index) for each
//! phase of DKG/Resharing.
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

use commonware_utils::quorum;
use itertools::Itertools;

use super::utils::threshold;
use crate::bls12381::{
    idkg::{ops, Error},
    primitives::{group::Share, poly},
};
use crate::PublicKey;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Gather commitments from all contributors.
pub struct P0 {
    previous: Option<poly::Public>,
    threshold: u32,
    concurrency: usize,

    dealers: Vec<PublicKey>,
    dealers_ordered: HashMap<PublicKey, u32>,

    recipients: Vec<PublicKey>,
    recipients_ordered: HashMap<PublicKey, u32>,

    commitments: BTreeMap<PublicKey, poly::Public>,
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
        let recipients_ordered = recipients
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();
        Self {
            threshold: threshold(recipients.len() as u32).expect("insufficient participants"),
            previous,
            concurrency,
            dealers,
            dealers_ordered,
            recipients,
            recipients_ordered,
            commitments: BTreeMap::new(),
            disqualified: HashSet::new(),
        }
    }

    /// Required number of commitments to continue procedure.
    fn required(&self) -> u32 {
        match &self.previous {
            Some(_) => quorum(self.dealers.len() as u32).unwrap(),
            None => quorum(self.recipients.len() as u32).unwrap(),
        }
    }

    /// Disqualify a contributor from the DKG for external reason (i.e. sending invalid messages).
    pub fn disqualify(&mut self, contributor: PublicKey) {
        self.disqualified.insert(contributor);
    }

    /// Verify and track a commitment from a dealer.
    pub fn commitment(&mut self, dealer: PublicKey, commitment: poly::Public) -> Result<(), Error> {
        // Check if contributor is disqualified
        if self.disqualified.contains(&dealer) {
            return Err(Error::ContributorDisqualified);
        }

        // Find the index of the contributor
        let idx = match self.dealers_ordered.get(&dealer) {
            Some(idx) => *idx,
            None => return Err(Error::ContirbutorInvalid),
        };

        // Check if commitment already exists
        if self.commitments.contains_key(&dealer) {
            return Err(Error::DuplicateCommitment);
        }

        // Verify the commitment is valid
        match ops::verify_commitment(self.previous.as_ref(), idx, &commitment, self.threshold) {
            Ok(()) => {
                self.commitments.insert(dealer, commitment);
            }
            Err(e) => {
                self.disqualified.insert(dealer);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Indicates whether we can proceed to the next phase.
    pub fn ready(&mut self) -> bool {
        // Drop commitments from disqualified contributors
        for disqualified in self.disqualified.iter() {
            self.commitments.remove(disqualified);
        }

        // See if we have enough commitments to proceed
        self.commitments.len() >= self.required() as usize
    }

    /// If there exist `required()` commitments, proceed to `P1`.
    /// Return the disqualified contributors.
    pub fn finalize(mut self) -> (Option<P1>, HashSet<PublicKey>) {
        // Drop commitments from disqualified contributors
        for disqualified in self.disqualified.iter() {
            self.commitments.remove(disqualified);
        }

        // Ensure we have enough commitments to proceed
        let required = self.required() as usize;
        if self.commitments.len() < required {
            return (None, self.disqualified);
        }

        // Select first `required()` commitments
        let keys = self
            .commitments
            .keys()
            .skip(required)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            self.commitments.remove(&key);
        }

        // Add self-acks for all commitments
        let mut acks = HashMap::new();
        for (idx, dealer) in self.dealers.iter().enumerate() {
            let Some(recipient_idx) = self.recipients_ordered.get(dealer) else {
                continue;
            };
            let entry = acks.entry(idx as u32).or_insert_with(HashSet::new);
            entry.insert(*recipient_idx);
        }

        // Allow the arbiter to proceed
        (
            Some(P1 {
                threshold: self.threshold,
                previous: self.previous,
                concurrency: self.concurrency,
                dealers: self.dealers,
                dealers_ordered: self.dealers_ordered,
                recipients: self.recipients,
                recipients_ordered: self.recipients_ordered,
                commitments: self.commitments,
                disqualified: self.disqualified.clone(),
                acks,
                final_commitments: None,
            }),
            self.disqualified,
        )
    }
}

/// Collect acknowledgements and complaints from all recipients.
pub struct P1 {
    threshold: u32,
    previous: Option<poly::Public>,
    concurrency: usize,

    dealers: Vec<PublicKey>,
    dealers_ordered: HashMap<PublicKey, u32>,

    recipients: Vec<PublicKey>,
    recipients_ordered: HashMap<PublicKey, u32>,

    commitments: BTreeMap<PublicKey, poly::Public>,
    disqualified: HashSet<PublicKey>,

    acks: HashMap<u32, HashSet<u32>>,

    final_commitments: Option<BTreeSet<u32>>,
}

/// Output of the DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    pub public: poly::Public,
    pub commitments: Vec<u32>,
}

/// Alias for a commitment from a dealer.
pub type Commitment = (u32, PublicKey, poly::Public);

impl P1 {
    /// Required number of acks to continue procedure.
    fn required(&self) -> u32 {
        quorum(self.recipients.len() as u32).unwrap()
    }

    /// Disqualify a contributor from the DKG for external reason (i.e. sending invalid messages).
    pub fn disqualify(&mut self, contributor: PublicKey) {
        self.disqualified.insert(contributor);
    }

    /// Get the public key of a dealer.
    pub fn dealer(&self, dealer: u32) -> Option<PublicKey> {
        self.dealers.get(dealer as usize).cloned()
    }

    /// Return all tracked commitments.
    pub fn commitments(&self) -> Vec<Commitment> {
        self.commitments
            .iter()
            .filter_map(|(contributor, commitment)| {
                if self.disqualified.contains(contributor) {
                    return None;
                }

                let idx = self.dealers_ordered.get(contributor).unwrap();
                Some((*idx, contributor.clone(), commitment.clone()))
            })
            .collect()
    }

    /// Verify and track an acknowledgement from a recipient for a dealer.
    pub fn ack(&mut self, recipient: PublicKey, dealer: u32) -> Result<(), Error> {
        // Check if contributor is disqualified
        if self.disqualified.contains(&recipient) {
            return Err(Error::ContributorDisqualified);
        }

        // Find the index of the recipient
        let idx = match self.recipients_ordered.get(&recipient) {
            Some(idx) => *idx,
            None => return Err(Error::ContirbutorInvalid),
        };

        {
            // Get dealer that submitted commitment
            let dealer = self
                .dealers
                .get(dealer as usize)
                .ok_or(Error::DealerInvalid)?;

            // Check if commitment is still valid
            if self.disqualified.contains(dealer) | !self.commitments.contains_key(dealer) {
                // We don't disqualify the submitter here as this could have happened
                // without their knowledge.
                return Err(Error::CommitmentDisqualified);
            }

            // Ensure we aren't sending a self-ack
            if recipient == *dealer {
                self.disqualified.insert(recipient);
                return Err(Error::SelfAck);
            }
        }

        // Store ack
        let entry = self.acks.entry(dealer).or_default();
        if entry.contains(&idx) {
            Err(Error::DuplicateAck)
        } else {
            entry.insert(idx);
            Ok(())
        }
    }

    /// Verify a complaint from a recipient for a dealer.
    ///
    /// If a complaint is valid, the dealer is disqualified. If a
    /// complaint is invalid, the recipient is disqualified.
    pub fn complaint(
        &mut self,
        recipient: PublicKey,
        dealer: u32,
        share: &Share,
    ) -> Result<(), Error> {
        // Check if contributor is disqualified
        if self.disqualified.contains(&recipient) {
            return Err(Error::ContributorDisqualified);
        }

        // Find the index of the contributor
        let idx = match self.recipients_ordered.get(&recipient) {
            Some(idx) => *idx,
            None => return Err(Error::ContirbutorInvalid),
        };

        // Find the dealer that submitted the commitment
        let dealer_key = self
            .dealers
            .get(dealer as usize)
            .ok_or(Error::DealerInvalid)?;

        if dealer_key == &recipient {
            return Err(Error::SelfComplaint);
        }

        // Check if commitment is still valid
        if self.disqualified.contains(dealer_key) | !self.commitments.contains_key(dealer_key) {
            // We don't disqualify the submitter here as this could have happened
            // without their knowledge.
            return Err(Error::CommitmentDisqualified);
        }

        // Verify complaint
        let commitment = self.commitments.get(dealer_key).unwrap();
        match ops::verify_share(
            self.previous.as_ref(),
            dealer,
            commitment,
            self.threshold,
            idx,
            share,
        ) {
            Ok(_) => {
                // Submitting a useless complaint is a disqualifying offense
                self.disqualified.insert(recipient);
                Err(Error::ComplaintInvalid)
            }
            Err(_) => {
                // Disqualify the dealer
                self.disqualified.insert(dealer_key.clone());
                Ok(())
            }
        }
    }

    /// Indicates whether we can finalize the procedure.
    pub fn ready(&mut self) -> bool {
        // Remove acks of disqualified recipients
        for acks in self.acks.values_mut() {
            for disqualified in self.disqualified.iter() {
                if let Some(idx) = self.recipients_ordered.get(disqualified) {
                    acks.remove(idx);
                }

                // If we can't find the recipient, it is probably a disqualified dealer.
            }
        }

        // Remove disqualified commitments
        for disqualified in self.disqualified.iter() {
            self.commitments.remove(disqualified);
            self.acks
                .remove(self.dealers_ordered.get(disqualified).unwrap());
        }

        // Record recipient in all commitments with at least `required()` acks
        let required = self.required() as usize;
        let mut recipients = BTreeMap::new();
        for dealer in self.commitments.keys() {
            // Get acks for commitment
            let dealer_idx = self.dealers_ordered.get(dealer).unwrap();
            let Some(recipient_acks) = self.acks.get(dealer_idx) else {
                println!("no acks for dealer {}", dealer_idx);
                continue;
            };

            // Skip if not `required()` acks
            //
            // We previously ensure self-acks are included in this count.
            if recipient_acks.len() < required {
                continue;
            }

            // Record commitment for all acks
            for recipient in recipient_acks {
                let acks = recipients.entry(*recipient).or_insert_with(BTreeSet::new);
                acks.insert(*dealer_idx);
            }
        }

        // Compute required acks
        let required_acks = match self.previous {
            Some(_) => threshold(self.dealers.len() as u32).unwrap(),
            None => self.threshold,
        } as usize;

        // Remove all recipients that don't have at least `threshold` commitments
        recipients.retain(|_, acks| acks.len() >= required_acks);

        // If there are not `required()` recipients with at least `threshold` acks, we cannot proceed.
        if recipients.len() < required {
            return false;
        }

        // Look for some subset of recipients of size `required()` that is present in
        // `threshold` commitments
        //
        // When provided a data structure with a deterministic iteration order, combinations
        // produces a deterministic order of combinations.
        for combination in recipients.keys().combinations(required) {
            // Create intersection over all acks
            let mut intersection = recipients.get(combination[0]).unwrap().clone();
            for acks in combination.into_iter().skip(1) {
                intersection = intersection
                    .intersection(recipients.get(acks).unwrap())
                    .cloned()
                    .collect();
            }

            // If intersection is of size `threshold`, we can proceed
            if intersection.len() >= required_acks {
                self.final_commitments = Some(intersection);
                return true;
            }
        }

        // There exists no combination of recipients with at least
        false
    }

    /// If there exist at least `threshold - 1` acks each for `required()` dealers, proceed to `P2`.
    pub fn finalize(self) -> (Result<Output, Error>, HashSet<PublicKey>) {
        // If no final commitments, we cannot proceed
        if self.final_commitments.is_none() {
            return (Err(Error::InsufficientDealings), self.disqualified);
        }

        // Recover group
        let public = match self.previous {
            Some(previous) => {
                let mut commitments = BTreeMap::new();
                for idx in self.final_commitments.unwrap() {
                    let dealer = self.dealers.get(idx as usize).unwrap();
                    let commitment = self.commitments.get(dealer).unwrap();
                    commitments.insert(idx, commitment.clone());
                }
                match ops::recover_public(&previous, commitments, self.threshold, self.concurrency)
                {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
            None => {
                let mut commitments = Vec::new();
                for idx in self.final_commitments.unwrap() {
                    let dealer = self.dealers.get(idx as usize).unwrap();
                    let commitment = self.commitments.get(dealer).unwrap();
                    commitments.push(commitment.clone());
                }
                match ops::construct_public(commitments, self.threshold) {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
        };

        // Generate output
        let output = Output {
            public,
            commitments: self
                .commitments
                .keys()
                .map(|contributor| *self.dealers_ordered.get(contributor).unwrap())
                .collect(),
        };

        // Return output
        (Ok(output), self.disqualified)
    }
}
