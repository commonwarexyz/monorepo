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

use super::utils::threshold;
use crate::bls12381::{
    dkg::{ops, Error},
    primitives::{group::Share, poly},
};
use crate::PublicKey;
use commonware_utils::quorum;
use itertools::Itertools;
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
    fn quorum(&self) -> u32 {
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
            None => return Err(Error::ContributorInvalid),
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

    /// If there exist `2f + 1` commitments, we are prepared to proceed to `P1`.
    pub fn prepared(&mut self) -> bool {
        // Drop commitments from disqualified contributors
        for disqualified in self.disqualified.iter() {
            self.commitments.remove(disqualified);
        }

        // See if we have enough commitments to proceed
        self.commitments.len() >= self.quorum() as usize
    }

    /// If we are prepared, proceed to `P1`.
    ///
    /// Return the disqualified contributors.
    pub fn finalize(mut self) -> (Option<P1>, HashSet<PublicKey>) {
        // If we aren't done, we cannot proceed
        if !self.prepared() {
            return (None, self.disqualified);
        }

        // Select first `2f + 1` commitments
        let required_commitments = self.quorum() as usize;
        let keys = self
            .commitments
            .keys()
            .skip(required_commitments)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            self.commitments.remove(&key);
        }

        // Add implicit acks for all selected commitments
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

                threshold_commitments: None,
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

    threshold_commitments: Option<BTreeSet<u32>>,
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
            None => return Err(Error::ContributorInvalid),
        };

        {
            // Get dealer that submitted commitment
            let dealer = self
                .dealers
                .get(dealer as usize)
                .ok_or(Error::DealerInvalid)?;

            // Check if commitment is still valid
            if self.disqualified.contains(dealer) || !self.commitments.contains_key(dealer) {
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
            None => return Err(Error::ContributorInvalid),
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
        if self.disqualified.contains(dealer_key) || !self.commitments.contains_key(dealer_key) {
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

    /// If there exist `2f + 1` acks from the same set of `f + 1` contributors for `f + 1` dealers, we are
    /// prepared to finalize.
    pub fn prepared(&mut self) -> bool {
        // Check if we already checked
        if self.threshold_commitments.is_some() {
            return true;
        }

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

        // Record recipients from commitments with at least `2f + 1` acks
        let recipient_quorum = quorum(self.recipients.len() as u32).unwrap() as usize;
        let mut recipients = BTreeMap::new();
        for dealer in self.commitments.keys() {
            // Get acks for commitment
            let dealer_idx = self.dealers_ordered.get(dealer).unwrap();
            let Some(dealer_acks) = self.acks.get(dealer_idx) else {
                continue;
            };

            // Skip commitment if not `2f + 1` acks
            //
            // We previously ensure self-acks are included in this count.
            if dealer_acks.len() < recipient_quorum {
                continue;
            }

            // Record acks for commitment
            for recipient in dealer_acks {
                let acks = recipients.entry(*recipient).or_insert_with(BTreeSet::new);
                acks.insert(*dealer_idx);
            }
        }

        // Remove all recipients that haven't ack'd at least `f + 1` commitments
        let dealer_threshold = threshold(self.dealers.len() as u32).unwrap() as usize;
        recipients.retain(|_, acks| acks.len() >= dealer_threshold);

        // If there aren't `2f + 1` recipients with at acks on at least `f + 1` commitments, we can't proceed
        if recipients.len() < recipient_quorum {
            return false;
        }

        // Look for some subset of recipients of size `2f + 1` that has ack'd the same `f + 1` commitments
        //
        // When provided a data structure with a deterministic iteration order, combinations
        // produces a deterministic order of combinations.
        for combination in recipients.keys().combinations(recipient_quorum) {
            // Create intersection of commitment acks over selected contributors
            let mut intersection = recipients.get(combination[0]).unwrap().clone();
            for acks in combination.into_iter().skip(1) {
                intersection = intersection
                    .intersection(recipients.get(acks).unwrap())
                    .cloned()
                    .collect();

                // Early exit if intersection has already dipped below required acks
                if intersection.len() < dealer_threshold {
                    break;
                }
            }

            // If intersection of commitments is of size `f + 1`, we are ready
            if intersection.len() >= dealer_threshold {
                // Limit to first `f + 1` commitments
                let intersection: BTreeSet<u32> =
                    intersection.into_iter().take(dealer_threshold).collect();

                // Cache intersection to avoid recomputation
                self.threshold_commitments = Some(intersection);
                return true;
            }
        }

        // There exists no combination of recipients that satisfy our requirements,
        // we can try again later
        false
    }

    /// If we are prepared to finalize, return the `Output`.
    pub fn finalize(mut self) -> (Result<Output, Error>, HashSet<PublicKey>) {
        // If we aren't prepared, we cannot generate the output
        if !self.prepared() {
            return (Err(Error::InsufficientDealings), self.disqualified);
        }
        let threshold_commitments = self.threshold_commitments.unwrap();

        // Recover group
        let public = match self.previous {
            Some(previous) => {
                let mut commitments = BTreeMap::new();
                for idx in &threshold_commitments {
                    let dealer = self.dealers.get(*idx as usize).unwrap();
                    let commitment = self.commitments.get(dealer).unwrap();
                    commitments.insert(*idx, commitment.clone());
                }
                match ops::recover_public(&previous, commitments, self.threshold, self.concurrency)
                {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
            None => {
                let mut commitments = Vec::new();
                for idx in &threshold_commitments {
                    let dealer = self.dealers.get(*idx as usize).unwrap();
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
            commitments: threshold_commitments.into_iter().collect(),
        };

        // Return output
        (Ok(output), self.disqualified)
    }
}
