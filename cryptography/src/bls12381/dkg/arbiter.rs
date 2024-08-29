//! Orchestrator of the DKG/Resharing procedure.
//!
//! # Deployment Options
//!
//! ## Recommended: All Contributors Run the Arbiter
//!
//! Each contributor should run its own instance of the arbiter over a replicated
//! log (deterministic order of events across all contributors) of commitments,
//! acknowledgements, complaints, and resolutions. All correct contributors, when given
//! the same log, will arrive at the same result (will recover the same group polynomial
//! and a share that can generate partial signatures over it). Using a replicated log allows
//! us to provide both reliable broadcast (all honest contributors see all messages from
//! all other honest contributors) and to enforce a "timeout" (using log index) for each
//! phase of DKG/Resharing (needed to support a `2f + 1` threshold in this construction).
//!
//! ## Trusted Alternative: Standalone Process
//!
//! It is possible to run the arbiter as a standalone process that contributors
//! must trust to track commitments, acks, complaints, and reveals. A rogue arbiter
//! could request reveals from all dealers for all participants and recover the group
//! secret key.
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
//! Submitting invalid information (invalid commitment) or refusing to submit required information (not sending a commitment)
//! qualifies as an attributable fault that disqualifies a dealer/recipient from a round of DKG/Resharing. A developer
//! can additionally handle such a fault as they see fit (may warrant additional punishment).
//!
//! # Warning
//!
//! It is up to the developer to authorize interaction with the arbiter. This is purposely
//! not provided by the Arbiter because this authorization function is highly dependent on
//! the context in which the contributor is being used.

use super::utils;
use crate::bls12381::{
    dkg::{ops, Error},
    primitives::{group::Share, poly},
};
use crate::PublicKey;
use std::collections::{HashMap, HashSet};

/// Gather commitments from all contributors.
pub struct P0 {
    threshold: u32,
    previous: Option<poly::Public>,
    concurrency: usize,

    dealers: Vec<PublicKey>,
    dealers_ordered: HashMap<PublicKey, u32>,

    recipients: Vec<PublicKey>,
    recipients_ordered: HashMap<PublicKey, u32>,

    commitments: HashMap<PublicKey, poly::Public>,
    disqualified: HashSet<PublicKey>,
}

impl P0 {
    /// Create a new abiter for a DKG/Resharing procedure.
    pub fn new(
        threshold: u32,
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
        dealers.sort();
        Self {
            threshold,
            previous,
            concurrency,
            dealers,
            dealers_ordered,
            recipients,
            recipients_ordered,
            commitments: HashMap::new(),
            disqualified: HashSet::new(),
        }
    }

    /// Required number of commitments to continue procedure.
    pub fn required(&self) -> u32 {
        match &self.previous {
            Some(previous) => previous.required(),
            None => self.threshold,
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

    /// If there exist at least `required()` commitments, proceed to `P1`.
    pub fn finalize(mut self) -> (Option<P1>, HashSet<PublicKey>) {
        // Disqualify any contributors who did not submit a commitment
        for contributor in self.dealers.iter() {
            if !self.commitments.contains_key(contributor) {
                self.disqualified.insert(contributor.clone());
            }
        }

        // Ensure we have enough commitments to proceed
        if self.commitments.len() < self.required() as usize {
            return (None, self.disqualified);
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
                acks: HashMap::new(),
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

    commitments: HashMap<PublicKey, poly::Public>,
    disqualified: HashSet<PublicKey>,

    acks: HashMap<u32, HashSet<u32>>,
}

/// Alias for a commitment from a dealer.
pub type Commitment = (u32, PublicKey, poly::Public);

/// Alias for a request for a missing share from a dealer
/// for a recipient.
pub type Request = (u32, u32);

impl P1 {
    /// Required number of commitments to continue procedure.
    pub fn required(&self) -> u32 {
        match &self.previous {
            Some(previous) => previous.required(),
            None => self.threshold,
        }
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

    /// Request missing dealings.
    fn requests(&self) -> (HashMap<u32, HashSet<u32>>, Vec<Request>) {
        // Compute missing shares
        let mut missing_dealings = HashMap::new(); // dealer -> {recipient}
        let mut required_reveals = HashMap::new(); // recipient -> {dealer}
        for (dealer, acks) in self.acks.iter() {
            for (recipient, recipient_bytes) in self.recipients.iter().enumerate() {
                // Skip any recipients that are disqualified or have already acked
                let dealer_bytes = self.dealers[*dealer as usize].clone();
                if *recipient_bytes == dealer_bytes {
                    continue;
                }
                if self.disqualified.contains(recipient_bytes) {
                    continue;
                }
                let recipient = recipient as u32;
                if acks.contains(&recipient) {
                    continue;
                }

                // Add dealer -> recipient to tracker
                let entry = missing_dealings.entry(*dealer).or_insert_with(HashSet::new);
                entry.insert(recipient);
                let entry = required_reveals
                    .entry(recipient)
                    .or_insert_with(HashSet::new);
                entry.insert(*dealer);
            }
        }

        // Do not request reveals for recipients with more than `max_reveals` missing shares
        let max_reveals = utils::max_reveals(self.threshold);
        for (recipient, dealers) in required_reveals.iter() {
            if dealers.len() <= max_reveals as usize {
                continue;
            }

            // Remove recipient from missing dealings
            for dealer in dealers.iter() {
                if let Some(recipients) = missing_dealings.get_mut(dealer) {
                    recipients.remove(recipient);
                }
            }

            // We do not disqualify dealers that would otherwise need to distribute
            // shares because a particular recipient may just be refusing to participate.
        }

        // Construct required reveals
        let mut reveals = Vec::new();
        for (dealer, recipients) in missing_dealings.iter() {
            for recipient in recipients.iter() {
                reveals.push((*dealer, *recipient));
            }
        }
        (missing_dealings, reveals)
    }

    /// If there exist at least `threshold - 1` acks each for `required()` dealers, proceed to `P2`.
    pub fn finalize(mut self) -> (Option<(P2, Vec<Request>)>, HashSet<PublicKey>) {
        // Remove acks of disqualified recipients
        for acks in self.acks.values_mut() {
            for disqualified in self.disqualified.iter() {
                if let Some(idx) = self.recipients_ordered.get(disqualified) {
                    acks.remove(idx);
                }

                // If we can't find the recipient, it is probably a disqualified dealer.
            }
        }

        // Disqualify any commitments without at least `self.threshold` acks
        for dealer in self.commitments.keys() {
            let idx = self.dealers_ordered.get(dealer).unwrap();
            let acks = match self.acks.get(idx) {
                Some(acks) => acks.len(),
                None => 0,
            };

            // Check against `self.threshold - 1` because we don't send an
            // ack for ourselves.
            if acks < (self.threshold - 1) as usize {
                self.disqualified.insert(dealer.clone());
            }
        }

        // Remove disqualified commitments
        for disqualified in self.disqualified.iter() {
            self.commitments.remove(disqualified);
            self.acks
                .remove(self.dealers_ordered.get(disqualified).unwrap());
        }

        // If there are not `self.required()` dealings with at least `self.required()` acks,
        // we cannot proceed.
        if self.acks.len() < self.required() as usize {
            return (None, self.disqualified);
        }

        // Allow the arbiter to proceed
        let (missing_dealings, requests) = self.requests();
        (
            Some((
                P2 {
                    threshold: self.threshold,
                    previous: self.previous,
                    concurrency: self.concurrency,
                    dealers: self.dealers,
                    dealers_ordered: self.dealers_ordered,
                    commitments: self.commitments,
                    disqualified: self.disqualified.clone(),
                    acks: self.acks,
                    missing_dealings,
                    resolutions: HashMap::new(),
                },
                requests,
            )),
            self.disqualified,
        )
    }
}

/// Output of the DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    pub public: poly::Public,
    pub commitments: Vec<u32>,
    pub resolutions: HashMap<(u32, u32), Share>,
}

/// Collect missing shares (if any) and recover the public polynomial.
pub struct P2 {
    threshold: u32,
    previous: Option<poly::Public>,
    concurrency: usize,

    dealers: Vec<PublicKey>,
    dealers_ordered: HashMap<PublicKey, u32>,

    commitments: HashMap<PublicKey, poly::Public>,
    disqualified: HashSet<PublicKey>,

    acks: HashMap<u32, HashSet<u32>>,

    missing_dealings: HashMap<u32, HashSet<u32>>,
    resolutions: HashMap<(u32, u32), Share>,
}

impl P2 {
    /// Required number of commitments to continue procedure.
    pub fn required(&self) -> u32 {
        match &self.previous {
            Some(previous) => previous.required(),
            None => self.threshold,
        }
    }

    /// Disqualify a contributor from the DKG for external reason (i.e. sending invalid messages).
    pub fn disqualify(&mut self, contributor: PublicKey) {
        self.disqualified.insert(contributor);
    }

    /// Get the ID of a dealer.
    pub fn dealer(&self, dealer: &PublicKey) -> Option<u32> {
        self.dealers_ordered.get(dealer).cloned()
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

    /// Verify and track a forced resolution from a dealer.
    pub fn reveal(&mut self, dealer: PublicKey, share: Share) -> Result<(), Error> {
        // Check if contributor is disqualified
        if self.disqualified.contains(&dealer) {
            return Err(Error::ContributorDisqualified);
        }

        // Find the index of the contributor
        let idx = match self.dealers_ordered.get(&dealer) {
            Some(idx) => *idx,
            None => return Err(Error::ContirbutorInvalid),
        };

        // Check if commitment is still valid
        if self.disqualified.contains(&dealer) | !self.commitments.contains_key(&dealer) {
            // We don't disqualify the submitter here as this could have happened
            // without their knowledge.
            return Err(Error::CommitmentDisqualified);
        }

        // Verify share
        let commitment = self.commitments.get(&dealer).unwrap();
        if let Err(e) = ops::verify_share(
            self.previous.as_ref(),
            idx,
            commitment,
            self.threshold,
            share.index,
            &share,
        ) {
            // Disqualify the dealer
            self.disqualified.insert(dealer);
            return Err(e);
        }

        // Store that resolution was successful
        let missing = match self.missing_dealings.get_mut(&idx) {
            Some(missing) => missing,
            None => {
                return Err(Error::UnexpectedReveal);
            }
        };
        if missing.remove(&share.index) {
            self.resolutions.insert((idx, share.index), share);
            Ok(())
        } else {
            Err(Error::UnexpectedReveal)
        }
    }

    /// If there exist at least `threshold` resolutions for `required()` dealers, recover
    /// the group public polynomial.
    pub fn finalize(mut self) -> (Result<Output, Error>, HashSet<PublicKey>) {
        // Remove any dealers that did not distribute all required shares (may not be `n`)
        for (dealer, recipients) in &self.missing_dealings {
            if recipients.is_empty() {
                continue;
            }
            self.disqualified
                .insert(self.dealers[*dealer as usize].clone());
        }

        // Remove any disqualified dealers
        for disqualified in self.disqualified.iter() {
            self.commitments.remove(disqualified);
            self.acks
                .remove(self.dealers_ordered.get(disqualified).unwrap());
        }

        // Determine if we have enough resolutions
        let required = self.required();
        if self.acks.len() < required as usize {
            return (Err(Error::InsufficientDealings), self.disqualified);
        }

        // Recover group
        let public = match self.previous {
            Some(previous) => {
                let commitments = self
                    .commitments
                    .iter()
                    .map(|(contributor, commitment)| {
                        let idx = self.dealers_ordered.get(contributor).unwrap();
                        (*idx, commitment.clone())
                    })
                    .collect();
                match ops::recover_public(&previous, commitments, self.threshold, self.concurrency)
                {
                    Ok(public) => public,
                    Err(e) => return (Err(e), self.disqualified),
                }
            }
            None => {
                let commitments = self.commitments.values().cloned().collect();
                match ops::construct_public(commitments, required) {
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
            resolutions: self.resolutions,
        };
        (Ok(output), self.disqualified)
    }
}
