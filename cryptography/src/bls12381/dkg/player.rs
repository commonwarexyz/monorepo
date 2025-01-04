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
    primitives::{
        group::{self, Element, Share},
        poly::{self, Eval},
    },
};
use crate::PublicKey;
use commonware_utils::quorum;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Output of a DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    pub public: poly::Public,
    pub share: Share,
}

/// Track commitments and shares distributed by dealers.
pub struct P0 {
    me: PublicKey,
    threshold: u32,
    previous: Option<poly::Public>,
    concurrency: usize,

    dealers_ordered: HashMap<PublicKey, u32>,
    recipients_ordered: HashMap<PublicKey, u32>,

    shares: HashMap<u32, (poly::Public, Share)>,
}

impl P0 {
    /// Create a new player for a DKG/Resharing procedure.
    pub fn new(
        me: PublicKey,
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
            me,
            threshold: quorum(recipients.len() as u32).expect("insufficient participants"),
            previous,
            concurrency,

            dealers_ordered,
            recipients_ordered,

            shares: HashMap::new(),
        }
    }

    /// Verify and track a commitment from a dealer.
    pub fn share(
        &mut self,
        dealer: PublicKey,
        commitment: poly::Public,
        share: Share,
    ) -> Result<(), Error> {
        // Ensure dealer is valid
        let idx = match self.dealers_ordered.get(&dealer) {
            Some(contributor) => *contributor,
            None => return Err(Error::DealerInvalid),
        };

        // Check that share is valid
        if share.index != self.recipients_ordered[&self.me] {
            return Err(Error::MisdirectedShare);
        }

        // If already have commitment from dealer, check if matches
        if let Some((existing_commitment, existing_share)) = self.shares.get(&idx) {
            if existing_commitment != &commitment {
                return Err(Error::MismatchedCommitment);
            }
            if existing_share != &share {
                return Err(Error::MismatchedShare);
            }
            return Err(Error::DuplicateShare);
        }

        // Verify that commitment is valid
        ops::verify_commitment(self.previous.as_ref(), idx, &commitment, self.threshold)?;

        // Verify that share is valid
        ops::verify_share(
            self.previous.as_ref(),
            idx,
            &commitment,
            self.threshold,
            share.index,
            &share,
        )?;

        // Store share
        self.shares.insert(idx, (commitment, share));
        Ok(())
    }

    /// Return whether a commitment has been received from a dealer.
    pub fn has(&self, dealer: PublicKey) -> bool {
        let Some(dealer) = self.dealers_ordered.get(&dealer) else {
            return false;
        };
        self.shares.contains_key(dealer)
    }

    /// Return the count of tracked commitments.
    pub fn count(&self) -> usize {
        self.shares.len()
    }

    /// If we are tracking shares for all provided `commitments`, recover
    /// the new group public polynomial and our share.
    pub fn finalize(
        mut self,
        commitments: Vec<u32>,
        reveals: HashMap<u32, (poly::Public, Share)>,
    ) -> Result<Output, Error> {
        // Ensure commitments equals required commitment count
        if commitments.len() != self.threshold as usize {
            return Err(Error::TooManyCommitments);
        }

        // Store reveals
        for (idx, (commitment, share)) in reveals {
            // Verify that commitment is valid
            ops::verify_commitment(self.previous.as_ref(), idx, &commitment, self.threshold)?;

            // Check that share is valid
            if share.index != self.recipients_ordered[&self.me] {
                return Err(Error::MisdirectedShare);
            }
            ops::verify_share(
                self.previous.as_ref(),
                idx,
                &commitment,
                self.threshold,
                share.index,
                &share,
            )?;

            // Store commitment
            // TODO: log if commitment already exists (then never got ack'd somehow)
            self.shares.insert(idx, (commitment, share));
        }

        // Ensure we have all required shares
        for dealer in &commitments {
            if !self.shares.contains_key(dealer) {
                return Err(Error::MissingShare);
            }
        }

        // Remove all valid not in commitments
        let commitments: HashSet<_> = commitments.into_iter().collect();
        self.shares.retain(|dealer, _| commitments.contains(dealer));

        // Construct secret
        let mut public = poly::Public::zero();
        let mut secret = group::Private::zero();
        match self.previous {
            None => {
                // Add all valid commitments/shares
                for share in self.shares.values() {
                    public.add(&share.0);
                    secret.add(&share.1.private);
                }
            }
            Some(previous) => {
                // Recover public via interpolation
                //
                // While it is tempting to remove this work (given we only need the secret
                // to generate a threshold signature), this polynomial is required to verify
                // dealings of future resharings.
                let commitments: BTreeMap<u32, poly::Public> = self
                    .shares
                    .iter()
                    .map(|(dealer, (commitment, _))| (*dealer, commitment.clone()))
                    .collect();
                public =
                    ops::recover_public(&previous, commitments, self.threshold, self.concurrency)?;

                // Recover share via interpolation
                let shares = self
                    .shares
                    .into_iter()
                    .map(|(dealer, (_, share))| Eval {
                        index: dealer,
                        value: share.private,
                    })
                    .collect::<Vec<_>>();
                secret = match poly::Private::recover(self.threshold, shares) {
                    Ok(share) => share,
                    Err(_) => return Err(Error::ShareInterpolationFailed),
                };
            }
        }

        // Return the public polynomial and share
        Ok(Output {
            public,
            share: Share {
                index: self.recipients_ordered[&self.me],
                private: secret,
            },
        })
    }
}
