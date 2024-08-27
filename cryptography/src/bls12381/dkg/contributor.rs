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
use std::collections::{BTreeMap, HashMap, HashSet};

/// Output of a DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output {
    pub public: poly::Public,
    pub commitments: Vec<poly::Public>,
    pub share: Share,
}

/// Generate shares and a commitment (optional).
pub struct P0 {
    me: PublicKey,
    threshold: u32,
    previous: Option<(poly::Public, Share)>,
    concurrency: usize,

    dealers_ordered: HashMap<PublicKey, u32>,
    recipients: Vec<PublicKey>,
    recipients_ordered: HashMap<PublicKey, u32>,
}

impl P0 {
    /// Create a new dealer for a DKG/Resharing procedure (optional).
    ///
    /// If `me` is not in `dealers`, this will panic.
    pub fn new(
        me: PublicKey,
        threshold: u32,
        previous: Option<(poly::Public, Share)>,
        mut dealers: Vec<PublicKey>,
        mut recipients: Vec<PublicKey>,
        concurrency: usize,
    ) -> Self {
        dealers.sort();
        let dealers_ordered = dealers
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect::<HashMap<_, _>>();
        if !dealers_ordered.contains_key(&me) {
            panic!("me must be in dealers");
        }
        recipients.sort();
        let recipients_ordered = recipients
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();
        Self {
            me,
            threshold,
            previous,
            concurrency,
            dealers_ordered,
            recipients,
            recipients_ordered,
        }
    }

    /// Construct commitment, shares, and optionally `P1` (if the dealer
    /// is also a recipient).
    pub fn finalize(self) -> (Option<P1>, poly::Public, Vec<Share>) {
        // Generate shares and commitment
        let (public, share) = match self.previous {
            Some((public, share)) => (Some(public), Some(share)),
            None => (None, None),
        };
        let (commitment, shares) =
            ops::generate_shares(share, self.recipients.len() as u32, self.threshold);

        // Proceed to next phase
        let p1 = if self.recipients_ordered.contains_key(&self.me) {
            // We manually construct P1 to avoid resorting the dealers/recipients
            Some(P1 {
                me: self.me,
                threshold: self.threshold,
                previous: public,
                concurrency: self.concurrency,
                dealers_ordered: self.dealers_ordered,
                recipients_ordered: self.recipients_ordered,
                commitments: HashMap::new(),
                valid: BTreeMap::new(),
            })
        } else {
            None
        };
        (p1, commitment, shares)
    }
}

/// Track commitments distributed by dealers.
pub struct P1 {
    me: PublicKey,
    threshold: u32,
    previous: Option<poly::Public>,
    concurrency: usize,

    dealers_ordered: HashMap<PublicKey, u32>,
    recipients_ordered: HashMap<PublicKey, u32>,

    commitments: HashMap<PublicKey, poly::Public>,

    valid: BTreeMap<u32, (poly::Public, Share)>,
}

impl P1 {
    /// Create a new contributor for a DKG/Resharing procedure.
    pub fn new(
        me: PublicKey,
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
        Self {
            me,
            threshold,
            previous,
            concurrency,
            dealers_ordered,
            recipients_ordered,
            commitments: HashMap::new(),
            valid: BTreeMap::new(),
        }
    }

    /// Required number of commitments to continue procedure.
    pub fn required(&self) -> u32 {
        match &self.previous {
            Some(previous) => previous.required(),
            None => self.threshold,
        }
    }

    /// Verify and track a commitment from a dealer.
    pub fn commitment(&mut self, dealer: PublicKey, commitment: poly::Public) -> Result<(), Error> {
        // Ensure contributor is valid
        let idx = match self.dealers_ordered.get(&dealer) {
            Some(contributor) => *contributor,
            None => return Err(Error::DealerInvalid),
        };

        // Verify that commitment is valid
        ops::verify_commitment(self.previous.as_ref(), idx, &commitment, self.threshold)?;

        // Store commitment
        self.commitments.insert(dealer, commitment);
        Ok(())
    }

    /// Return whether a commitment has been received from a dealer.
    pub fn has(&self, dealer: PublicKey) -> bool {
        self.commitments.contains_key(&dealer)
    }

    /// Return the count of tracked commitments.
    pub fn count(&self) -> usize {
        self.commitments.len()
    }

    /// If there exist at least `required()` commitments, proceed to `P2`.
    pub fn finalize(self) -> Option<P2> {
        // Ensure there are enough commitments to proceed
        if self.commitments.len() < self.required() as usize {
            return None;
        }

        // Proceed to next phase
        Some(P2 {
            me: self.me,
            threshold: self.threshold,
            previous: self.previous,
            concurrency: self.concurrency,
            dealers_ordered: self.dealers_ordered,
            recipients_ordered: self.recipients_ordered,
            commitments: self.commitments,
            valid: self.valid,
        })
    }
}

/// Track shares distributed by dealers.
pub struct P2 {
    me: PublicKey,
    threshold: u32,
    previous: Option<poly::Public>,
    concurrency: usize,

    dealers_ordered: HashMap<PublicKey, u32>,
    recipients_ordered: HashMap<PublicKey, u32>,

    commitments: HashMap<PublicKey, poly::Public>,

    valid: BTreeMap<u32, (poly::Public, Share)>,
}

impl P2 {
    /// Required number of commitments to continue procedure.
    pub fn required(&self) -> u32 {
        match &self.previous {
            Some(previous) => previous.required(),
            None => self.threshold,
        }
    }

    /// Verify and track a share from a dealer.
    pub fn share(&mut self, dealer: PublicKey, share: Share) -> Result<(), Error> {
        // Ensure contributor is valid
        let idx = match self.dealers_ordered.get(&dealer) {
            Some(contributor) => *contributor,
            None => return Err(Error::DealerInvalid),
        };

        // Ensure share is for us
        if share.index != self.recipients_ordered[&self.me] {
            return Err(Error::MisdirectedShare);
        }

        // Verify that share is valid
        let commitment = match self.commitments.get(&dealer) {
            Some(commitment) => commitment.clone(),
            None => return Err(Error::MissingCommitment),
        };
        ops::verify_share(
            self.previous.as_ref(),
            idx,
            &commitment,
            self.threshold,
            share.index,
            &share,
        )?;

        // Store share for later use
        //
        // If we receive multiple shares from the same dealer, we will
        // only keep the last.
        self.valid.insert(idx, (commitment, share));
        Ok(())
    }

    /// If we are tracking shares for all provided `commitments`, recover
    /// the new group public polynomial and our share.
    pub fn finalize(mut self, commitments: Vec<u32>) -> Result<Output, Error> {
        // Ensure we have all required shares
        for dealer in &commitments {
            if !self.valid.contains_key(dealer) {
                return Err(Error::MissingShare);
            }
        }

        // Remove all valid not in commitments
        let commitments: HashSet<_> = commitments.into_iter().collect();
        for dealer in self.valid.keys().cloned().collect::<Vec<_>>() {
            if !commitments.contains(&dealer) {
                self.valid.remove(&dealer);
            }
        }

        // Ensure we have enough shares to construct a secret
        let required = self.required();
        let shares = self.valid.len();
        if shares < required as usize {
            return Err(Error::InsufficientDealings);
        }

        // Construct secret
        let mut public = poly::Public::zero();
        let mut t_commitments = Vec::new();
        let mut secret = group::Private::zero();
        match self.previous {
            None => {
                // Add all valid commitments/shares
                for share in self.valid.values() {
                    public.add(&share.0);
                    t_commitments.push(share.0.clone());
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
                    .valid
                    .iter()
                    .take(required as usize)
                    .map(|(dealer, (commitment, _))| (*dealer, commitment.clone()))
                    .collect();
                t_commitments = commitments.values().cloned().collect();
                public =
                    ops::recover_public(&previous, commitments, self.threshold, self.concurrency)?;

                // Recover share via interpolation
                let shares = self
                    .valid
                    .into_iter()
                    .take(required as usize)
                    .map(|(dealer, (_, share))| Eval {
                        index: dealer,
                        value: share.private,
                    })
                    .collect::<Vec<_>>();
                secret = match poly::Private::recover(required, shares) {
                    Ok(share) => share,
                    Err(_) => return Err(Error::ShareInterpolationFailed),
                };
            }
        }

        // Return the public polynomial and share
        Ok(Output {
            public,
            commitments: t_commitments,
            share: Share {
                index: self.recipients_ordered[&self.me],
                private: secret,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed25519::insecure_signer, Scheme};
    use std::collections::HashMap;

    fn create_and_verify_shares(n: u32, t: u32, dealers: u32, concurrency: usize) {
        // Create contributors
        let mut contributors = (0..n)
            .map(|i| insecure_signer(i as u16).me())
            .collect::<Vec<_>>();
        contributors.sort();

        // Create shares
        let mut contributor_shares = HashMap::new();
        let mut commitments = Vec::new();
        for i in 0..n {
            let me = contributors[i as usize].clone();
            let contributor = P0::new(
                me,
                t,
                None,
                contributors.clone(),
                contributors.clone(),
                concurrency,
            );
            let (contributor, public, shares) = contributor.finalize();
            contributor_shares.insert(i, (public.clone(), shares, contributor.unwrap()));
            commitments.push(public);
        }

        // Distribute commitments
        for i in 0..dealers {
            let dealer = contributors[i as usize].clone();
            for j in 0..n {
                // Get recipient share
                let (commitment, _, _) = contributor_shares.get(&i).unwrap();
                let commitment = commitment.clone();

                // Send share to recipient
                let (_, _, ref mut recipient) = contributor_shares.get_mut(&j).unwrap();
                recipient.commitment(dealer.clone(), commitment).unwrap();
            }
        }

        // Convert to p2
        let mut p2 = HashMap::new();
        for i in 0..n {
            let (_, shares, contributor) = contributor_shares.remove(&i).unwrap();
            let contributor = contributor.finalize().unwrap();
            p2.insert(i, (shares, contributor));
        }
        let mut contributor_shares = p2;

        // Distribute shares
        for i in 0..dealers {
            let dealer = contributors[i as usize].clone();
            for j in 0..n {
                // Get recipient share
                let (shares, _) = contributor_shares.get(&i).unwrap();
                let share = shares[j as usize];

                // Send share to recipient
                let (_, recipient) = contributor_shares.get_mut(&j).unwrap();
                recipient.share(dealer.clone(), share).unwrap();
            }
        }

        // Finalize
        let included_commitments = (0..dealers).collect::<Vec<_>>();
        let commitments = commitments[0..dealers as usize].to_vec();
        let mut group: Option<poly::Public> = None;
        for i in 0..n {
            let (_, contributor) = contributor_shares.remove(&i).unwrap();
            let output = contributor
                .finalize(included_commitments.clone())
                .expect("unable to finalize");
            assert_eq!(output.commitments, commitments);
            match &group {
                Some(group) => {
                    assert_eq!(output.public, *group);
                }
                None => {
                    group = Some(output.public);
                }
            }
        }
    }

    #[test]
    fn test_simple_dkg() {
        create_and_verify_shares(5, 3, 5, 4);
    }

    #[test]
    fn test_large_dkg() {
        create_and_verify_shares(100, 67, 80, 4);
    }
}
