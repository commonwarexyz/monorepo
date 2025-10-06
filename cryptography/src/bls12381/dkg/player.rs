//! Participants in a DKG/Resharing procedure that receive dealings from dealers
//! and eventually maintain a share of a shared secret.

use crate::{
    bls12381::{
        dkg::{
            ops::{recover_public_with_weights, Commitment},
            Error,
        },
        primitives::{
            group::{self, Element, Share},
            poly::{self, Eval},
            variant::Variant,
        },
    },
    PublicKey,
};
use commonware_utils::quorum;
use std::collections::{BTreeMap, HashMap};

/// Output of a DKG/Resharing procedure.
#[derive(Clone)]
pub struct Output<V: Variant> {
    /// The group polynomial output by the DKG/Resharing procedure.
    pub public: poly::Public<V>,

    /// The player's share of the shared secret that corresponds to
    /// the group polynomial. Any `2f + 1` players can combine their
    /// shares to recover the shared secret.
    pub share: Share,
}

/// Track commitments and dealings distributed by dealers.
pub struct Player<P: PublicKey, V: Variant> {
    me: u32,
    dealer_threshold: u32,
    player_threshold: u32,
    previous: Option<poly::Public<V>>,
    concurrency: usize,

    dealers: HashMap<P, u32>,

    dealings: HashMap<u32, (Commitment<V>, Share)>,
}

impl<P: PublicKey, V: Variant> Player<P, V> {
    /// Create a new player for a DKG/Resharing procedure.
    pub fn new(
        me: P,
        previous: Option<poly::Public<V>>,
        mut dealers: Vec<P>,
        mut recipients: Vec<P>,
        concurrency: usize,
    ) -> Self {
        dealers.sort();
        let dealers = dealers
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect::<HashMap<P, _>>();
        recipients.sort();
        let mut me_idx = None;
        for (idx, recipient) in recipients.iter().enumerate() {
            if recipient == &me {
                me_idx = Some(idx);
                break;
            }
        }
        Self {
            me: me_idx.expect("player not in recipients") as u32,
            dealer_threshold: quorum(dealers.len() as u32),
            player_threshold: quorum(recipients.len() as u32),
            previous,
            concurrency,

            dealers,

            dealings: HashMap::new(),
        }
    }

    /// Verify and track a commitment from a dealer.
    pub fn share(
        &mut self,
        dealer: P,
        commitment: poly::Public<V>,
        share: Share,
    ) -> Result<(), Error> {
        // Ensure dealer is valid
        let dealer_idx = match self.dealers.get(&dealer) {
            Some(contributor) => *contributor,
            None => return Err(Error::DealerInvalid),
        };

        // Check that share is valid
        if share.index != self.me {
            return Err(Error::MisdirectedShare);
        }

        // If already have commitment from dealer, check if matches
        if let Some((existing_commitment, existing_share)) = self.dealings.get(&dealer_idx) {
            if existing_commitment.as_ref() != &commitment {
                return Err(Error::MismatchedCommitment);
            }
            if existing_share != &share {
                return Err(Error::MismatchedShare);
            }
            return Err(Error::DuplicateShare);
        }

        // Verify that commitment is valid
        let commitment = Commitment::<V>::new(
            self.previous.as_ref(),
            commitment,
            dealer_idx,
            self.player_threshold,
        )?;

        // Verify that share is valid
        commitment.verify_share(share.index, &share)?;

        // Store dealings
        self.dealings.insert(dealer_idx, (commitment, share));
        Ok(())
    }

    /// If we are tracking shares for all provided `commitments`, recover
    /// the new group public polynomial and our share.
    pub fn finalize(
        mut self,
        commitments: BTreeMap<u32, poly::Public<V>>,
        reveals: BTreeMap<u32, Share>,
    ) -> Result<Output<V>, Error> {
        // Ensure commitments equals required commitment count
        let dealer_threshold = self.dealer_threshold as usize;
        if commitments.len() != dealer_threshold {
            return Err(Error::InvalidCommitments);
        }

        // Iterate over selected commitments and confirm they match what we've acknowledged
        // or that we have received a reveal.
        let mut selected = BTreeMap::new();
        for (idx, commitment) in commitments {
            match self.dealings.remove(&idx) {
                Some((existing, share)) => {
                    // If our stored commitment matches the one we are receiving,
                    // we do nothing (as our share is valid).
                    if existing.as_ref() == &commitment {
                        selected.insert(idx, (existing, share));
                        continue;
                    }

                    // If our stored commitment does not match the one we are receiving,
                    // we must have received a reveal for this commitment (this is dealer
                    // equivocation).
                    let commitment = Commitment::<V>::new(
                        self.previous.as_ref(),
                        commitment.clone(),
                        idx,
                        self.player_threshold,
                    )?;
                    let share = reveals.get(&idx).ok_or(Error::MissingShare)?.clone();

                    // Check that share is valid
                    commitment.verify_share(self.me, &share)?;

                    // Store dealing
                    selected.insert(idx, (commitment, share));
                }
                None => {
                    // We must have received a reveal for this commitment.
                    let commitment = Commitment::<V>::new(
                        self.previous.as_ref(),
                        commitment.clone(),
                        idx,
                        self.player_threshold,
                    )?;
                    let share = reveals.get(&idx).ok_or(Error::MissingShare)?.clone();

                    // Check that share is valid
                    commitment.verify_share(self.me, &share)?;

                    // Store dealing
                    selected.insert(idx, (commitment, share));
                }
            }
        }
        if selected.len() != dealer_threshold {
            return Err(Error::MissingShare);
        }

        // Construct secret
        let mut public = poly::Public::<V>::zero();
        let mut secret = group::Private::zero();
        match self.previous {
            None => {
                // Add all valid commitments/dealings
                for (commitment, private) in selected.values() {
                    public.add(commitment.as_ref());
                    secret.add(private.as_ref());
                }
            }
            Some(previous) => {
                // Compute weights
                let indices = selected.keys().copied().collect::<Vec<_>>();
                let weights = poly::compute_weights(indices)
                    .map_err(|_| Error::PublicKeyInterpolationFailed)?;

                // Recover public via interpolation
                //
                // While it is tempting to remove this work (given we only need the secret
                // to generate a threshold signature), this polynomial is required to verify
                // dealings of future resharings.
                let commitments: BTreeMap<u32, Commitment<V>> = self
                    .dealings
                    .iter()
                    .map(|(dealer, (commitment, _))| (*dealer, commitment.clone()))
                    .collect();
                public = recover_public_with_weights::<V>(
                    &previous,
                    commitments,
                    &weights,
                    self.player_threshold,
                    self.concurrency,
                )?;

                // Recover share via interpolation
                let dealings = self
                    .dealings
                    .into_iter()
                    .map(|(dealer, (_, share))| Eval {
                        index: dealer,
                        value: share.private,
                    })
                    .collect::<Vec<_>>();
                secret = match poly::Private::recover_with_weights(&weights, &dealings) {
                    Ok(share) => share,
                    Err(_) => return Err(Error::ShareInterpolationFailed),
                };
            }
        }

        // Return the public polynomial and share
        Ok(Output {
            public,
            share: Share {
                index: self.me,
                private: secret,
            },
        })
    }
}
