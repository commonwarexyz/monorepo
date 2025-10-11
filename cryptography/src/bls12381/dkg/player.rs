//! Participants in a DKG/Resharing procedure that receive dealings from dealers
//! and eventually maintain a share of a shared secret.

use crate::{
    bls12381::{
        dkg::{
            arbiter,
            ops::{self, verify_commitment, verify_share},
            Error,
        },
        primitives::{
            group::{self, Element, Scalar, Share},
            poly::{self, Eval, Weight},
            variant::Variant,
        },
    },
    PublicKey,
};
use commonware_utils::{quorum, set::Ordered};
use std::collections::{btree_map::Entry, BTreeMap};

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

/// Collector of inputs for [`Player::finalize`]
#[derive(Clone)]
pub struct FinalizeInput<V: Variant> {
    // The commitments for each dealer
    pub commitments: BTreeMap<u32, poly::Public<V>>,
    /// The player's revealed share for each dealer
    pub reveals: BTreeMap<u32, Share>,
    /// Optional: The group polynomial output by the DKG/Resharing procedure
    pub group_poly: Option<poly::Public<V>>,
    /// Optional: Barycentric Weights for Lagrange interpolation
    pub weights: Option<BTreeMap<u32, Weight>>,
}

impl<V: Variant> FinalizeInput<V> {
    pub fn new(commitments: BTreeMap<u32, poly::Public<V>>, reveals: BTreeMap<u32, Share>) -> Self {
        Self {
            commitments,
            reveals,
            group_poly: None,
            weights: None,
        }
    }
    pub fn from_arbiter_output(value: arbiter::Output<V>, player_idx: u32) -> Self {
        let reveals = value
            .reveals
            .into_iter()
            .filter_map(|(k, vec)| {
                // Find the first Share whose index matches `idx`
                vec.into_iter()
                    .find(|share| share.index == player_idx)
                    .map(|share| (k, share))
            })
            .collect();
        Self {
            commitments: value.commitments,
            reveals,
            group_poly: Some(value.public),
            weights: value.weights,
        }
    }
}

/// Track commitments and dealings distributed by dealers.
pub struct Player<P: PublicKey, V: Variant> {
    me: u32,
    dealer_threshold: u32,
    player_threshold: u32,
    previous: Option<poly::Public<V>>,
    concurrency: usize,

    dealers: Ordered<P>,

    dealings: BTreeMap<u32, (poly::Public<V>, Share)>,
}

impl<P: PublicKey, V: Variant> Player<P, V> {
    /// Create a new player for a DKG/Resharing procedure.
    pub fn new(
        me: P,
        previous: Option<poly::Public<V>>,
        dealers: Ordered<P>,
        recipients: Ordered<P>,
        concurrency: usize,
    ) -> Self {
        let me_idx = recipients.position(&me).expect("player not in recipients") as u32;
        Self {
            me: me_idx,
            dealer_threshold: quorum(dealers.len() as u32),
            player_threshold: quorum(recipients.len() as u32),
            previous,
            concurrency,

            dealers,

            dealings: BTreeMap::new(),
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
        let dealer_idx = match self.dealers.position(&dealer) {
            Some(contributor) => contributor,
            None => return Err(Error::DealerInvalid),
        } as u32;

        // Check that share is valid
        if share.index != self.me {
            return Err(Error::MisdirectedShare);
        }

        // If already have commitment from dealer, check if matches
        if let Some((existing_commitment, existing_share)) = self.dealings.get(&dealer_idx) {
            if existing_commitment != &commitment {
                return Err(Error::MismatchedCommitment);
            }
            if existing_share != &share {
                return Err(Error::MismatchedShare);
            }
            return Err(Error::DuplicateShare);
        }

        // Verify that commitment is valid
        verify_commitment::<V>(
            self.previous.as_ref(),
            &commitment,
            dealer_idx,
            self.player_threshold,
        )?;

        // Verify that share is valid
        verify_share::<V>(&commitment, share.index, &share)?;

        // Store dealings
        self.dealings.insert(dealer_idx, (commitment, share));
        Ok(())
    }

    /// If we are tracking shares for all provided `commitments`, recover
    /// the new group public polynomial and our share.
    pub fn finalize(mut self, input: FinalizeInput<V>) -> Result<Output<V>, Error> {
        let commitments = input.commitments;
        let reveals = input.reveals;

        // Ensure commitments equals required commitment count
        let dealer_threshold = self.dealer_threshold as usize;
        if commitments.len() != dealer_threshold {
            return Err(Error::InvalidCommitments);
        }
        // Remove all dealings not in commitments
        self.dealings
            .retain(|dealer, _| commitments.contains_key(dealer));

        self.verify_commitments_and_reveals(reveals, commitments)?;

        if self.dealings.len() != dealer_threshold {
            return Err(Error::MissingShare);
        }

        // Construct secret
        let (public, secret) = match self.previous.take() {
            None => self.compute_share(input.group_poly),
            Some(previous) => self.recompute_share(previous, input.group_poly, input.weights)?,
        };

        // Return the public polynomial and share
        Ok(Output {
            public,
            share: Share {
                index: self.me,
                private: secret,
            },
        })
    }

    fn verify_commitments_and_reveals(
        &mut self,
        mut reveals: BTreeMap<u32, Share>,
        commitments: BTreeMap<u32, poly::Public<V>>,
    ) -> Result<(), Error> {
        // Iterate over selected commitments and confirm they match what we've acknowledged
        // or that we have received a reveal.
        for (idx, commitment) in commitments {
            match self.dealings.entry(idx) {
                Entry::Occupied(mut entry) => {
                    // If our stored commitment matches the one we are receiving,
                    // we do nothing (as our share is valid).
                    let (stored_commitment, stored_share) = entry.get_mut();
                    if stored_commitment == &commitment {
                        continue;
                    }

                    // If our stored commitment does not match the one we are receiving,
                    // we must have received a reveal for this commitment (this is dealer
                    // equivocation).
                    verify_commitment::<V>(
                        self.previous.as_ref(),
                        &commitment,
                        idx,
                        self.player_threshold,
                    )?;
                    let share = reveals.remove(&idx).ok_or(Error::MissingShare)?;

                    // Check that reveal is valid (updating stored commitment and share, if so)
                    verify_share::<V>(&commitment, self.me, &share)?;
                    *stored_commitment = commitment;
                    *stored_share = share;
                }
                Entry::Vacant(entry) => {
                    // We must have received a reveal for this commitment
                    verify_commitment::<V>(
                        self.previous.as_ref(),
                        &commitment,
                        idx,
                        self.player_threshold,
                    )?;
                    let share = reveals.remove(&idx).ok_or(Error::MissingShare)?;

                    // Check that reveal is valid
                    verify_share::<V>(&commitment, self.me, &share)?;
                    entry.insert((commitment, share));
                }
            }
        }
        Ok(())
    }

    fn compute_share(
        &self,
        group_poly: Option<poly::Public<V>>,
    ) -> (poly::Poly<<V as Variant>::Public>, Scalar) {
        // Add all valid commitments/dealings
        let mut secret = group::Private::zero();
        let compute_public = group_poly.is_none();
        let mut public_sum = group_poly.unwrap_or_else(poly::Public::<V>::zero);
        for (commitment, private) in self.dealings.values() {
            if compute_public {
                public_sum.add(commitment);
            }
            secret.add(private.as_ref());
        }
        (public_sum, secret)
    }

    fn recompute_share(
        &mut self,
        previous: poly::Public<V>,
        group_poly: Option<poly::Public<V>>,
        weights: Option<BTreeMap<u32, Weight>>,
    ) -> Result<(poly::Poly<<V as Variant>::Public>, Scalar), Error> {
        // Construct commitments and shares
        let mut indices = Vec::with_capacity(self.dealings.len());
        let mut commitments = BTreeMap::new();
        let mut dealings = Vec::with_capacity(self.dealings.len());
        while let Some((dealer, (commitment, share))) = self.dealings.pop_first() {
            indices.push(dealer);
            commitments.insert(dealer, commitment);
            dealings.push(Eval {
                index: dealer,
                value: share.private,
            });
        }

        // Compute weights
        let weights = match weights {
            Some(w) => w,
            None => {
                let indices = commitments.keys().copied().collect::<Vec<_>>();
                poly::compute_weights(indices).map_err(|_| Error::PublicKeyInterpolationFailed)?
            }
        };

        // Recover public via interpolation
        //
        // While it is tempting to remove this work (given we only need the secret
        // to generate a threshold signature), this polynomial is required to verify
        // dealings of future resharings.
        let public = match group_poly {
            Some(p) => p,
            None => ops::recover_public_with_weights::<V>(
                &previous,
                &commitments,
                &weights,
                self.player_threshold,
                self.concurrency,
            )?,
        };

        // Recover share via interpolation
        let secret = match poly::Private::recover_with_weights(&weights, &dealings) {
            Ok(share) => share,
            Err(_) => return Err(Error::ShareInterpolationFailed),
        };
        Ok((public, secret))
    }
}
