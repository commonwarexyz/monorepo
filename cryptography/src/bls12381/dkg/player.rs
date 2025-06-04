//! Participants in a DKG/Resharing procedure that receive dealings from dealers
//! and eventually maintain a share of a shared secret.

use crate::{
    bls12381::{
        dkg::{ops, Error},
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

    dealings: HashMap<u32, (poly::Public<V>, Share)>,
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
            if existing_commitment != &commitment {
                return Err(Error::MismatchedCommitment);
            }
            if existing_share != &share {
                return Err(Error::MismatchedShare);
            }
            return Err(Error::DuplicateShare);
        }

        // Verify that commitment is valid
        ops::verify_commitment::<V>(
            self.previous.as_ref(),
            dealer_idx,
            &commitment,
            self.player_threshold,
        )?;

        // Verify that share is valid
        ops::verify_share::<V>(
            self.previous.as_ref(),
            dealer_idx,
            &commitment,
            self.player_threshold,
            share.index,
            &share,
        )?;

        // Store dealings
        self.dealings.insert(dealer_idx, (commitment, share));
        Ok(())
    }

    /// If we are tracking shares for all provided `commitments`, recover
    /// the new group public polynomial and our share.
    pub fn finalize(
        mut self,
        commitments: HashMap<u32, poly::Public<V>>,
        reveals: HashMap<u32, Share>,
    ) -> Result<Output<V>, Error> {
        // Ensure commitments equals required commitment count
        let dealer_threshold = self.dealer_threshold as usize;
        if commitments.len() != dealer_threshold {
            return Err(Error::InvalidCommitments);
        }

        // Store reveals
        for (idx, share) in reveals {
            // Verify that commitment is valid
            let commitment = commitments.get(&idx).ok_or(Error::MissingCommitment)?;
            ops::verify_commitment::<V>(
                self.previous.as_ref(),
                idx,
                commitment,
                self.player_threshold,
            )?;

            // Check that share is valid
            if share.index != self.me {
                return Err(Error::MisdirectedShare);
            }
            ops::verify_share::<V>(
                self.previous.as_ref(),
                idx,
                commitment,
                self.player_threshold,
                share.index,
                &share,
            )?;

            // Store dealing
            self.dealings.insert(idx, (commitment.clone(), share));
        }

        // Remove all dealings not in commitments
        self.dealings
            .retain(|dealer, _| commitments.contains_key(dealer));
        if self.dealings.len() != dealer_threshold {
            return Err(Error::MissingShare);
        }
        assert_eq!(self.dealings.len(), commitments.len());

        // Construct secret
        let mut public = poly::Public::<V>::zero();
        let mut secret = group::Private::zero();
        match self.previous {
            None => {
                // Add all valid commitments/dealings
                for dealing in self.dealings.values() {
                    public.add(&dealing.0);
                    secret.add(&dealing.1.private);
                }
            }
            Some(previous) => {
                // Compute weights
                let indices = commitments.keys().copied().collect::<Vec<_>>();
                let weights = poly::compute_weights(indices)
                    .map_err(|_| Error::PublicKeyInterpolationFailed)?;

                // Recover public via interpolation
                //
                // While it is tempting to remove this work (given we only need the secret
                // to generate a threshold signature), this polynomial is required to verify
                // dealings of future resharings.
                let commitments: BTreeMap<u32, poly::Public<V>> = self
                    .dealings
                    .iter()
                    .map(|(dealer, (commitment, _))| (*dealer, commitment.clone()))
                    .collect();
                public = ops::recover_public_with_weights::<V>(
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
