use crate::fixed::wire;

struct Record {
    leader: PublicKey,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    null_vote_retry: Option<SystemTime>,

    // Track one proposal per view
    requested_proposal: bool,
    proposal: Option<(Hash /* proposal */, wire::Proposal)>,
    verified_proposal: bool,
    broadcast_vote: bool,
    broadcast_finalize: bool,

    // Track votes for all proposals (ensuring any participant only has one recorded vote)
    proposal_voters: HashMap<PublicKey, Hash>,
    proposal_votes: HashMap<Hash, HashMap<PublicKey, wire::Vote>>,
    broadcast_proposal_notarization: bool,

    timeout_fired: bool,
    null_votes: HashMap<PublicKey, wire::Vote>,
    broadcast_null_notarization: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<PublicKey, Hash>,
    finalizes: HashMap<Hash, HashMap<PublicKey, wire::Finalize>>,
    broadcast_finalization: bool,
}

impl Record {
    pub fn new(
        leader: PublicKey,
        leader_deadline: Option<SystemTime>,
        advance_deadline: Option<SystemTime>,
    ) -> Self {
        Self {
            leader,
            leader_deadline,
            advance_deadline,
            null_vote_retry: None,

            requested_proposal: false,
            proposal: None,
            verified_proposal: false,
            broadcast_vote: false,
            broadcast_finalize: false,

            proposal_voters: HashMap::new(),
            proposal_votes: HashMap::new(),
            broadcast_proposal_notarization: false,

            timeout_fired: false,
            null_votes: HashMap::new(),
            broadcast_null_notarization: false,

            finalizers: HashMap::new(),
            finalizes: HashMap::new(),
            broadcast_finalization: false,
        }
    }

    fn add_verified_vote(&mut self, skip_invalid: bool, vote: wire::Vote) {
        // Determine whether or not this is a null vote
        let public_key = &vote.signature.as_ref().unwrap().public_key;
        if vote.hash.is_none() {
            // Check if already issued finalize
            if self.finalizers.contains_key(public_key) && !skip_invalid {
                warn!(
                    view = vote.view,
                    signer = hex(public_key),
                    "already voted finalize",
                );
                return;
            }

            // Store the null vote
            self.null_votes.insert(public_key.clone(), vote);
            return;
        }
        let hash = vote.hash.clone().unwrap();

        // Check if already voted
        if !skip_invalid {
            if let Some(previous_vote) = self.proposal_voters.get(public_key) {
                warn!(
                    view = vote.view,
                    signer = hex(public_key),
                    previous_vote = hex(previous_vote),
                    "already voted"
                );
                return;
            }
        }

        // Store the vote
        self.proposal_voters
            .insert(public_key.clone(), hash.clone());
        let entry = self.proposal_votes.entry(hash).or_default();
        entry.insert(public_key.clone(), vote);
    }

    fn notarizable_proposal(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<(Option<Hash>, Height, &HashMap<PublicKey, wire::Vote>)> {
        if !force
            && (self.broadcast_proposal_notarization
                || self.broadcast_null_notarization
                || !self.verified_proposal)
        {
            // We only want to broadcast a notarization if we have verified some proposal at
            // this point.
            return None;
        }
        for (proposal, votes) in self.proposal_votes.iter() {
            if (votes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a notarization for
            let height = match &self.proposal {
                Some((hash, pro)) => {
                    if hash != proposal {
                        debug!(
                            view = pro.view,
                            proposal = hex(proposal),
                            reason = "proposal mismatch",
                            "skipping notarization broadcast"
                        );
                        continue;
                    }
                    debug!(
                        view = pro.view,
                        height = pro.height,
                        proposal = hex(proposal),
                        "broadcasting notarization"
                    );
                    pro.height
                }
                None => {
                    continue;
                }
            };

            // There should never exist enough votes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_proposal_notarization = true;
            return Some((Some(proposal.clone()), height, votes));
        }
        None
    }

    fn notarizable_null(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<(Option<Hash>, Height, &HashMap<PublicKey, wire::Vote>)> {
        if !force && (self.broadcast_null_notarization || self.broadcast_proposal_notarization) {
            return None;
        }
        if (self.null_votes.len() as u32) < threshold {
            return None;
        }
        self.broadcast_null_notarization = true;
        Some((None, 0, &self.null_votes))
    }

    fn add_verified_finalize(&mut self, skip_invalid: bool, finalize: wire::Finalize) {
        // Check if also issued null vote
        let public_key = &finalize.signature.as_ref().unwrap().public_key;
        if self.null_votes.contains_key(public_key) && !skip_invalid {
            warn!(
                view = finalize.view,
                signer = hex(public_key),
                "already voted null",
            );
            return;
        }

        // Check if already finalized
        if !skip_invalid {
            if let Some(previous_finalize) = self.finalizers.get(public_key) {
                warn!(
                    view = finalize.view,
                    signer = hex(public_key),
                    previous_finalize = hex(previous_finalize),
                    "already voted finalize"
                );
                return;
            }
        }

        // Store the finalize
        self.finalizers
            .insert(public_key.clone(), finalize.hash.clone());
        let entry = self.finalizes.entry(finalize.hash.clone()).or_default();
        entry.insert(public_key.clone(), finalize);
    }

    fn finalizable_proposal(
        &mut self,
        threshold: u32,
    ) -> Option<(Hash, Height, &HashMap<PublicKey, wire::Finalize>)> {
        if self.broadcast_finalization || !self.verified_proposal {
            // We only want to broadcast a finalization if we have verified some proposal at
            // this point.
            return None;
        }
        for (proposal, finalizes) in self.finalizes.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have the proposal we are going to broadcast a finalization for
            let height = match &self.proposal {
                Some((hash, pro)) => {
                    if hash != proposal {
                        debug!(
                            proposal = hex(proposal),
                            hash = hex(hash),
                            reason = "proposal mismatch",
                            "skipping finalization broadcast"
                        );
                        continue;
                    }
                    pro.height
                }
                None => {
                    continue;
                }
            };

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            self.broadcast_finalization = true;
            return Some((proposal.clone(), height, finalizes));
        }
        None
    }
}
