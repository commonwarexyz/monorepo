module replica {
    import types.* from "./types"
    import defs.* from "./defs"
    import option.* from "./option"

    // Total number of replicas.
    const N: int
    // Maximum number of byzantine(faulty) replicas.
    const F: int
    // Identities with local replica state and correct-style transitions.
    // This is CORRECT together with TWINS: a twin runs the honest code, but shares its
    // signing key with its sibling, so the pair models one faulty logical replica.
    const REPLICA_IDS: Set[ReplicaId]
    // Identities of the honest replicas checked by the safety invariants.
    const CORRECT: Set[ReplicaId]
    // Identities of the byzantine replicas.
    const BYZANTINE: Set[ReplicaId]
    // Twin actors run correct-style transitions but represent faulty logical replicas.
    const TWINS: Set[ReplicaId]
    // The set of all views.
    const VIEWS: Set[ViewNumber]
    // Identifiers of valid blocks.
    const VALID_BLOCK_IDS: Set[str]
    // All replicas.
    pure val Replicas = REPLICA_IDS.union(BYZANTINE)
    // The keys of the replicas, normally, one unique key per replica.
    // For modeling byzantine behaviour via twin replicas use the same keys.
    const REPLICA_KEYS: ReplicaId -> ReplicaKey

    // Quorums:
    pure val L = N - F;
    pure val M = 2*F + 1;

    // Produce replica's signature
    pure def sig_of(id: ReplicaId): ReplicaKey = REPLICA_KEYS.get(id)

    // Quorums are counted over KEYS, never over actor identities: two twins share one key
    // and must therefore contribute exactly one signature to any quorum.
    pure val CORRECT_KEYS = CORRECT.map(id => sig_of(id))
    pure val FAULTY_KEYS = BYZANTINE.union(TWINS).map(id => sig_of(id))

    const INVALID_BLOCK_IDS: Set[str]
    pure val AllBlockIds = VALID_BLOCK_IDS.union(INVALID_BLOCK_IDS)
    // Byzantine replicas may attach any height in VIEWS to any block identifier.
    pure val ByzantineBlocks: Set[Block] = tuples(AllBlockIds, VIEWS).map(((id, height)) =>
        mkBlock(id, height))

    // The states of the correct replicas
    var replica_state: ReplicaId -> ReplicaState
    // the leader function from the view to the replicas identities
    var leader: ViewNumber -> ReplicaId

    // proposals sent by the replicas, correct and byzantine
    var sent_proposal: Set[Proposal]
    // notarize and nullify votes sent by the replicas, correct and byzantine
    var sent_vote: Set[Vote]
    // `notarization` and `nullification` messages sent by the replicas, correct and byzantine
    var sent_certificate: Set[Certificate]

    // notarize and nullify votes received by the correct replicas
    var store_vote: ReplicaId -> Set[Vote]
    // notarization and nullification certificates received or assembled by the correct replicas
    var store_certificate: ReplicaId -> Set[Certificate]

    // history of received proposals
    var ghost_proposal: ReplicaId -> Set[Proposal]
    // proposals committed by every correct replica
    var ghost_committed_blocks: ReplicaId -> Set[Block]
    // Unique mapping of blocks to their parents (as required by Section 2 in the Minimmit paper).
    // Genesis has itself as the parent.
    var ghost_block_parent: Block -> Block

    // Filter votes by view and kind.
    pure def select_votes(view: ViewNumber, kind: Kind, votes: Set[Vote]): Set[Vote] = {
        votes.filter(v => vote_kind(v) == kind and vote_view(v) == view)
    }

    // Has a replica notarized a block in the current view?
    def has_notarized(r: ReplicaState): bool = {
        r.notarized.get(r.view).is_some()
    }

    // Did replica `id` itself broadcast a notarize in `view`? This reads the replica's own
    // per-actor record of the votes it sent (`ghost_sent_votes`), so it identifies the actor
    // precisely even when several actors share one signing key. Matching a signature in the
    // global vote pool would conflate same-key actors (a twin's notarize carries the same
    // `sig_of(id)`), whereas a replica's `ghost_sent_votes` entry belongs to that replica alone.
    // A `Some(_)` in the sequence marks a notarize; a `None` marks a nullify.
    def has_notarized_view(id: ReplicaId, view: ViewNumber): bool = {
        val sent = replica_state.get(id).ghost_sent_votes.get(view)
        sent.indices().exists(i => sent[i].is_some())
    }

    // Does a set of certificates have a notarization certificate for a view?
    pure def is_view_notarized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => cert_kind(v) == NotarizationKind and cert_view(v) == view),
        certificates.exists(v => cert_kind(v) == FinalizationKind and cert_view(v) == view)
    }

    // Does a set of certificates have a notarization certificate for a view,
    // block id (hash), and ghost height?
    pure def is_view_notarized_with_id_and_height(
        view: ViewNumber,
        block_id: str,
        block_height: int,
        certificates: Set[Certificate],
    ): bool = or {
        view == GENESIS_VIEW and
            block_id == GENESIS_BLOCK.id and
            block_height == GENESIS_BLOCK.ghost_height,
        certificates.exists(c => and {
            cert_kind(c) == NotarizationKind,
            cert_view(c) == view,
            cert_block(c).id == block_id,
            cert_block(c).ghost_height == block_height,
        }),
        certificates.exists(c => and {
            cert_kind(c) == FinalizationKind,
            cert_view(c) == view,
            cert_block(c).id == block_id,
            cert_block(c).ghost_height == block_height,
        }),
    }

    pure def select_notarize_votes_for_proposal(proposal: Proposal, votes: Set[Vote]): Set[Vote] = {
        select_votes(proposal.view, NotarizeKind, votes)
            .filter(v => vote_proposal(v) == Some(proposal))
    }

    // Does a set of votes have an M-quorum for a proposal?
    pure def is_view_notarized_votes(proposal: Proposal, votes: Set[Vote]): bool = or {
        proposal.view == GENESIS_VIEW,
        select_notarize_votes_for_proposal(proposal, votes)
            .map(v => vote_sig(v))
            .size() >= M
    }

    pure def is_view_finalized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => cert_kind(v) == FinalizationKind and cert_view(v) == view)
    }

    // Does a set of votes have an L-quorum for a proposal?
    pure def is_view_finalized_votes(proposal: Proposal, votes: Set[Vote]): bool = or {
        proposal.view == GENESIS_VIEW,
        select_notarize_votes_for_proposal(proposal, votes)
            .map(v => vote_sig(v))
            .size() >= L
    }

    // Does a set of certificates contain nullification certificates for this view?
    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => cert_kind(v) == NullificationKind and cert_view(v) == view)
    }

    pure def is_view_nullified_votes(view: ViewNumber, votes: Set[Vote]): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NullifyKind, votes)
            .map(v => vote_sig(v))
            .size() >= M
    }

    // Does a set of certificates contain nullifications certificates for all views in the interval (v1, v2)?
    def are_views_nullified(v1: ViewNumber, v2: ViewNumber, certificates: Set[Certificate]): bool = {
        VIEWS.filter(v => v > v1 and v < v2).forall(v => is_view_nullified(v, certificates))
    }

    // the block parent in the proposal is indeed the only parent of the block
    def is_proposal_with_valid_parent_block(p: Proposal): bool = and {
        ghost_block_parent.keys().contains(p.block),
        ghost_block_parent.get(p.block) == p.block_parent,
    }

    // Return the block and every mapped ancestor. The traversal is bounded by
    // the number of known blocks and stops at a missing parent or a cycle.
    // Genesis is a sentinel rather than a committed proposal, so omit it.
    def block_and_ancestors(block: Block): Set[Block] = {
        val traversal = ghost_block_parent.keys().fold(
            { current: block, blocks: Set(block) },
            (acc, _) => {
                if (acc.current == GENESIS_BLOCK
                        or not(ghost_block_parent.keys().contains(acc.current))) {
                    acc
                } else {
                    val parent = ghost_block_parent.get(acc.current)
                    {
                        current: parent,
                        blocks: acc.blocks.union(Set(parent)),
                    }
                }
            })
        traversal.blocks.exclude(Set(GENESIS_BLOCK))
    }

    // Replica `r` ensures there are nullifications for all views `(view_parent, view)`,
    // and that there is a `notarization(c', view_parent)` for the parent block `c'`.
    def valid_parent(
        view: ViewNumber,
        view_parent: ViewNumber,
        block_parent: Block,
        certificates: Set[Certificate],
    ): bool = {
        is_view_notarized_with_id_and_height(
            view_parent, block_parent.id, block_parent.ghost_height, certificates) and
            are_views_nullified(view_parent, view, certificates)
    }

    // Create a nullify certificate from a set of votes.
    def create_nullification(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = select_votes(view, NullifyKind, votes)
        val votes_count = similar_votes.size()

        if (votes_count < M)
            None
        else
            Some(nullification(view, similar_votes.map(v => vote_sig(v)), sig_of(id)))
    }

    def create_notarization(id: ReplicaId, proposal: Proposal, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = select_notarize_votes_for_proposal(proposal, votes)

        val votes_count = similar_votes.size()
        if (votes_count < M)
            None
        else if (votes_count >= L)
            Some(finalization(proposal, similar_votes.map(v => vote_sig(v)), sig_of(id)))
        else
            Some(notarization(proposal, similar_votes.map(v => vote_sig(v)), sig_of(id)))
    }

    // Check whether a proposal cannot be notarized in a view.
    def is_proposal_in_view_cannot_be_notarized(proposal: Proposal, view: ViewNumber, votes: Set[Vote]): bool = {
        val vs1 = votes.filter(v => and {
            vote_kind(v) == NotarizeKind,
            vote_view(v) == view,
            vote_proposal(v) != Some(proposal),
        }).map(v => vote_sig(v))
        val vs2 = votes.filter(v =>
            vote_kind(v) == NullifyKind and vote_view(v) == view
        ).map(v => vote_sig(v))
        vs1.union(vs2).size() >= M
    }

    // Is there a contradiction for the notarized block in the set of votes?
    def is_contradicted(self: ReplicaState, view: ViewNumber, votes: Set[Vote]): bool = {
        match self.notarized.get(view) {
            | Some(p) => is_proposal_in_view_cannot_be_notarized(p, view, votes)
            | None => false
        }
    }

    // Enter the next view on a certificate for the current view (Algorithm 1, lines 16-22).
    // Views advance one at a time: a certificate for a later view does not move the replica.
    // It stays in the store and takes effect via `on_stored_certificate` once its view is current.
    pure def enter_new_view(self: ReplicaState, cert: Certificate): ReplicaState = {
        val new_view = cert_view(cert) + 1
        val advance = self.view == cert_view(cert)
        if (not(VIEWS.contains(new_view)))
            self // no change
        else
            {
                ...self,
                propose_sent: if (advance) false else self.propose_sent,
                nullified: if (advance) false else self.nullified,
                timer_cancelled: if (advance) false else self.timer_cancelled,
                view: 
                    if (advance) new_view else self.view,
                last_finalized: 
                    if (self.last_finalized < cert_view(cert) and cert_kind(cert) == FinalizationKind)
                        cert_view(cert)
                    else
                        self.last_finalized,
                ghost_last_seen_notarization:
                    if (self.ghost_last_seen_notarization < cert_view(cert) and cert_kind(cert) != NullificationKind)
                        cert_view(cert)
                    else
                        self.ghost_last_seen_notarization
            }
    }

    // A predicate `is_select_parent(id, pb, pv)` iff `(pb, pv) = select_parent(r, r.view)`.
    def is_select_parent(id: ReplicaId, parent_block: Block, parent_view: ViewNumber): bool = {
        val v = replica_state.get(id).view
        val certs = store_certificate.get(id)
        // valid_parent is deliberately different from the code below.
        and {
            // all views in the interval (parent_view, v) are nullified
            VIEWS.forall(i => (parent_view < i and i < v) implies and {
                not(is_view_notarized(i, certs)),
                is_view_nullified(i, certs),
            }),
            // the parent block is notarized in the parent view
            or {
                certs.exists(c => and {
                    cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
                    cert_view(c) == parent_view,
                    cert_block(c) == parent_block,
                }),
                parent_view < 0 and parent_block == GENESIS_BLOCK,
            }
        }
    }

    // Initialize all replicas with genesis.
    action init = {
        pure val label_init = true
        // Non‑deterministically choose any total leader function (View → ReplicaId)
        nondet l = VIEWS.setOfMaps(Replicas).oneOf()
        initWithLeader(l)
    }

    action initWithLeader(l: ViewNumber -> ReplicaId): bool = all {
        replica_state' = REPLICA_IDS.mapBy(id => {
            view  : 0,
            ghost_last_seen_notarization: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            notarized: VIEWS.mapBy(_ => None),
            propose_sent: false,
            nullified: false,
            timer_cancelled: false,
            ghost_sent_votes: VIEWS.mapBy(_ => List())
        }),
        sent_proposal' = Set(),
        sent_vote'    = Set(),
        sent_certificate' = Set(),
        store_vote'   = REPLICA_IDS.mapBy(_ => Set()),
        store_certificate'   = REPLICA_IDS.mapBy(_ => Set()),
        ghost_committed_blocks' = REPLICA_IDS.mapBy(_ => Set()),
        ghost_proposal' = REPLICA_IDS.mapBy(id => Set()),
        ghost_block_parent' = Set(GENESIS_BLOCK).mapBy(_ => GENESIS_BLOCK),
        leader'       = l
    }

    // A step by a correct or byzantine replica.
    action step = {
        any {
            pure val label_correct = true
            {
                correct_step
            },
            pure val label_byzantine = true
            all {
                byzantine_replica_step,
                _unchanged_replica_state,
            }
        }
    }

    // Every transition available to a correct-style actor, INCLUDING proposing.
    // Configurations that model faults purely with twins have no byzantine actor and therefore
    // use this as their whole `step`; they must not silently lose the proposer transition.
    action correct_step = any {
        pure val label_replica = true
        {
            correct_replica_step
        },
        pure val label_proposer = true
        all {
            nondet id = oneOf(REPLICA_IDS)
            // Non-deterministically choose the next block, use it only for the case of None below.
            nondet new_block_id = oneOf(VALID_BLOCK_IDS)
            // Non-deterministically choose the parent block and parent view (checked in proposer_step)
            nondet parent_block =
                oneOf(store_certificate.get(id).map(cert => cert_block(cert)).union(Set(GENESIS_BLOCK)))
            nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            proposer_step(id, new_block_id, parent_block, parent_view),
        }
    }

    action disabled_action: bool = all {
        false,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        sent_certificate' = sent_certificate,
        ghost_committed_blocks' = ghost_committed_blocks,
        sent_vote' = sent_vote,
        replica_state' = replica_state,
        sent_proposal' = sent_proposal,
        leader' = leader,
        ghost_proposal' = ghost_proposal,
        ghost_block_parent' = ghost_block_parent,
    }

    // A step by a correct-style actor (a correct replica or a twin), except for the proposer step.
    action correct_replica_step(): bool = all {
        nondet id = oneOf(REPLICA_IDS)
        // Non‑deterministically pick one enabled internal action
        any {
            pure val label_timer = true
            {
                on_timer_expired(id)
            },
            pure val label_proposal = true
            all {
                sent_proposal != Set(),
                nondet p = oneOf(sent_proposal)
                on_proposal(id, p)
            },
            pure val label_notarize_vote = true
            {
                nondet votes = oneOf(powerset(sent_vote))
                all {
                    votes != Set(),
                    votes.forall(v => vote_kind(v) == NotarizeKind),
                    nondet one_vote = oneOf(votes)
                    match vote_proposal(one_vote) {
                        | Some(proposal) => on_vote_notarize(id, proposal, votes)
                        | None => disabled_action
                    }
                }
            },
            pure val label_nullify_vote = true
            {
                nondet votes = oneOf(powerset(sent_vote))
                nondet view = VIEWS.oneOf()
                on_vote_nullify(id, view, votes)
            },
            pure val label_contradiction = true
            {
                nondet view = oneOf(VIEWS)
                on_nullify_by_contradiction(id, view)
            },
            pure val label_certificate = true
            all {
                sent_certificate != Set(),
                nondet cert = oneOf(sent_certificate)
                on_certificate(id, cert)
            },
            pure val label_stored_certificate = true
            all {
                store_certificate.get(id) != Set(),
                nondet cert = oneOf(store_certificate.get(id))
                on_stored_certificate(id, cert)
            },
        },
    }

    // 8.1. A proposer step by the view leader.
    action proposer_step(id: ReplicaId, new_block_id: str,
                         parent_block: Block, parent_view: ViewNumber): bool = all {
        val self = replica_state.get(id)
        val new_block = mkBlock(new_block_id, parent_block.ghost_height + 1)

        all {
            // Compare KEYS, not actor ids: a twin shares its sibling's key, so both twins of the
            // view's logical leader may propose. That is exactly how a twin pair equivocates.
            sig_of(id) == sig_of(leader.get(self.view)),
            VALID_BLOCK_IDS.contains(new_block_id),
            not(self.propose_sent),
            not(self.timer_cancelled),
            // make sure that parent_block and parent_view are chosen according to select_parent
            is_select_parent(id, parent_block, parent_view),
            // enforce that the new block has only one parent (this is the protocol assumption)
            or {
                not(ghost_block_parent.keys().contains(new_block)),
                ghost_block_parent.get(new_block) == parent_block,
            },

            val proposal: Proposal = {
                view: self.view,
                view_parent: parent_view,
                block: new_block,
                block_parent: parent_block,
                sig: sig_of(id),
            }
            all {
                // send the proposal
                sent_proposal' = sent_proposal.union(Set(proposal)),
                replica_state' = replica_state.set(id, {
                    ...self,
                    propose_sent: true,
                    // "Treat propose(r, c, v, (c', v')) as r's notarize(c, v)"
                    notarized: self.notarized.put(self.view, Some(proposal)),
                    ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(Some(proposal)))
                }),
                // "Treat propose(r, c, v, (c', v')) as r's notarize(c, v)"
                sent_vote' = sent_vote.union(Set(notarize(proposal, sig_of(id)))),
                ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),
                // unchanged
                sent_certificate' = sent_certificate,
                store_vote'    = store_vote,
                store_certificate' = store_certificate,
                leader' = leader,
                ghost_committed_blocks' = ghost_committed_blocks,
                ghost_block_parent' = ghost_block_parent.put(new_block, parent_block),
            }
        }
    }

    // -------------------------------------------------
    // Handle proposal (first valid one wins)
    // -------------------------------------------------

    // 8.2. Notarize
    action on_proposal(id: ReplicaId, proposal: Proposal): bool = all {
        val self = replica_state.get(id)
        val certificates = store_certificate.get(id)
        val notarize_vote = notarize(proposal, sig_of(id))
        all {
            not(self.has_notarized()),
            not(self.nullified),
            // check that the latest block is not dummy block
            proposal.block != DUMMY_BLOCK,
            // Accept only proposals for current view we are working on
            proposal.view == self.view,
            // the ghost_height is an increment, this is a proof constraint
            proposal.block.ghost_height == proposal.block_parent.ghost_height + 1,
            // the block parent in the proposal is indeed the only parent of the block
            is_proposal_with_valid_parent_block(proposal),

            // "If !verify(c, c'), return."
            VALID_BLOCK_IDS.contains(proposal.block.id),

            // the proposer is the leader of this view
            proposal.sig == sig_of(leader.get(proposal.view)),
            proposal.view_parent < proposal.view,
            proposal.view_parent >= self.last_finalized,

            valid_parent(
                proposal.view,
                proposal.view_parent,
                proposal.block_parent,
                certificates,
            ),

            // Send the notarize vote to all replicas (including ourselves).
            sent_vote' = sent_vote.union(Set(notarize_vote)),
            // Store proposal
            ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),
            replica_state' = replica_state.set(id, {
                ...self,
                notarized: self.notarized.put(self.view, Some(proposal)),
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(Some(proposal)))
            }),

            // unchanged
            store_vote'  = store_vote,
            sent_proposal'  = sent_proposal,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            ghost_block_parent' = ghost_block_parent,
        }
    }

    // -------------------------------------------------
    // Handle a subset of received votes
    // -------------------------------------------------

    // 8.6 Nullify by Contradiction
    action on_nullify_by_contradiction(id: ReplicaId, view: ViewNumber): bool = all {
        val self = replica_state.get(id)

        all {
            self.view == view,
            self.has_notarized(),
            not(self.nullified),
            is_contradicted(self, view, store_vote.get(id)),

            sent_vote' = sent_vote.union(Set(nullify(view, sig_of(id)))),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(None))
            }),

            store_vote' = store_vote,
            ghost_committed_blocks' = ghost_committed_blocks,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            sent_proposal' = sent_proposal,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
            ghost_block_parent' = ghost_block_parent,
        }
    }
    
    // 8.4. Notarization & Finalization
    action on_vote_notarize(id: ReplicaId, proposal: Proposal, votes: Set[Vote]): bool = all {
        val self = replica_state.get(id)
        val store = store_vote.get(id)
        all {
            votes != Set(),
            votes.forall(v => and {
                // Note, `view` is not the current view of the replica,
                // it is `view` from the input needed to be able pass the concrete view parameter into underlying functions, e.g., `is_view_finalized`.
                vote_view(v) == proposal.view,
                vote_kind(v) == NotarizeKind,
                vote_proposal(v) == Some(proposal),
            }),
            // validate that the proposal has the correct parent
            is_proposal_with_valid_parent_block(proposal),
            val new_store = store_vote.get(id).union(votes)

            all {
                store_vote' = store_vote.set(id, new_store),

                val certificates = store_certificate.get(id)

                val was_notarized =
                    is_view_notarized(proposal.view, certificates) or
                    is_view_notarized_votes(proposal, store)
                val now_notarized =
                    is_view_notarized_votes(proposal, new_store)

                val was_finalized =
                    is_view_finalized(proposal.view, certificates) or
                    is_view_finalized_votes(proposal, store)
                val now_finalized =
                    is_view_finalized_votes(proposal, new_store)
                
                val is_new_cert = or {
                    not(was_notarized) and now_notarized,
                    not(was_finalized) and now_finalized,
                }
                
                match create_notarization(id, proposal, new_store) {
                    | Some(cert) =>  {
                        _process_certificate(id, cert, is_new_cert)
                    }
                    | None => all {
                        store_certificate' = store_certificate,
                        sent_certificate' = sent_certificate,
                        replica_state' = replica_state,
                        ghost_committed_blocks' = ghost_committed_blocks,
                        sent_vote'=sent_vote
                    }
                },
                sent_proposal' = sent_proposal,
                leader' = leader,
                ghost_proposal' = ghost_proposal,
                ghost_block_parent' = ghost_block_parent,
            }
        }
    }

    // 8.5.2. Nullification
    action on_vote_nullify(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): bool = all {
        val self = replica_state.get(id)
        val certificates = store_certificate.get(id)
        val store = store_vote.get(id)
        all {
            votes != Set(),
            votes.forall(v => and {
                vote_view(v) == view,
                vote_kind(v) == NullifyKind,
                not(v.in(store)),
            }),
            val new_store = store_vote.get(id).union(votes)

            all {
                store_vote' = store_vote.set(id, new_store),

                val was_nullified = is_view_nullified(view, certificates)
                val now_nullified = is_view_nullified_votes(view, new_store)
                val is_new_cert = or {
                    not(was_nullified) and now_nullified,
                }
                
                match create_nullification(id, view, new_store) {
                    | Some(cert) =>  {
                        _process_certificate(id, cert, is_new_cert)
                    }
                    | None => all {
                        store_certificate' = store_certificate,
                        sent_certificate' = sent_certificate,
                        replica_state' = replica_state,
                        ghost_committed_blocks' = ghost_committed_blocks,
                        sent_vote'=sent_vote
                    }
                },
                sent_proposal' = sent_proposal,
                leader' = leader,
                ghost_proposal' = ghost_proposal,
                ghost_block_parent' = ghost_block_parent,
            }
        }
    }

    // -------------------------------------------------
    // Handle a certificate message
    // -------------------------------------------------
    action on_certificate(id: ReplicaId, cert: Certificate): bool = all {
        val self = replica_state.get(id)
        val certificates = store_certificate.get(id)

        all {
            not(contains_certificate(store_certificate.get(id), cert)),

            or {
                cert_kind(cert) == NullificationKind and
                    cert_signatures(cert).size() >= M and
                    not(is_view_nullified(cert_view(cert), certificates)),
                cert_kind(cert) == NotarizationKind and
                    cert_signatures(cert).size() >= M and
                    not(is_view_notarized(cert_view(cert), certificates)),
                cert_kind(cert) == FinalizationKind and
                    cert_signatures(cert).size() >= L and
                    not(is_view_finalized(cert_view(cert), certificates)),
            },
            
            // is_new_cert set to true, because this is a certificate and at this moment the view is not nullified, notarized, or finalized
            _process_certificate(id, cert, true),

            // unchanged
            sent_proposal' = sent_proposal,
            store_vote' = store_vote,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
            ghost_block_parent' = ghost_block_parent,
        }
    }

    // Algorithm 1, lines 16-22, as a state condition rather than an arrival handler: a
    // certificate that was stored for a later view acts once that view becomes current.
    // With `is_new_cert = false`, `_process_certificate` neither stores, forwards, nor commits
    // again; it only votes along (for a notarization) and enters the next view.
    action on_stored_certificate(id: ReplicaId, cert: Certificate): bool = all {
        val self = replica_state.get(id)

        all {
            cert.in(store_certificate.get(id)),
            cert_view(cert) == self.view,
            _process_certificate(id, cert, false),

            // unchanged
            sent_proposal' = sent_proposal,
            store_vote' = store_vote,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
            ghost_block_parent' = ghost_block_parent,
        }
    }

    action _process_certificate(id: ReplicaId, cert: Certificate, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        // Algorithm 1, line 20: vote along with an M-notarization for the current view. This
        // does not depend on `is_new_cert`, so a notarization that was stored for a later view
        // still triggers the vote once that view becomes current (`on_stored_certificate`).
        val should_send_notarize_vote = and {
            self.view == cert_view(cert),
            not(self.has_notarized()),
            not(self.nullified),
            cert_kind(cert) == NotarizationKind or cert_kind(cert) == FinalizationKind,
        }

        all {
            cert_signatures(cert).size() >= M,

            if (is_new_cert) all {
                store_certificate' = store_certificate.setBy(id, old => add_certificate(old, cert)),
                sent_certificate' = add_certificate(sent_certificate, cert),
            } else all {
                store_certificate' = store_certificate,
                sent_certificate' = sent_certificate,
            },
        
            if (cert_kind(cert) == FinalizationKind and cert_view(cert) > self.last_finalized and is_new_cert)
                match cert_proposal(cert) {
                    | Some(p) =>
                        ghost_committed_blocks' = ghost_committed_blocks.setBy(
                            id, old => old.union(block_and_ancestors(p.block)))
                    | None =>
                        ghost_committed_blocks' = ghost_committed_blocks
                }
            else 
                ghost_committed_blocks' = ghost_committed_blocks
            ,

            val new_self = enter_new_view(self, cert)
            
            if (should_send_notarize_vote) 
                match cert_proposal(cert) {
                    | Some(p) => all {
                        sent_vote' = sent_vote.union(Set(notarize(p, sig_of(id)))),
                        replica_state' = replica_state.set(id, {
                            ...new_self,
                            notarized: self.notarized.put(cert_view(cert), Some(p)),
                            ghost_sent_votes: self.ghost_sent_votes.setBy(cert_view(cert), old => old.append(Some(p)))
                        }),
                    }
                    | None => all {
                        sent_vote' = sent_vote,
                        replica_state' = replica_state.set(id, new_self),
                    }
                }
            else 
                all {
                    sent_vote' = sent_vote,
                    replica_state' = replica_state.set(id, new_self),
                },
        }
    }

    // -------------------------------------------------
    // Backup timer: If timer expires, broadcast nullify(v) if not yet broadcast notarize(c, v).
    // -------------------------------------------------

    action on_timer_expired(id: ReplicaId): bool = all {
        val self = replica_state.get(id)
        val vote = nullify(self.view, sig_of(id))

        all {
            not(self.timer_cancelled),
            not(self.has_notarized()),
            not(self.nullified),

            // changed
            sent_vote' = sent_vote.union(Set(vote)),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                timer_cancelled: true,
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(None))
            }),

            // unchanged
            sent_proposal'  = sent_proposal,
            store_vote'  = store_vote,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            ghost_proposal' = ghost_proposal,
            ghost_block_parent' = ghost_block_parent,
        }
    }

    // -------------------------------------------------
    // Byzantine behavior (completely adversarial)
    // -------------------------------------------------

    action byzantine_replica_step: bool = all {
        BYZANTINE != Set(),

        // Adversary may inject arbitrary well-typed vote messages.
        all {
            nondet senders = BYZANTINE.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet block = ByzantineBlocks.union(Set(DUMMY_BLOCK)).oneOf()
            nondet block_parent = ByzantineBlocks.union(Set(GENESIS_BLOCK)).oneOf()
            nondet view_parent = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            nondet k = oneOf(Set(NotarizeKind, NullifyKind))
            nondet proposal_sig = oneOf(BYZANTINE)
            val proposal = {
                view: view,
                block: block,
                block_parent: block_parent,
                view_parent: view_parent,
                sig: sig_of(proposal_sig)
            }
            val votes =
                if (k == NullifyKind)
                    senders.map(sender => nullify(view, sig_of(sender)))
                else
                    senders.map(sender => notarize(proposal, sig_of(sender)))
            sent_vote' = sent_vote.union(votes),
        },
        // Adversary may inject arbitrary certificates.
        all {
            nondet sender = BYZANTINE.oneOf()
            nondet senders = BYZANTINE.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet block = ByzantineBlocks.oneOf()
            nondet block_parent = ByzantineBlocks.union(Set(GENESIS_BLOCK)).oneOf()
            nondet view_parent = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            nondet kind = oneOf(Set(NotarizeKind, NullifyKind))
            val proposal = {
                view: view,
                block: block,
                block_parent: block_parent,
                view_parent: view_parent,
                sig: sig_of(sender)
            }
            val votes =
                if (kind == NullifyKind) {
                    sent_vote.filter(v => and {
                        vote_view(v) == view,
                        vote_kind(v) == kind
                    })
                } else {
                    sent_vote.filter(v => and {
                        vote_kind(v) == kind,
                        vote_proposal(v) == Some(proposal)
                    })
                }
            // The adversary may pad with the KEYS it controls, i.e. those of BYZANTINE and of
            // any twins: two twins share one key, so they contribute one signature, not two.
            nondet agg_sig = votes.map(v => vote_sig(v)).union(FAULTY_KEYS).powerset().oneOf()
            val cert =
                if (kind == NullifyKind) {
                    nullification(view, agg_sig, sig_of(sender))
                } else if (votes.size() >= L) {
                    finalization(proposal, agg_sig, sig_of(sender))
                } else {
                    notarization(proposal, agg_sig, sig_of(sender))
                }
            sent_certificate' = add_certificate(sent_certificate, cert)
        },
        // Adversary may inject arbitrary proposal.
        all {
            nondet view_parent = VIEWS.oneOf()
            nondet view = VIEWS.oneOf()
            nondet byz = oneOf(BYZANTINE)
            nondet block = ByzantineBlocks.oneOf()
            nondet block_parent = ByzantineBlocks.oneOf()
            val proposal = {
                view: view,
                block: block,
                block_parent: block_parent,
                view_parent: view_parent,
                sig: sig_of(byz)
            }
            sent_proposal' = sent_proposal.union(Set(proposal)),
        }
    }

    // Part of the state that is not touched by the Byzantine validators.
    action _unchanged_replica_state = all {
        ghost_committed_blocks' = ghost_committed_blocks,
        replica_state' = replica_state,
        store_vote'    = store_vote,
        store_certificate' = store_certificate,
        leader' = leader,
        ghost_proposal' = ghost_proposal,
        ghost_block_parent' = ghost_block_parent,
    }

    // -------------------------------------------------
    // Invariants
    // -------------------------------------------------

    // Assumptions and thresholds.
    // N counts logical replicas, i.e. KEYS, not modelled actors: a twin pair is two actors but
    // one key and therefore one logical replica. So the budget is stated over CORRECT_KEYS and
    // FAULTY_KEYS rather than over the identity sets.
    val assumptions_valid = all {
        Replicas.forall(r => REPLICA_KEYS.keys().contains(r)),
        REPLICA_IDS == CORRECT.union(TWINS),
        CORRECT.intersect(TWINS) == Set(),
        CORRECT.intersect(BYZANTINE) == Set(),
        TWINS.intersect(BYZANTINE) == Set(),
        // No honest key is also a faulty key, and honest keys are distinct per replica.
        CORRECT_KEYS.intersect(FAULTY_KEYS) == Set(),
        CORRECT_KEYS.size() == CORRECT.size(),
        CORRECT_KEYS.size() + FAULTY_KEYS.size() == N,
        // Twins and byzantine replicas together stay inside the fault budget.
        FAULTY_KEYS.size() <= F,
        N >= 5*F+1,
        2*M <= L + 1, // Liveness guard, prevents equivocation stall.
        M + L > N + F, // Every M-quorum and every L-quorum share at least one honest replica.
    }

    pure def committed_sets_agree(blocks1: Set[Block], blocks2: Set[Block]): bool = {
        tuples(blocks1, blocks2).forall(((b1, b2)) =>
            b1.ghost_height != b2.ghost_height or b1.id == b2.id)
    }

    // No two correct replicas commit different proposals at the same height.
    val agreement = tuples(CORRECT, CORRECT).forall(((p1, p2)) => {
        val blocks1 = ghost_committed_blocks.get(p1)
        val blocks2 = ghost_committed_blocks.get(p2)
        committed_sets_agree(blocks1, blocks2)
    })

    def votes_seq_correct(votes: List[Option[Proposal]]): bool = {
        (length(votes) == 2 and votes[0].is_some() and votes[1].is_none()) or
        length(votes) <= 1
    }

    // A correct replica should not send two votes in the same view.
    // Honest replicas may not broadcast a notarize(c, v) after first broadcasting a nullify(v).
    val no_vote_equivocation_inv = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => votes_seq_correct(self.ghost_sent_votes.get(v)))

    })

    // It is impossible to produce both a nullification and finalization certificate for the same slot v.
    // If some honest player sees that iteration h is finalized,
    // then no honest player will ever see that h is nullified.
    val no_nullification_and_finalization_in_the_same_view = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        val votes = store_vote.get(id)
        val views_with_nullification =
            certs.filter(c => cert_kind(c) == NullificationKind).map(c => cert_view(c))
        val observed_votes = votes.filter(vote => vote_kind(vote) == NotarizeKind)
        val views_with_finalization =
            VIEWS.filter(v => observed_votes.exists(vote =>
                match vote_proposal(vote) {
                    | Some(p) => p.view == v and is_view_finalized_votes(p, votes)
                    | None => false
                }))
        views_with_nullification.intersect(views_with_finalization) == Set()
    })

    // No equivocation.
    val no_proposal_equivocation = tuples(sent_proposal, sent_proposal).forall(((m1, m2)) => or {
        not(m1.view == m2.view and m1.sig == m2.sig),
        FAULTY_KEYS.contains(m1.sig),
        m1.block == m2.block,
    })

    val valid_last_finalized = CORRECT.forall(id => {
        val self = replica_state.get(id)
        self.last_finalized <= self.ghost_last_seen_notarization
    })


    // Make sure that no invalid certificates are stored.
    val certificates_are_valid_inv = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        certs.forall(cert => and {
            cert_view(cert) >= 0,
            or {
                cert_signatures(cert).size() >= M and
                    (cert_kind(cert) == NotarizationKind or cert_kind(cert) == NullificationKind),
                cert_signatures(cert).size() >= L and cert_kind(cert) == FinalizationKind,
            },
            cert_kind(cert) == NotarizationKind or
                cert_kind(cert) == NullificationKind or
                cert_kind(cert) == FinalizationKind,
            (cert_block(cert) == DUMMY_BLOCK) iff (cert_kind(cert) == NullificationKind),
            VALID_BLOCK_IDS.contains(cert_block(cert).id) or (cert_block(cert) == DUMMY_BLOCK)
        })
    })

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => self.notarized.get(v).is_some() iff has_notarized_view(id, v))
    })

    // Suppose that a block B for some slot v is finalized, then no other block B' for slot v can be finalized.
    val validity = tuples(CORRECT, CORRECT, VIEWS).forall(((id1, id2, v)) => {
        val certs1 = store_certificate.get(id1).filter(c => and {
            cert_signatures(c).size() >= L,
            cert_kind(c) == FinalizationKind,
            cert_view(c) == v,
        })
        val certs2 = store_certificate.get(id2).filter(c => and {
            cert_signatures(c).size() >= L,
            cert_kind(c) == FinalizationKind,
            cert_view(c) == v,
        })

        or {
            certs1 == Set(),
            certs2 == Set(),
            certs1.map(c => cert_block(c)) == certs2.map(c => cert_block(c))
        }
    })

    // If there is a finalized block in a view v, there is no nullification in the same view.
    val no_nullification_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        val observed_votes = votes.filter(vote => vote_kind(vote) == NotarizeKind)
        or {
            observed_votes.forall(vote =>
                match vote_proposal(vote) {
                    | Some(p) => p.view != v or not(is_view_finalized_votes(p, votes))
                    | None => true
                }),
            select_votes(v, NullifyKind, votes)
                .map(vote => vote_sig(vote))
                .size() < M
        }
    })

    // If there is a finalized block in a view v, there is no notarization for another block in the same view.
    val no_notarization_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        val observed_votes = votes.filter(vote => vote_kind(vote) == NotarizeKind)
        observed_votes.forall(vote =>
            match vote_proposal(vote) {
                | Some(p) => or {
                    p.view != v,
                    not(is_view_finalized_votes(p, votes)),
                    select_votes(v, NotarizeKind, votes)
                        .filter(other_vote => vote_proposal(other_vote) != Some(p))
                        .map(other_vote => vote_sig(other_vote))
                        .size() < M
                }
                | None => true
            })
    })

    val safe_finalization = all {
        no_notarization_in_finalized_view,
        no_nullification_in_finalized_view
    }

    val all_invariants = all {
        no_proposal_equivocation,
        agreement,
        no_vote_equivocation_inv,
        no_nullification_and_finalization_in_the_same_view,
        validity,
        valid_last_finalized,
        certificates_are_valid_inv,
        notarized_consistency,
        safe_finalization,
    }

    val safe = all_invariants

    // Test invariants.

    val correct_nodes_sent_certificates_valid =
        sent_certificate.filter(cert => CORRECT_KEYS.contains(cert_ghost_sender(cert))).forall(cert => {
            cert_signatures(cert).size() >= M
    })
    val store_certificates_are_valid = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        certs.forall(cert => cert_signatures(cert).size() >= M)
    })

    val certificates_are_valid = and {
        correct_nodes_sent_certificates_valid,
        store_certificates_are_valid
    }

    // Examples.

    // Check this invariant to see an example of having a finalized block.
    val block_example = not(CORRECT.exists(id => {
        ghost_committed_blocks.get(id).size() >= 1
    }))

    val finalized_example = not(CORRECT.exists(id => {
        replica_state.get(id).last_finalized >= 0
    }))

    val notarized_example = not(CORRECT.exists(id => {
       replica_state.get(id).ghost_last_seen_notarization >= 0
    }))

    val two_chained_blocks_example = not(CORRECT.exists(id => {
        ghost_committed_blocks.get(id).size() >= 2
    }))

    // Check this invariant to see an example of having at least one vote.
    val one_vote_example = CORRECT.forall(id => {
        store_vote.get(id).size() <= 0
    })

    // Check this invariant to see an example of having a subquorum of votes.
    val votes_subquorum_example = CORRECT.forall(id => {
        store_vote.get(id).size() <= M
    })

    // Check this invariant to see an example of having a quorum of votes.
    val votes_quorum_example = CORRECT.forall(id => {
        store_vote.get(id).size() <= L
    })

    // Check this invariant to see an example of having a certificate.
    val cert = CORRECT.forall(id => {
        store_certificate.get(id).size() <= 1
    })

    // Check this invariant to see an example of a replica reaching view > 2.
    val view = CORRECT.forall(id => {
        replica_state.get(id).view < 2
    })
}
