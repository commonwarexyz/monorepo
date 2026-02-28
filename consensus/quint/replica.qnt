module replica {
    import types.* from "./types"
    import defs.* from "./defs"
    import option.* from "./option"

    // Total number of replicas.
    const N: int
    // Maximum number of byzantine(faulty) replicas.
    const F: int
    // Identities of the correct replicas.
    const CORRECT: Set[ReplicaId]
    // Identities of the byzantine replicas.
    const BYZANTINE: Set[ReplicaId]
    // The set of all views.
    const VIEWS: Set[ViewNumber]
    // the set of all valid blocks
    const VALID_BLOCKS: Set[Block]
    // externally invalid blocks (for adversarial tests)
    const INVALID_BLOCKS: Set[Block]
    // All replicas.
    pure val Replicas = CORRECT.union(BYZANTINE)
    // The keys of the replicas, normally, one unique key per replica.
    // For modeling byzantine behaviour via twin replicas use the same keys.
    const REPLICA_KEYS: ReplicaId -> ReplicaKey

    // Quorums:
    pure val L = N - F;
    pure val M = 2*F + 1;

    // Produce replica's signature
    pure def sig_of(id: ReplicaId): ReplicaKey = REPLICA_KEYS.get(id)

    pure val AllBlocks = VALID_BLOCKS.union(INVALID_BLOCKS)
    pure val ByzantineSigs = BYZANTINE.map(id => sig_of(id))
    pure val LEADER_INACTIVITY_WINDOW = 2

    // The states of the correct replicas
    var replica_state: ReplicaId -> ReplicaState
    // the leader function from the view to the replicas identities
    var leader: ViewNumber -> ReplicaId

    // proposals sent by the replicas, correct and byzantine
    var sent_proposal: Set[Proposal]
    // votes sent by the replicas, correct and byzantine
    var sent_vote: Set[Vote]
    // certificates sent by the replicas, correct and byzantine
    var sent_certificate: Set[Certificate]

    // votes received by the correct replicas
    var store_vote: ReplicaId -> Set[Vote]
    // certificates received or assembled by the correct replicas
    var store_certificate: ReplicaId -> Set[Certificate]

    // history of received proposals
    var ghost_proposal: ReplicaId -> Set[Proposal]
    // sequence of finalized blocks observed by each correct replica
    var ghost_committed_blocks: ReplicaId -> List[Block]
    // Replica-local deterministic certification policy from the application.
    var certify_policy: ReplicaId -> (Block -> bool)

    // Filter votes by view and kind.
    pure def vote_view(v: Vote): ViewNumber = {
        match (v) {
            | Notarize(n) => n.view
            | Nullify(n) => n.view
            | Finalize(f) => f.view
        }
    }

    pure def vote_sig(v: Vote): Signature = {
        match (v) {
            | Notarize(n) => n.sig
            | Nullify(n) => n.sig
            | Finalize(f) => f.sig
        }
    }

    pure def vote_block(v: Vote): Block = {
        match (v) {
            | Notarize(n) => n.block
            | Nullify(_) => EMPTY_BLOCK
            | Finalize(f) => f.block
        }
    }

    pure def vote_kind(v: Vote): Kind = {
        match (v) {
            | Notarize(_) => NotarizeKind
            | Nullify(_) => NullifyKind
            | Finalize(_) => FinalizeKind
        }
    }

    pure def is_notarize(v: Vote): bool = {
        match (v) {
            | Notarize(_) => true
            | _ => false
        }
    }

    pure def is_nullify(v: Vote): bool = {
        match (v) {
            | Nullify(_) => true
            | _ => false
        }
    }

    pure def is_finalize(v: Vote): bool = {
        match (v) {
            | Finalize(_) => true
            | _ => false
        }
    }

    pure def cert_view(c: Certificate): ViewNumber = {
        match (c) {
            | Notarization(n) => n.view
            | Nullification(n) => n.view
            | Finalization(f) => f.view
        }
    }

    pure def cert_signatures(c: Certificate): Set[Signature] = {
        match (c) {
            | Notarization(n) => n.signatures
            | Nullification(n) => n.signatures
            | Finalization(f) => f.signatures
        }
    }

    pure def cert_ghost_sender(c: Certificate): Signature = {
        match (c) {
            | Notarization(n) => n.ghost_sender
            | Nullification(n) => n.ghost_sender
            | Finalization(f) => f.ghost_sender
        }
    }

    pure def cert_block(c: Certificate): Block = {
        match (c) {
            | Notarization(n) => n.block
            | Nullification(_) => EMPTY_BLOCK
            | Finalization(f) => f.block
        }
    }

    pure def cert_kind(c: Certificate): Kind = {
        match (c) {
            | Notarization(_) => NotarizationKind
            | Nullification(_) => NullificationKind
            | Finalization(_) => FinalizationKind
        }
    }

    pure def is_notarization_cert(c: Certificate): bool = {
        match (c) {
            | Notarization(_) => true
            | _ => false
        }
    }

    pure def is_nullification_cert(c: Certificate): bool = {
        match (c) {
            | Nullification(_) => true
            | _ => false
        }
    }

    pure def is_finalization_cert(c: Certificate): bool = {
        match (c) {
            | Finalization(_) => true
            | _ => false
        }
    }

    pure def select_votes(view: ViewNumber, kind: Kind, votes: Set[Vote]): Set[Vote] = {
        votes.filter(v => vote_kind(v) == kind and vote_view(v) == view)
    }

    def has_sent_vote(id: ReplicaId, view: ViewNumber, kind: Kind): bool = {
        sent_vote.exists(v => vote_sig(v) == id and vote_view(v) == view and vote_kind(v) == kind)
    }

    def has_sent_nullify(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, NullifyKind)
    }

    def has_sent_finalize(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, FinalizeKind)
    }

    def has_participated_in_view(id: ReplicaId, view: ViewNumber): bool = or {
        sent_vote.exists(v => vote_sig(v) == id and vote_view(v) == view),
        sent_proposal.exists(p => p.sig == id and p.view == view),
    }

    // The designated leader for `view` is considered inactive if they have not
    // participated in any of the previous `LEADER_INACTIVITY_WINDOW` views.
    def leader_inactive(view: ViewNumber): bool = {
        val designated = leader.get(view)
        val previous_views = VIEWS.filter(v => and {
            v < view,
            v >= view - LEADER_INACTIVITY_WINDOW,
        })
        previous_views.forall(v => not(has_participated_in_view(designated, v)))
    }

    pure def has_notarized(r: ReplicaState): bool = {
        r.notarized.get(r.view) != EMPTY_BLOCK
    }

    pure def has_notarized_view(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): bool = {
        votes.exists(v => vote_view(v) == view and is_notarize(v) and vote_sig(v) == id)
    }

    // Does a set of certificates have a notarization/finalization certificate for a view?
    pure def is_view_notarized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c => is_notarization_cert(c) and cert_view(c) == view),
        certificates.exists(c => is_finalization_cert(c) and cert_view(c) == view)
    }

    pure def is_view_notarized_votes(view: ViewNumber, votes: Set[Vote], block: Block): bool = or {
        view == GENESIS_VIEW and block == GENESIS_BLOCK,
        select_votes(view, NotarizeKind, votes)
            .filter(v => vote_block(v) == block)
            .map(v => vote_sig(v))
            .size() >= M
    }

    pure def is_view_finalized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c => is_finalization_cert(c) and cert_view(c) == view)
    }

    pure def is_view_finalized_votes(view: ViewNumber, votes: Set[Vote], block: Block): bool = or {
        view == GENESIS_VIEW and block == GENESIS_BLOCK,
        select_votes(view, FinalizeKind, votes)
            .filter(v => vote_block(v) == block)
            .map(v => vote_sig(v))
            .size() >= M
    }

    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c => is_nullification_cert(c) and cert_view(c) == view)
    }

    pure def is_view_nullified_votes(view: ViewNumber, votes: Set[Vote]): bool = {
        select_votes(view, NullifyKind, votes)
            .filter(v => is_nullify(v))
            .map(v => vote_sig(v))
            .size() >= M
    }

    pure def is_block_notarized(view: ViewNumber, block: Block, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW and block == GENESIS_BLOCK,
        certificates.exists(c => and {
            cert_view(c) == view,
            cert_block(c) == block,
            is_notarization_cert(c) or is_finalization_cert(c),
        })
    }

    pure def is_block_finalized(view: ViewNumber, block: Block, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW and block == GENESIS_BLOCK,
        certificates.exists(c => and {
            cert_view(c) == view,
            cert_block(c) == block,
            is_finalization_cert(c),
        })
    }

    // Does a set of certificates contain nullification certificates for all views in (v1, v2)?
    pure def are_views_nullified(v1: ViewNumber, v2: ViewNumber, certificates: Set[Certificate]): bool = {
        VIEWS.filter(v => v > v1 and v < v2).forall(v => is_view_nullified(v, certificates))
    }

    // Parent is valid if all intermediate views are nullified and the parent is either:
    // (a) finalized, or (b) notarized and locally certified.
    pure def valid_parent(
        self: ReplicaState,
        view: ViewNumber,
        parent_block: Block,
        parent_view: ViewNumber,
        certificates: Set[Certificate]
    ): bool = and {
        parent_view < view,
        parent_view >= GENESIS_VIEW,
        are_views_nullified(parent_view, view, certificates),
        or {
            is_block_finalized(parent_view, parent_block, certificates),
            and {
                is_block_notarized(parent_view, parent_block, certificates),
                self.certified.get(parent_view) == parent_block,
            }
        }
    }

    // A predicate `is_select_parent(id, pb, pv)` iff `(pb, pv)` can be selected by id in current view.
    def is_select_parent(id: ReplicaId, parent_block: Block, parent_view: ViewNumber): bool = {
        val self = replica_state.get(id)
        val certs = store_certificate.get(id)
        valid_parent(self, self.view, parent_block, parent_view, certs)
    }

    // Certification is deterministic and may depend on replica id.
    def can_certify(id: ReplicaId, block: Block): bool = {
        certify_policy.get(id).get(block)
    }

    // Enter a new view, unless it is older than the current view or outside modeled bounds.
    pure def enter_view(self: ReplicaState, new_view: ViewNumber): ReplicaState = {
        if (not(VIEWS.contains(new_view)) or self.view >= new_view)
            self
        else
            {
                ...self,
                view: new_view,
                propose_sent: false,
                nullified: false,
                leader_timeout_cancelled: false,
                advance_timeout_cancelled: false
            }
    }

    def create_nullification(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            vote_view(v) == view,
            is_nullify(v)
        })
        val signers = similar_votes.map(v => vote_sig(v))

        if (signers.size() < M)
            None
        else
            Some(nullification(view, signers, id))
    }

    def create_notarization(id: ReplicaId, view: ViewNumber, block: Block, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            vote_view(v) == view,
            is_notarize(v),
            vote_block(v) == block
        })
        val signers = similar_votes.map(v => vote_sig(v))

        if (signers.size() < M)
            None
        else
            Some(notarization(view, block, signers, id))
    }

    def create_finalization(id: ReplicaId, view: ViewNumber, block: Block, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            vote_view(v) == view,
            is_finalize(v),
            vote_block(v) == block
        })
        val signers = similar_votes.map(v => vote_sig(v))

        if (signers.size() < M)
            None
        else
            Some(finalization(view, block, signers, id))
    }

    action init = {
        // Non-deterministically choose any total leader function (View -> ReplicaId)
        nondet l = VIEWS.setOfMaps(Replicas).oneOf()
        initWithLeader(l)
    }

    action initWithLeader(l: ViewNumber -> ReplicaId): bool = {
        val default_block_policy = AllBlocks.union(Set(GENESIS_BLOCK, EMPTY_BLOCK)).mapBy(_ => true)
        val default_certify_policy = Replicas.mapBy(_ => default_block_policy)
        initWithLeaderAndCertify(l, default_certify_policy)
    }

    action initWithLeaderAndCertify(
        l: ViewNumber -> ReplicaId,
        certify: ReplicaId -> (Block -> bool)
    ): bool = all {
        replica_state' = CORRECT.mapBy(id => {
            view: FIRST_VIEW,
            ghost_last_seen_notarization: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            notarized: VIEWS.mapBy(_ => EMPTY_BLOCK),
            certified: VIEWS.mapBy(_ => EMPTY_BLOCK),
            propose_sent: false,
            nullified: false,
            leader_timeout_cancelled: false,
            advance_timeout_cancelled: false,
            ghost_sent_votes: VIEWS.mapBy(_ => List())
        }),
        sent_proposal' = Set(),
        sent_vote' = Set(),
        sent_certificate' = Set(),
        store_vote' = CORRECT.mapBy(_ => Set()),
        store_certificate' = CORRECT.mapBy(_ => Set()),
        ghost_committed_blocks' = CORRECT.mapBy(_ => List()),
        ghost_proposal' = CORRECT.mapBy(_ => Set()),
        leader' = l,
        certify_policy' = certify
    }

    // A step by a correct or byzantine replica.
    action step = {
        any {
            {
                correct_replica_step
            },
            all {
                nondet id = oneOf(CORRECT)
                nondet new_block = oneOf(VALID_BLOCKS)
                nondet parent_block = oneOf(AllBlocks.union(Set(GENESIS_BLOCK)))
                nondet parent_view = VIEWS.oneOf()
                proposer_step(id, new_block, parent_block, parent_view),
            },
            all {
                byzantine_replica_step,
                _unchanged_replica_state,
            }
        }
    }

    // A step by a correct replica, except for the proposer step.
    action correct_replica_step(): bool = all {
        nondet id = oneOf(CORRECT)
        val self = replica_state.get(id)
        val skip_timeout = and {
            id != leader.get(self.view),
            leader_inactive(self.view),
            not(self.nullified),
        }
        // Skip "leader timeout" and "certification timeout" if a designated leader hasn't participated in
        // some number of views (again to trigger early view transition for an unresponsive leader).
        if (skip_timeout) {
            on_timeout(id)
        } else {
            any {
                {
                    on_timeout(id)
                },
                all {
                    sent_proposal != Set(),
                    nondet p = oneOf(sent_proposal)
                    on_proposal(id, p)
                },
                {
                    nondet votes = oneOf(powerset(sent_vote))
                    nondet view = VIEWS.oneOf()
                    nondet block = AllBlocks.oneOf()
                    on_vote_notarize(id, view, block, votes)
                },
                {
                    nondet votes = oneOf(powerset(sent_vote))
                    nondet view = VIEWS.oneOf()
                    nondet block = AllBlocks.oneOf()
                    on_vote_finalize(id, view, block, votes)
                },
                {
                    nondet votes = oneOf(powerset(sent_vote))
                    nondet view = VIEWS.oneOf()
                    on_vote_nullify(id, view, votes)
                },
                all {
                    sent_certificate != Set(),
                    nondet cert = oneOf(sent_certificate)
                    on_certificate(id, cert)
                },
            }
        }
    }

    // Upon entering a view, the leader may propose and implicitly cast notarize(c, v).
    action proposer_step(
        id: ReplicaId,
        new_block: Block,
        parent_block: Block,
        parent_view: ViewNumber
    ): bool = all {
        val self = replica_state.get(id)
        val certs = store_certificate.get(id)
        all {
            id == leader.get(self.view),
            not(self.propose_sent),
            not(self.nullified),
            any {
                // Proposal success path
                all {
                    VALID_BLOCKS.contains(new_block),
                    valid_parent(self, self.view, parent_block, parent_view, certs),

                    val proposal: Proposal = {
                        view: self.view,
                        view_parent: parent_view,
                        block: new_block,
                        block_parent: parent_block,
                        sig: sig_of(id),
                    }

                    all {
                        sent_proposal' = sent_proposal.union(Set(proposal)),
                        sent_vote' = sent_vote.union(Set(notarize(self.view, id, new_block))),
                        replica_state' = replica_state.set(id, {
                            ...self,
                            propose_sent: true,
                            leader_timeout_cancelled: true,
                            notarized: self.notarized.put(self.view, new_block),
                            ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NotarizeKind))
                        }),
                        ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),

                        // unchanged
                        store_vote' = store_vote,
                        sent_certificate' = sent_certificate,
                        store_certificate' = store_certificate,
                        leader' = leader,
                        ghost_committed_blocks' = ghost_committed_blocks,
                        certify_policy' = certify_policy
                    }
                },
                // Proposal failure path: immediate timeout expiry
                // Treat local proposal failure as immediate timeout expiry and broadcast `nullify(v)`.
                all {
                    sent_vote' = sent_vote.union(Set(nullify(self.view, id))),
                    replica_state' = replica_state.set(id, {
                        ...self,
                        nullified: true,
                        leader_timeout_cancelled: true,
                        advance_timeout_cancelled: true,
                        ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NullifyKind))
                    }),

                    // unchanged
                    sent_proposal' = sent_proposal,
                    sent_certificate' = sent_certificate,
                    store_vote' = store_vote,
                    store_certificate' = store_certificate,
                    leader' = leader,
                    ghost_proposal' = ghost_proposal,
                    ghost_committed_blocks' = ghost_committed_blocks,
                    certify_policy' = certify_policy
                }
            }
        }
    }

    // Upon receiving first leader proposal in current view:
    // - cancel leader timeout
    // - if valid parent and block valid -> notarize
    // - if block invalid -> nullify
    action on_proposal(id: ReplicaId, proposal: Proposal): bool = all {
        val self = replica_state.get(id)
        val certs = store_certificate.get(id)
        all {
            proposal.view == self.view,
            proposal.sig == sig_of(leader.get(proposal.view)),
            proposal.view_parent < proposal.view,
            proposal.view_parent >= GENESIS_VIEW,
            not(has_notarized(self)),
            not(self.nullified),

            any {
                all {
                    VALID_BLOCKS.contains(proposal.block),
                    valid_parent(self, proposal.view, proposal.block_parent, proposal.view_parent, certs),

                    sent_vote' = sent_vote.union(Set(notarize(proposal.view, id, proposal.block))),
                    replica_state' = replica_state.set(id, {
                        ...self,
                        leader_timeout_cancelled: true,
                        notarized: self.notarized.put(self.view, proposal.block),
                        ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NotarizeKind))
                    }),
                },
                // Treat local verification failure as immediate timeout expiry and broadcast `nullify(v)`.
                all {
                    not(VALID_BLOCKS.contains(proposal.block)),

                    sent_vote' = sent_vote.union(Set(nullify(proposal.view, id))),
                    replica_state' = replica_state.set(id, {
                        ...self,
                        nullified: true,
                        leader_timeout_cancelled: true,
                        advance_timeout_cancelled: true,
                        ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NullifyKind))
                    }),
                }
            },

            ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),

            // unchanged
            store_vote' = store_vote,
            sent_proposal' = sent_proposal,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            certify_policy' = certify_policy
        }
    }

    // Upon receiving votes for notarize(c, v):
    // - collect votes
    // - on 2f+1: create notarization cert, attempt certification
    action on_vote_notarize(id: ReplicaId, view: ViewNumber, block: Block, votes: Set[Vote]): bool = all {
        val store = store_vote.get(id)
        all {
            votes != Set(),
            votes.forall(v => and {
                vote_view(v) == view,
                is_notarize(v),
                vote_block(v) == block,
            }),

            val new_store = store.union(votes)
            val certs = store_certificate.get(id)
            val had_notarization = certs.exists(c => and {
                is_notarization_cert(c),
                cert_view(c) == view,
                cert_block(c) == block,
            })
            val now_notarized = is_view_notarized_votes(view, new_store, block)

            all {
                store_vote' = store_vote.set(id, new_store),

                match create_notarization(id, view, block, new_store) {
                    | Some(cert) => all {
                        now_notarized,
                        _process_notarization_certificate(id, cert, not(had_notarization))
                    }
                    | None => all {
                        store_certificate' = store_certificate,
                        sent_certificate' = sent_certificate,
                        sent_vote' = sent_vote,
                        replica_state' = replica_state,
                        ghost_committed_blocks' = ghost_committed_blocks,
                    }
                },

                // unchanged
                sent_proposal' = sent_proposal,
                leader' = leader,
                ghost_proposal' = ghost_proposal,
                certify_policy' = certify_policy
            }
        }
    }

    // Upon receiving votes for finalize(c, v):
    // - collect votes
    // - on 2f+1: create finalization cert and enter v+1
    action on_vote_finalize(id: ReplicaId, view: ViewNumber, block: Block, votes: Set[Vote]): bool = all {
        val store = store_vote.get(id)
        all {
            votes != Set(),
            votes.forall(v => and {
                vote_view(v) == view,
                is_finalize(v),
                vote_block(v) == block,
            }),

            val new_store = store.union(votes)
            val certs = store_certificate.get(id)
            val had_finalization = certs.exists(c => and {
                is_finalization_cert(c),
                cert_view(c) == view,
                cert_block(c) == block,
            })
            val now_finalized = is_view_finalized_votes(view, new_store, block)

            all {
                store_vote' = store_vote.set(id, new_store),

                match create_finalization(id, view, block, new_store) {
                    | Some(cert) => all {
                        now_finalized,
                        _process_finalization_certificate(id, cert, not(had_finalization))
                    }
                    | None => all {
                        store_certificate' = store_certificate,
                        sent_certificate' = sent_certificate,
                        sent_vote' = sent_vote,
                        replica_state' = replica_state,
                        ghost_committed_blocks' = ghost_committed_blocks,
                    }
                },

                // unchanged
                sent_proposal' = sent_proposal,
                leader' = leader,
                ghost_proposal' = ghost_proposal,
                certify_policy' = certify_policy
            }
        }
    }

    // Upon receiving votes for nullify(v):
    // - collect votes
    // - on 2f+1: create nullification cert and enter v+1
    //
    // Additional Simplex rule:
    // if a non-leader replica receives nullify(v) from the current leader of view v,
    // it treats this as immediate timeout expiry and broadcasts nullify(v).
    action on_vote_nullify(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): bool = all {
        val store = store_vote.get(id)
        val self = replica_state.get(id)
        all {
            votes != Set(),
            votes.forall(v => and {
                vote_view(v) == view,
                is_nullify(v),
            }),

            val new_store = store.union(votes)
            val certs = store_certificate.get(id)
            val had_nullification = certs.exists(c => is_nullification_cert(c) and cert_view(c) == view)
            val now_nullified = is_view_nullified_votes(view, new_store)
            val leader_nullify_trigger = and {
                self.view == view,
                id != leader.get(view),
                not(self.nullified),
                votes.exists(v => vote_sig(v) == leader.get(view)),
            }

            all {
                store_vote' = store_vote.set(id, new_store),

                match create_nullification(id, view, new_store) {
                    | Some(cert) => all {
                        now_nullified,
                        if (not(had_nullification))
                            all {
                                store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                                sent_certificate' = sent_certificate.union(Set(cert)),
                            }
                        else
                            all {
                                store_certificate' = store_certificate,
                                sent_certificate' = sent_certificate,
                            },
                        ghost_committed_blocks' = ghost_committed_blocks,
                        if (leader_nullify_trigger)
                            all {
                                sent_vote' = sent_vote.union(Set(nullify(view, id))),
                                replica_state' = replica_state.set(id, enter_view({
                                    ...self,
                                    nullified: true,
                                    leader_timeout_cancelled: true,
                                    advance_timeout_cancelled: true,
                                    ghost_sent_votes: self.ghost_sent_votes.setBy(view, old => old.append(NullifyKind))
                                }, cert_view(cert) + 1)),
                            }
                        else
                            all {
                                sent_vote' = sent_vote,
                                replica_state' = replica_state.set(id, enter_view(self, cert_view(cert) + 1)),
                            }
                    }
                    | None => all {
                        store_certificate' = store_certificate,
                        sent_certificate' = sent_certificate,
                        if (leader_nullify_trigger)
                            all {
                                sent_vote' = sent_vote.union(Set(nullify(view, id))),
                                replica_state' = replica_state.set(id, {
                                    ...self,
                                    nullified: true,
                                    leader_timeout_cancelled: true,
                                    advance_timeout_cancelled: true,
                                    ghost_sent_votes: self.ghost_sent_votes.setBy(view, old => old.append(NullifyKind))
                                }),
                            }
                        else
                            all {
                                sent_vote' = sent_vote,
                                replica_state' = replica_state,
                            },
                        ghost_committed_blocks' = ghost_committed_blocks,
                    }
                },

                // unchanged
                sent_proposal' = sent_proposal,
                leader' = leader,
                ghost_proposal' = ghost_proposal,
                certify_policy' = certify_policy
            }
        }
    }

    // Handle certificate message.
    action on_certificate(id: ReplicaId, cert: Certificate): bool = all {
        val certs = store_certificate.get(id)
        all {
            not(cert.in(certs)),
            or {
                is_notarization_cert(cert) and cert_signatures(cert).size() >= M,
                is_nullification_cert(cert) and cert_signatures(cert).size() >= M,
                is_finalization_cert(cert) and cert_signatures(cert).size() >= M,
            },

            if (is_notarization_cert(cert)) {
                _process_notarization_certificate(id, cert, true)
            } else if (is_nullification_cert(cert)) {
                _process_nullification_certificate(id, cert, true)
            } else {
                _process_finalization_certificate(id, cert, true)
            },

            // unchanged
            sent_proposal' = sent_proposal,
            store_vote' = store_vote,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
            certify_policy' = certify_policy
        }
    }

    action _process_notarization_certificate(id: ReplicaId, cert: Certificate, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        all {
            is_notarization_cert(cert),
            cert_signatures(cert).size() >= M,

            if (is_new_cert) all {
                store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                sent_certificate' = sent_certificate.union(Set(cert)),
            } else all {
                store_certificate' = store_certificate,
                sent_certificate' = sent_certificate,
            },

            val cert_view_num = cert_view(cert)
            val cert_block_val = cert_block(cert)
            val seen_notarization = if (self.ghost_last_seen_notarization < cert_view_num) cert_view_num else self.ghost_last_seen_notarization
            val can_send_finalize = and {
                can_certify(id, cert_block_val),
                self.certified.get(cert_view_num) == EMPTY_BLOCK,
                not(has_sent_finalize(id, cert_view_num)),
                not(has_sent_nullify(id, cert_view_num)),
            }
            val can_send_nullify = and {
                not(can_certify(id, cert_block_val)),
                not(has_sent_nullify(id, cert_view_num)),
            }

            if (can_send_finalize)
                all {
                    sent_vote' = sent_vote.union(Set(finalize(cert_view_num, id, cert_block_val))),
                    replica_state' = replica_state.set(id,
                        enter_view({
                            ...self,
                            advance_timeout_cancelled: if (self.view == cert_view_num) true else self.advance_timeout_cancelled,
                            ghost_last_seen_notarization: seen_notarization,
                            certified: self.certified.put(cert_view_num, cert_block_val),
                            ghost_sent_votes: self.ghost_sent_votes.setBy(cert_view_num, old => old.append(FinalizeKind))
                        }, cert_view_num + 1)
                    ),
                    ghost_committed_blocks' = ghost_committed_blocks,
                }
            else if (can_send_nullify)
                all {
                    sent_vote' = sent_vote.union(Set(nullify(cert_view_num, id))),
                    replica_state' = replica_state.set(id, {
                        ...self,
                        nullified: if (self.view == cert_view_num) true else self.nullified,
                        advance_timeout_cancelled: if (self.view == cert_view_num) true else self.advance_timeout_cancelled,
                        ghost_last_seen_notarization: seen_notarization,
                        ghost_sent_votes: self.ghost_sent_votes.setBy(cert_view_num, old => old.append(NullifyKind))
                    }),
                    ghost_committed_blocks' = ghost_committed_blocks,
                }
            else
                all {
                    sent_vote' = sent_vote,
                    replica_state' = replica_state.set(id, {
                        ...self,
                        advance_timeout_cancelled: if (self.view == cert_view_num) true else self.advance_timeout_cancelled,
                        ghost_last_seen_notarization: seen_notarization
                    }),
                    ghost_committed_blocks' = ghost_committed_blocks,
                }
        }
    }

    action _process_nullification_certificate(id: ReplicaId, cert: Certificate, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        all {
            is_nullification_cert(cert),
            cert_signatures(cert).size() >= M,

            if (is_new_cert) all {
                store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                sent_certificate' = sent_certificate.union(Set(cert)),
            } else all {
                store_certificate' = store_certificate,
                sent_certificate' = sent_certificate,
            },

            sent_vote' = sent_vote,
            replica_state' = replica_state.set(id, enter_view(self, cert_view(cert) + 1)),
            ghost_committed_blocks' = ghost_committed_blocks
        }
    }

    action _process_finalization_certificate(id: ReplicaId, cert: Certificate, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        all {
            is_finalization_cert(cert),
            cert_signatures(cert).size() >= M,

            if (is_new_cert) all {
                store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                sent_certificate' = sent_certificate.union(Set(cert)),
            } else all {
                store_certificate' = store_certificate,
                sent_certificate' = sent_certificate,
            },

            val cert_view_num = cert_view(cert)
            val cert_block_val = cert_block(cert)
            val seen_notarization = if (self.ghost_last_seen_notarization < cert_view_num) cert_view_num else self.ghost_last_seen_notarization
            val newer = cert_view_num > self.last_finalized

            all {
                if (is_new_cert and newer)
                    ghost_committed_blocks' = ghost_committed_blocks.setBy(id, old => old.append(cert_block_val))
                else
                    ghost_committed_blocks' = ghost_committed_blocks,

                sent_vote' = sent_vote,
                replica_state' = replica_state.set(id,
                    enter_view({
                        ...self,
                        last_finalized: if (newer) cert_view_num else self.last_finalized,
                        ghost_last_seen_notarization: seen_notarization
                    }, cert_view_num + 1)
                )
            }
        }
    }

    // On leader timeout or advance timeout firing, broadcast nullify(v).
    action on_timeout(id: ReplicaId): bool = all {
        val self = replica_state.get(id)
        all {
            not(self.nullified),

            sent_vote' = sent_vote.union(Set(nullify(self.view, id))),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                leader_timeout_cancelled: true,
                advance_timeout_cancelled: true,
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NullifyKind))
            }),

            // unchanged
            sent_proposal' = sent_proposal,
            store_vote' = store_vote,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            ghost_proposal' = ghost_proposal,
            certify_policy' = certify_policy
        }
    }

    // Byzantine behavior (completely adversarial)
    action byzantine_replica_step: bool = all {
        BYZANTINE != Set(),

        // Adversary may inject arbitrary well-typed vote messages.
        all {
            nondet sender = BYZANTINE.oneOf()
            nondet view = VIEWS.oneOf()
            nondet block = AllBlocks.oneOf()
            nondet k = oneOf(Set(NotarizeKind, NullifyKind, FinalizeKind))
            val vote = if (k == NotarizeKind) {
                notarize(view, sender, block)
            } else if (k == NullifyKind) {
                nullify(view, sender)
            } else {
                finalize(view, sender, block)
            }
            sent_vote' = sent_vote.union(Set(vote)),
        },

        // Adversary may inject arbitrary certificates.
        all {
            nondet sender = BYZANTINE.oneOf()
            nondet signers = Replicas.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet block = AllBlocks.oneOf()
            nondet kind = oneOf(Set(NotarizationKind, NullificationKind, FinalizationKind))
            val cert = if (kind == NotarizationKind) {
                notarization(view, block, signers, sender)
            } else if (kind == NullificationKind) {
                nullification(view, signers, sender)
            } else {
                finalization(view, block, signers, sender)
            }
            sent_certificate' = sent_certificate.union(Set(cert))
        },

        // Adversary may inject arbitrary proposal.
        all {
            nondet view_parent = VIEWS.oneOf()
            nondet view = VIEWS.oneOf()
            nondet sig = BYZANTINE.oneOf()
            nondet block = AllBlocks.oneOf()
            nondet block_parent = AllBlocks.union(Set(GENESIS_BLOCK)).oneOf()
            val proposal = {
                view: view,
                block: block,
                block_parent: block_parent,
                view_parent: view_parent,
                sig: sig
            }
            sent_proposal' = sent_proposal.union(Set(proposal)),
        }
    }

    // Part of the state not touched by byzantine validators.
    action _unchanged_replica_state = all {
        ghost_committed_blocks' = ghost_committed_blocks,
        replica_state' = replica_state,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        leader' = leader,
        ghost_proposal' = ghost_proposal,
        certify_policy' = certify_policy
    }

    // -------------------------------------------------
    // Invariants
    // -------------------------------------------------

    // Assumptions and thresholds.
    val assumptions_valid = all {
        CORRECT.size() + BYZANTINE.size() == N,
        CORRECT.intersect(BYZANTINE) == Set(),
        N >= 3*F + 1,
        M == 2*F + 1,
        M <= N,
    }

    // No two correct replicas disagree on finalized chains (prefix agreement).
    val agreement = tuples(CORRECT, CORRECT).forall(((p1, p2)) => {
        val blocks1 = ghost_committed_blocks.get(p1)
        val blocks2 = ghost_committed_blocks.get(p2)
        or {
            and {
                blocks1.length() <= blocks2.length(),
                blocks1.indices().forall(i => blocks1[i] == blocks2[i]),
            },
            and {
                blocks2.length() <= blocks1.length(),
                blocks2.indices().forall(i => blocks2[i] == blocks1[i]),
            }
        }
    })

    def votes_seq_correct(votes: List[Kind]): bool = or {
        votes == List(),
        and {
            votes.length() == 1,
            or {
                votes[0] == NotarizeKind,
                votes[0] == NullifyKind,
                votes[0] == FinalizeKind,
            }
        },
        and {
            votes.length() == 2,
            votes[0] == NotarizeKind,
            or {
                votes[1] == NullifyKind,
                votes[1] == FinalizeKind,
            }
        }
    }

    // A correct replica cannot equivocate in a view.
    // Allowed patterns: notarize->finalize, notarize->nullify, single vote.
    val no_vote_equivocation_inv = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => votes_seq_correct(self.ghost_sent_votes.get(v)))
    })

    // No view may contain both nullification and finalization certificates.
    val no_nullification_and_finalization_in_the_same_view = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        val nullified_views = certs.filter(c => is_nullification_cert(c)).map(c => cert_view(c))
        val finalized_views = certs.filter(c => is_finalization_cert(c)).map(c => cert_view(c))
        nullified_views.intersect(finalized_views) == Set()
    })

    // No correct proposer sends two different proposals in the same view.
    val no_proposal_equivocation = tuples(sent_proposal, sent_proposal).forall(((m1, m2)) => or {
        not(m1.view == m2.view and m1.sig == m2.sig),
        ByzantineSigs.contains(m1.sig),
        m1.block == m2.block,
    })

    val valid_last_finalized = CORRECT.forall(id => {
        val self = replica_state.get(id)
        self.last_finalized <= self.ghost_last_seen_notarization
    })

    // Make sure no invalid certificates are stored.
    val certificates_are_valid_inv = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        certs.forall(cert => and {
            cert_view(cert) >= GENESIS_VIEW,
            cert_signatures(cert).size() >= M,
            cert_kind(cert) == NotarizationKind or cert_kind(cert) == NullificationKind or cert_kind(cert) == FinalizationKind,
            if (is_nullification_cert(cert)) {
                true
            } else {
                VALID_BLOCKS.contains(cert_block(cert)) or INVALID_BLOCKS.contains(cert_block(cert)) or cert_block(cert) == GENESIS_BLOCK
            }
        })
    })

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => self.notarized.get(v) != EMPTY_BLOCK iff has_notarized_view(id, v, sent_vote))
    })

    // If a block B for view v is finalized, no other block B' at v can be finalized.
    val validity = tuples(CORRECT, CORRECT, VIEWS).forall(((id1, id2, v)) => {
        val certs1 = store_certificate.get(id1).filter(c => is_finalization_cert(c) and cert_view(c) == v)
        val certs2 = store_certificate.get(id2).filter(c => is_finalization_cert(c) and cert_view(c) == v)

        or {
            certs1 == Set(),
            certs2 == Set(),
            certs1.map(c => cert_block(c)) == certs2.map(c => cert_block(c))
        }
    })

    // If there is a finalized block in view v, there is no nullification in view v.
    val no_nullification_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val certs = store_certificate.get(id)
        or {
            not(certs.exists(c => is_finalization_cert(c) and cert_view(c) == v)),
            not(certs.exists(c => is_nullification_cert(c) and cert_view(c) == v)),
        }
    })

    // If there is a finalized block in view v, there is no notarization for another block in view v.
    val no_notarization_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val certs = store_certificate.get(id)
        AllBlocks.forall(b => or {
            not(certs.exists(c => is_finalization_cert(c) and cert_view(c) == v and cert_block(c) == b)),
            not(certs.exists(c => is_notarization_cert(c) and cert_view(c) == v and cert_block(c) != b)),
        })
    })

    val finalize_requires_notarization = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        sent_vote
            .filter(v => vote_sig(v) == id and is_finalize(v))
            .forall(v => is_block_notarized(vote_view(v), vote_block(v), certs))
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
        finalize_requires_notarization,
    }

    val safe = all_invariants

    // Test invariants.

    val correct_nodes_sent_certificates_valid = sent_certificate
        .filter(cert => cert_ghost_sender(cert).in(CORRECT))
        .forall(cert => cert_signatures(cert).size() >= M)

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
        ghost_committed_blocks.get(id).length() >= 1
    }))

    val finalized_example = not(CORRECT.exists(id => {
        replica_state.get(id).last_finalized >= FIRST_VIEW
    }))

    val notarized_example = not(CORRECT.exists(id => {
        replica_state.get(id).ghost_last_seen_notarization >= FIRST_VIEW
    }))

    val two_chained_blocks_example = not(CORRECT.exists(id => {
        ghost_committed_blocks.get(id).length() >= 2
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
        store_vote.get(id).size() <= M
    })

    // Check this invariant to see an example of having a certificate.
    val cert = CORRECT.forall(id => {
        store_certificate.get(id).size() <= 1
    })

    // Check this invariant to see an example of a replica reaching view > 2.
    val view = CORRECT.forall(id => {
        replica_state.get(id).view < 3
    })
}
