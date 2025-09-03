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
    // the set of all blocks
    const VALID_BLOCKS: Set[Block]
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

    const INVALID_BLOCKS: Set[Block]
    pure val AllBlocks = VALID_BLOCKS.union(INVALID_BLOCKS)

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
    // sequences of blocks committed by every correct replica
    var ghost_committed_blocks: ReplicaId -> List[Block]

    // Filter votes by view and kind.
    pure def select_votes(view: ViewNumber, kind: Kind, votes: Set[Vote]): Set[Vote] = {
        votes.filter(v => v.kind == kind and v.view == view)
    }

    // Has a replica notarized a block in the current view?
    def has_notarized(r: ReplicaState): bool = {
        r.notarized.get(r.view) != EMPTY_BLOCK
    }

    def has_notarized_view(id: ReplicaId, view:ViewNumber, votes: Set[Vote]): bool = {
        votes.exists(v=> v.view == view and v.kind == NotarizeKind and v.sig == id)
    }

    // Does a set of certificates have a notarization certificate for a view?
    pure def is_view_notarized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == NotarizationKind and v.view == view),
        certificates.exists(v => v.kind == FinalizationKind and v.view == view)
    }

    // Does a set of certificates have a notarization certificate for a view?
    pure def is_view_notarized_votes(view: ViewNumber, votes: Set[Vote], block: Block): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NotarizeKind, votes)
            .filter(v => v.block == block)
            .map(v => v.sig)
            .size() >= M
    }

    pure def is_view_finalized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == FinalizationKind and v.view == view)
    }

    // Does a set of votes have a quorum of votes for a view?
    pure def is_view_finalized_votes(view: ViewNumber, votes: Set[Vote], block: Block): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NotarizeKind, votes)
            .filter(v => v.block == block)
            .map(v => v.sig)
            .size() >= L
    }

    // Does a set of certificates contain nullification certificates for this view?
    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == NullificationKind and v.view == view)
    }

    pure def is_view_nullified_votes(view: ViewNumber, votes: Set[Vote]): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NullifyKind, votes)
            .filter(v => v.block == DUMMY_BLOCK)
            .map(v => v.sig)
            .size() >= M
    }

    // Does a set of certificates contain nullifications certificates for all views in the interval (v1, v2)?
    def are_views_nullified(v1: ViewNumber, v2: ViewNumber, certificates: Set[Certificate]): bool = {
        VIEWS.filter(v => v > v1 and v < v2).forall(v => is_view_nullified(v, certificates))
    }

    // Replica `r` ensures there are nullifications for all views `(view_parent, view)`,
    // and that there is a `notarization(c', view_parent)` for the parent block `c'`.
    def valid_parent(view: ViewNumber, view_parent: ViewNumber, certificates: Set[Certificate]): bool = {
        is_view_notarized(view_parent, certificates) and
            are_views_nullified(view_parent + 1, view - 1, certificates)
    }

    // Create a nullify certificate from a set of votes.
    def create_nullification(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            v.view == view,
            v.kind == NullifyKind,
            v.block == DUMMY_BLOCK
        })
        val votes_count = similar_votes.size()

        if (votes_count < M)
            None
        else
            Some({
                view: view,
                block: DUMMY_BLOCK,
                signatures: similar_votes.map(v => v.sig),
                ghost_sender: id,
                kind: NullificationKind
            })
    }

    def create_notarization(id: ReplicaId,
            view: ViewNumber, block: Block, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            v.view == view,
            v.kind == NotarizeKind,
            v.block == block
        })

        val votes_count = similar_votes.size()
        if (votes_count < M)
            None
        else
            Some({
                view: view,
                block: block,
                signatures: similar_votes.map(v => v.sig),
                ghost_sender: id,
                kind: if (votes_count >= L) FinalizationKind else NotarizationKind
            })
    }

    // Check whether a block cannot be notarized in a view.
    def is_block_in_view_cannot_be_notarized(b: Block, view: ViewNumber, votes: Set[Vote]): bool = {
        val vs1 = votes.filter(v => v.kind == NotarizeKind and v.view == view and v.block != b).map(v => v.sig)
        val vs2 = votes.filter(v => v.kind == NullifyKind and v.view == view).map(v => v.sig)
        vs1.union(vs2).size() >= M
    }

    // Is there a contradiction for the notarized block in the set of votes?
    def is_contradicted(self: ReplicaState, view: ViewNumber, votes: Set[Vote]): bool = {
        val c = self.notarized.get(view)
        if (c != EMPTY_BLOCK)
            is_block_in_view_cannot_be_notarized(c, view, votes)
        else
            false
    }

    // Enter a new view, unless it is older than the current view.
    pure def enter_new_view(self: ReplicaState, cert: Certificate): ReplicaState = {
        val new_view = cert.view + 1
        if (not(VIEWS.contains(new_view)))
            self // no change
        else
            {
                ...self,
                propose_sent: if (self.view < new_view) false else self.propose_sent,
                nullified: if (self.view < new_view) false else self.nullified,
                timer_cancelled: if (self.view < new_view) false else self.timer_cancelled,
                view: 
                    if (self.view < new_view) new_view else self.view,
                last_finalized: 
                    if (self.last_finalized < cert.view and cert.kind == FinalizationKind) cert.view else self.last_finalized,
                ghost_last_seen_notarization:
                    if (self.ghost_last_seen_notarization < cert.view and cert.kind != NullificationKind) cert.view else self.ghost_last_seen_notarization
            }
    }

    // A predicate `is_select_parent(id, pb, pv)` iff `(pb, pv) = select_parent(r, r.view)`.
    def is_select_parent(id: ReplicaId, parent_block: Block, parent_view: ViewNumber): bool = {
        val v = replica_state.get(id).view
        val certs = store_certificate.get(id)
        // note that `valid_parent` is different from the code below
        and {
            // all views in the interval (parent_view, v) are nullified
            VIEWS.forall(i => (parent_view < i and i < v) implies and {
                not(is_view_notarized(i, certs)),
                is_view_nullified(i, certs),
            }),
            // the parent block is notarized in the parent view
            or {
                certs.exists(c => and {
                    c.kind == NotarizationKind or c.kind == FinalizationKind,
                    c.view == parent_view,
                    c.block == parent_block,
                }),
                parent_view < 0 and parent_block == GENESIS_BLOCK,
            }
        }
    }

    // Initialize all replicas with genesis.
    action init = {
        // Non‑deterministically choose any total leader function (View → ReplicaId)
        nondet l = VIEWS.setOfMaps(Replicas).oneOf()
        initWithLeader(l)
    }

    action initWithLeader(l: ViewNumber -> ReplicaId): bool = all {
        replica_state' = CORRECT.mapBy(id => {
            view  : 0,
            ghost_last_seen_notarization: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            notarized: VIEWS.mapBy(_ => EMPTY_BLOCK),
            propose_sent: false,
            nullified: false,
            timer_cancelled: false,
            ghost_sent_votes: VIEWS.mapBy(_ => List())
        }),
        sent_proposal' = Set(),
        sent_vote'    = Set(),
        sent_certificate' = Set(),
        store_vote'   = CORRECT.mapBy(_ => Set()),
        store_certificate'   = CORRECT.mapBy(_ => Set()),
        ghost_committed_blocks' = CORRECT.mapBy(id => List()),
        ghost_proposal' = CORRECT.mapBy(id => Set()),
        leader'       = l
    }

    // A step by a correct or byzantine replica.
    action step = {
        any {
            {
                correct_replica_step
            },
            all {
                nondet id = oneOf(CORRECT)
                // Non-deterministically choose the next block, use it only for the case of None below.
                nondet new_block = oneOf(VALID_BLOCKS)
                // Non-deterministically choose the parent block and parent view (checked in proposer_step)
                nondet parent_block = oneOf(AllBlocks.union(Set(GENESIS_BLOCK)))
                nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
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
        // Non‑deterministically pick one enabled internal action
        any {
            {
                on_timer_expired(id)
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
                on_vote_nullify(id, view, votes)
            },
            {
                nondet view = oneOf(VIEWS)
                on_nullify_by_contradiction(id, view)
            },
            all {
                sent_certificate != Set(),
                nondet cert = oneOf(sent_certificate)
                on_certificate(id, cert)
            },
        },
    }

    // 8.1. A proposer step by the view leader.
    action proposer_step(id: ReplicaId, new_block: Block,
                         parent_block: Block, parent_view: ViewNumber): bool = all {
        val self = replica_state.get(id)

        all {
            id == leader.get(self.view),
            not(self.propose_sent),
            not(self.timer_cancelled),
            // make sure that parent_block and parent_view are chosen according to select_parent
            is_select_parent(id, parent_block, parent_view),

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
                    notarized: self.notarized.put(self.view, new_block),
                    ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(new_block))
                }),
                // "Treat propose(r, c, v, (c', v')) as r's notarize(c, v)"
                sent_vote' = sent_vote.union(Set(notarize(self.view, id, new_block))),
                ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),
                // unchanged
                sent_certificate' = sent_certificate,
                store_vote'    = store_vote,
                store_certificate' = store_certificate,
                leader' = leader,
                ghost_committed_blocks' = ghost_committed_blocks,
            }
        }
    }

    // -------------------------------------------------
    // ── Handle proposal (first valid one wins)
    // -------------------------------------------------

    // 8.2. Notarize
    action on_proposal(id: ReplicaId, proposal: Proposal): bool = all {
        val self = replica_state.get(id)
        val certificates = store_certificate.get(id)
        val notarize_vote = notarize(proposal.view, id, proposal.block)
        all {
            not(self.has_notarized()),
            not(self.nullified),
            // check that the latest block is not dummy block
            proposal.block != DUMMY_BLOCK,
            // Accept only proposals for current view we are working on
            proposal.view == self.view,

            // "If !verify(c, c'), return."
            VALID_BLOCKS.contains(proposal.block),

            // the proposer is the leader of this view
            proposal.sig == sig_of(leader.get(proposal.view)),
            proposal.view_parent < proposal.view,
            proposal.view_parent >= self.last_finalized,

            valid_parent(proposal.view, proposal.view_parent, certificates),

            // Send the notarize vote to all replicas (including ourselves).
            sent_vote' = sent_vote.union(Set(notarize_vote)),
            // Store proposal
            ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),
            replica_state' = replica_state.set(id, {
                ...self,
                notarized: self.notarized.put(self.view, proposal.block),
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(proposal.block))
            }),

            // unchanged
            store_vote'  = store_vote,
            sent_proposal'  = sent_proposal,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
        }
    }

    // -------------------------------------------------
    // ── Handle a subset of received votes
    // -------------------------------------------------

    // 8.6 Nullify by Contradiction
    action on_nullify_by_contradiction(id: ReplicaId, view: ViewNumber): bool = all {
        val self = replica_state.get(id)

        all {
            self.view == view,
            self.has_notarized(),
            not(self.nullified),
            is_contradicted(self, view, store_vote.get(id)),

            sent_vote' = sent_vote.union(Set(nullify(view, id))),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(DUMMY_BLOCK))
            }),

            store_vote' = store_vote,
            ghost_committed_blocks' = ghost_committed_blocks,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            sent_proposal' = sent_proposal,
            leader' = leader,
            ghost_proposal' = ghost_proposal

        }
    }
    
    // 8.4. Notarization & Finalization
    action on_vote_notarize(id: ReplicaId, view: ViewNumber, block: Block, votes: Set[Vote]): bool = all {
        val self = replica_state.get(id)
        val store = store_vote.get(id)
        all {
            votes != Set(),
            votes.forall(v => and {
                // Note, `view` is not the current view of the replica,
                // it is `view` from the input needed to be able pass the concrete view parameter into underlying functions, e.g., `is_view_finalized`.
                v.view == view, v.kind == NotarizeKind, v.block == block,
            }),
            val new_store = store_vote.get(id).union(votes)

            all {
                store_vote' = store_vote.set(id, new_store),

                val certificates = store_certificate.get(id)

                val was_notarized = is_view_notarized(view, certificates) or is_view_notarized_votes(view, store, block)
                val now_notarized = is_view_notarized_votes(view, new_store, block)

                val was_finalized = is_view_finalized(view, certificates) or is_view_finalized_votes(view, store, block)
                val now_finalized = is_view_finalized_votes(view, new_store, block)
                
                val is_new_cert = or {
                    not(was_notarized) and now_notarized,
                    not(was_finalized) and now_finalized,
                }
                
                match create_notarization(id, view, block, new_store) {
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
                ghost_proposal' = ghost_proposal
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
            votes.forall(v => v.view == view and v.kind == NullifyKind and not(v.in(store))),
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
                ghost_proposal' = ghost_proposal
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
            not(cert.in(store_certificate.get(id))),

            or {
                cert.kind == NullificationKind and cert.signatures.size() >= M and not(is_view_nullified(cert.view, certificates)),
                cert.kind == NotarizationKind  and cert.signatures.size() >= M and not(is_view_notarized(cert.view, certificates)),
                cert.kind == FinalizationKind  and cert.signatures.size() >= L and not(is_view_finalized(cert.view, certificates)),
            },
            
            // is_new_cert set to true, because this is a certificate and at this moment the view is not nullified, notarized, or finalized
            _process_certificate(id, cert, true),

            // unchanged
            sent_proposal' = sent_proposal,
            store_vote' = store_vote,
            leader' = leader,
            ghost_proposal' = ghost_proposal
        }
    }

    action _process_certificate(id: ReplicaId, cert: Certificate, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        val should_send_notarize_vote = and {
            self.view == cert.view,
            not(self.has_notarized()),
            not(self.nullified),
            cert.kind == NotarizationKind or cert.kind == FinalizationKind,
            is_new_cert
        }

        all {
            cert.signatures.size() >= M,

            if (is_new_cert) all {
                store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                sent_certificate' = sent_certificate.union(Set(cert)),
            } else all {
                store_certificate' = store_certificate,
                sent_certificate' = sent_certificate,
            },
        
            if (cert.kind == FinalizationKind and cert.view > self.last_finalized and is_new_cert)
                ghost_committed_blocks' = ghost_committed_blocks.setBy(id, old => old.append(cert.block))
            else 
                ghost_committed_blocks' = ghost_committed_blocks
            ,

            val new_self = enter_new_view(self, cert)
            
            if (should_send_notarize_vote) 
                all {
                    sent_vote' = sent_vote.union(Set(notarize(cert.view, id, cert.block))),
                    replica_state' = replica_state.set(id, {
                        ...new_self,
                        notarized: self.notarized.put(cert.view, cert.block),
                        ghost_sent_votes: self.ghost_sent_votes.setBy(cert.view, old => old.append(cert.block))
                    }),
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
        val vote = nullify(self.view, id)

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
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(DUMMY_BLOCK))
            }),

            // unchanged
            sent_proposal'  = sent_proposal,
            store_vote'  = store_vote,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            ghost_proposal' = ghost_proposal
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
            nondet block = AllBlocks.union(Set(DUMMY_BLOCK)).oneOf()
            nondet sig = oneOf(BYZANTINE)
            nondet k = oneOf(Set(NotarizeKind, NullifyKind))
            val votes = senders.map(s => {
                view: view,
                block: block,
                sig: sig,
                kind: k
            })
            sent_vote' = sent_vote.union(votes),
        },
        // Adversary may inject arbitrary certificates.
        all {
            nondet sender = BYZANTINE.oneOf()
            nondet senders = BYZANTINE.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet block = AllBlocks.oneOf()
            nondet kind = oneOf(Set(NotarizeKind, NullifyKind))
            val votes = sent_vote.filter(v => and {
                v.view == view,
                v.block == block,
                v.kind == kind
            })
            nondet agg_sig = votes.map(v => v.sig).union(BYZANTINE).powerset().oneOf()
            val cert_kind = if (kind == NullifyKind) {
                NullificationKind
            } else if (votes.size()>= L) FinalizationKind else NotarizationKind
            val cert = {
                view: view,
                block: block,
                signatures: agg_sig,
                ghost_sender: sender,
                kind: cert_kind
            }
            sent_certificate' = sent_certificate.union(Set(cert))
        },
        // Adversary may inject arbitrary proposal.
        all {
            nondet view_parent = VIEWS.oneOf()
            nondet view = VIEWS.oneOf()
            nondet sig = oneOf(BYZANTINE)
            nondet block = AllBlocks.oneOf()
            nondet block_parent = AllBlocks.oneOf()
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

    // Part of the state that is not touched by the Byzantine validators.
    action _unchanged_replica_state = all {
        ghost_committed_blocks' = ghost_committed_blocks,
        replica_state' = replica_state,
        store_vote'    = store_vote,
        store_certificate' = store_certificate,
        leader' = leader,
        ghost_proposal' = ghost_proposal
    }

    // -------------------------------------------------
    // Invariants
    // -------------------------------------------------

    // Assumptions and thresholds.
    val assumptions_valid = all {
        CORRECT.size() + BYZANTINE.size() == N,
        CORRECT.intersect(BYZANTINE) == Set(),
        N >= 5*F+1,
        2*M <= L + 1, // Liveness guard, prevents equivocation stall.
        M + L > N + F, // Every M-quorum and every L-quorum share at least one honest replica.
    } 

    // No two correct replicas disagree on the committed blocks.
    val agreement = tuples(CORRECT, CORRECT).forall(((p1, p2)) => {
        val blocks1 = ghost_committed_blocks.get(p1)
        val blocks2 = ghost_committed_blocks.get(p2)
        or {
            blocks1.length() > blocks2.length(),
            blocks1.indices().forall(i => blocks1[i] == blocks2[i])
        }
    })

    def votes_seq_correct(votes: List[Block]): bool = {
        (length(votes) == 2 and votes[0]!=DUMMY_BLOCK and votes[1] == DUMMY_BLOCK) or
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
            certs.filter(c => c.kind == NullificationKind).map(c => c.view)
        val views_with_finalization =
            VIEWS.filter(v => AllBlocks.exists(h => is_view_finalized_votes(v, votes, h)))
        views_with_nullification.intersect(views_with_finalization) == Set()
    })

    // No equivocation.
    val no_proposal_equivocation = tuples(sent_proposal, sent_proposal).forall(((m1, m2)) => or {
        not(m1.view == m2.view and m1.sig == m2.sig),
        BYZANTINE.contains(m1.sig),
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
            cert.view >= 0,
            or {
                cert.signatures.size() >= M and (cert.kind == NotarizationKind or cert.kind == NullificationKind),
                cert.signatures.size() >= L and cert.kind == FinalizationKind,
            },
            cert.kind == NotarizationKind or cert.kind == NullificationKind or cert.kind == FinalizationKind,
            (cert.block == DUMMY_BLOCK) iff (cert.kind == NullificationKind),
            VALID_BLOCKS.contains(cert.block) or (cert.block == DUMMY_BLOCK)
        })
    })

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => self.notarized.get(v)!=EMPTY_BLOCK iff has_notarized_view(id, v, sent_vote))
    })

    // Suppose that a block B for some slot v is finalized, then no other block B' for slot v can be finalized.
    val validity = tuples(CORRECT, CORRECT, VIEWS).forall(((id1, id2, v)) => {
        val certs1 = store_certificate.get(id1).filter(c => and {
            c.signatures.size() >= L, c.kind == FinalizationKind, c.view == v
        })
        val certs2 = store_certificate.get(id2).filter(c => and {
            c.signatures.size() >= L, c.kind == FinalizationKind, c.view == v
        })

        or {
            certs1 == Set(),
            certs2 == Set(),
            certs1.map(c => c.block) == certs2.map(c => c.block)
        }
    })

    // If there is a finalized block in a view v, there is no nullification in the same view.
    val no_nullification_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        or {
            AllBlocks.forall(b => not(is_view_finalized_votes(v, votes, b))),
            select_votes(v, NullifyKind, votes)
                .map(vote => vote.sig)
                .size() < M
        }
    })

    // If there is a finalized block in a view v, there is no notarization for another block in the same view.
    val no_notarization_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        AllBlocks.forall(b => or {
            not(is_view_finalized_votes(v, votes, b)),
            select_votes(v, NotarizeKind, votes)
                .filter(vote => vote.block != b)
                .map(vote => vote.sig)
                .size() < M
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

    val correct_nodes_sent_certificates_valid = sent_certificate.filter(cert => cert.ghost_sender.in(CORRECT)).forall(cert => {
        cert.signatures.size() >= M
    })
    val store_certificates_are_valid = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        certs.forall(cert => cert.signatures.size() >= M)
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
        replica_state.get(id).last_finalized >= 0
    }))

    val notarized_example = not(CORRECT.exists(id => {
       replica_state.get(id).ghost_last_seen_notarization >= 0
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
