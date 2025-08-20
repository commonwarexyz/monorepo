module replica {
    import types.* from "./types"
    import defs.* from "./defs"
    import option.* from "./option"

    // Total number of replicas.
    const N: int
    // Maximum number of faulty replicas.
    const F: int
    // Identities of the correct replicas.
    const CORRECT: Set[ReplicaId]
    // Identities of the faulty replicas.
    const FAULTY: Set[ReplicaId]
    // The set of all views.
    const VIEWS: Set[ViewNumber]
    // the set of all blocks
    const VALID_BLOCKS: Set[BlockHash]
    // All replicas.
    pure val Replicas = CORRECT.union(FAULTY)
    
    // Quorums:
    pure val L = N - F;
    pure val M = 2*F + 1;

    // Produce replica's signature
    pure def sig_of(id: str): str = id

    const INVALID_BLOCKS: Set[BlockHash]
    pure val AllBlocks = VALID_BLOCKS.union(INVALID_BLOCKS)

    // The states of the correct replicas
    var replica_state: ReplicaId -> ReplicaState
    // the leader function from the view to the replicas identities
    var leader: ViewNumber -> ReplicaId

    // proposals sent by the replicas, correct and faulty
    var sent_proposal: Set[Proposal]
    // notarize and nullify votes sent by the replicas, correct and faulty
    var sent_vote: Set[Vote]
    // `notarization` and `nullification` messages sent by the replicas, correct and faulty
    var sent_certificate: Set[Certificate]

    // notarize and nullify votes received by the correct replicas
    var store_vote: ReplicaId -> Set[Vote]
    // notarization and nullification certificates received or assembled by the correct replicas
    var store_certificate: ReplicaId -> Set[Certificate]

    // history of received proposals
    var ghost_proposal: ReplicaId -> Set[Proposal]
    // sequences of blocks committed by every correct replica
    var ghost_committed_blocks: ReplicaId -> List[BlockHash]

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

    // Get the block hashes from the certificates that were notarized.
    pure def notarized_blocks(certificates: Set[Certificate]): Set[BlockHash] = {
        certificates.filter(v => v.kind == NotarizationKind).map(v => v.block_hash)
    }

    // Does a set of certificates have a notarization certificate for a view?
    pure def is_view_notarized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == NotarizationKind and v.view == view)
    }

    // Does a set of votes have a quorum of votes for a view?
    pure def is_view_finalized(view: ViewNumber, votes: Set[Vote], block_hash: BlockHash): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NotarizeKind, votes)
            .filter(v => v.block_hash == block_hash)
            .map(v => v.sig)
            .size() >= L
    }

    // Does a set of certificates contain nullification certificates for this view?
    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == NullificationKind and v.view == view)
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
            v.block_hash == DUMMY_BLOCK_HASH
        })
        val votes_count = similar_votes.size()

        if (votes_count < M) {
            None
        } else {
            Some({
                view: view,
                block_hash: DUMMY_BLOCK_HASH,
                signatures: similar_votes.map(v => v.sig),
                ghost_sender: id,
                kind: NullificationKind
            })
        }
    }

    def create_notarization(id: ReplicaId,
            view: ViewNumber, block_hash: BlockHash, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            v.view == view,
            v.kind == NotarizeKind,
            v.block_hash == block_hash
        })

        val votes_count = similar_votes.size()
        if (votes_count < M) {
            None
        } else {
            Some({
                view: view,
                block_hash: block_hash,
                signatures: similar_votes.map(v => v.sig),
                ghost_sender: id,
                kind: NotarizationKind
            })
        }
    }

    // Check whether a block cannot be notarized in a view.
    def is_block_in_view_cannot_be_notarized(b: BlockHash, view: ViewNumber, votes: Set[Vote]): bool = {
        val vs1 = votes.filter(v => v.kind == NotarizeKind and v.view == view and v.block_hash != b).map(v => v.sig)
        val vs2 = votes.filter(v => v.kind == NullifyKind and v.view == view).map(v => v.sig)
        vs1.union(vs2).size() >= M
    }

    // Is there a contradiction for the notarized block in the set of votes?
    def is_contradicted(self: ReplicaState, view: ViewNumber, votes: Set[Vote]): bool = {
        val c = self.notarized.get(view)
        if (c != EMPTY_BLOCK) {
            is_block_in_view_cannot_be_notarized(c, view, votes)
        } else {
            false
        }
    }

    // Replica did not vote for dummy block (in other words, the replica did not complain or did not timeout)
    def replica_did_not_send_nullify(id: ReplicaId, view: ViewNumber): bool = {
        not({ view: view, block_hash: DUMMY_BLOCK_HASH, kind: NullifyKind, sig: id }.in(sent_vote))
    }

    // Has the replica sent a nullify vote for the dummy block?
    def has_replica_sent_nullify(id: ReplicaId, view: ViewNumber): bool = {
        { view: view, kind: NullifyKind, block_hash: DUMMY_BLOCK_HASH, sig: id }.in(sent_vote)
    }

    // Enter a new view, unless it is older than the current view.
    pure def enter_new_view(self: ReplicaState, cert_view: ViewNumber, notarized: bool): ReplicaState = {
        val new_view = cert_view + 1
        if (new_view <= self.view or not(VIEWS.contains(new_view))) {
            self // no change
        } else {
            {
                ...self,
                propose_sent: false,
                nullified: false,
                // TODO: diff: in the spec r.timer = 2Δ;
                timer_cancelled: false,
                view: new_view,
                ghost_last_seen_notarization:
                    if (notarized) cert_view else self.ghost_last_seen_notarization
            }
        }
    }

    // A predicate `is_select_parent(id, pb, pv)` iff `(pb, pv) = select_parent(r, r.view)`.
    def is_select_parent(id: ReplicaId, parent_block: BlockHash, parent_view: ViewNumber): bool = {
        val v = replica_state.get(id).view
        val certs = store_certificate.get(id)
        // note that `valid_parent` is different from the code below
        and {
            // all views in the interval (parent_view, v) are nullified
            VIEWS.forall(i => (parent_view < i and i < v) implies and {
                not(i.is_view_notarized(certs)),
                i.is_view_nullified(certs),
            }),
            // the parent block is notarized in the parent view
            or {
                certs.exists(c => and {
                    c.kind == NotarizationKind,
                    c.view == parent_view,
                    c.block_hash == parent_block,
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
        ghost_committed_blocks' = CORRECT.mapBy(_ => List()),
        ghost_proposal' = CORRECT.mapBy(id => Set()),
        leader'       = l
    }

    // A step by a correct or faulty replica.
    action step = {
        any {
            {
                nondet id = oneOf(CORRECT)
                replica_step(id)
            },
            all {
                nondet id = oneOf(CORRECT)
                // Non-deterministically choose the next block, use it only for the case of None below.
                nondet new_block = oneOf(VALID_BLOCKS)
                // Non-deterministically choose the parent block and parent view (checked in proposer_step)
                nondet parent_block = oneOf(AllBlocks.union(Set(hash(GENESIS_BLOCK))))
                nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
                proposer_step(id, new_block, parent_block, parent_view),
            },
            all {
                faulty_step,
                _unchanged_replica_state,
            }
        }
    }

    // A step by a correct replica, except for the proposer step.
    action replica_step(id: ReplicaId): bool = all {
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
                nondet block_hash = AllBlocks.oneOf()
                on_vote_notarize(id, view, block_hash, votes)
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
    action proposer_step(id: ReplicaId, new_block: BlockHash,
                         parent_block: BlockHash, parent_view: ViewNumber): bool = all {
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
                    ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(hash(new_block)))
                }),
                // "Treat propose(r, c, v, (c', v')) as r's notarize(c, v)"
                sent_vote' = sent_vote.union(Set(notarize(self.view, id, hash(new_block)))),
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
        val notarize_vote = notarize(proposal.view, id, hash(proposal.block))
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
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(hash(proposal.block)))
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
        val certificates = store_certificate.get(id)
        all {
            self.view == view,
            self.has_notarized(),
            not(self.nullified),
            is_contradicted(self, view, store_vote.get(id)),

            sent_vote' = sent_vote.union(Set(nullify(view, id))),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                ghost_sent_votes: self.ghost_sent_votes.setBy(view, old => old.append(DUMMY_BLOCK_HASH))
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
    action on_vote_notarize(id: ReplicaId, view: ViewNumber,
                            block_hash: BlockHash, votes: Set[Vote]): bool = all {
        val self = replica_state.get(id)
        val store = store_vote.get(id)

        all {
            votes != Set(),
            votes.forall(v => and {
                v.view == view, v.kind == NotarizeKind, v.block_hash == block_hash,
            }),
            val new_store = store_vote.get(id).union(votes)

            all {
                store_vote' = store_vote.set(id, new_store),
                // try to create a notarization certificate
                val maybe_cert = create_notarization(id, view, block_hash, new_store)
                val should_send_notarize_vote = self.view == view and is_some(maybe_cert) and not(self.has_notarized()) and not(self.nullified)
                val new_self = match maybe_cert {
                    | Some(cert) => enter_new_view(self, cert.view, true)
                    | None => self
                }

                val was_finalized = self.last_finalized >= view
                val now_finalized = is_view_finalized(view, new_store, block_hash)
                val certificates = store_certificate.get(id)
                all {
                    val is_new_notarization = or {
                        not(is_view_notarized(view, certificates)),
                        not(was_finalized) and now_finalized,
                    }
                    match maybe_cert {
                        | Some(cert) => all {
                            if (is_new_notarization) all {
                                store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                                sent_certificate' = sent_certificate.union(Set(cert)),
                            } else all {
                                store_certificate' = store_certificate,
                                sent_certificate' = sent_certificate,
                            },
                            if (should_send_notarize_vote) all {
                                sent_vote' = sent_vote.union(Set(notarize(view, id, block_hash))),
                            } else all {
                                sent_vote' = sent_vote,
                            }
                        }

                        | None => all {
                            store_certificate' = store_certificate,
                            sent_certificate' = sent_certificate,
                            sent_vote' = sent_vote,
                        }
                    },

                    val self_maybe_notarize = if (should_send_notarize_vote)  {
                    {
                        ...new_self,
                        notarized: self.notarized.put(view, block_hash),
                        ghost_sent_votes: new_self.ghost_sent_votes.setBy(view, old => old.append(block_hash))
                    }
                    } else {
                        new_self
                    }


                    if (not(was_finalized) and now_finalized) {

                        all {
                            ghost_committed_blocks' =
                                ghost_committed_blocks.setBy(id, old => old.append(block_hash)),
                            replica_state' = replica_state.set(id, {
                                ...self_maybe_notarize,
                                last_finalized: view,
                            }),
                        }
                    } else {
                        all {
                            ghost_committed_blocks' = ghost_committed_blocks,
                            replica_state' = replica_state.set(id, self_maybe_notarize),
                        }
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
                val is_new_nullification = not(is_view_nullified(view, certificates))
                match create_nullification(id, view, new_store) {
                    | Some(cert) => all {
                        if (is_new_nullification) all {
                            store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                            sent_certificate' = sent_certificate.union(Set(cert)),
                        } else all {
                            store_certificate' = store_certificate,
                            sent_certificate' = sent_certificate,
                        },
                        val new_self = enter_new_view(self, cert.view, false)
                        replica_state' = replica_state.set(id, new_self)
                    }
                    | None => all {
                        store_certificate' = store_certificate,
                        sent_certificate' = sent_certificate,
                        replica_state' = replica_state
                    }
                },
                ghost_committed_blocks' = ghost_committed_blocks,
                sent_vote' = sent_vote,
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
            // verify view
            cert.view >= self.view, // not in spec
            // verify certificate: Certificate of ≥ M notarize(c, v) or nullify(v) messages
            cert.signatures.size() >= M,
            // Store the certificate if we do not have already had it.
            //not(cert.in(store_certificate.get(id))),
            _process_certificate(id, certificates, cert),

            // unchanged
            sent_proposal'  = sent_proposal,
            store_vote'    = store_vote,
            leader' = leader,
            ghost_proposal' = ghost_proposal
        }
    }

    action _process_certificate(id: ReplicaId, certificates: Set[Certificate], cert: Certificate): bool = all {
        val self = replica_state.get(id)
        all {
            not(cert.in(store_certificate.get(id))),

            if (not(
                (cert.kind == NotarizationKind and is_view_notarized(cert.view, certificates))
                or
                (cert.kind == NullificationKind and is_view_nullified(cert.view, certificates))
            )) {
                all {
                    store_certificate' = store_certificate.setBy(id, old => old.union(Set(cert))),
                    sent_certificate' = sent_certificate.union(Set(cert)),
                    val new_self = enter_new_view(self, cert.view, cert.kind == NotarizationKind)
                    if (cert.kind == NotarizationKind and not(self.has_notarized()) and not(self.nullified)) all {
                        sent_vote' = sent_vote.union(Set(notarize(cert.view, id, cert.block_hash))),
                        replica_state' = replica_state.set(id, {
                            ...new_self,
                            notarized: self.notarized.put(cert.view, cert.block_hash),
                            ghost_sent_votes: self.ghost_sent_votes.setBy(cert.view, old => old.append(cert.block_hash))
                        })
                    } else all {
                        sent_vote' = sent_vote,
                        replica_state' = replica_state.set(id, new_self)
                    },

                }

            } else {
                all {
                    store_certificate' = store_certificate,
                    sent_certificate' = sent_certificate,
                    replica_state' = replica_state,
                    sent_vote' = sent_vote,
                }
            },
            ghost_committed_blocks' = ghost_committed_blocks,
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
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(DUMMY_BLOCK_HASH))
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

    action faulty_step: bool = all {
        FAULTY != Set(),

        // Adversary may inject arbitrary well-typed vote messages.
        all {
            nondet senders = FAULTY.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet block_hash = AllBlocks.union(Set(DUMMY_BLOCK_HASH)).oneOf()
            nondet sig = oneOf(FAULTY)
            nondet k = oneOf(Set(NotarizeKind, NullifyKind))
            val votes = senders.map(s => {
                view: view,
                block_hash: block_hash,
                sig: sig,
                kind: k
            })
            sent_vote' = sent_vote.union(votes),
        },
        // Adversary may inject arbitrary certificates.
        all {
            nondet sender = FAULTY.oneOf()
            nondet senders = FAULTY.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet block_hash = AllBlocks.oneOf()
            nondet sig = oneOf(FAULTY)
            nondet kind = oneOf(Set(NotarizationKind, NullificationKind))
            val votes = sent_vote.filter(v => and {
                v.view == view,
                v.block_hash == block_hash,
                v.kind == kind
            })
            nondet agg_sig = votes.map(v => v.sig).union(FAULTY).powerset().oneOf()
            val cert = {
                view: view,
                block_hash: block_hash,
                signatures: agg_sig,
                ghost_sender: sender,
                kind: kind
            }
            sent_certificate' = sent_certificate.union(Set(cert))
        },
        // Adversary may inject arbitrary proposal.
        all {
            nondet view_parent = VIEWS.oneOf()
            nondet view = VIEWS.oneOf()
            nondet sig = oneOf(FAULTY)
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
        CORRECT.size() + FAULTY.size() == N,
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

    def votes_seq_correct(votes: List[BlockHash]): bool = {
        (length(votes) == 2 and votes[0]!=DUMMY_BLOCK_HASH and votes[1] == DUMMY_BLOCK_HASH) or
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
            VIEWS.filter(v => AllBlocks.exists(h => is_view_finalized(v, votes, h)))
        views_with_nullification.intersect(views_with_finalization) == Set()
    })

    // No equivocation.
    val no_proposal_equivocation = tuples(sent_proposal, sent_proposal).forall(((m1, m2)) => or {
        not(m1.view == m2.view and m1.sig == m2.sig),
        FAULTY.contains(m1.sig),
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
            cert.signatures.size() >= M,
            cert.kind == NotarizationKind or cert.kind == NullificationKind,
            (cert.block_hash == DUMMY_BLOCK_HASH) iff (cert.kind == NullificationKind),
            VALID_BLOCKS.contains(cert.block_hash) or (cert.block_hash == DUMMY_BLOCK_HASH)
        })
    })

    val notarized_consistence = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => self.notarized.get(v)!=EMPTY_BLOCK iff has_notarized_view(id, v, sent_vote))
    })

    // Suppose that a block B for some slot v is finalized, then no other block B' for slot v can be finalized.
    val validity = tuples(CORRECT, CORRECT, VIEWS).forall(((id1, id2, v)) => {
        val certs1 = store_certificate.get(id1).filter(c => and {
            c.signatures.size() >= L, c.kind == NotarizationKind, c.view == v
        })
        val certs2 = store_certificate.get(id2).filter(c => and {
            c.signatures.size() >= L, c.kind == NotarizationKind, c.view == v
        })

        or {
            certs1 == Set(),
            certs2 == Set(),
            certs1.map(c => c.block_hash) == certs2.map(c => c.block_hash)
        }
    })

    // If there is a finalized block in a view v, there is no nullification in the same view.
    val no_nullification_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        or {
            AllBlocks.forall(b => not(is_view_finalized(v, votes, b))),
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
            not(is_view_finalized(v, votes, b)),
            select_votes(v, NotarizeKind, votes)
                .filter(vote => vote.block_hash != b)
                .map(vote => vote.sig)
                .size() < M
        })
    })

    val safe_finalization = all {
        no_notarization_in_finalized_view,
        no_nullification_in_finalized_view
    }

    val new_notarizations_only = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        VIEWS.forall(v => certs.filter(cert=>cert.view == v and cert.kind==NullificationKind).size()<=1) and
        VIEWS.forall(v => certs.filter(cert=>cert.view == v and cert.kind==NotarizationKind).size()<=1)
    })

    val all_invariants = all {
        no_proposal_equivocation,
        agreement,
        no_vote_equivocation_inv,
        no_nullification_and_finalization_in_the_same_view,
        validity,
        valid_last_finalized,
        certificates_are_valid_inv,
        notarized_consistence,
        safe_finalization,
        new_notarizations_only
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