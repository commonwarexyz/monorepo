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
    // sequences of committed proposals for every correct replica
    var ghost_committed_blocks: ReplicaId -> List[Proposal]

    // Filter votes by view and kind.
    pure def select_votes(view: ViewNumber, kind: Kind, votes: Set[Vote]): Set[Vote] = {
        votes.filter(v => v.kind == kind and v.view == view)
    }

    // The vote a replica casts on adopting a certificate's proposal. The None branch is
    // unreachable: `should_send_notarize_vote` only fires for a notarization or finalization.
    pure def cert_notarize_vote(id: ReplicaId, c: Certificate): Vote = {
        match c.proposal {
            | Some(p) => notarize(p, sig_of(id))
            | None => nullify(c.view, sig_of(id))
        }
    }

    // Has a replica notarized a proposal in the current view?
    def has_notarized(r: ReplicaState): bool = {
        r.notarized.get(r.view) != None
    }

    def has_notarized_view(id: ReplicaId, view:ViewNumber, votes: Set[Vote]): bool = {
        votes.exists(v=> v.view == view and v.kind == NotarizeKind and v.sig == sig_of(id))
    }

    // Does a set of certificates have a notarization certificate for a view?
    pure def is_view_notarized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == NotarizationKind and v.view == view),
        certificates.exists(v => v.kind == FinalizationKind and v.view == view)
    }

    // Does a set of votes contain an M-quorum for this exact proposal? Votes are counted per
    // proposal, not per (block, view): two proposals naming the same block with different
    // parents are different proposals, so their votes never join the same quorum.
    pure def is_proposal_notarized_votes(p: Proposal, votes: Set[Vote]): bool = {
        select_votes(p.view, NotarizeKind, votes)
            .filter(v => v.proposal == Some(p))
            .map(v => v.sig)
            .size() >= M
    }

    // Does a set of certificates already certify this exact proposal? minimmit.md 9.2 allows
    // several `notarization(*, v)` in one view, so freshness is judged per proposal: a
    // notarization for a second proposal in a view that already has one is still new, and
    // must be stored and rebroadcast rather than silently dropped.
    pure def is_proposal_certified(p: Option[Proposal], certificates: Set[Certificate]): bool = {
        certificates.exists(c => and {
            c.kind == NotarizationKind or c.kind == FinalizationKind,
            c.proposal == p,
        })
    }

    pure def is_proposal_finalized(p: Option[Proposal], certificates: Set[Certificate]): bool = {
        certificates.exists(c => c.kind == FinalizationKind and c.proposal == p)
    }

    pure def is_view_finalized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == FinalizationKind and v.view == view)
    }

    // Does a set of votes contain an L-quorum for this exact proposal?
    pure def is_proposal_finalized_votes(p: Proposal, votes: Set[Vote]): bool = {
        select_votes(p.view, NotarizeKind, votes)
            .filter(v => v.proposal == Some(p))
            .map(v => v.sig)
            .size() >= L
    }

    // Does a set of votes finalize some proposal in this view?
    pure def is_view_finalized_votes(view: ViewNumber, votes: Set[Vote]): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NotarizeKind, votes)
            .exists(v => v.proposal.option_has(p => is_proposal_finalized_votes(p, votes)))
    }

    // Does a set of certificates contain nullification certificates for this view?
    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(v => v.kind == NullificationKind and v.view == view)
    }

    pure def is_view_nullified_votes(view: ViewNumber, votes: Set[Vote]): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NullifyKind, votes)
            .map(v => v.sig)
            .size() >= M
    }

    // Does a set of certificates contain nullifications certificates for all views in the interval (v1, v2)?
    def are_views_nullified(v1: ViewNumber, v2: ViewNumber, certificates: Set[Certificate]): bool = {
        VIEWS.filter(v => v > v1 and v < v2).forall(v => is_view_nullified(v, certificates))
    }

    // Replica `r` ensures there are nullifications for all views `(v', v)`, and that there is
    // a `notarization(c', v')` for the parent block `c'` -- for that exact block, not merely
    // for the view. minimmit.md 7 says the proof is `notarization(c', v') in r.proofs[v']`,
    // and 8.2 additionally requires `verify(c, c')`; carrying the parent in the proposal is
    // what lets this be checked at all.
    def valid_parent(proposal: Proposal, certificates: Set[Certificate]): bool = and {
        or {
            proposal.view_parent == GENESIS_VIEW and proposal.block_parent == GENESIS_BLOCK,
            certificates.exists(c => and {
                c.kind == NotarizationKind or c.kind == FinalizationKind,
                c.view == proposal.view_parent,
                c.proposal.option_has(pp => pp.block == proposal.block_parent),
            }),
        },
        are_views_nullified(proposal.view_parent, proposal.view, certificates),
    }

    // The unique finalized proposal that extends the committed chain whose tip is `tip`,
    // provided every view skipped in between is nullified.
    //
    // The parent link is read off the certificate's own proposal, so it is fixed when the
    // block is proposed and cannot be changed afterwards. Deriving it instead from the
    // global `sent_proposal` made it a moving target: that set is never pruned, so a later
    // proposal naming the same block with a different parent could retract a block that had
    // already been committed.
    def next_committable_cert(tip: Proposal, certificates: Set[Certificate]): Option[Certificate] = {
        val candidates = certificates.filter(c => and {
            c.kind == FinalizationKind,
            c.view > tip.view,
            c.proposal.option_has(p => p.view_parent == tip.view and p.block_parent == tip.block),
            are_views_nullified(tip.view, c.view, certificates),
        })
        if (candidates.size() == 1)
            candidates.fold(None, (_acc, c) => Some(c))
        else
            None
    }

    // Rebuild the committed chain from the locally stored certificates, walking forward
    // from genesis. This is how "finalize `c` and all of its ancestors" (minimmit.md 8.4)
    // is realized: a replica that never learned an ancestor's finalization, or that is
    // missing a nullification covering a gap, simply cannot commit past it.
    // Folding over VIEWS is enough, since the chain grows by at most one block per step.
    def rebuild_committed_chain(certificates: Set[Certificate]): List[Proposal] = {
        VIEWS.fold((List(), GENESIS_PROPOSAL), (acc, _view) =>
            match next_committable_cert(acc._2, certificates) {
                | Some(c) => match c.proposal {
                    | Some(p) => (acc._1.append(p), p)
                    | None => acc
                  }
                | None => acc
            }
        )._1
    }

    // Create a nullify certificate from a set of votes.
    def create_nullification(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            v.view == view,
            v.kind == NullifyKind
        })
        val votes_count = similar_votes.size()

        if (votes_count < M)
            None
        else
            Some({
                view: view,
                proposal: None,
                signatures: similar_votes.map(v => v.sig),
                ghost_sender: id,
                kind: NullificationKind
            })
    }

    // Assemble a certificate for one proposal. The quorum is "same proposal", not
    // "same block and view".
    def create_notarization(id: ReplicaId,
            proposal: Proposal, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            v.kind == NotarizeKind,
            v.proposal == Some(proposal)
        })

        val votes_count = similar_votes.size()
        if (votes_count < M)
            None
        else
            Some({
                view: proposal.view,
                proposal: Some(proposal),
                signatures: similar_votes.map(v => v.sig),
                ghost_sender: id,
                kind: if (votes_count >= L) FinalizationKind else NotarizationKind
            })
    }

    // Check whether a proposal cannot be notarized in a view. A notarize vote for a
    // different proposal conflicts even when it names the same block, because the two
    // proposals build on different parents and their votes never join one quorum.
    def is_proposal_in_view_cannot_be_notarized(p: Proposal, view: ViewNumber, votes: Set[Vote]): bool = {
        val vs1 = votes.filter(v => and {
            v.kind == NotarizeKind,
            v.view == view,
            v.proposal != Some(p),
        }).map(v => v.sig)
        val vs2 = votes.filter(v => v.kind == NullifyKind and v.view == view).map(v => v.sig)
        vs1.union(vs2).size() >= M
    }

    // Is there a contradiction for the notarized proposal in the set of votes?
    def is_contradicted(self: ReplicaState, view: ViewNumber, votes: Set[Vote]): bool = {
        match self.notarized.get(view) {
            | Some(p) => is_proposal_in_view_cannot_be_notarized(p, view, votes)
            | None => false
        }
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
            parent_view < v,
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
                    c.proposal.option_has(p => p.block == parent_block),
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
            notarized: VIEWS.mapBy(_ => None),
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
            correct_step,
            all {
                byzantine_replica_step,
                _unchanged_replica_state,
            }
        }
    }

    action correct_step = any {
            correct_replica_step,
        all {
            nondet id = oneOf(CORRECT)
            // Non-deterministically choose the next block, use it only for the case of None below.
            nondet new_block = oneOf(VALID_BLOCKS)
            // Non-deterministically choose the parent block and parent view (checked in proposer_step)
            nondet parent_block = oneOf(AllBlocks.union(Set(GENESIS_BLOCK)))
            nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            proposer_step(id, new_block, parent_block, parent_view),
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
            all {
                sent_proposal != Set(),
                nondet votes = oneOf(powerset(sent_vote))
                nondet p = oneOf(sent_proposal)
                on_vote_notarize(id, p, votes)
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
            sig_of(id) == sig_of(leader.get(self.view)),
            not(self.propose_sent),
            not(self.has_notarized()),
            not(self.nullified),
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
        val notarize_vote = notarize(proposal, sig_of(id))
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

            valid_parent(proposal, certificates),

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
            ghost_proposal' = ghost_proposal

        }
    }

    // 8.4. Notarization & Finalization
    action on_vote_notarize(id: ReplicaId, proposal: Proposal, votes: Set[Vote]): bool = all {
        val self = replica_state.get(id)
        val store = store_vote.get(id)
        val view = proposal.view
        all {
            votes != Set(),
            votes.forall(v => and {
                // Note, `proposal.view` is not the current view of the replica; the votes
                // are all for one proposal, which is what a quorum is counted over.
                v.kind == NotarizeKind, v.proposal == Some(proposal),
            }),
            val new_store = store_vote.get(id).union(votes)

            all {
                store_vote' = store_vote.set(id, new_store),

                val certificates = store_certificate.get(id)

                val was_notarized = is_proposal_certified(Some(proposal), certificates) or is_proposal_notarized_votes(proposal, store)
                val now_notarized = is_proposal_notarized_votes(proposal, new_store)

                val was_finalized = is_proposal_finalized(Some(proposal), certificates) or is_proposal_finalized_votes(proposal, store)
                val now_finalized = is_proposal_finalized_votes(proposal, new_store)

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
                cert.kind == NotarizationKind  and cert.signatures.size() >= M and not(is_proposal_certified(cert.proposal, certificates)),
                cert.kind == FinalizationKind  and cert.signatures.size() >= L and not(is_proposal_finalized(cert.proposal, certificates)),
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
        val next_certs = if (is_new_cert)
            store_certificate.get(id).union(Set(cert))
        else
            store_certificate.get(id)
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
                store_certificate' = store_certificate.set(id, next_certs),
                sent_certificate' = sent_certificate.union(Set(cert)),
            } else all {
                store_certificate' = store_certificate,
                sent_certificate' = sent_certificate,
            },

            // The committed chain is derived from the stored certificates rather than
            // accumulated, so it cannot drift from them: it never depends on the order
            // certificates arrive in, and never records a block whose ancestry is missing.
            ghost_committed_blocks' = if (is_new_cert)
                ghost_committed_blocks.set(id, rebuild_committed_chain(next_certs))
            else
                ghost_committed_blocks,

            val new_self = enter_new_view(self, cert)

            if (should_send_notarize_vote)
                all {
                    sent_vote' = sent_vote.union(Set(cert_notarize_vote(id, cert))),
                    replica_state' = replica_state.set(id, {
                        ...new_self,
                        notarized: self.notarized.put(cert.view, cert.proposal),
                        ghost_sent_votes: self.ghost_sent_votes.setBy(cert.view, old => old.append(cert.proposal))
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
            ghost_proposal' = ghost_proposal
        }
    }

    // -------------------------------------------------
    // Byzantine behavior (completely adversarial)
    // -------------------------------------------------

    action byzantine_replica_step: bool = all {
        BYZANTINE != Set(),

        // Adversary may inject arbitrary well-typed vote messages. A notarize vote is for
        // some proposal that exists; the adversary can first inject any proposal it likes.
        all {
            nondet senders = BYZANTINE.powerset().oneOf()
            nondet view = VIEWS.oneOf()
            nondet p = oneOf(sent_proposal.union(Set(GENESIS_PROPOSAL)))
            nondet k = oneOf(Set(NotarizeKind, NullifyKind))
            val votes = senders.map(sender =>
                if (k == NullifyKind) nullify(view, sig_of(sender)) else notarize(p, sig_of(sender)))
            sent_vote' = sent_vote.union(votes),
        },
        // Adversary may inject arbitrary certificates.
        all {
            nondet sender = BYZANTINE.oneOf()
            nondet view = VIEWS.oneOf()
            nondet p = oneOf(sent_proposal.union(Set(GENESIS_PROPOSAL)))
            nondet kind = oneOf(Set(NotarizeKind, NullifyKind))
            val cert_view = if (kind == NullifyKind) view else p.view
            val cert_prop = if (kind == NullifyKind) None else Some(p)
            val votes = sent_vote.filter(v => and {
                v.view == cert_view,
                v.proposal == cert_prop,
                v.kind == kind
            })
            nondet agg_sig = votes.map(v => v.sig).union(BYZANTINE.map(id => sig_of(id))).powerset().oneOf()
            val cert_kind = if (kind == NullifyKind) {
                NullificationKind
            } else if (agg_sig.size()>= L) FinalizationKind else NotarizationKind
            val cert = {
                view: cert_view,
                proposal: cert_prop,
                signatures: agg_sig,
                ghost_sender: sender,
                kind: cert_kind
            }
            sent_certificate' = sent_certificate.union(Set(cert))
        },
        // Adversary may inject arbitrary proposal.
        all {
            nondet view_parent = oneOf(VIEWS.union(Set(GENESIS_VIEW)))
            nondet view = oneOf(VIEWS.union(Set(GENESIS_VIEW)))
            nondet byz = oneOf(BYZANTINE)
            nondet block = oneOf(AllBlocks.union(Set(GENESIS_BLOCK)))
            nondet block_parent = oneOf(AllBlocks.union(Set(GENESIS_BLOCK)))
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
        ghost_proposal' = ghost_proposal
    }

    // -------------------------------------------------
    // Invariants
    // -------------------------------------------------

    // Assumptions and thresholds.
    val assumptions_valid = all {
        CORRECT.size() + BYZANTINE.size() == N,
        BYZANTINE.size() <= F,
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

    def votes_seq_correct(votes: List[Option[Proposal]]): bool = {
        (length(votes) == 2 and votes[0] != None and votes[1] == None) or
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
            VIEWS.filter(v => is_view_finalized_votes(v, votes))
        views_with_nullification.intersect(views_with_finalization) == Set()
    })

    // No equivocation. A leader may send only one proposal per view, and the whole proposal
    // is compared, not just its block: since the parent is part of what is signed, the same
    // block offered with a different parent is a different proposal, and sending both is
    // equivocation. `m1.view == m2.view and m1.sig == m2.sig` already hold in this branch, so
    // `m1 == m2` amounts to comparing (block, block_parent, view_parent).
    val no_proposal_equivocation = tuples(sent_proposal, sent_proposal).forall(((m1, m2)) => or {
        not(m1.view == m2.view and m1.sig == m2.sig),
        Replicas.exists(r => sig_of(r) == m1.sig and BYZANTINE.contains(r)),
        Replicas.filter(r => sig_of(r) == m1.sig).size() > 1, // twins mode enabled
        m1 == m2,
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
            (cert.proposal == None) iff (cert.kind == NullificationKind),
            cert.proposal.option_has(p => VALID_BLOCKS.contains(p.block) and p.view == cert.view)
                or (cert.kind == NullificationKind)
        })
    })

    // The signatures a certificate could legitimately carry. An honest signature must
    // correspond to a vote that replica actually broadcast; a byzantine replica may sign
    // anything, so its own identities are always admissible.
    //
    // Backing is taken from `sent_vote` alone, deliberately. `store_vote` is not consulted:
    // `on_vote_notarize` and `on_vote_nullify` accept a vote set by shape, exactly as
    // `on_certificate` accepts a certificate by shape, so counting stored votes as cast
    // would let the same forgery move down one layer -- hand a replica forged honest votes
    // and any certificate built from them becomes "backed". Under `step` this costs nothing,
    // because `correct_replica_step` draws votes from `powerset(sent_vote)` and a store is
    // therefore always a subset of what was broadcast.
    def cert_backing(cert: Certificate): Set[Signature] = {
        val votes = if (cert.kind == NullificationKind)
            select_votes(cert.view, NullifyKind, sent_vote)
        else
            select_votes(cert.view, NotarizeKind, sent_vote).filter(v => v.proposal == cert.proposal)
        votes.map(v => v.sig).union(BYZANTINE.map(id => sig_of(id)))
    }

    // Certificate signatures cannot be forged. `on_certificate` accepts a certificate by its
    // shape alone: kind, number of signatures, and block validity. It never checks that the
    // signatures belong to replicas that really voted, so it depends on this property being
    // true. Two places make it true: `byzantine_replica_step`, which builds `agg_sig` from
    // the signatures of real votes plus BYZANTINE, and `create_notarization` /
    // `create_nullification`, which build `signatures` from votes the replica observed.
    //
    // If a later change ever lets a certificate with unbacked signatures reach a replica,
    // two steps are enough to store finalizations for two different blocks in the same view
    // and break `validity`. See `forgedFinalizationCertificatesViolateValidityTest`.
    val certificates_are_backed = and {
        sent_certificate.forall(cert => cert.signatures.subseteq(cert_backing(cert))),
        CORRECT.forall(id =>
            store_certificate.get(id).forall(cert => cert.signatures.subseteq(cert_backing(cert)))),
    }

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => self.notarized.get(v) != None iff has_notarized_view(id, v, sent_vote))
    })

    // Suppose that a proposal is finalized for some view v, then no other proposal for view v
    // can be finalized -- neither at the same replica nor at any other one.
    //
    // Stated as global uniqueness rather than as pairwise agreement between two replicas.
    // Agreement is implied by uniqueness but does not imply it: two replicas that both hold
    // the same pair of conflicting finalizations agree, and a single replica trivially agrees
    // with itself. `validity` has to stand on its own, because it is verified in a job of its
    // own (`scripts/invariant.sh` runs one invariant per job) and cannot lean on
    // `certificates_are_backed` being checked alongside it.
    //
    // The comparison is on the whole proposal, not just its block: a block offered with a
    // different parent is a different proposal (see `no_proposal_equivocation`).
    val validity = VIEWS.forall(v => {
        val finalized_proposals = CORRECT.fold(Set(), (acc, id) =>
            acc.union(store_certificate.get(id)
                .filter(c => and {
                    c.kind == FinalizationKind,
                    c.signatures.size() >= L,
                    c.view == v,
                })
                .map(c => c.proposal)))
        finalized_proposals.size() <= 1
    })

    // If there is a finalized block in a view v, there is no nullification in the same view.
    val no_nullification_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        or {
            not(is_view_finalized_votes(v, votes)),
            select_votes(v, NullifyKind, votes)
                .map(vote => vote.sig)
                .size() < M
        }
    })

    // If there is a finalized block in a view v, there is no notarization for another block in the same view.
    val no_notarization_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val self = replica_state.get(id)
        val votes = store_vote.get(id)
        select_votes(v, NotarizeKind, votes).forall(fin_vote => or {
            not(fin_vote.proposal.option_has(p => is_proposal_finalized_votes(p, votes))),
            select_votes(v, NotarizeKind, votes)
                .filter(vote => vote.proposal != fin_vote.proposal)
                .map(vote => vote.sig)
                .size() < M
        })
    })

    val safe_finalization = all {
        no_notarization_in_finalized_view,
        no_nullification_in_finalized_view
    }

    // Every committed block must come from a finalization certificate stored locally.
    // This pins down the derived chain: it catches a `rebuild_committed_chain` that
    // invents links the replica cannot justify.
    val committed_blocks_are_finalized = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        val certs = store_certificate.get(id)
        chain.indices().forall(i => certs.exists(c => and {
            c.kind == FinalizationKind,
            c.proposal == Some(chain[i]),
        }))
    })

    // Every committed proposal builds on the one committed before it, and the first builds
    // on genesis. The chain is a real chain, not just a list of finalized blocks.
    val committed_chain_is_connected = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        chain.indices().forall(i => {
            val parent = if (i == 0) GENESIS_PROPOSAL else chain[i - 1]
            and {
                chain[i].view_parent == parent.view,
                chain[i].block_parent == parent.block,
            }
        })
    })

    // No view carries both a nullification and a finalization certificate -- not even in two
    // different replicas' stores. This is what makes the committed sequence the same at
    // every correct replica, and so it is what `agreement` rests on: if one replica commits
    // the finalization of view v1 and another commits a later view v2 rooted at the same
    // parent, the second must hold a nullification for v1, since the gap (parent, v2) covers
    // it. The per-replica form of this check would be true in exactly that state, which is
    // why it is quantified across all stored certificates.
    val no_nullification_and_finalization_globally = {
        val all_certs = CORRECT.fold(Set(), (acc, id) => acc.union(store_certificate.get(id)))
        val nullified = all_certs.filter(c => c.kind == NullificationKind).map(c => c.view)
        val finalized = all_certs.filter(c => c.kind == FinalizationKind).map(c => c.view)
        nullified.intersect(finalized) == Set()
    }

    val all_invariants = all {
        no_proposal_equivocation,
        agreement,
        no_vote_equivocation_inv,
        no_nullification_and_finalization_in_the_same_view,
        validity,
        valid_last_finalized,
        certificates_are_valid_inv,
        certificates_are_backed,
        notarized_consistency,
        safe_finalization,
        committed_blocks_are_finalized,
        committed_chain_is_connected,
        no_nullification_and_finalization_globally,
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
