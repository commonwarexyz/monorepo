module replica {
    import types.* from "./types"
    import defs.* from "./defs"
    import option.* from "./option"

    // Total number of replicas.
    const N: int
    // Maximum number of byzantine(faulty) replicas.
    const F: int
    // Identities with local replica state and correct-style transitions.
    const REPLICA_IDS: Set[ReplicaId]
    // Identities of the honest replicas checked by the safety invariants.
    const CORRECT: Set[ReplicaId]
    // Identities of the byzantine replicas.
    const BYZANTINE: Set[ReplicaId]
    // Twin actors run correct-style transitions but represent faulty logical replicas.
    const TWINS: Set[ReplicaId]
    // The set of all views.
    const VIEWS: Set[ViewNumber]
    // the set of all blocks
    const VALID_BLOCKS: Set[Block]
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

    pure val CORRECT_KEYS = CORRECT.map(id => sig_of(id))
    pure val FAULTY_KEYS = BYZANTINE.union(TWINS).map(id => sig_of(id))

    const INVALID_BLOCKS: Set[Block]
    pure val AllBlocks = VALID_BLOCKS.union(INVALID_BLOCKS)

    // The states of the local correct-style actors
    var replica_state: ReplicaId -> ReplicaState
    // the leader function from the view to the replicas identities
    var leader: ViewNumber -> ReplicaId

    // proposals sent by the replicas, correct and byzantine
    var sent_proposal: Set[Proposal]
    // notarize and nullify votes sent by the replicas, correct and byzantine
    var sent_vote: Set[Vote]
    // `notarization` and `nullification` messages sent by the replicas, correct and byzantine
    var sent_certificate: Set[Certificate]

    // notarize and nullify votes received by the local correct-style actors
    var store_vote: ReplicaId -> Set[Vote]
    // notarization and nullification certificates received or assembled by the local correct-style actors
    var store_certificate: ReplicaId -> Set[Certificate]

    // history of received proposals
    var ghost_proposal: ReplicaId -> Set[Proposal]
    // sequences of committed proposals for every local correct-style actor
    var ghost_committed_blocks: ReplicaId -> List[Proposal]

    pure def vote_kind(vote: Vote): Kind = {
        match vote {
            | Notarize(_) => NotarizeKind
            | Nullify(_) => NullifyKind
        }
    }

    pure def vote_view(vote: Vote): ViewNumber = {
        match vote {
            | Notarize(v) => v.proposal.view
            | Nullify(v) => v.view
        }
    }

    pure def vote_sig(vote: Vote): Signature = {
        match vote {
            | Notarize(v) => v.sig
            | Nullify(v) => v.sig
        }
    }

    pure def vote_proposal(vote: Vote): Option[Proposal] = {
        match vote {
            | Notarize(v) => Some(v.proposal)
            | Nullify(_) => None
        }
    }

    pure def cert_view(cert: Certificate): ViewNumber = {
        match cert {
            | Notarization(c) => c.proposal.view
            | Nullification(c) => c.view
        }
    }

    pure def cert_signatures(cert: Certificate): Set[Signature] = {
        match cert {
            | Notarization(c) => c.signatures
            | Nullification(c) => c.signatures
        }
    }

    pure def cert_ghost_sender(cert: Certificate): Signature = {
        match cert {
            | Notarization(c) => c.ghost_sender
            | Nullification(c) => c.ghost_sender
        }
    }

    pure def cert_proposal(cert: Certificate): Option[Proposal] = {
        match cert {
            | Notarization(c) => Some(c.proposal)
            | Nullification(_) => None
        }
    }

    pure def cert_kind(cert: Certificate): Kind = {
        match cert {
            | Notarization(c) =>
                if (c.signatures.size() >= L) FinalizationKind else NotarizationKind
            | Nullification(_) => NullificationKind
        }
    }

    // Filter votes by view and kind.
    pure def select_votes(view: ViewNumber, kind: Kind, votes: Set[Vote]): Set[Vote] = {
        votes.filter(v => vote_kind(v) == kind and vote_view(v) == view)
    }

    // Has a replica notarized a proposal in the current view?
    def has_notarized(r: ReplicaState): bool = {
        r.notarized.get(r.view) != None
    }

    def has_notarized_view(id: ReplicaId, view:ViewNumber, votes: Set[Vote]): bool = {
        votes.exists(v => and {
            vote_view(v) == view,
            vote_kind(v) == NotarizeKind,
            vote_sig(v) == sig_of(id),
        })
    }

    // Does a set of certificates have a notarization certificate for a view?
    // The `>= M` threshold is explicit so this helper is self-contained: `cert_kind` classifies a
    // Notarization of any size below L as NotarizationKind, so without the bound an under-threshold
    // certificate would count as a notarization.
    pure def is_view_notarized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c => and {
            cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
            cert_signatures(c).size() >= M,
            cert_view(c) == view,
        })
    }

    // Does a set of votes contain an M-quorum for this exact proposal? Votes are counted per
    // proposal, not per (block, view): two proposals naming the same block with different
    // parents are different proposals, so their votes never join the same quorum.
    pure def is_proposal_notarized_votes(p: Proposal, votes: Set[Vote]): bool = {
        select_votes(p.view, NotarizeKind, votes)
            .filter(v => vote_proposal(v) == Some(p))
            .map(v => vote_sig(v))
            .size() >= M
    }

    // Does a set of certificates already certify this exact proposal? minimmit.md 9.2 allows
    // several `notarization(*, v)` in one view, so freshness is judged per proposal: a
    // notarization for a second proposal in a view that already has one is still new, and
    // must be stored and rebroadcast rather than silently dropped.
    pure def is_proposal_certified(p: Option[Proposal], certificates: Set[Certificate]): bool = {
        certificates.exists(c => and {
            cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
            cert_proposal(c) == p,
        })
    }

    pure def is_proposal_finalized(p: Option[Proposal], certificates: Set[Certificate]): bool = {
        certificates.exists(c =>
            cert_kind(c) == FinalizationKind and cert_proposal(c) == p)
    }

    pure def is_view_finalized(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c =>
            cert_kind(c) == FinalizationKind and cert_view(c) == view)
    }

    // Does a set of votes contain an L-quorum for this exact proposal?
    pure def is_proposal_finalized_votes(p: Proposal, votes: Set[Vote]): bool = {
        select_votes(p.view, NotarizeKind, votes)
            .filter(v => vote_proposal(v) == Some(p))
            .map(v => vote_sig(v))
            .size() >= L
    }

    // Does a set of votes finalize some proposal in this view?
    pure def is_view_finalized_votes(view: ViewNumber, votes: Set[Vote]): bool = or {
        view == GENESIS_VIEW,
        select_votes(view, NotarizeKind, votes)
            .exists(v => vote_proposal(v).option_has(p => is_proposal_finalized_votes(p, votes)))
    }

    // Does a set of certificates contain a nullification certificate for this view? The `>= M`
    // threshold is explicit so this helper is self-contained rather than depending on
    // `certificates_are_valid_inv` to reject an under-threshold nullification certificate.
    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c => and {
            cert_kind(c) == NullificationKind,
            cert_signatures(c).size() >= M,
            cert_view(c) == view,
        })
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

    // Replica `r` ensures there are nullifications for all views `(v', v)`, and that there is
    // a `notarization(c', v')` for the parent block `c'`. The certificate must be for that
    // exact block, not merely for the view. minimmit.md 7 says the proof is
    // `notarization(c', v') in r.proofs[v']`, and 8.2 additionally requires `verify(c, c')`;
    // carrying the parent in the proposal is what lets this be checked at all.
    def valid_parent(proposal: Proposal, certificates: Set[Certificate]): bool = and {
        or {
            proposal.view_parent == GENESIS_VIEW and proposal.block_parent == GENESIS_BLOCK,
            certificates.exists(c => and {
                cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
                cert_view(c) == proposal.view_parent,
                cert_proposal(c).option_has(pp => pp.block == proposal.block_parent),
            }),
        },
        are_views_nullified(proposal.view_parent, proposal.view, certificates),
    }

    // Walk a finalized block's ancestry down to genesis, following the parent links carried by
    // the proposals. Because a block commits to its parent (`block_commits_to_parent`), every
    // notarized proposal for a given (block, view) names the same parent, so this walk is
    // unambiguous. Returns the chain genesis-first if the whole ancestry is present locally --
    // each ancestor carries a notarization (or finalization) and every skipped view is
    // nullified and None if any link or covering nullification is missing. Folding over
    // VIEWS bounds the depth, since the chain has at most one block per view.
    def ancestry_if_complete(target: Proposal, certificates: Set[Certificate]): Option[List[Proposal]] = {
        val walked = VIEWS.fold((target, List(target), true, false), (acc, _view) => {
            val current = acc._1
            val chain = acc._2
            val alive = acc._3
            val done = acc._4
            if (done or not(alive))
                acc
            else if (current.view_parent == GENESIS_VIEW and current.block_parent == GENESIS_BLOCK)
                // reached genesis: complete only if every view skipped below `current` (i.e. in
                // (GENESIS_VIEW, current.view)) is nullified -- a genesis-parented block at a view
                // above 0 still needs those gaps covered
                if (are_views_nullified(GENESIS_VIEW, current.view, certificates))
                    (current, chain, true, true)
                else
                    (current, chain, false, true)
            else {
                // the parent must be notarized (or finalized) for the exact (block, view) it
                // names, sit at a strictly lower view than `current`, and every view between it
                // and `current` must be nullified (the strict-view check makes `are_views_nullified`
                // non-vacuous, rejecting a malformed proposal whose parent view is >= its own view)
                val parents = certificates.filter(c => and {
                    cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
                    cert_view(c) == current.view_parent,
                    cert_proposal(c).option_has(pp => pp.block == current.block_parent),
                }).fold(Set(), (s, c) => match cert_proposal(c) { | Some(pp) => s.union(Set(pp)) | None => s })
                if (current.view_parent < current.view
                        and parents.size() >= 1
                        and are_views_nullified(current.view_parent, current.view, certificates)) {
                    val parent = parents.fold(GENESIS_PROPOSAL, (_a, pp) => pp)
                    (parent, List(parent).concat(chain), true, false)
                } else
                    (current, chain, false, true)  // ancestry incomplete or malformed: stop
            }
        })
        if (walked._4 and walked._3) Some(walked._2) else None
    }

    // Rebuild the committed chain from the locally stored certificates. This realizes
    // minimmit.md 8.4 "finalize `c` and all of its ancestors": commit the ancestry of the
    // highest finalized block whose full chain is present locally. A block is committed once it
    // carries a notarization and some descendant carries a finalization; a replica missing an
    // ancestor's notarization, or a nullification covering a gap, simply cannot commit past it.
    // Finalized blocks are chain-related (safety), so the longest complete ancestry is the
    // ancestry of the highest such finalized block.
    def rebuild_committed_chain(certificates: Set[Certificate]): List[Proposal] = {
        val finalized = certificates
            .filter(c => cert_kind(c) == FinalizationKind)
            .fold(Set(), (s, c) => match cert_proposal(c) { | Some(p) => s.union(Set(p)) | None => s })
        finalized.fold(List(), (best, p) =>
            match ancestry_if_complete(p, certificates) {
                | Some(chain) => if (chain.length() > best.length()) chain else best
                | None => best
            })
    }

    // Create a nullify certificate from a set of votes.
    def create_nullification(id: ReplicaId, view: ViewNumber, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            vote_view(v) == view,
            vote_kind(v) == NullifyKind
        })
        val votes_count = similar_votes.size()

        if (votes_count < M)
            None
        else
            Some(nullification(
                view,
                similar_votes.map(v => vote_sig(v)),
                sig_of(id)
            ))
    }

    // Assemble a certificate for one proposal. The quorum is "same proposal", not
    // "same block and view".
    def create_notarization(id: ReplicaId,
            proposal: Proposal, votes: Set[Vote]): Option[Certificate] = {
        val similar_votes: Set[Vote] = votes.filter(v => and {
            vote_kind(v) == NotarizeKind,
            vote_proposal(v) == Some(proposal)
        })

        val votes_count = similar_votes.size()
        if (votes_count < M)
            None
        else
            Some(notarization(
                proposal,
                similar_votes.map(v => vote_sig(v)),
                sig_of(id)
            ))
    }

    // Check whether a proposal cannot be notarized in a view. A notarize vote for a
    // different proposal conflicts even when it names the same block, because the two
    // proposals build on different parents and their votes never join one quorum.
    def is_proposal_in_view_cannot_be_notarized(p: Proposal, view: ViewNumber, votes: Set[Vote]): bool = {
        val vs1 = votes.filter(v => and {
            vote_kind(v) == NotarizeKind,
            vote_view(v) == view,
            vote_proposal(v) != Some(p),
        }).map(v => vote_sig(v))
        val vs2 = votes
            .filter(v => vote_kind(v) == NullifyKind and vote_view(v) == view)
            .map(v => vote_sig(v))
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
        val view = cert_view(cert)
        val kind = cert_kind(cert)
        val new_view = view + 1
        // The replica can only enter `view + 1` if that view exists and is ahead of it. The
        // watermarks, however, record that a finalization/notarization for `view` was observed;
        // they advance regardless of whether `view + 1` is enterable -- in particular a
        // finalization at the top of VIEWS still advances `last_finalized`, which also feeds
        // `on_proposal`'s `proposal.view_parent >= self.last_finalized` guard.
        val can_advance = VIEWS.contains(new_view) and self.view < new_view
        {
            ...self,
            propose_sent: if (can_advance) false else self.propose_sent,
            nullified: if (can_advance) false else self.nullified,
            timer_cancelled: if (can_advance) false else self.timer_cancelled,
            view: if (can_advance) new_view else self.view,
            last_finalized:
                if (self.last_finalized < view and kind == FinalizationKind) view else self.last_finalized,
            ghost_last_seen_notarization:
                if (self.ghost_last_seen_notarization < view and kind != NullificationKind) view else self.ghost_last_seen_notarization
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
                    cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
                    cert_view(c) == parent_view,
                    cert_proposal(c).option_has(p => p.block == parent_block),
                }),
                parent_view < 0 and parent_block == GENESIS_BLOCK,
            }
        }
    }

    // Initialize all local correct-style actors with genesis.
    action init = {
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
        ghost_committed_blocks' = REPLICA_IDS.mapBy(id => List()),
        ghost_proposal' = REPLICA_IDS.mapBy(id => Set()),
        leader'       = l
    }

    // A step by a correct-style actor or byzantine replica.
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
            nondet id = oneOf(REPLICA_IDS)
            // Non-deterministically choose the next block, use it only for the case of None below.
            nondet new_block = oneOf(VALID_BLOCKS)
            // Non-deterministically choose the parent block and parent view (checked in proposer_step)
            nondet parent_block = oneOf(AllBlocks.union(Set(GENESIS_BLOCK)))
            nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            proposer_step(id, new_block, parent_block, parent_view),
        }
    }

    // A step by a correct-style actor, except for the proposer step.
    action correct_replica_step(): bool = all {
        nondet id = oneOf(REPLICA_IDS)
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
            // hash binding: an honest build produces a block that commits to its parent, so a
            // block already used with a different parent cannot be re-proposed here.
            sent_proposal.forall(q => or {
                q.block != new_block,
                q.block_parent == parent_block and q.view_parent == parent_view,
            }),

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
                vote_kind(v) == NotarizeKind,
                vote_proposal(v) == Some(proposal),
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
                cert_kind(cert) == NullificationKind
                    and cert_signatures(cert).size() >= M
                    and not(is_view_nullified(cert_view(cert), certificates)),
                cert_kind(cert) == NotarizationKind
                    and cert_signatures(cert).size() >= M
                    and not(is_proposal_certified(cert_proposal(cert), certificates)),
                cert_kind(cert) == FinalizationKind
                    and cert_signatures(cert).size() >= L
                    and not(is_proposal_finalized(cert_proposal(cert), certificates)),
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
        all {
            cert_signatures(cert).size() >= M,

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

            // Certificate handling only stores the proof, rebroadcasts it, and enters the next
            // view; it does not cast a notarize vote (minimmit.md 8.4). A notarize vote is emitted
            // solely on the proposal path (minimmit.md 8.2, see `on_proposal`).
            sent_vote' = sent_vote,
            replica_state' = replica_state.set(id, enter_new_view(self, cert)),
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
            val certificate_view = if (kind == NullifyKind) view else p.view
            val cert_prop = if (kind == NullifyKind) None else Some(p)
            val votes = sent_vote.filter(v => and {
                vote_view(v) == certificate_view,
                vote_proposal(v) == cert_prop,
                vote_kind(v) == kind
            })
            nondet agg_sig = votes
                .map(v => vote_sig(v))
                .union(BYZANTINE.map(id => sig_of(id)))
                .powerset()
                .oneOf()
            val cert = if (kind == NullifyKind)
                nullification(certificate_view, agg_sig, sig_of(sender))
            else
                notarization(p, agg_sig, sig_of(sender))
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
            all {
                // hash binding (collision-resistance): even the adversary cannot bind an
                // existing block to a different parent. It can still pick a fresh block, or
                // re-state an already-bound (block, parent), so the step stays enabled.
                sent_proposal.forall(q => or {
                    q.block != block,
                    q.block_parent == block_parent and q.view_parent == view_parent,
                }),
                sent_proposal' = sent_proposal.union(Set(proposal)),
            }
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
        Replicas.forall(r => REPLICA_KEYS.keys().contains(r)),
        REPLICA_IDS == CORRECT.union(TWINS),
        CORRECT.intersect(TWINS) == Set(),
        CORRECT.intersect(BYZANTINE) == Set(),
        TWINS.intersect(BYZANTINE) == Set(),
        CORRECT_KEYS.intersect(FAULTY_KEYS) == Set(),
        CORRECT_KEYS.size() == CORRECT.size(),
        CORRECT_KEYS.size() + FAULTY_KEYS.size() == N,
        FAULTY_KEYS.size() <= F,
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

    // No honest replica ever holds evidence for BOTH a finalization and a nullification of the
    // same view, whether that evidence is a raw quorum of votes or an assembled certificate.
    // The two sides are read symmetrically (same stores, same granularity), so the check can no
    // longer pass merely because finalization was observed as votes while nullification was
    // observed as a certificate. The cross-replica / certificate form is
    // `no_nullification_and_finalization_globally`.
    val no_nullification_and_finalization_in_the_same_view = CORRECT.forall(id => {
        val certs = store_certificate.get(id)
        val votes = store_vote.get(id)
        val nullified_views = VIEWS.filter(v => or {
            is_view_nullified_votes(v, votes),   // >= M nullify votes
            is_view_nullified(v, certs),         // a NullificationKind cert
        })
        val finalized_views = VIEWS.filter(v => or {
            is_view_finalized_votes(v, votes),   // >= L notarize votes
            is_view_finalized(v, certs),         // a FinalizationKind cert
        })
        nullified_views.intersect(finalized_views) == Set()
    })

    // No equivocation. A leader may send only one proposal per view, and the whole proposal
    // is compared, not just its block: since the parent is part of what is signed, the same
    // block offered with a different parent is a different proposal, and sending both is
    // equivocation. `m1.view == m2.view and m1.sig == m2.sig` already hold in this branch, so
    // `m1 == m2` amounts to comparing (block, block_parent, view_parent).
    val no_proposal_equivocation = tuples(sent_proposal, sent_proposal).forall(((m1, m2)) => or {
        not(m1.view == m2.view and m1.sig == m2.sig),
        FAULTY_KEYS.contains(m1.sig),
        m1 == m2,
    })

    // A Block is the digest of its container and commits to its parent (minimmit.md 10, "block
    // digests"): the same block cannot be built on two different parents, because a
    // collision-resistant hash binds the parent into the block. This is what makes a finalized
    // block's ancestry unambiguous, so `rebuild_committed_chain` can safely commit
    // notarized-only ancestors of a finalized block. Sibling of `no_proposal_equivocation`,
    // which keys on (view, sig); this keys on the block and applies to every proposer,
    // including faulty ones, since even a byzantine leader cannot forge a hash collision.
    val block_commits_to_parent = tuples(sent_proposal, sent_proposal).forall(((p1, p2)) => or {
        p1.block != p2.block,
        p1.block_parent == p2.block_parent and p1.view_parent == p2.view_parent,
    })

    val valid_last_finalized = CORRECT.forall(id => {
        val self = replica_state.get(id)
        self.last_finalized <= self.ghost_last_seen_notarization
    })


    // Make sure that no invalid certificates are stored. Variant/proposal consistency is
    // structural, and finalization is derived from signature count. Only raw payload
    // constraints remain here.
    val certificates_are_valid_inv = CORRECT.forall(id => {
        store_certificate.get(id).forall(cert => match cert {
            | Notarization(c) => and {
                c.proposal.view >= 0,
                c.signatures.size() >= M,
                VALID_BLOCKS.contains(c.proposal.block),
            }
            | Nullification(c) => and {
                c.view >= 0,
                c.signatures.size() >= M,
            }
        })
    })

    // The signatures a certificate could legitimately carry. An honest signature must
    // correspond to a vote that replica actually broadcast; a byzantine replica may sign
    // anything, so its own identities are always admissible.
    //
    // Backing is taken from `sent_vote` alone, deliberately. `store_vote` is not consulted:
    // `on_vote_notarize` and `on_vote_nullify` accept a vote set by shape, exactly as
    // `on_certificate` accepts a certificate by shape, so counting stored votes as cast
    // would let the same forgery move down one layer. Hand a replica forged honest votes and
    // any certificate built from them becomes "backed". Under `step` this costs nothing,
    // because `correct_replica_step` draws votes from `powerset(sent_vote)` and a store is
    // therefore always a subset of what was broadcast.
    def cert_backing(cert: Certificate): Set[Signature] = {
        val votes = if (cert_kind(cert) == NullificationKind)
            select_votes(cert_view(cert), NullifyKind, sent_vote)
        else
            select_votes(cert_view(cert), NotarizeKind, sent_vote)
                .filter(v => vote_proposal(v) == cert_proposal(cert))
        votes.map(v => vote_sig(v)).union(FAULTY_KEYS)
    }

    // Certificate signatures cannot be forged. `on_certificate` accepts a certificate by its
    // variant and signature threshold. It never checks that the signatures belong to replicas
    // that really voted, so it depends on this property. Two places make it true:
    // `byzantine_replica_step`, which builds `agg_sig` from
    // the signatures of real votes plus BYZANTINE, and `create_notarization` /
    // `create_nullification`, which build `signatures` from votes the replica observed.
    //
    // If a later change ever lets a certificate with unbacked signatures reach a replica,
    // two steps are enough to store finalizations for two different blocks in the same view
    // and break `validity`. See `forgedFinalizationCertificatesViolateValidityTest`.
    val certificates_are_backed = and {
        sent_certificate.forall(cert => cert_signatures(cert).subseteq(cert_backing(cert))),
        CORRECT.forall(id =>
            store_certificate.get(id).forall(cert =>
                cert_signatures(cert).subseteq(cert_backing(cert)))),
    }

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => self.notarized.get(v) != None iff has_notarized_view(id, v, sent_vote))
    })

    // Suppose that a proposal is finalized for some view v, then no other proposal for view v
    // can be finalized at the same replica or any other one.
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
                    cert_kind(c) == FinalizationKind,
                    // Keep the raw threshold so a lowered kind threshold cannot admit a
                    // sub-L certificate as a finalization.
                    cert_signatures(c).size() >= L,
                    cert_view(c) == v,
                })
                .map(c => cert_proposal(c))))
        finalized_proposals.size() <= 1
    })

    // Finalization agreement across replicas: no two correct replicas finalize different
    // proposals in the same view. If a correct replica finalizes a proposal (its block AND its
    // parent) in view v (by an L-quorum of notarize votes it has observed, or by a stored
    // L-signature finalization certificate) then every other correct replica that finalizes
    // anything in view v finalizes that same proposal. Equivalently, at most one proposal is
    // finalized per view across all correct replicas. This is the pairwise-agreement companion
    // of `validity` (the certificate-only global-uniqueness form); counting votes as well as
    // certificates makes it fire as soon as an L-quorum exists, before a certificate is
    // assembled. The comparison is on the whole proposal, so agreeing on the finalized block
    // means agreeing on its parent too.
    val finalization_agreement = VIEWS.forall(v => {
        val finalized = CORRECT.fold(Set(), (acc, id) => {
            val votes = store_vote.get(id)
            val by_votes = select_votes(v, NotarizeKind, votes)
                .filter(vote => vote_proposal(vote).option_has(p => is_proposal_finalized_votes(p, votes)))
                .map(vote => vote_proposal(vote))
            val by_cert = store_certificate.get(id)
                .filter(c => and {
                    cert_kind(c) == FinalizationKind,
                    cert_signatures(c).size() >= L,
                    cert_view(c) == v,
                })
                .map(c => cert_proposal(c))
            acc.union(by_votes).union(by_cert)
        })
        finalized.size() <= 1
    })

    // If there is a finalized block in a view v, there is no nullification in the same view.
    // Finalization and nullification are each recognized from raw votes OR a certificate (an
    // L-quorum of notarize votes or a FinalizationKind cert; an M-quorum of nullify votes or a
    // NullificationKind cert), so this holds even when the evidence is a stored certificate with
    // no corresponding raw votes.
    val no_nullification_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val votes = store_vote.get(id)
        val certs = store_certificate.get(id)
        not(and {
            is_view_finalized_votes(v, votes) or is_view_finalized(v, certs),
            is_view_nullified_votes(v, votes) or is_view_nullified(v, certs),
        })
    })

    // If there is a finalized block in a view v, there is no notarization for another block in
    // the same view. Both a finalization and a conflicting notarization are recognized from raw
    // votes OR a stored certificate.
    val no_notarization_in_finalized_view = tuples(CORRECT, VIEWS).forall(((id, v)) => {
        val votes = store_vote.get(id)
        val certs = store_certificate.get(id)
        // proposals finalized in view v: an L-quorum of raw votes or a finalization certificate
        val finalized_props = select_votes(v, NotarizeKind, votes)
            .filter(vote => vote_proposal(vote).option_has(p => is_proposal_finalized_votes(p, votes)))
            .map(vote => vote_proposal(vote))
            .union(certs
                .filter(c => cert_kind(c) == FinalizationKind and cert_view(c) == v)
                .map(c => cert_proposal(c)))
        // proposals notarized in view v: an M-quorum of raw votes or a notarization/finalization cert
        val notarized_props = select_votes(v, NotarizeKind, votes)
            .filter(vote => vote_proposal(vote).option_has(p => is_proposal_notarized_votes(p, votes)))
            .map(vote => vote_proposal(vote))
            .union(certs
                .filter(c => (cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind) and cert_view(c) == v)
                .map(c => cert_proposal(c)))
        // a finalized proposal is the only proposal notarized in its view
        finalized_props.forall(fp => notarized_props.forall(np => np == fp))
    })

    val safe_finalization = all {
        no_notarization_in_finalized_view,
        no_nullification_in_finalized_view
    }

    // Every committed block is justified by locally stored certificates: each carries a
    // notarization (or finalization), and the tip carries a finalization. Under minimmit.md 8.4
    // "finalize `c` and all of its ancestors", the ancestors are committed on the strength of
    // the tip's finalization and need only be notarized; the tip itself must be finalized. This
    // pins down the derived chain and catches a `rebuild_committed_chain` that invents links the
    // replica cannot justify. The signature thresholds are repeated explicitly (>= M for a
    // notarization, >= L for the tip's finalization) so this invariant is self-contained when run
    // on its own: `cert_kind` classifies any Notarization below L as NotarizationKind regardless
    // of its size, so without these bounds an under-threshold certificate would justify a commit.
    val committed_blocks_are_finalized = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        val certs = store_certificate.get(id)
        and {
            chain.indices().forall(i => certs.exists(c => and {
                cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
                cert_signatures(c).size() >= M,
                cert_proposal(c) == Some(chain[i]),
            })),
            chain.length() > 0 implies certs.exists(c => and {
                cert_kind(c) == FinalizationKind,
                cert_signatures(c).size() >= L,
                cert_proposal(c) == Some(chain[chain.length() - 1]),
            }),
        }
    })

    // Every committed proposal builds on the one committed before it, the first builds on
    // genesis, views strictly increase along the chain, and every view skipped between a
    // committed block and its committed parent is nullified. The chain is a real chain, not just
    // a list of finalized blocks, and it has no uncovered gaps. A chain like [view 0, view 2]
    // with no nullification for view 1 is rejected here, as is any block whose parent view is not
    // strictly below its own (which would make the gap check vacuous), matching what
    // `rebuild_committed_chain`/`ancestry_if_complete` would build.
    val committed_chain_is_connected = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        val certs = store_certificate.get(id)
        chain.indices().forall(i => {
            val parent = if (i == 0) GENESIS_PROPOSAL else chain[i - 1]
            and {
                chain[i].view_parent == parent.view,
                chain[i].block_parent == parent.block,
                parent.view < chain[i].view,
                are_views_nullified(parent.view, chain[i].view, certs),
            }
        })
    })

    // No view carries evidence for both a nullification and a finalization, not even in two
    // different replicas' stores. This is what makes the committed sequence the same at
    // every correct replica, and so it is what `agreement` rests on: if one replica commits
    // the finalization of view v1 and another commits a later view v2 rooted at the same
    // parent, the second must hold a nullification for v1, since the gap (parent, v2) covers
    // it. The per-replica form of this check would be true in exactly that state, which is
    // why it is quantified across the honest network's combined stores.
    //
    // Evidence is counted symmetrically in both forms (a raw quorum of votes (>= L notarize
    // or >= M nullify) or an assembled certificate) across the union of all correct
    // replicas' votes and certificates, mirroring
    // `no_nullification_and_finalization_in_the_same_view`. Counting votes as well as
    // certificates makes the check fire as soon as the honest network holds a quorum, before
    // any certificate is assembled, and keeps it meaningful even if a future change let an
    // unbacked certificate reach a store.
    val no_nullification_and_finalization_globally = {
        val all_certs = CORRECT.fold(Set(), (acc, id) => acc.union(store_certificate.get(id)))
        val all_votes = CORRECT.fold(Set(), (acc, id) => acc.union(store_vote.get(id)))
        val nullified = VIEWS.filter(v => or {
            is_view_nullified_votes(v, all_votes),   // >= M nullify votes
            is_view_nullified(v, all_certs),         // a NullificationKind cert
        })
        val finalized = VIEWS.filter(v => or {
            is_view_finalized_votes(v, all_votes),   // >= L notarize votes
            is_view_finalized(v, all_certs),         // a FinalizationKind cert
        })
        nullified.intersect(finalized) == Set()
    }

    val all_invariants = all {
        no_proposal_equivocation,
        block_commits_to_parent,
        agreement,
        no_vote_equivocation_inv,
        no_nullification_and_finalization_in_the_same_view,
        validity,
        finalization_agreement,
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

    val correct_nodes_sent_certificates_valid = sent_certificate
        .filter(cert => CORRECT_KEYS.contains(cert_ghost_sender(cert)))
        .forall(cert => {
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
