// The consensus layer of Multimmit as a state machine: views, leader
// blocks, votes, novotes, nullifications, V-QCs, and the extraction of
// the total ordering upon finalisation.
//
// This is Minimmit's consensus, with two differences: leader blocks
// carry a chain proposal naming a tip per chain rather than
// transactions, and a vote is a vector reporting, per chain, how far up
// the voter can support that proposal. Everything else -- one round of
// voting for
// finality at n-t, every view producing either a V-notarization or a
// nullification, proposals anchored on a V-QC with nullifications for
// every skipped view -- is unchanged.
//
// The layer's whole dependence on the chain layer is two monotone
// variables of da.qnt, `da_voted` and `store_da_cert`, read at exactly
// four places: forming a vote's positions and extensions, choosing an
// anchor and payloads when proposing. It never reads block data, never
// waits for it and never fetches it: a voter reports what it holds and
// votes on that.
//
// Correspondingly, Prop, Tips, TipsF, settledness, Horiz, Ord and Emit
// are called from here but defined elsewhere: chainrules.qnt for the
// per-chain rules, sweep.qnt for the multichain ones. Nothing below
// reaches inside a tip.

module consensus {
    import types.* from "./types"
    import option.* from "./option"
    import blocks.* from "./blocks"
    import defs.* from "./defs"
    import chainrules.* from "./chainrules"
    import sweep.* from "./sweep"

    // -------------------------------------------------
    // Parameters
    // -------------------------------------------------

    // N processors, of which at most T may be faulty as far as the
    // protocol's thresholds are concerned, and F actually are. See the
    // note on Params in types.qnt: T is the paper's f, F its f_a.
    const N: int
    const T: int
    const F: int

    // Correct-style actors (correct replicas and twins), the byzantine
    // ones, and the key each actor signs with. Twins share a key: they
    // are two actors but one logical replica, which is how a twin pair
    // equivocates without exceeding the fault budget.
    const REPLICA_IDS: Set[ReplicaId]
    const CORRECT: Set[ReplicaId]
    const TWINS: Set[ReplicaId]
    const BYZANTINE: Set[ReplicaId]
    const REPLICA_KEYS: ReplicaId -> ReplicaKey

    // Chain i belongs to processor p_i. Chains are pinned to replicas -- a
    // DA-vote is unicast to the block's producer. Horizontal sweep requires an
    // ordering on the chains. Hence, we use integers from 1.to(N) as chain ids.
    pure val CHAINS: Set[ChainId] = 1.to(N)
    
    const CHAIN_OF: ReplicaId -> ChainId

    // Bounds that make the model finite.
    const PAYLOADS: Set[PayloadId]
    const MAX_HEIGHT: int
    const VIEWS: Set[ViewNumber]
    // The greatest hash value H(Q) may take: V-QC hashes are allocated
    // from 1..MAX_VQC_HASH, with 0 reserved for Q_gen. The state machine
    // keeps the assignment a bijection, so that the abstract hash is
    // injective (see `id_is_ok_for`, `vqc_id_matches_key` and
    // `vqc_content_has_unique_id`). The bound
    // caps how many distinct V-QCs a run may assemble.
    const MAX_VQC_HASH: int

    const PIPELINE_D: int
    const EXT_E: int

    pure val PARAMS: Params = { n: N, t: T, d: PIPELINE_D, e: EXT_E }

    // Thresholds.
    pure val D = da_quorum(PARAMS)      // n - 2t : DA-certificates
    pure val M = null_quorum(PARAMS)    // 2t + 1 : nullifications, V-QC tally, carry
    pure val L = vqc_quorum(PARAMS)      // n - t  : V-QC size, finalising pool

    pure val Replicas = REPLICA_IDS.union(BYZANTINE)
    pure def sig_of(id: ReplicaId): ReplicaKey = REPLICA_KEYS.get(id)
    pure val CORRECT_KEYS = CORRECT.map(id => sig_of(id))
    pure val FAULTY_KEYS = BYZANTINE.union(TWINS).map(id => sig_of(id))

    // The chain layer. Its variables are part of this state machine.
    import da(
        DA_REPLICA_IDS = REPLICA_IDS,
        DA_BYZANTINE = BYZANTINE,
        DA_REPLICA_KEYS = REPLICA_KEYS,
        DA_CHAIN_OF = CHAIN_OF,
        DA_PAYLOADS = PAYLOADS,
        DA_MAX_HEIGHT = MAX_HEIGHT,
        DA_PARAMS = { n: N, t: T, d: PIPELINE_D, e: EXT_E }
    ).* from "./da"

    // -------------------------------------------------
    // State
    // -------------------------------------------------

    var replica_state: ReplicaId -> ReplicaState

    // Broadcast messages, and what each actor has received. "Disseminate"
    // means send to all; a replica regards a message it sends to itself
    // as immediately received.
    var sent_leader_block: Set[LeaderBlock]
    var store_leader_block: ReplicaId -> Set[LeaderBlock]
    var sent_vote: Set[Vote]
    var store_vote: ReplicaId -> Set[Vote]
    var sent_certificate: Set[Certificate]
    var store_certificate: ReplicaId -> Set[Certificate]

    // The abstract hash function on V-QCs, maintained injective: an id
    // is in use for at most one V-QC, and a V-QC gets at most one id.
    var ghost_vqc: VQcHash -> VQC

    // -------------------------------------------------
    // Derived views of the state
    // -------------------------------------------------

    // Is `id` the leader of view v? Compared by CHAIN, not by actor id:
    // a twin shares its sibling's chain, so both twins of the view's
    // logical leader may propose -- which is exactly how a twin pair
    // equivocates on a leader block.
    def is_leader(id: ReplicaId, v: ViewNumber): bool = {
        CHAIN_OF.get(id) == lead(v, PARAMS)
    }

    // The V-QCs `id` holds.
    def held_vqcs(id: ReplicaId): Set[VQC] = {
        store_certificate.get(id).fold(Set(), (acc, c) =>
            match c {
                | Notarization(q) => acc.union(Set(q))
                | Nullification(_) => acc
            })
    }

    def has_nullification(id: ReplicaId, v: ViewNumber): bool = {
        store_certificate.get(id).exists(c =>
            cert_kind(c) == NullificationKind and cert_view(c) == v)
    }

    def has_vqc(id: ReplicaId, v: ViewNumber): bool = {
        store_certificate.get(id).exists(c =>
            cert_kind(c) == NotarizationKind and cert_view(c) == v)
    }

    // Hashes identify V-QCs. Keep this as a direct lookup over the
    // certificate store rather than materialising the full held-V-QC set.
    def has_vqc_hash(id: ReplicaId, h: VQcHash): bool = {
        store_certificate.get(id).exists(c =>
            match c {
                | Notarization(q) => q.id == h
                | Nullification(_) => false
            })
    }

    // Every baseline V-QC accounts for exactly L view messages from
    // distinct signers. A replica may hold more than L candidates, or
    // several Byzantine messages from one signer, so assembly must choose
    // the message set rather than consume the entire monotone store.
    pure def vqc_message_subsets(messages: Set[Vote], v: ViewNumber): Set[Set[Vote]] = {
        val eligible = messages.filter(x =>
            vote_view(x) == v and
            (vote_kind(x) == NotarizeKind or vote_kind(x) == NovoteKind))
        eligible.powerset().filter(ws => and {
            ws.size() == L,
            ws.map(x => vote_sig(x)).size() == L,
        })
    }

    // SelectAnchor(State, v): the V-QC the leader of view v builds on.
    // The greatest view v' < v for which the replica holds a V-QC, and
    // then the V-QC it forwarded when that view first became new, rather
    // than one reassembled now.
    //
    // Returning the forwarded object is required for liveness. A V-QC
    // assembled privately at proposal time may contain a vote no other
    // correct replica holds, and since proposal validity requires the
    // exact object referenced, no correct replica could then vote.
    // Anchoring on what was already sent to all rules this out by
    // construction, and the forwarding also delivers the anchor in
    // time.
    def select_anchor(id: ReplicaId, v: ViewNumber): Option[VQC] = {
        val self = replica_state.get(id)
        val candidates = VIEWS.filter(w => w < v and self.forwarded.get(w) != None)
        if (candidates == Set())
            None
        else {
            val best = candidates.fold(-1, (acc, w) => max(acc, w))
            self.forwarded.get(best)
        }
    }

    // ProposeChains(Q, v): the leader's chain proposal.
    //  - the anchor is the highest DA-certificate the leader holds for
    //    the chain, if that beats Tips(Q)_j, and Tips(Q)_j otherwise;
    //  - the payloads are the leader's own DA-voted blocks extending the
    //    base, up to d of them.
    def propose_chains(id: ReplicaId, q: VQC): ChainProposal = {
        val tq = tips(q, PARAMS)
        val certs = store_da_cert.get(id)
        val voted = da_voted.get(id)
        CHAINS.mapBy(j => {
            val b = tq.get(j)
            val better = certs.filter(c =>
                c.block.chain == j and block_height(c.block) > block_height(b))
            val anchor =
                if (better == Set())
                    HashAnchor(b)
                else
                    CertAnchor(better.fold(
                        better.fold(da_cert(b, Set(), "x"), (_, c) => c),
                        (acc, c) => if (block_height(c.block) > block_height(acc.block)) c else acc))
            {
                anchor: anchor,
                payloads: longest_da_voted_run(voted, anchor_block(anchor), PIPELINE_D),
            }
        })
    }

    // "State contains a valid proposal ell for view v": the pure core is
    // proposal_wellformed in sweep.qnt; the stateful conditions are here.
    def is_valid_proposal(id: ReplicaId, lb: LeaderBlock): bool = {
        val certs = store_certificate.get(id)
        and {
            // (i) exactly one leader block of this shape by lead(v)
            store_leader_block.get(id).filter(x =>
                x.view == lb.view and is_leader_block_of_view_leader(x)).size() == 1,
            // (ii) the referenced V-QC is held and C is well-formed w.r.t. its tips
            certs.exists(c =>
                match c {
                    | Notarization(q) => and {
                        q.id == lb.parent_vqc,
                        proposal_wellformed(lb, q, PARAMS),
                        // (iii) every skipped view is nullified
                        VIEWS.forall(w =>
                            (vqc_view(q) < w and w < lb.view) implies has_nullification(id, w)),
                    }
                    | Nullification(_) => false
                }),
        }
    }

    // A leader block is attributable to the view's leader exactly when
    // some actor owning that view's chain could have signed it. Leader
    // blocks carry no separate signature field: the producer of chain
    // lead(v) is the only party able to sign one.
    def is_leader_block_of_view_leader(lb: LeaderBlock): bool = {
        Replicas.exists(r => is_leader(r, lb.view))
    }

    // Enter a new view, unless it is not newer than the current one.
    pure def enter_new_view(self: ReplicaState, new_view: ViewNumber, views: Set[ViewNumber]): ReplicaState = {
        if (not(views.contains(new_view)) or self.view >= new_view)
            self
        else {
            ...self,
            view: new_view,
            nullified: false,
            propose_sent: false,
            timer_cancelled: false,
        }
    }

    // -------------------------------------------------
    // Assembling certificates
    // -------------------------------------------------

    // May `h` be used as the hash of the V-QC `q0`? Yes iff `h` is the id
    // already bound to q0's content, or -- if that content has no id yet
    // -- an unused one. This is what keeps the abstract hash injective.
    //
    // The comparison normalises away `id` and `ghost_sender`, neither of
    // which is part of what the hash covers: two replicas assembling the
    // same V-QC must reach the same hash. EMPTY_VQC_HASH is used as the
    // normalising value only because it is never an allocated id.
    pure def vqc_content(q: VQC): VQC = {
        { ...q, id: EMPTY_VQC_HASH, ghost_sender: "" }
    }

    def id_is_ok_for(h: VQcHash, q0: VQC): bool = {
        val bound = ghost_vqc.keys()
            .filter(k => vqc_content(ghost_vqc.get(k)) == vqc_content(q0))
        if (bound == Set())
            not(ghost_vqc.keys().contains(h))
        else
            bound.contains(h)
    }

    // -------------------------------------------------
    // Actions
    // -------------------------------------------------

    action init = all {
        replica_state' = REPLICA_IDS.mapBy(_ => {
            view: 1,
            nullified: false,
            propose_sent: false,
            timer_cancelled: false,
            notarized: VIEWS.mapBy(_ => None),
            forwarded: VIEWS.mapBy(w =>
                if (w == GENESIS_VIEW) Some(genesis_vqc(CHAINS)) else None),
            ghost_sent_votes: VIEWS.mapBy(_ => List()),
            ghost_log: List(),
        }),
        sent_leader_block' = Set(),
        store_leader_block' = REPLICA_IDS.mapBy(_ => Set()),
        sent_vote' = Set(),
        store_vote' = REPLICA_IDS.mapBy(_ => Set()),
        sent_certificate' = Set(),
        // Q_gen is "considered received by all processors at the start
        // of the execution", so it must be in the certificate store, not
        // merely referenced: otherwise no view-1 proposal can resolve
        // its parent_vqc and no correct replica votes.
        store_certificate' = REPLICA_IDS.mapBy(_ => Set(Notarization(genesis_vqc(CHAINS)))),
        ghost_vqc' = Map(GENESIS_VQC_HASH -> genesis_vqc(CHAINS)),
        da_init,
    }

    action consensus_unchanged = all {
        replica_state' = replica_state,
        sent_leader_block' = sent_leader_block,
        store_leader_block' = store_leader_block,
        sent_vote' = sent_vote,
        store_vote' = store_vote,
        sent_certificate' = sent_certificate,
        store_certificate' = store_certificate,
        ghost_vqc' = ghost_vqc,
    }

    action disabled_action: bool = all {
        false,
        consensus_unchanged,
        da_unchanged,
    }

    // 8.5. Propose (Algorithm 2, lines 3-5). The leader of view v takes
    // the V-QC it last forwarded, reads a safe-to-extend tip per chain
    // off it, and proposes up to d payload entries above each.
    action on_propose(id: ReplicaId): bool = {
        val self = replica_state.get(id)
        match select_anchor(id, self.view) {
            | None => disabled_action
            | Some(q) => all {
                is_leader(id, self.view),
                not(self.propose_sent),
                VIEWS.contains(self.view),
                // the leader can supply a nullification for every view it
                // skipped, since it advanced through them by nullification
                VIEWS.forall(w =>
                    (vqc_view(q) < w and w < self.view) implies has_nullification(id, w)),
                val lb = { view: self.view, parent_vqc: q.id, proposal: propose_chains(id, q) }
                all {
                    sent_leader_block' = sent_leader_block.union(Set(lb)),
                    replica_state' = replica_state.set(id, { ...self, propose_sent: true }),
                },
                store_leader_block' = store_leader_block,
                sent_vote' = sent_vote,
                store_vote' = store_vote,
                sent_certificate' = sent_certificate,
                store_certificate' = store_certificate,
                ghost_vqc' = ghost_vqc,
                da_unchanged,
            }
        }
    }

    // Delivery of a broadcast leader block.
    action on_deliver_leader_block(id: ReplicaId, lb: LeaderBlock): bool = all {
        sent_leader_block.contains(lb),
        store_leader_block' = store_leader_block.set(id, store_leader_block.get(id).union(Set(lb))),
        replica_state' = replica_state,
        sent_leader_block' = sent_leader_block,
        sent_vote' = sent_vote,
        store_vote' = store_vote,
        sent_certificate' = sent_certificate,
        store_certificate' = store_certificate,
        ghost_vqc' = ghost_vqc,
        da_unchanged,
    }

    // 8.6. Vote (Algorithm 2, lines 6-8). On a valid proposal for the
    // current view, broadcast a single vote reporting how far up each
    // chain the voter can endorse it, plus up to e fresh blocks of its
    // own beyond that.
    def make_notarize_vote(id: ReplicaId, lb: LeaderBlock): Vote = {
        val voted = da_voted.get(id)
        val pos = vote_positions(voted, lb, PARAMS)
        val ext = vote_extensions(voted, lb, pos, PARAMS)
        notarize(lb, pos, ext, sig_of(id))
    }

    action on_vote(id: ReplicaId, lb: LeaderBlock): bool = {
        val self = replica_state.get(id)
        val v = make_notarize_vote(id, lb)
        all {
            lb.view == self.view,
            self.notarized.get(self.view) == None,
            not(self.nullified),
            store_leader_block.get(id).contains(lb),
            is_valid_proposal(id, lb),
            sent_vote' = sent_vote.union(Set(v)),
            replica_state' = replica_state.set(id, {
                ...self,
                notarized: self.notarized.set(self.view, Some(lb)),
                timer_cancelled: true,
                ghost_sent_votes: self.ghost_sent_votes.set(
                    self.view, self.ghost_sent_votes.get(self.view).append(Some(lb))),
            }),
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            store_vote' = store_vote,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            ghost_vqc' = ghost_vqc,
            da_unchanged,
        }
    }

    // 8.7. Timeout (Algorithm 2, lines 9-10). If the timer expires
    // without having voted, broadcast both novote(v) and nullify(v). A
    // correct replica never both votes and sends a novote for one view
    // -- that exclusivity is what lets a V-QC account exactly for who
    // did and did not vote.
    action on_timeout(id: ReplicaId): bool = {
        val self = replica_state.get(id)
        all {
            not(self.timer_cancelled),
            self.notarized.get(self.view) == None,
            not(self.nullified),
            VIEWS.contains(self.view),
            sent_vote' = sent_vote.union(Set(
                novote(self.view, sig_of(id)),
                nullify(self.view, sig_of(id)))),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                timer_cancelled: true,
                ghost_sent_votes: self.ghost_sent_votes.set(
                    self.view, self.ghost_sent_votes.get(self.view).append(None)),
            }),
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            store_vote' = store_vote,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            ghost_vqc' = ghost_vqc,
            da_unchanged,
        }
    }

    // 8.10. Nullify by contradiction (Algorithm 2, lines 16-19). A
    // replica that has voted for an ell that cannot be finalised
    // broadcasts nullify(v) -- NOT novote, since it did vote -- to
    // ensure some proof for view v will exist.
    action on_nullify_by_contradiction(id: ReplicaId): bool = {
        val self = replica_state.get(id)
        val v = self.view
        match self.notarized.get(v) {
            | None => disabled_action
            | Some(lb) => all {
                not(self.nullified),
                VIEWS.contains(v),
                // M distinct signers sent a view-v message not
                // supporting ell (Algorithm 2, lines 16-18).
                val others = store_vote.get(id).filter(x => and {
                    vote_view(x) == v,
                    vote_leader_block(x) != Some(lb),
                })
                others.map(x => vote_sig(x)).size() >= M,
                sent_vote' = sent_vote.union(Set(nullify(v, sig_of(id)))),
                replica_state' = replica_state.set(id, { ...self, nullified: true }),
                sent_leader_block' = sent_leader_block,
                store_leader_block' = store_leader_block,
                store_vote' = store_vote,
                sent_certificate' = sent_certificate,
                store_certificate' = store_certificate,
                ghost_vqc' = ghost_vqc,
                da_unchanged,
            }
        }
    }

    // The paper's pool is indexed by leader block and signer: if a
    // Byzantine signer equivocates, the first vote a replica receives
    // for that leader block is the one it retains. Votes from that signer
    // for other leader blocks remain independently eligible.
    pure def insert_received_vote(pool: Set[Vote], x: Vote): Set[Vote] = {
        match x {
            | Notarize(v) =>
                if (notarize_votes(pool).exists(old =>
                    old.leader_block == v.leader_block and old.sig == v.sig))
                    pool
                else
                    pool.union(Set(x))
            | Novote(_) => pool.union(Set(x))
            | Nullify(_) => pool.union(Set(x))
        }
    }

    // Delivery of a broadcast vote.
    action on_deliver_vote(id: ReplicaId, v: Vote): bool = all {
        sent_vote.contains(v),
        store_vote' = store_vote.set(id, insert_received_vote(store_vote.get(id), v)),
        replica_state' = replica_state,
        sent_leader_block' = sent_leader_block,
        store_leader_block' = store_leader_block,
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_certificate' = store_certificate,
        ghost_vqc' = ghost_vqc,
        da_unchanged,
    }

    // 8.8. Assemble a nullification from M nullify shares, to be
    // disseminated if new (Algorithm 2, line 2).
    action on_nullification(id: ReplicaId, v: ViewNumber): bool = {
        val sigs = select_votes(v, NullifyKind, store_vote.get(id)).map(x => vote_sig(x))
        val c = nullification(v, sigs, sig_of(id))
        all {
            sigs.size() >= M,
            not(has_nullification(id, v)),
            // A correct sender receives its own broadcast immediately.
            // Storing c here also makes the guard above terminate without
            // an artificial delivery step.
            sent_certificate' = sent_certificate.union(Set(c)),
            store_certificate' = store_certificate.set(
                id, store_certificate.get(id).union(Set(c))),
            replica_state' = replica_state,
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            sent_vote' = sent_vote,
            store_vote' = store_vote,
            ghost_vqc' = ghost_vqc,
            da_unchanged,
        }
    }

    // 8.9. Assemble a V-QC, to be disseminated if new (Algorithm 2,
    // line 2): L view-v messages by distinct signers, of which at least
    // M are votes for one leader block -- the designated
    // proposal. Novotes and votes for other leader blocks make up the
    // rest, and the three signer sets are disjoint.
    action on_vqc(id: ReplicaId, lb: LeaderBlock, h: VQcHash): bool = {
        val self = replica_state.get(id)
        val v = lb.view
        nondet selected = oneOf(vqc_message_subsets(store_vote.get(id), v))
        val selected_votes = notarize_votes(selected)
        val tally = selected_votes.filter(x => vote_matches(x, lb))
        val others = selected_votes.filter(x => not(vote_matches(x, lb)))
        val novotes = select_votes(v, NovoteKind, selected).map(x => vote_sig(x))
        val q0: VQC = {
            id: h,
            leader_block: lb,
            votes: tally,
            novotes: novotes,
            other_votes: others,
            ghost_sender: sig_of(id),
        }
        all {
            VIEWS.contains(v),
            1 <= h, h <= MAX_VQC_HASH,
            vqc_wellformed(q0, PARAMS),
            id_is_ok_for(h, q0),
            not(has_vqc(id, v)),
            sent_certificate' = sent_certificate.union(Set(Notarization(q0))),
            ghost_vqc' = ghost_vqc.put(h, q0),
            // The assembler holds what it just built. Without this the
            // guard above would read a store the action never writes, so
            // a replica could assemble a second V-QC for the view before
            // delivering the first to itself; the paper's `new` covers
            // V-QCs newly received or assembled. Assembly also broadcasts
            // q0, so record it in `forwarded` immediately; received V-QCs
            // populate the same per-view index on delivery.
            store_certificate' = store_certificate.set(
                id, store_certificate.get(id).union(Set(Notarization(q0)))),
            replica_state' = replica_state.set(id,
                if (self.forwarded.get(v) == None)
                    { ...self, forwarded: self.forwarded.set(v, Some(q0)) }
                else
                    self),
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            sent_vote' = sent_vote,
            store_vote' = store_vote,
            da_unchanged,
        }
    }

    // Delivery stores a certificate and records the first V-QC forwarded
    // for its view (8.4). View entry is a separate state-triggered rule:
    // a future proof must remain inert until its view becomes current.
    action on_deliver_certificate(id: ReplicaId, c: Certificate): bool = {
        val self = replica_state.get(id)
        val v = cert_view(c)
        val delivery =
            match c {
                | Notarization(q) =>
                    {
                        unseen: not(has_vqc_hash(id, q.id)),
                        updated:
                            if (self.forwarded.get(v) == None)
                                { ...self, forwarded: self.forwarded.set(v, Some(q)) }
                            else
                                self,
                    }
                | Nullification(_) => { unseen: true, updated: self }
            }
        all {
            sent_certificate.contains(c),
            VIEWS.contains(v),
            // A V-QC may arrive through several forwarders, whose
            // ghost_sender fields make the message records distinct. Its
            // hash identifies the logical certificate, so retain only the
            // first such record locally. Distinct V-QCs for the same view
            // remain admissible because their hashes differ.
            delivery.unseen,
            store_certificate' = store_certificate.set(id, store_certificate.get(id).union(Set(c))),
            replica_state' = replica_state.set(id, delivery.updated),
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            sent_vote' = sent_vote,
            store_vote' = store_vote,
            sent_certificate' = sent_certificate,
            ghost_vqc' = ghost_vqc,
            da_unchanged,
        }
    }

    // Algorithm 2, lines 11-14, as a state condition rather than an
    // arrival handler. If both proof kinds are held, the V-QC branch has
    // precedence so an eligible replica votes along before view entry.
    // No separate proposal delivery or validity check is required: the
    // V-QC itself designates the leader block to vote for.
    action on_view_proof(id: ReplicaId): bool = {
        val self = replica_state.get(id)
        val v = self.view
        match self.forwarded.get(v) {
        | Some(q) => {
            val lb = q.leader_block
            val should_vote = self.notarized.get(v) == None and not(self.nullified)
            val advanced = advance_on_view_proof(self, v, VIEWS)
            val updated =
                if (should_vote)
                    {
                        ...advanced,
                        notarized: advanced.notarized.set(v, Some(lb)),
                        ghost_sent_votes: advanced.ghost_sent_votes.set(
                            v, advanced.ghost_sent_votes.get(v).append(Some(lb))),
                    }
                else
                    advanced
            all {
                if (should_vote)
                    sent_vote' = sent_vote.union(Set(make_notarize_vote(id, lb)))
                else
                    sent_vote' = sent_vote,
                replica_state' = replica_state.set(id, updated),
                sent_leader_block' = sent_leader_block,
                store_leader_block' = store_leader_block,
                store_vote' = store_vote,
                sent_certificate' = sent_certificate,
                store_certificate' = store_certificate,
                ghost_vqc' = ghost_vqc,
                da_unchanged,
            }
        }
        | None => all {
            has_nullification(id, v),
            replica_state' = replica_state.set(
                id, advance_on_view_proof(self, v, VIEWS)),
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            sent_vote' = sent_vote,
            store_vote' = store_vote,
            sent_certificate' = sent_certificate,
            store_certificate' = store_certificate,
            ghost_vqc' = ghost_vqc,
            da_unchanged,
        }
        }
    }

    // 8.11. Finalize and emit (Algorithm 2, lines 21-22). L votes for
    // one leader block finalize it: the replica extracts the ordering
    // and appends to its log. Emission works off the vote pool directly
    // and never assembles an L-QC: the pool rules dominate the rules for
    // every L-QC assemblable from it, so pooling can emit strictly more.
    //
    // Assignment rather than append: successive values extend one
    // another, and appending would duplicate the prefix on every
    // re-firing. A computed value that fails to extend what is already
    // logged indicates a bug, so this guards rather than truncates.
    action on_finalize(id: ReplicaId, lb: LeaderBlock): bool = {
        val self = replica_state.get(id)
        // Extraction receives exactly the selected pool for this leader
        // block, never unrelated votes or two equivocations by one signer.
        val pool = notarize_votes(store_vote.get(id)).filter(v => vote_matches(v, lb))
        val maybe_emitted = emit(
            pool, lb, held_vqcs(id).union(Set(genesis_vqc(CHAINS))), PARAMS)
        match maybe_emitted {
        | None => disabled_action
        | Some(emitted) => all {
                pool_finalizes(pool, lb, PARAMS),
                emitted.length() > self.ghost_log.length(),
                // the new value must extend the old one
                self.ghost_log.indices().forall(j => emitted[j] == self.ghost_log[j]),
                replica_state' = replica_state.set(id, { ...self, ghost_log: emitted }),
                sent_leader_block' = sent_leader_block,
                store_leader_block' = store_leader_block,
                sent_vote' = sent_vote,
                store_vote' = store_vote,
                sent_certificate' = sent_certificate,
                store_certificate' = store_certificate,
                ghost_vqc' = ghost_vqc,
                da_unchanged,
            }
        }
    }

    // -------------------------------------------------
    // Driving the chain layer from a scripted scenario
    // -------------------------------------------------
    //
    // The two layers constrain disjoint sets of variables, so a step of
    // one must supply the other's frame. `step` below does that for
    // random exploration; these wrappers do it for scripted tests, which
    // need to fire a specific chain-layer action rather than any of them.
    // That the frames compose without interference is the split working.

    action chain_produce(id: ReplicaId, parent: Block, pl: PayloadId): bool = all {
        da_produce(id, parent, pl),
        consensus_unchanged,
    }

    action chain_da_vote(id: ReplicaId, b: Block): bool = all {
        da_vote_step(id, b),
        consensus_unchanged,
    }

    action chain_certify(b: Block): bool = all {
        da_certify_step(b),
        consensus_unchanged,
    }

    // Frame the chain layer for scripted consensus-state fixtures.
    action chain_layer_unchanged: bool = da_unchanged

    // Observers, so that a test need not reach into the chain layer.
    def da_voted_of(id: ReplicaId): Set[Block] = da_voted.get(id)
    def produced_blocks: Set[Block] = produced
    def sent_da_certificates: Set[DACert] = sent_da_cert

    // -------------------------------------------------
    // Steps
    // -------------------------------------------------

    action correct_replica_step: bool = all {
        nondet id = oneOf(REPLICA_IDS)
        any {
            on_propose(id),
            on_view_proof(id),
            on_timeout(id),
            on_nullify_by_contradiction(id),
            all {
                sent_leader_block != Set(),
                nondet lb = oneOf(sent_leader_block)
                on_deliver_leader_block(id, lb),
            },
            all {
                store_leader_block.get(id) != Set(),
                nondet lb = oneOf(store_leader_block.get(id))
                on_vote(id, lb),
            },
            all {
                sent_vote != Set(),
                nondet x = oneOf(sent_vote)
                on_deliver_vote(id, x),
            },
            all {
                nondet v = oneOf(VIEWS)
                on_nullification(id, v),
            },
            all {
                store_leader_block.get(id) != Set(),
                nondet lb = oneOf(store_leader_block.get(id))
                nondet h = oneOf(1.to(MAX_VQC_HASH))
                on_vqc(id, lb, h),
            },
            all {
                sent_certificate != Set(),
                nondet c = oneOf(sent_certificate)
                on_deliver_certificate(id, c),
            },
            all {
                store_leader_block.get(id) != Set(),
                nondet lb = oneOf(store_leader_block.get(id))
                on_finalize(id, lb),
            },
        },
    }

    // The adversary may send any well-formed message signed under a key
    // it controls, in any multiplicity, to any subset of replicas, and
    // may withhold any message. Selective disclosure is in scope: the
    // model achieves it by letting delivery be a separate, per-replica
    // action.
    //
    // These finite domains are deliberately Cartesian. In particular,
    // every chain chooses its proposal payloads, position and extension
    // independently; restricting one Byzantine choice to every chain
    // would miss exactly the cross-chain carry behaviours of interest.
    pure def bounded_payload_lists(limit: int): Set[List[PayloadId]] = {
        1.to(limit).fold(Set(List()), (acc, _) =>
            acc.union(tuples(acc, PAYLOADS).map(((xs, pl)) => xs.append(pl))))
    }

    pure val BYZANTINE_PARENT_HASHES =
        Set(EMPTY_VQC_HASH).union(0.to(MAX_VQC_HASH))

    pure val BYZANTINE_HASH_PATHS = bounded_payload_lists(MAX_HEIGHT)

    // The bounded syntactic leader-block universe. It intentionally does
    // not call proposal_wellformed: a Byzantine leader may sign a block
    // with an unknown parent, junk or stale hash anchors, or certificate
    // anchors that fail the proposal-validity height test. Correct voters
    // continue to reject those through is_valid_proposal. Certificate
    // anchors must nevertheless be authentic broadcasts: the adversary
    // cannot forge a threshold signature.
    def bounded_byzantine_leader_block(lb: LeaderBlock): bool = and {
        VIEWS.contains(lb.view),
        lb.view > GENESIS_VIEW,
        BYZANTINE_PARENT_HASHES.contains(lb.parent_vqc),
        lb.proposal.keys() == CHAINS,
        CHAINS.forall(i => {
            val entry = lb.proposal.get(i)
            and {
                entry.payloads.length() <= PIPELINE_D,
                entry.payloads.indices().forall(j => PAYLOADS.contains(entry.payloads[j])),
                match entry.anchor {
                    | HashAnchor(b) => and {
                        b.chain == i,
                        block_height(b) <= MAX_HEIGHT,
                        b.payloads.indices().forall(j => PAYLOADS.contains(b.payloads[j])),
                    }
                    | CertAnchor(c) => and {
                        c.block.chain == i,
                        sent_da_cert.contains(c),
                        da_cert_wellformed(c, PARAMS),
                    }
                },
            }
        }),
    }

    action byzantine_leader_block_step(byz: ReplicaId, lb: LeaderBlock): bool = all {
        BYZANTINE.contains(byz),
        is_leader(byz, lb.view),
        bounded_byzantine_leader_block(lb),
        sent_leader_block' = sent_leader_block.union(Set(lb)),
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        ghost_vqc' = ghost_vqc,
    }

    action byzantine_notarize_vote_step(
        byz: ReplicaId,
        lb: LeaderBlock,
        positions: Positions,
        extensions: Extensions
    ): bool = {
        val x: NotarizeVote = {
            leader_block: lb,
            positions: positions,
            extensions: extensions,
            sig: sig_of(byz),
        }
        all {
            BYZANTINE.contains(byz),
            sent_leader_block.contains(lb),
            vote_wellformed(x, PARAMS),
            lb.proposal.keys().forall(i =>
                extensions.get(i).indices().forall(j =>
                    PAYLOADS.contains(extensions.get(i)[j]))),
            sent_vote' = sent_vote.union(Set(Notarize(x))),
            sent_leader_block' = sent_leader_block,
            sent_certificate' = sent_certificate,
            ghost_vqc' = ghost_vqc,
        }
    }

    action byzantine_step: bool = {
        nondet byz = oneOf(BYZANTINE)
        any {
            // Atomically inject any bounded, syntactically well-formed
            // leader block for a view controlled by this Byzantine key.
            // `None` selects the independently chosen hash anchor for a
            // chain; `Some(c)` selects an authentic DA-certificate.
            all {
                val controlled_views = VIEWS.filter(v =>
                    v > GENESIS_VIEW and is_leader(byz, v))
                nondet v = oneOf(controlled_views)
                nondet h = oneOf(BYZANTINE_PARENT_HASHES)
                nondet hash_paths = oneOf(CHAINS.setOfMaps(BYZANTINE_HASH_PATHS))
                val cert_options = sent_da_cert.map(c => Some(c)).union(Set(None))
                nondet cert_anchors = oneOf(CHAINS.setOfMaps(cert_options))
                nondet payloads = oneOf(
                    CHAINS.setOfMaps(bounded_payload_lists(PIPELINE_D)))
                val lb = {
                    view: v,
                    parent_vqc: h,
                    proposal: CHAINS.mapBy(i => {
                        anchor: match cert_anchors.get(i) {
                            | Some(c) => CertAnchor(c)
                            | None => HashAnchor(mkBlock(i, hash_paths.get(i)))
                        },
                        payloads: payloads.get(i),
                    }),
                }
                all {
                    controlled_views != Set(),
                    byzantine_leader_block_step(byz, lb),
                }
            },
            // Atomically choose every chain's admissible position and
            // bounded extension independently for a seen leader block.
            all {
                sent_leader_block != Set(),
                nondet lb = oneOf(sent_leader_block)
                val position_maps = lb.proposal.keys()
                    .setOfMaps(0.to(PIPELINE_D))
                    .filter(ps => lb.proposal.keys().forall(i =>
                        ps.get(i) <= num_proposal_entries(lb.proposal, i)))
                nondet positions = oneOf(position_maps)
                nondet extensions = oneOf(lb.proposal.keys().setOfMaps(
                    bounded_payload_lists(EXT_E)))
                byzantine_notarize_vote_step(byz, lb, positions, extensions)
            },
            // novote and nullify freely
            all {
                nondet v = oneOf(VIEWS)
                sent_vote' = sent_vote.union(Set(
                    novote(v, sig_of(byz)), nullify(v, sig_of(byz)))),
                sent_leader_block' = sent_leader_block,
                sent_certificate' = sent_certificate,
                ghost_vqc' = ghost_vqc,
            },
            // Assemble a V-QC from any exact-L subset available on the
            // network, rather than only locally stored messages. The
            // paper's `new` rule binds correct processors only, so there
            // is no once-per-view guard here. Only the abstract hash is
            // constrained -- id_is_ok_for keeps it injective, as it must
            // be for ghost_vqc to model H at all.
            all {
                sent_leader_block != Set(),
                nondet lb = oneOf(sent_leader_block)
                nondet h = oneOf(1.to(MAX_VQC_HASH))
                val v = lb.view
                nondet selected = oneOf(vqc_message_subsets(sent_vote, v))
                val selected_votes = notarize_votes(selected)
                val tally = selected_votes.filter(x => vote_matches(x, lb))
                val others = selected_votes.filter(x => not(vote_matches(x, lb)))
                val novotes = select_votes(v, NovoteKind, selected).map(x => vote_sig(x))
                val q0: VQC = {
                    id: h,
                    leader_block: lb,
                    votes: tally,
                    novotes: novotes,
                    other_votes: others,
                    ghost_sender: sig_of(byz),
                }
                all {
                    VIEWS.contains(v),
                    vqc_wellformed(q0, PARAMS),
                    id_is_ok_for(h, q0),
                    sent_certificate' = sent_certificate.union(Set(Notarization(q0))),
                    ghost_vqc' = ghost_vqc.put(h, q0),
                    sent_leader_block' = sent_leader_block,
                    sent_vote' = sent_vote,
                },
            },
        }
    }


    action byzantine_step_framed: bool = all {
        byzantine_step,
        replica_state' = replica_state,
        store_leader_block' = store_leader_block,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        da_unchanged,
    }

    action byzantine_leader_block_step_framed(
        byz: ReplicaId,
        lb: LeaderBlock
    ): bool = all {
        byzantine_leader_block_step(byz, lb),
        replica_state' = replica_state,
        store_leader_block' = store_leader_block,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        da_unchanged,
    }

    action byzantine_notarize_vote_step_framed(
        byz: ReplicaId,
        lb: LeaderBlock,
        positions: Positions,
        extensions: Extensions
    ): bool = all {
        byzantine_notarize_vote_step(byz, lb, positions, extensions),
        replica_state' = replica_state,
        store_leader_block' = store_leader_block,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        da_unchanged,
    }

    action step = any {
        correct_replica_step,
        all {
            BYZANTINE != Set(),
            byzantine_step_framed,
        },
        // the chain layer runs concurrently with, and independently of,
        // the consensus layer
        all {
            da_step,
            consensus_unchanged,
        },
    }

    // -------------------------------------------------
    // Invariants
    // -------------------------------------------------

    val assumptions_valid = all {
        Replicas.forall(r => REPLICA_KEYS.keys().contains(r)),
        REPLICA_IDS == CORRECT.union(TWINS),
        CORRECT.intersect(TWINS) == Set(),
        CORRECT.intersect(BYZANTINE) == Set(),
        TWINS.intersect(BYZANTINE) == Set(),
        CORRECT_KEYS.intersect(FAULTY_KEYS) == Set(),
        CORRECT_KEYS.size() == CORRECT.size(),
        CORRECT_KEYS.size() + FAULTY_KEYS.size() == N,
        // the actual fault count stays inside the assumed bound
        FAULTY_KEYS.size() == F,
        F <= T,
        N >= 5 * T + 1,
        // every M-quorum and every L-quorum share a correct replica
        M + L > N + T,
    }

    // Every correct replica's retained notarization pool is a partial
    // function from (leader block, signer) to vote. Network delivery is
    // nondeterministic, so different replicas may retain different first
    // votes from a Byzantine signer without either storing both.
    val vote_pool_one_per_signer = REPLICA_IDS.forall(id => {
        val pool = notarize_votes(store_vote.get(id))
        tuples(pool, pool).forall(((v1, v2)) =>
            (v1.leader_block == v2.leader_block and v1.sig == v2.sig) implies v1 == v2)
    })

    // L1 -- if an L-QC for a leader block is present, every V-QC for
    // that view designates the same leader block. The model represents
    // an L-QC by a locally held finalising vote pool, so compare each
    // such pool directly with stored V-QCs. Two differently designated
    // V-QCs are permitted when no L-QC is present.
    val l1_lqc_vqc_designation = REPLICA_IDS.forall(lqc_holder => {
        val pool = notarize_votes(store_vote.get(lqc_holder))
        val lqc_blocks = pool.map(v => v.leader_block).filter(lb =>
            pool_finalizes(pool, lb, PARAMS))
        REPLICA_IDS.forall(vqc_holder =>
            store_certificate.get(vqc_holder).forall(c =>
                match c {
                    | Notarization(q) => lqc_blocks.forall(lb =>
                        lb.view != q.leader_block.view or lb == q.leader_block)
                    | Nullification(_) => true
                }))
    })

    // L2 -- no view has both a nullification and an L-notarization.
    val l2_no_nullify_and_finalize = VIEWS.forall(v => {
        val finalized = REPLICA_IDS.exists(id => {
            val pool = notarize_votes(store_vote.get(id)).filter(x => x.leader_block.view == v)
            pool != Set() and pool.exists(x => pool_finalizes(pool, x.leader_block, PARAMS))
        })
        val nullified = REPLICA_IDS.exists(id => has_nullification(id, v))
        not(finalized and nullified)
    })

    // A2 -- every safe-to-extend tip names a block that was actually
    // produced. The drop-t rank guarantees a correct reporter, so a
    // drop-0 rule would let one faulty vote anchor the next proposal on
    // junk and stall the chain.
    val a2_tips_are_real = REPLICA_IDS.forall(id =>
        store_certificate.get(id).forall(c =>
            match c {
                | Notarization(q) =>
                    CHAINS.forall(j => {
                        val b = tips(q, PARAMS).get(j)
                        block_height(b) == 0 or produced.contains(b)
                    })
                | Nullification(_) => true
            }))

    // E1a -- the finalised tip never sits above the safe-to-extend tip
    // of any same-view V-QC. This is the whole of consistency across the
    // two layers.
    val e1a_final_below_safe = REPLICA_IDS.forall(id => {
        val pool = notarize_votes(store_vote.get(id))
        store_certificate.get(id).forall(c =>
            match c {
                | Notarization(q) =>
                    pool_finalizes(pool, q.leader_block, PARAMS) implies
                        CHAINS.forall(j => {
                            val safe = tips(q, PARAMS).get(j)
                            val final_tip = tips_f(pool, q.leader_block, PARAMS).get(j)
                            safe.does_extend_block(final_tip)
                        })
                | Nullification(_) => true
            })
    })

    // E5 -- agreement. The logs of any two correct replicas are
    // compatible: one is a prefix of the other.
    pure def prefix_compatible(l1: List[Block], l2: List[Block]): bool = {
        val shorter = min(l1.length(), l2.length())
        0.to(shorter - 1).forall(j => l1[j] == l2[j])
    }

    val agreement = tuples(CORRECT, CORRECT).forall(((p1, p2)) =>
        prefix_compatible(replica_state.get(p1).ghost_log, replica_state.get(p2).ghost_log))

    // Every ghost-map binding agrees with the id embedded in its V-QC.
    // This checks the representation invariant separately from content
    // uniqueness, so the embedded id cannot make the latter vacuous.
    val vqc_id_matches_key = ghost_vqc.keys().forall(h => ghost_vqc.get(h).id == h)

    // A logical V-QC has exactly one abstract hash. `id` and `ghost_sender`
    // are representation metadata rather than hashed content, so normalize
    // them before comparing two bindings.
    val vqc_content_has_unique_id =
        tuples(ghost_vqc.keys(), ghost_vqc.keys()).forall(((h1, h2)) =>
            (vqc_content(ghost_vqc.get(h1)) == vqc_content(ghost_vqc.get(h2)))
                implies h1 == h2)

    val all_invariants = all {
        da_invariants,
        vqc_id_matches_key,
        vqc_content_has_unique_id,
        vote_pool_one_per_signer,
        l1_lqc_vqc_designation,
        l2_no_nullify_and_finalize,
        a2_tips_are_real,
        e1a_final_below_safe,
        agreement,
    }

    // Algorithm 2 consumes only a proof for the current view. Proofs for
    // other views remain in State until their view becomes current.
    pure def advance_on_view_proof(
        self: ReplicaState,
        proof_view: ViewNumber,
        views: Set[ViewNumber]
    ): ReplicaState = {
        if (proof_view == self.view)
            enter_new_view(self, self.view + 1, views)
        else
            self
    }

    // Witnesses: check as invariants to obtain a run reaching the state.
    val no_leader_block = sent_leader_block == Set()
    val no_vote = notarize_votes(sent_vote) == Set()
    // Q_gen does not count: init seeds it into every store, so without
    // the exemption this witness is false in the initial state and the
    // run it yields is empty.
    val no_vqc = REPLICA_IDS.forall(id =>
        store_certificate.get(id).forall(c =>
            cert_kind(c) == NullificationKind or cert_view(c) == GENESIS_VIEW))
    val no_log = REPLICA_IDS.forall(id => replica_state.get(id).ghost_log == List())
}
