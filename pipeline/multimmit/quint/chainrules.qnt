// The per-chain rules of the Multimmit specification: Prop, endorsement,
// the two rank rules and their extension carries (Tips and TipsF for one
// chain), settledness, and the vote-forming functions Positions and
// Extensions.
//
// Every definition here is indexed by a single chain and never looks at
// another one, so a one-chain instance exercises the whole module. The
// multichain lifts of Tips, TipsF and settledness, and the sweep that
// turns tips into a log, are in sweep.qnt; the dividing line is the type
// Tips = ChainId -> Block, which belongs to sweep.qnt. (Positions and
// Extensions are maps too, but they are parts of a message rather than
// of the extraction apparatus, so their pointwise lifts stay here.)
//
// All definitions are pure functions of a chain proposal and a set of
// votes -- never of a replica's state. This is required, not
// incidental: Tips must evaluate identically at every replica, or one
// replica accepts a proposal another rejects and the extracted
// orderings diverge. The candidate universe of an extension carry is
// exactly the blocks the votes themselves endorse (each vote's endorsed
// path is reconstructible from C and that vote's own positions and
// extensions), never a search over the blocks a replica happens to hold.
//
// Why the two kinds of threshold differ. Positions use rank rules
// (discard the top f, respectively the top 3f) while extensions use
// endorsement thresholds (2f+1, respectively unanimity above a fully
// supported proposal path). The rank rules are sound precisely because
// the proposal pins one block per position, so all votes on a chain's
// positions lie on a common path and a rank determines a block.
// Extensions lie above anything pinned: under an equivocating producer
// two votes at the same height may endorse incompatible blocks, a rank
// would then determine only a height, and the branch-aware repair at the
// same thresholds is impossible. Hence the strengthened thresholds,
// which are forced at n = 5f+1.

module chainrules {
    import types.* from "./types"
    import option.* from "./option"
    import blocks.* from "./blocks"
    import defs.* from "./defs"

    // -------------------------------------------------
    // Prop
    // -------------------------------------------------

    // Prop(C, i, k): the block specified at position k on chain i,
    // position 0 being the base and position k >= 1 the block extending
    // the base by the first k payloads of x_i (k is clamped to [0, m_i]
    // for totality).
    //
    // Entries specify blocks by payload alone, with chain, height and
    // parent supplied by context, so the specified blocks form a chain
    // by construction and no signatures are needed inside a proposal.
    // Nothing certifies that they exist: a leader may propose junk
    // payloads, and correct voters report a lower position.
    pure def prop(c: ChainProposal, i: ChainId, k: int): Block = {
        val entry = c.get(i)
        val kk = min(max(k, 0), entry.payloads.length())
        { chain: i, payloads: anchor_block(entry.anchor).payloads.concat(entry.payloads.slice(0, kk)) }
    }

    // The proposed tip for chain i: Prop(C, i, m_i). When m_i = 0, the
    // proposed tip is the base itself.
    pure def proposed_tip(c: ChainProposal, i: ChainId): Block = {
        prop(c, i, num_proposal_entries(c, i))
    }

    // -------------------------------------------------
    // Endorsement
    // -------------------------------------------------

    // The endorsed tip of a vote for chain i: the last block specified
    // by its extensions eps(i), and its position block Prop(C, i, pi(i))
    // if eps(i) is empty. Extensions are anchored at the vote's reported
    // position, not at the proposed tip, which is what makes the
    // frontier leader-proof: an honest chain's fresh blocks are endorsed
    // by every correct vote whatever the leader proposed, junk entries
    // included. (A vote with pi(i) < m_i and a non-empty eps(i) is legal
    // and not a defect: it is exactly the case of a leader whose entries
    // for chain i are junk or stale, where the voter reports a low
    // position and attaches the chain's true recent blocks from there.)
    pure def endorsed_tip(v: NotarizeVote, i: ChainId): Block = {
        val position_block = prop(v.leader_block.proposal, i, v.positions.get(i))
        { chain: i, payloads: position_block.payloads.concat(v.extensions.get(i)) }
    }

    // A vote endorses the transaction block b if b lies at or above the
    // proposal's base for b's chain and is an ancestor of, or equal to,
    // the vote's endorsed tip. Thus a vote endorses every block on the
    // path it endorses, however that path is split between positions and
    // extensions.
    //
    // Why the height check. Endorsement is ancestry within the
    // proposal's own tree: the path Prop(C, i, 0..m_i) extended by each
    // vote's extension blocks. It is not global block ancestry. A hash
    // anchor gives only a (hash, height) pair and no parent, so the
    // proposal says nothing about what lies beneath its base, and blocks
    // down there are outside the domain of endorsement, Tips, TipsF and
    // settledness. Without the check, `does_extend_block` would answer
    // for them anyway -- blocks are paths, so global ancestry is
    // readable off any block -- giving a strictly larger relation that
    // differs from the intended one exactly below the base.
    //
    // The only caller in the protocol is `carry_candidates`, whose
    // candidates are ancestors of endorsed tips taken from the position
    // block upwards, hence never below the base.
    pure def endorses(v: NotarizeVote, b: Block): bool = and {
        v.leader_block.proposal.keys().contains(b.chain),
        pure val base = anchor_block(v.leader_block.proposal.get(b.chain).anchor)
        block_height(b) >= block_height(base),
        endorsed_tip(v, b.chain).does_extend_block(b),
    }

    // -------------------------------------------------
    // The rank rules
    // -------------------------------------------------

    // On the ranges below: every rank runs over 0..d with a guard
    // k <= m_i, rather than directly over 0..m_i. The two are equivalent,
    // since well-formedness caps |x_i| at d, but only the first has a
    // constant bound, which a symbolic model checker requires. The same
    // applies to every height-indexed range in blocks.qnt, which is
    // bounded by the model's height cap.
    //
    // The rank rule of Tips: order the positions reported for chain i by
    // the votes from greatest to least (with multiplicity, one voice per
    // signer), discard the first f, and take the next value, i.e. the
    // greatest k such that at least f+1 signers report a position >= k;
    // 0 if there is no such k (in particular for Q_gen, whose vote set
    // is empty).
    //
    // Two obligations pin the drop-f rank. Safety: it sits at or above
    // the finalised position. Availability: it is reported by at least
    // one correct voter, so Tips names a block someone holds; a drop-0
    // rule would let a single faulty vote anchor the next proposal on
    // junk and stall the chain.
    pure def safe_position(votes: Tally, i: ChainId, m: int, p: Params): int = {
        val ks = 0.to(p.d).filter(k => and {
            k <= m,
            signers(votes.filter(v => v.positions.get(i) >= k)).size() >= p.t + 1,
        })
        ks.fold(0, (acc, k) => max(acc, k))
    }

    // The rank rule of TipsF: the (3f+1)-th largest position reported
    // for chain i over the pool (one voice per signer), i.e. the
    // greatest k such that at least 3f+1 signers report a position >= k;
    // 0 if there is no such k.
    pure def final_position(pool: Tally, i: ChainId, m: int, p: Params): int = {
        val ks = 0.to(p.d).filter(k => and {
            k <= m,
            signers(pool.filter(v => v.positions.get(i) >= k)).size() >= 3 * p.t + 1,
        })
        ks.fold(0, (acc, k) => max(acc, k))
    }

    // The candidate universe of an extension carry above `b`: the blocks
    // that votes in `vs` endorse, at or above b's height. Each vote's
    // endorsed path is reconstructible from its own leader block and
    // (positions, extensions), so this is a pure function of the vote
    // set -- never a search over held blocks.
    pure def carry_candidates(vs: Tally, i: ChainId, b: Block, threshold: int): Set[Block] = {
        vs.map(v => endorsed_tip(v, i))
            .fold(Set(), (acc, t) => acc.union(ancestors_from(t, block_height(b))))
            .filter(bb => and {
                bb.does_extend_block(b),
                signers(vs.filter(v => endorses(v, bb))).size() >= threshold,
            })
    }

    // -------------------------------------------------
    // Tips and TipsF, for one chain
    // -------------------------------------------------

    // Tips(Q) for chain i: the rank-rule block b_i = Prop(C, i, k_i),
    // then the extension carry -- the deepest block on chain i extending
    // b_i that at least 2f+1 tally signers endorse, if there is one,
    // ties broken deterministically by least hash.
    //
    // The rank runs over Q's tally, i.e. the votes for the leader block
    // Q contains, not merely "votes for C". An equivocating leader may
    // sign two blocks sharing a chain proposal but differing in parent;
    // votes for the other one sit in Q.other_votes and must not be
    // ranked.
    pure def tips_chain(q: VQC, i: ChainId, p: Params): Block = {
        val c = q.leader_block.proposal
        val tally = q.votes.filter(v => vote_matches(v, q.leader_block))
        val b = prop(c, i, safe_position(tally, i, num_proposal_entries(c, i), p))
        deepest_or(b, carry_candidates(tally, i, b, null_quorum(p)))
    }

    // TipsF for chain i, over a pool P of votes for ell by distinct
    // processors with |P| >= n-f. If k*_i < m_i the finalised tip is
    // Prop(C, i, k*_i); if k*_i = m_i it is the deepest block extending
    // the proposed tip that at least n-f pool signers endorse (and the
    // proposed tip itself if there is none).
    //
    // No tie-break is needed at the unanimity threshold: two
    // incompatible blocks each endorsed by >= n-f votes of P would have
    // endorsing sets meeting in 2(n-f) - |P| >= n-2f >= 3f+1 > f
    // signers, hence in a correct one, whose single vote endorses one
    // path, so `deepest_or`'s tie-break is never reached here.
    //
    // The condition k*_i = m_i cannot be dropped. Without it an
    // equivocating producer -- a producer, not a leader, which matters
    // since no quantifier of the block inclusion theorem depends on the
    // leader -- can arrange two executions sharing one bit-identical
    // V-QC in which incompatible blocks are finalised, leaving no
    // extraction rule on that V-QC safe in both.
    pure def tips_f_chain(pool: Tally, lb: LeaderBlock, i: ChainId, p: Params): Block = {
        val pl = pool.filter(v => vote_matches(v, lb))
        val c = lb.proposal
        val m = num_proposal_entries(c, i)
        val k = final_position(pl, i, m, p)
        val b = prop(c, i, k)
        if (k < m)
            b
        else
            deepest_or(b, carry_candidates(pl, i, b, vqc_quorum(p)))
    }

    // Chain i is settled w.r.t. the pool P if k*_i = m_i and
    // beta_i + (n - |P|) <= f, where beta_i is the number of pool
    // signers endorsing some block strictly extending b*_i = TipsF(P)_i.
    // Then at most f correct votes endorsing blocks beyond b*_i can
    // exist at all, seen or unseen, so no V-QC can carry chain i past
    // b*_i and emission may safely skip the chain's later slots. For a
    // bare L-QC (|P| = n-f) this reduces to: no vote in the L-QC
    // endorses any block strictly extending TipsF(P)_i.
    //
    // beta_i is computed from endorsed tips, not by a search over held
    // blocks: endorsement is closed under ancestry, so a vote endorses
    // something strictly beyond b*_i exactly when its endorsed tip does.
    // A search over held blocks is not just unnecessary but incorrect:
    // it would make settledness replica-dependent.
    //
    // The k*_i = m_i conjunct cannot be dropped: below the proposed tip
    // a V-QC's tip advances at threshold f+1, which f faulty votes and a
    // single correct vote from outside P can meet, and no pool can
    // certify that the latter does not exist.
    pure def is_settled(pool: Tally, lb: LeaderBlock, i: ChainId, p: Params): bool = {
        pure val pl = pool.filter(v => vote_matches(v, lb))
        pure val b = tips_f_chain(pool, lb, i, p)
        pure val beta = signers(pl.filter(v => strictly_extends(endorsed_tip(v, i), b))).size()
        and {
            pure val ne = num_proposal_entries(lb.proposal, i)
            final_position(pl, i, ne, p) == ne,
            beta + (p.n - signers(pl).size()) <= p.t,
        }
    }

    // -------------------------------------------------
    // Vote forming: Positions and Extensions
    // -------------------------------------------------
    //
    // These are the only definitions in the pure layers that read a
    // replica-local value, namely `da_voted`, the set of blocks the
    // voter has DA-voted for. With the certificate store, they are the
    // entire interface from the chain layer to the consensus layer:
    // a voter reports what it holds rather than fetching what it lacks,
    // so no processor blocks or fetches on the critical path to voting.

    // Positions(State, ell): for each chain i, the greatest k <= m_i
    // such that the voter has DA-voted Prop(C, i, k') for every k' in
    // [1, k]. Found by locating the first gap and stopping just below
    // it -- one pass, over the constant range 1..d, since a range whose
    // bounds are not literals is beyond Apalache.
    pure def vote_positions(da_voted: Set[Block], lb: LeaderBlock, p: Params): Positions = {
        pure def vote_position_on(i: ChainId): int = {
            // The ranks the proposal offers, capped by the pipelining
            // window: a vote never reports a position above d.
            val cap = min(num_proposal_entries(lb.proposal, i), p.d)
            // The least rank in 1..cap whose proposal block the voter
            // has not DA-voted, or cap + 1 if the prefix is gap-free.
            val first_gap = 1.to(p.d)
                .filter(k => k <= cap and not(da_voted.contains(prop(lb.proposal, i, k))))
                .fold(cap + 1, (acc, k) => min(acc, k))
            first_gap - 1
        }
        lb.proposal.keys().mapBy(i => vote_position_on(i))
    }

    // The payloads of the longest run of at most `limit` consecutive
    // DA-voted blocks extending `from_block` (and the empty sequence if
    // there is none). Ties -- possible only if the replica DA-voted
    // incompatible blocks, which correct replicas never do -- are broken
    // by least hash.
    //
    // Both places where a replica turns its own DA-voting history into a
    // sequence of payloads use this: a voter's extensions, taken above
    // its reported position with limit e, and a leader's payload
    // entries, taken above the anchor with limit d.
    pure def longest_da_voted_run(
        voted: Set[Block],
        from_block: Block,
        limit: int
    ): List[PayloadId] = {
        val h0 = block_height(from_block)
        // A candidate is a DA-voted block at most `limit` above
        // `from_block` with every block between the two DA-voted as
        // well. The gap-free check walks the offsets 1..limit rather
        // than the heights h0+1..height(b), whose bounds are not
        // literals and so do not translate for Apalache. Offsets past
        // the candidate's own height are vacuous.
        val candidates = voted.filter(b => and {
            strictly_extends(b, from_block),
            block_height(b) <= h0 + limit,
            1.to(limit).forall(j =>
                (h0 + j <= block_height(b))
                    implies voted.contains(ancestor_at(b, h0 + j))),
        })
        val tip = deepest_or(from_block, candidates)
        tip.payloads.slice(h0, block_height(tip))
    }

    // Extensions(State, ell): for each chain i, the payloads of the
    // longest sequence of at most e consecutive DA-voted blocks on
    // chain i extending the vote's position block Prop(C, i, pi(i)).
    // The second of the two maps a vote carries.
    pure def vote_extensions(
        da_voted: Set[Block],
        lb: LeaderBlock,
        positions: Positions,
        p: Params
    ): Extensions = {
        lb.proposal.keys().mapBy(i =>
            longest_da_voted_run(da_voted, prop(lb.proposal, i, positions.get(i)), p.e))
    }
}
