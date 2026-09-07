// Unit tests for the pure extraction layers. No state machine is
// imported: these tests exercise blocks.qnt, defs.qnt, chainrules.qnt
// and sweep.qnt directly, at parameters chosen for the test rather than
// for any instance under check. Needing to import a state machine here
// would mean the purity boundary has leaked.

module tests_extraction {
    import types.* from "../types"
    import option.* from "../option"
    import blocks.* from "../blocks"
    import defs.* from "../defs"
    import chainrules.* from "../chainrules"
    import sweep.* from "../sweep"

    // -------------------------------------------------
    // Fixtures
    // -------------------------------------------------

    // The full payload path of each of four chains; a block of chain i
    // at height h is the first h payloads of PATHS[i]. Payloads are
    // ints (they are hash values, and the carry tie-break orders them);
    // the tens digit names the chain purely to keep traces readable.
    pure val PATHS: ChainId -> List[PayloadId] = Map(
        1 -> [11, 12, 13, 14],
        2 -> [21, 22, 23, 24],
        3 -> [31, 32, 33, 34],
        4 -> [41, 42, 43, 44]
    )

    // The block of chain i at height h.
    pure def blk(i: ChainId, h: Height): Block = {
        mkBlock(i, PATHS.get(i).slice(0, h))
    }

    // -------------------------------------------------
    // 1. The rank rules: n = 11, f = 2, so M = 5 and L = 9
    // -------------------------------------------------
    //
    // A proposal makes four entries above the anchor. The nine votes of
    // an L-QC report positions 4, 4, 4, 3, 3, 3, 3, 2, 1:
    //
    //   position:   0(anchor)   1     2     3        4
    //   votes:                  *     *     ****     ***
    //                                       ^        ^
    //                                       |        `- safe to extend
    //                                       |           (drop top f = 2)
    //                                       `---------- finalized
    //                                                   (drop top 3f = 6)
    //
    // Discarding the top 3f = 6 leaves position 3 as the finalised tip;
    // discarding the top f = 2 leaves position 4 as safe to extend. The
    // safe-to-extend tip always sits at or above the finalised tip --
    // this is the whole of consistency across the two layers.

    pure val P11: Params = { n: 11, t: 2, d: 4, e: 2 }

    pure val LB_RANK: LeaderBlock = {
        view: 1,
        parent_vqc: GENESIS_VQC_HASH,
        proposal: Map(1 -> {
            anchor: HashAnchor(genesis_block(1)),
            payloads: [101, 102, 103, 104],
        }),
    }

    pure def rank_vote(sig: Signature, pos: int): NotarizeVote = {
        {
            leader_block: LB_RANK,
            positions: Map(1 -> pos),
            extensions: Map(1 -> List()),
            sig: sig,
        }
    }

    // The nine votes 4, 4, 4, 3, 3, 3, 3, 2, 1.
    pure val POOL_RANK: Tally = Set(
        rank_vote("s1", 4), rank_vote("s2", 4), rank_vote("s3", 4),
        rank_vote("s4", 3), rank_vote("s5", 3), rank_vote("s6", 3), rank_vote("s7", 3),
        rank_vote("s8", 2), rank_vote("s9", 1)
    )

    pure val Q_RANK: VQC = {
        id: 1,
        leader_block: LB_RANK,
        votes: POOL_RANK,
        novotes: Set(),
        other_votes: Set(),
        ghost_sender: "s1",
    }

    run rankRulesTest = all {
        // the parameters of the example
        null_quorum(P11) == 5,
        vqc_quorum(P11) == 9,
        signers(POOL_RANK).size() == 9,

        // drop the top f = 2: position 4 is safe to extend
        safe_position(POOL_RANK, 1, 4, P11) == 4,
        // drop the top 3f = 6: position 3 is finalised
        final_position(POOL_RANK, 1, 4, P11) == 3,

        // and the same two statements at the level of blocks
        tips_chain(Q_RANK, 1, P11) == prop(LB_RANK.proposal, 1, 4),
        tips_f_chain(POOL_RANK, LB_RANK, 1, P11) == prop(LB_RANK.proposal, 1, 3),

        // the safe-to-extend tip sits at or above the finalised tip
        tips_chain(Q_RANK, 1, P11)
            .does_extend_block(tips_f_chain(POOL_RANK, LB_RANK, 1, P11)),

        // chain 1 is not settled: k* = 3 falls short of m = 4, so the
        // chain may yet gain blocks at this slot and emission must halt
        not(is_settled(POOL_RANK, LB_RANK, 1, P11)),
    }

    // Ord and Emit are unavailable until every V-QC on the reference
    // chain can be resolved. They must never interpret a partial path as
    // an ordering prefix.
    run incompleteVqcAncestryTest = {
        val qgen = genesis_vqc(Set(1))
        val complete = Set(qgen, Q_RANK)
        all {
            vqc_ancestry(Q_RANK, Set(Q_RANK)) == None,
            ord(Q_RANK, Set(Q_RANK), P11) == None,
            vqc_ancestry(Q_RANK, complete) == Some([qgen, Q_RANK]),
            is_some(ord(Q_RANK, complete, P11)),
            emit(POOL_RANK, LB_RANK, Set(), P11) == None,
            is_some(emit(POOL_RANK, LB_RANK, complete, P11)),
        }
    }

    // -------------------------------------------------
    // 2. The horizontal sweep, on four chains
    // -------------------------------------------------
    //
    //   D     [1D]g   [2D]g
    //   C      1C      2C     [3C]g   [4C]g
    //   B      1B     [2B]r    3B      4B
    //   A     [1A]r    2A     [3A]r   [4A]r
    //
    // Red (r) = tips of the referenced V-QC, green (g) = tips of the
    // new one. Every chain's first new block is appended before any
    // chain's second, so chain 2's block C -- its FIRST new block --
    // is ordered in the first pass alongside the other chains' firsts,
    // even though it sits at a greater height than theirs.

    pure val TIPS_LO: Tips = Map(1 -> blk(1, 1), 2 -> blk(2, 2), 3 -> blk(3, 1), 4 -> blk(4, 1))
    pure val TIPS_HI: Tips = Map(1 -> blk(1, 4), 2 -> blk(2, 4), 3 -> blk(3, 3), 4 -> blk(4, 3))

    run horizTest = all {
        horiz(TIPS_LO, TIPS_HI, 4) == [
            // offset 1: every chain's first new block
            blk(1, 2), blk(2, 3), blk(3, 2), blk(4, 2),
            // offset 2: every chain's second
            blk(1, 3), blk(2, 4), blk(3, 3), blk(4, 3),
            // offset 3: only chain 1 has anything left
            blk(1, 4)
        ],

        // the sweep determines only the interleaving, never which
        // blocks are included: every block above each chain's old tip
        // appears exactly once
        horiz(TIPS_LO, TIPS_HI, 4).length() == 3 + 2 + 2 + 2,

        // nothing to append when the tips have not moved
        horiz(TIPS_HI, TIPS_HI, 4) == [],
    }

    // -------------------------------------------------
    // 3. Endorsement is base-relative
    // -------------------------------------------------
    //
    // A proposal for chain 1 anchored at height 2, making one entry.
    // A vote reporting position 1 endorses the base and the entry, but
    // must not endorse anything below the base: blocks beneath it lie
    // outside the domain of the extraction rules, because the anchor
    // names the base by identifier only and the proposal does not speak
    // about the base's parent.
    //
    // Read as global block ancestry -- which the path representation
    // makes possible -- blk(1, 1) *is* an ancestor of the endorsed tip,
    // so this test fails the moment the base guard in `endorses` is
    // dropped.

    pure val LB_BASE: LeaderBlock = {
        view: 1,
        parent_vqc: GENESIS_VQC_HASH,
        proposal: Map(1 -> {
            anchor: HashAnchor(blk(1, 2)),
            payloads: [13],
        }),
    }

    pure val VOTE_BASE: NotarizeVote = {
        leader_block: LB_BASE,
        positions: Map(1 -> 1),
        extensions: Map(1 -> List()),
        sig: "s1",
    }

    run baseGuardTest = all {
        // the proposal's base and its single entry
        prop(LB_BASE.proposal, 1, 0) == blk(1, 2),
        prop(LB_BASE.proposal, 1, 1) == blk(1, 3),
        endorsed_tip(VOTE_BASE, 1) == blk(1, 3),

        // the vote endorses the entry and the base
        endorses(VOTE_BASE, blk(1, 3)),
        endorses(VOTE_BASE, blk(1, 2)),

        // but nothing below the base, even though global ancestry holds
        not(endorses(VOTE_BASE, blk(1, 1))),
        blk(1, 3).does_extend_block(blk(1, 1)),

        // nor anything above the endorsed tip
        not(endorses(VOTE_BASE, blk(1, 4))),
    }

    // -------------------------------------------------
    // 4. Extensions are anchored at the voter's position
    // -------------------------------------------------
    //
    // A vote may report a low position -- because the leader's entries
    // are junk or stale -- and still attach the chain's true recent
    // blocks from there. This is what makes the frontier leader-proof.

    pure val LB_JUNK: LeaderBlock = {
        view: 1,
        parent_vqc: GENESIS_VQC_HASH,
        proposal: Map(1 -> {
            anchor: HashAnchor(genesis_block(1)),
            // 101 is junk: no block with this payload was ever produced
            payloads: [101, 102],
        }),
    }

    pure val VOTE_JUNK: NotarizeVote = {
        leader_block: LB_JUNK,
        // position 0: the voter DA-voted none of the proposed entries
        positions: Map(1 -> 0),
        // but it attaches the chain's real blocks, from the base up
        extensions: Map(1 -> [11, 12]),
        sig: "s1",
    }

    run extensionAnchoringTest = all {
        // the extension is anchored at the reported position (the base),
        // not at the proposed tip
        endorsed_tip(VOTE_JUNK, 1) == blk(1, 2),
        endorses(VOTE_JUNK, blk(1, 1)),
        endorses(VOTE_JUNK, blk(1, 2)),
        // the junk entries capture nothing
        not(endorses(VOTE_JUNK, prop(LB_JUNK.proposal, 1, 1))),
    }

    // -------------------------------------------------
    // 5. The carry tie-break is load-bearing
    // -------------------------------------------------
    //
    // At N = 6, T = 1 the carry threshold is M = 2T + 1 = 3, and two
    // DISJOINT M-sets fit inside N. So an equivocating producer can have
    // two incompatible blocks at one height each endorsed by exactly M
    // signers, and the extension carry of Tips then has two deepest
    // candidates. Something must choose between them, and every replica
    // must choose the SAME one, or Tips differs across replicas and the
    // extracted orderings fork.
    //
    // The tie-break is what resolves it: least hash among the deepest
    // candidates. It is not decoration -- without it the fold defining
    // the carry would depend on the candidate set's iteration order, and
    // Tips would differ across replicas.
    //
    // Contrast TipsF, whose carry threshold is L = N - T. There two
    // endorsing sets must meet in 2L - |P| >= N - 2T > T signers, hence
    // in a correct one, whose single vote endorses one path -- so the
    // deepest candidate is unique and the tie-break is never reached.

    pure val P6: Params = { n: 6, t: 1, d: 1, e: 1 }

    // A proposal for chain 1 with no payload entries: the position block
    // is the base, and everything above it arrives as extensions.
    pure val LB_TIE: LeaderBlock = {
        view: 1,
        parent_vqc: GENESIS_VQC_HASH,
        proposal: Map(1 -> { anchor: HashAnchor(genesis_block(1)), payloads: List() }),
    }

    pure def tie_vote(sig: Signature, pl: PayloadId): NotarizeVote = {
        {
            leader_block: LB_TIE,
            positions: Map(1 -> 0),
            extensions: Map(1 -> [pl]),
            sig: sig,
        }
    }

    // Three signers endorse the block with payload `x`, three the
    // incompatible one with payload `y`.
    pure def tie_vqc(x: PayloadId, y: PayloadId): VQC = {
        {
            id: 1,
            leader_block: LB_TIE,
            votes: Set(
                tie_vote("s1", x), tie_vote("s2", x), tie_vote("s3", x),
                tie_vote("s4", y), tie_vote("s5", y), tie_vote("s6", y)
            ),
            novotes: Set(),
            other_votes: Set(),
            ghost_sender: "s1",
        }
    }

    run carryTieBreakTest = all {
        // the tie is real: two incompatible blocks at one height, each
        // endorsed by exactly the carry threshold
        null_quorum(P6) == 3,
        incompatible(mkBlock(1, [11]), mkBlock(1, [12])),
        signers(tie_vqc(11, 12).votes.filter(v => endorses(v, mkBlock(1, [11])))).size() == 3,
        signers(tie_vqc(11, 12).votes.filter(v => endorses(v, mkBlock(1, [12])))).size() == 3,

        // least hash wins, whichever way the two are presented -- so the
        // rule is deterministic and does not depend on the iteration
        // order of the candidate set
        tips_chain(tie_vqc(11, 12), 1, P6) == mkBlock(1, [11]),
        tips_chain(tie_vqc(12, 11), 1, P6) == mkBlock(1, [11]),
        tips_chain(tie_vqc(13, 12), 1, P6) == mkBlock(1, [12]),
    }
}
