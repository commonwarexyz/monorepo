// The block algebra of the Multimmit chain layer: heights, parents,
// ancestors, the extension (ancestry) relation, and the deterministic
// "deepest, then least hash" choice used by the extraction rules.
//
// Everything here concerns one chain at a time and knows nothing about
// messages, proposals, votes or certificates. It is the lowest layer of
// the specification: types -> blocks -> defs -> chainrules -> sweep.
//
// Blocks are paths (see types.qnt): a block is its chain together with
// the sequence of payloads from the chain's genesis block up to itself,
// so that H is the identity, the height is the path length, and ancestry
// is the prefix relation on paths.
//
// Two ancestry relations, easily confused
//
// `does_extend_block` is global ancestry: it relates any two blocks of
// one chain, at any heights. The extraction rules use a different
// relation -- ancestry within a proposal's own tree, i.e. the path
// Prop(C, i, 0..m_i) extended by each vote's extension blocks. The two
// agree above a proposal's base and disagree below it, which is where
// the "strictly above the base" guard of the block inclusion theorem
// applies.
//
// Since a block's whole ancestry is readable from the block itself,
// nothing stops a caller from using the global relation where the
// proposal-local one is meant. Extraction code therefore reaches
// `does_extend_block` only through `endorses` in chainrules.qnt, which
// checks the height against the base first. No current caller reaches
// below a base, so that check is defensive rather than load-bearing;
// see the comment on `endorses`.

module blocks {
    import types.* from "./types"

    // -------------------------------------------------
    // Small helpers
    // -------------------------------------------------

    // The maximum of two integers
    pure def max(x: int, y: int): int = {
        if (x > y) x else y
    }

    // The minimum of two integers
    pure def min(x: int, y: int): int = {
        if (x < y) x else y
    }

    // -------------------------------------------------
    // Blocks, parents, and ancestors
    // -------------------------------------------------

    pure def block_height(b: Block): Height = b.payloads.length()

    // The parent of b (a genesis block is its own parent).
    pure def block_parent(b: Block): Block = {
        if (block_height(b) == 0)
            b
        else
            { chain: b.chain, payloads: b.payloads.slice(0, block_height(b) - 1) }
    }

    // The ancestor of b at height h (clamped to [0, height(b)] for
    // totality).
    pure def ancestor_at(b: Block, h: Height): Block = {
        if (h >= block_height(b))
            b
        else if (h <= 0)
            genesis_block(b.chain)
        else
            { chain: b.chain, payloads: b.payloads.slice(0, h) }
    }

    // Does b extend a, i.e., is a an ancestor of b? The ancestors of b
    // are b and all ancestors of its parent, so the relation is
    // reflexive. This is global ancestry; see the module comment before
    // using it in extraction code.
    pure def does_extend_block(b: Block, a: Block): bool = {
        if (b.chain != a.chain or block_height(a) > block_height(b))
            false
        else
            b.payloads.slice(0, block_height(a)) == a.payloads
    }

    // Does b strictly extend a, i.e., is a a proper ancestor of b?
    pure def strictly_extends(b: Block, a: Block): bool = {
        b.does_extend_block(a) and b != a
    }

    // Two transaction blocks on the same chain are incompatible if
    // neither is an ancestor of the other.
    pure def incompatible(b1: Block, b2: Block): bool = and {
        b1.chain == b2.chain,
        not(b1.does_extend_block(b2)),
        not(b2.does_extend_block(b1)),
    }

    // The ancestors of b at heights h0..height(b): b and its ancestors
    // down to height h0. This definition uses the modeling of blocks as
    // chains, so we can compute the ancestors in one pass. A more natural
    // but less efficient definition (quadratic) is given in
    // ancestors_from_inefficient.
    pure def ancestors_from(b: Block, h0: Height): Set[Block] = {
        pure val lo = max(h0, 0)
        // go over the block payloads and produce blocks in the range [0, height(b)]
        b.payloads
            .foldl(
                {
                    path: List(),
                    blocks: if (lo == 0) Set(genesis_block(b.chain)) else Set()
                },
                (st, x) => {
                    pure val path = st.path.append(x)
                    {
                        path: path,
                        blocks: if (path.length() >= lo)
                            st.blocks.union(Set(mkBlock(b.chain, path)))
                        else
                            st.blocks,
                    }
                }
            )
            .blocks
    }

    // The reference definition of `ancestors_from`, kept for comparison
    // with the folded version above. Not used by the specification.
    pure def ancestors_from_inefficient(b: Block, h0: Height): Set[Block] = {
        max(h0, 0).to(block_height(b)).map(h => ancestor_at(b, h))
    }

    // -------------------------------------------------
    // The deterministic "deepest, then least hash" choice
    // -------------------------------------------------
    //
    // The extension carry of Tips and TipsF picks a deepest candidate,
    // breaking ties by least hash. Any fixed total order on block
    // identifiers will do, provided every replica uses the same one:
    // Tips must evaluate identically at every replica, or one replica
    // accepts a proposal another rejects and the extracted orderings
    // diverge. Payloads being ints, the order is the lexicographic one
    // on payload paths, and every replica has it for free.

    // Lexicographic comparison of the payload paths of two blocks, i.e.
    // comparison of hash values in the "least hash" tie-breaks. A strict
    // total order on the blocks of one chain.
    //
    // The first differing index is taken in one pass: the fold takes the
    // minimum directly, rather than collecting the differing indices and
    // folding again. `min` is commutative, so the iteration order of the
    // index set does not matter. The domain is `indices()` rather than a
    // 0..n-1 range, whose bounds would not be literals and so would not
    // translate for Apalache.
    pure def block_lt(b1: Block, b2: Block): bool = {
        val n = min(block_height(b1), block_height(b2))
        val j0 = b1.payloads.indices().fold(n, (m, j) =>
            if (j < n and b1.payloads[j] != b2.payloads[j]) min(m, j) else m)
        if (j0 == n)
            // one path is a prefix of the other: the shorter is smaller
            block_height(b1) < block_height(b2)
        else
            b1.payloads[j0] < b2.payloads[j0]
    }

    // The block preferred by the "deepest, then least hash" rule.
    pure def deeper_block(b1: Block, b2: Block): Block = {
        if (block_height(b1) > block_height(b2))
            b1
        else if (block_height(b2) > block_height(b1))
            b2
        else if (block_lt(b1, b2))
            b1
        else
            b2
    }

    // A deepest block of `candidates`, ties broken deterministically by
    // least hash, and `base` itself if `candidates` is empty. The fold is
    // well-defined: deeper_block is the join of a total order
    // (associative, commutative and idempotent), so the result does not
    // depend on the set's iteration order. Callers pass candidates that
    // all extend `base`.
    pure def deepest_or(base: Block, candidates: Set[Block]): Block = {
        candidates.fold(base, (acc, b) => deeper_block(acc, b))
    }
}
