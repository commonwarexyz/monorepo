// The multichain layer: the tips vectors Tips(Q) and TipsF(P), the
// horizontal sweep Horiz, the total ordering Ord(Q), the emittable
// prefix Emit(P), and the well-formedness of a chain proposal against
// the tips of the V-QC it references.
//
// This is the only module that sees more than one chain at a time, and
// even here the coupling is confined to the sweep. Tips, TipsF and
// settledness are pointwise lifts of the per-chain rules in
// chainrules.qnt; what Horiz, Ord and Emit add is only the interleaving
// of the chains, never which blocks are included. A
// one-chain instance therefore exercises every threshold rule with the
// sweep trivial, which is the quickest way to tell "thresholds wrong"
// from "sweep wrong".
//
// The dividing line against chainrules.qnt is the type
// Tips = ChainId -> Block: it belongs here, and so does everything that
// consumes or produces one.

module sweep {
    import types.* from "./types"
    import option.* from "./option"
    import blocks.* from "./blocks"
    import defs.* from "./defs"
    import chainrules.* from "./chainrules"

    // -------------------------------------------------
    // The tips vectors: pointwise lifts
    // -------------------------------------------------

    // Tips(Q): the safe-to-extend tips of the V-QC Q, one per chain --
    // where the next leader must build. Each coordinate is computable
    // from Q alone, since anchors specify bases explicitly, and
    // Tips(Q_gen)_i = g_i for each chain i (Q_gen designates no
    // proposal, its vote set is empty, so every rank rule yields 0 and
    // every anchor is the chain's genesis block).
    pure def tips(q: VQC, p: Params): Tips = {
        q.leader_block.proposal.keys().mapBy(i => tips_chain(q, i, p))
    }

    // TipsF(P): the finalised tips of a pool P of votes for the leader
    // block ell, one per chain. An L-QC is the special case |P| = n-f.
    // The leader block is explicit because the pool alone determines
    // neither the chain proposal nor the counts m_i.
    pure def tips_f(pool: Tally, lb: LeaderBlock, p: Params): Tips = {
        lb.proposal.keys().mapBy(i => tips_f_chain(pool, lb, i, p))
    }

    // The settledness map of the pool, per chain.
    pure def settled_chains(pool: Tally, lb: LeaderBlock, p: Params): ChainId -> bool = {
        lb.proposal.keys().mapBy(i => is_settled(pool, lb, i, p))
    }

    // -------------------------------------------------
    // Proposal well-formedness
    // -------------------------------------------------

    // The pure core of "State contains a valid proposal ell for view v":
    // ell references the V-QC q, for an earlier view, and ell's chain
    // proposal C is well-formed with respect to Tips(q) -- for each
    // chain j, either a_j is the explicit anchor for Tips(q)_j, or a_j
    // is a valid DA-certificate for chain j of height greater than that
    // of Tips(q)_j; and |x_j| <= d.
    //
    // The remaining, stateful conditions belong to the state machine:
    // ell is signed by lead(v) and is the only leader block by lead(v)
    // for view v in State, State contains q, and State contains a
    // nullification for each view in the open interval (q.view, v).
    //
    // Voters do not verify that the proposed blocks exist; they report
    // a lower position when they have not DA-voted them. Note
    // also that this condition performs no compatibility check on a
    // DA-certificate anchor: a certified anchor may sit on a branch
    // incompatible with Tips(q)_j, which is possible only under an
    // equivocating producer, and which Horiz below handles by reading
    // the appended blocks off the new tip's own path.
    pure def proposal_wellformed(lb: LeaderBlock, q: VQC, p: Params): bool = and {
        lb.parent_vqc == q.id,
        lb.view > q.leader_block.view,
        lb.proposal.keys() == q.leader_block.proposal.keys(),
        val tq = tips(q, p)
        lb.proposal.keys().forall(j => and {
            match lb.proposal.get(j).anchor {
                | HashAnchor(b) => b == tq.get(j)
                | CertAnchor(c) => and {
                    c.block.chain == j,
                    block_height(c.block) > block_height(tq.get(j)),
                    da_cert_wellformed(c, p),
                }
            },
            lb.proposal.get(j).payloads.length() <= p.d,
        })
    }

    // -------------------------------------------------
    // Horiz: the interleaving
    // -------------------------------------------------

    // Horiz(T, T'): visit the positions (o, i) above T in horizontal
    // order -- by offset o first, then by chain index i -- and append,
    // at each position whose height is at most height(T'_i) on its chain
    // i, the ancestor of T'_i at that height. Every chain's first new
    // block is thus appended before any chain's second.
    //
    // The definition fixes only how the chains are interleaved, never
    // which blocks are included: for each i, every block on T'_i's path
    // above height(T_i) appears. In the intended case T'_i extends T_i;
    // the definition does not require it, and when a proposal's anchor
    // jumps to a DA-certificate on a branch incompatible with T_i --
    // possible only under an equivocating producer -- the appended
    // blocks are read off T'_i's own path.
    //
    // Alternative sweeps (vertical, hybrid, leader-scheduled,
    // blame-ordered) may be substituted without affecting the analysis,
    // provided the ordering is a deterministic function of (T, T') and
    // of the ancestry of the blocks they name. With blocks represented
    // as paths that ancestry travels inside the block, so no header
    // retrieval is needed to compute a segment.
    //
    // Chains are indexed 1..n, one per processor, so `n` gives the
    // ordered inner sweep directly and every index in range(1, n + 1) is
    // a chain. Tips vectors of any other shape yield the empty sequence,
    // which keeps horiz total.
    //
    // Offset is the outer loop and chain index the inner; that nesting
    // is the horizontal order. Swapping them gives the vertical order,
    // emitting each chain's whole new segment before moving on.
    pure def horiz(t: Tips, t2: Tips, n: int): List[Block] = {
        if (t.keys() != 1.to(n) or t2.keys() != t.keys())
            List()
        else {
            val max_offset = t.keys().fold(0, (a, i) =>
                max(a, block_height(t2.get(i)) - block_height(t.get(i))))
            range(1, max_offset + 1).foldl(List(), (acc, o) =>
                range(1, n + 1).foldl(acc, (acc2, i) => {
                    val h = block_height(t.get(i)) + o
                    if (h <= block_height(t2.get(i)))
                        acc2.append(ancestor_at(t2.get(i), h))
                    else
                        acc2
                }))
        }
    }

    // The sweep rho of Emit: visit the positions above T in horizontal
    // order and, at each position, on chain j say: if the position's
    // height is at most that of TF_j, append the ancestor of TF_j at
    // that height; otherwise, if chain j is settled, append nothing and
    // continue; otherwise, HALT.
    //
    // Emission must halt at an unsettled chain's frontier because such a
    // chain may yet gain a block at that slot, and a block so gained
    // would precede, in horizontal order, other chains' blocks at later
    // offsets. If every chain is settled, no halt occurs and rho is the
    // whole of Horiz(T, TF). A chain's potential growth is in any case
    // bounded: no vote endorses blocks more than e beyond its reported
    // position, so chains are never "potentially infinite".
    //
    // This is `horiz` with a halt: same positions, same nesting (offset
    // outer, chain inner), same append. So rho is always a prefix of
    // Horiz(T, TF), and equals it when no chain halts the sweep, which
    // is the paper's rho <= Horiz. `n` gives the inner sweep as it does
    // there.
    pure def emit_sweep(t: Tips, tf: Tips, settled: ChainId -> bool, n: int): List[Block] = {
        if (t.keys() != 1.to(n) or tf.keys() != t.keys() or settled.keys() != t.keys())
            List()
        else {
            val max_offset = t.keys().fold(0, (a, i) =>
                max(a, block_height(tf.get(i)) - block_height(t.get(i))))
            range(1, max_offset + 1).foldl(
                { halted: false, out: List() },
                (acc, o) =>
                    // once halted nothing more is appended, so the whole
                    // inner sweep is skipped rather than walked
                    if (acc.halted)
                        acc
                    else
                        range(1, n + 1).foldl(acc, (acc2, i) =>
                            if (acc2.halted)
                                acc2
                            else {
                                val h = block_height(t.get(i)) + o
                                if (h <= block_height(tf.get(i)))
                                    { ...acc2, out: acc2.out.append(ancestor_at(tf.get(i), h)) }
                                else if (settled.get(i))
                                    acc2
                                else
                                    { ...acc2, halted: true }
                            })
            ).out
        }
    }

    // -------------------------------------------------
    // Ord and Emit
    // -------------------------------------------------

    // The V-QC with hash `id` in `vqcs`, if there is exactly one (hash
    // injectivity is a model assumption; on a byzantine violation the
    // reference is treated as unresolvable).
    pure def resolve_vqc(id: VQcHash, vqcs: Set[VQC]): Option[VQC] = {
        val matching = vqcs.filter(q => q.id == id)
        if (matching.size() == 1)
            Some(matching.fold(genesis_vqc(Set()), (_, q) => q))
        else
            None
    }

    // The complete chain of V-QCs referenced from q, root-first. Missing
    // or ambiguous parents and reference cycles make the ancestry
    // unavailable: returning a partial path would let Ord silently drop
    // a certified prefix. The fold over `vqcs` bounds the walk, which is
    // how the recursive paper definition is expressed here.
    pure def vqc_ancestry(q: VQC, vqcs: Set[VQC]): Option[List[VQC]] = {
        val walk = vqcs.fold(
            {
                current: q,
                path: [q],
                done: q.id == GENESIS_VQC_HASH,
                complete: true,
            },
            (acc, _) =>
                if (acc.done)
                    acc
                else
                    match resolve_vqc(acc.current.leader_block.parent_vqc, vqcs) {
                        | None => { ...acc, done: true, complete: false }
                        | Some(parent) =>
                            if (acc.path.foldl(false, (seen, x) => seen or x.id == parent.id))
                                { ...acc, done: true, complete: false }
                            else {
                                current: parent,
                                path: List(parent).concat(acc.path),
                                done: parent.id == GENESIS_VQC_HASH,
                                complete: acc.complete,
                            }
                    })
        if (walk.done and walk.complete)
            Some(walk.path)
        else
            None
    }

    // Ord(Q): the sequence of transaction blocks specified by the V-QC
    // Q, defined over the referenced V-QCs by
    //   Ord(Q_gen) = lambda,
    //   Ord(Q)     = Ord(Q') ++ Horiz(Tips(Q'), Tips(Q)),
    // where Q references Q'. The recursion resolves parent references in
    // `vqcs`. If any referenced V-QC is unavailable, Ord is unavailable
    // until retrieval completes; it never returns a partial ordering.
    //
    // Because validity forces each proposal to extend, chain by chain,
    // the tips of the V-QC it references, every Ord(Q) has Ord(Q') as a
    // prefix: the ordering only ever grows.
    pure def ord(q: VQC, vqcs: Set[VQC], p: Params): Option[List[Block]] = {
        match vqc_ancestry(q, vqcs) {
            | None => None
            | Some(ancestry) => {
                val res = ancestry.foldl(
                    { prev: None, out: List() },
                    (acc, x) =>
                        match acc.prev {
                            | None => { prev: Some(x), out: acc.out }
                            | Some(pq) => {
                                prev: Some(x),
                                out: acc.out.concat(horiz(tips(pq, p), tips(x, p), p.n)),
                            }
                        })
                Some(res.out)
            }
        }
    }

    // Emit(P) for a pool P of votes for the leader block ell (with at
    // least n-f distinct signers), where ell references the V-QC Q':
    //   Emit(P) = Ord(Q') ++ rho,
    // with rho the sweep from Tips(Q') towards TipsF(P), halting at the
    // first empty slot of an unsettled chain.
    //
    // Emission is monotone: every quantity it reads only improves as
    // votes arrive, so successive values of Emit(P) are prefixes of one
    // common sequence and a processor may re-emit as its pool grows.
    // Pooling strictly dominates any single L-QC assemblable from the
    // pool, which is why no L-QC is ever assembled.
    //
    // A view v pool finalises tips chain by chain, but the portion of
    // the ordering extractable immediately may be capped at the frontier
    // of a lagging chain; the remainder is extracted a view later, via
    // the view v V-QC that the next leader block references -- and that
    // holds even if the next leader tries to censor, since anchoring is
    // all-or-nothing.
    pure def emit(pool: Tally, lb: LeaderBlock, vqcs: Set[VQC], p: Params): Option[List[Block]] = {
        match resolve_vqc(lb.parent_vqc, vqcs) {
            | None => None
            | Some(parent) =>
                match ord(parent, vqcs, p) {
                    | None => None
                    | Some(prefix) => Some(prefix.concat(emit_sweep(
                            tips(parent, p),
                            tips_f(pool, lb, p),
                            settled_chains(pool, lb, p),
                            p.n)))
                }
        }
    }
}
