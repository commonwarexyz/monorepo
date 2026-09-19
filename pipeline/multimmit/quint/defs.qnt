// Message-level definitions for the Multimmit model: accessors on votes,
// chain proposals and certificates, the quorum sizes, and the
// well-formedness predicates that gate every message a replica accepts.
//
// This module covers the syntax of messages. It knows what a vote and
// a V-QC are made of and how many signers each certificate needs, but
// nothing about blocks, ancestry or the extraction rules. Those live in
// blocks.qnt (block algebra), chainrules.qnt (the per-chain extraction
// rules) and sweep.qnt (the multichain sweep):
//
//    types -> blocks -> defs -> chainrules -> sweep
//
// Quorums are counted over signatures (keys), never over vote values: a
// faulty processor may sign more than one vote for one leader block, and
// a pool retains one voice per key. Every counting definition below goes
// through `signers` for that reason, and the well-formedness predicates
// require the certified vote sets to have one vote per signer.
//
// All definitions are pure and take the protocol parameters as an
// explicit Params record (see types.qnt).

module defs {
    import types.* from "./types"
    import option.* from "./option"

    // -------------------------------------------------
    // Vote accessors
    // -------------------------------------------------

    pure def vote_view(vote: Vote): ViewNumber = {
        match vote {
            | Notarize(v) => v.leader_block.view
            | Novote(v) => v.view
            | Nullify(v) => v.view
        }
    }

    pure def vote_kind(vote: Vote): Kind = {
        match vote {
            | Notarize(_) => NotarizeKind
            | Novote(_) => NovoteKind
            | Nullify(_) => NullifyKind
        }
    }

    pure def vote_sig(vote: Vote): Signature = {
        match vote {
            | Notarize(v) => v.sig
            | Novote(v) => v.sig
            | Nullify(v) => v.sig
        }
    }

    pure def vote_leader_block(vote: Vote): Option[LeaderBlock] = {
        match vote {
            | Notarize(v) => Some(v.leader_block)
            | Novote(_) => None
            | Nullify(_) => None
        }
    }

    // Filter votes by view and kind.
    pure def select_votes(view: ViewNumber, kind: Kind, votes: Set[Vote]): Set[Vote] = {
        votes.filter(v => vote_kind(v) == kind and vote_view(v) == view)
    }

    // The notarize votes contained in a set of (sum-typed) votes.
    pure def notarize_votes(votes: Set[Vote]): Tally = {
        votes.fold(Set(), (acc, v) =>
            match v {
                | Notarize(nv) => acc.union(Set(nv))
                | Novote(_) => acc
                | Nullify(_) => acc
            })
    }

    // The signer set of a set of votes. See the module comment: this is
    // the only legitimate way to count a vote set.
    pure def signers(votes: Set[NotarizeVote]): Set[Signature] = {
        votes.map(v => v.sig)
    }

    // Does the vote have the shape required for the leader block ell: it
    // votes for ell and its position/extension maps range over ell's
    // chains. The extraction functions consider only matching votes,
    // which keeps them total on arbitrary (byzantine) input.
    // Filtering a pool by this gives the votes for the leader block ell.
    pure def vote_matches(v: NotarizeVote, lb: LeaderBlock): bool = and {
        v.leader_block == lb,
        v.positions.keys() == lb.proposal.keys(),
        v.extensions.keys() == lb.proposal.keys(),
    }

    // -------------------------------------------------
    // Chain proposal accessors
    // -------------------------------------------------

    // The base specified by an anchor: for an explicit (hash, height)
    // pair the block it determines, for a DA-certificate the certified
    // block. Either way the anchor names the base explicitly, so a chain
    // proposal is interpretable in isolation -- no other V-QC is needed
    // to resolve it. Applied to `entry.anchor`, this is the base for
    // chain i specified by the proposal entry C(i).
    pure def anchor_block(a: Anchor): Block = {
        match a {
            | HashAnchor(b) => b
            | CertAnchor(c) => c.block
        }
    }

    // m_i: the number of payload entries the chain proposal C makes for
    // chain i.
    pure def num_proposal_entries(c: ChainProposal, i: ChainId): int = {
        c.get(i).payloads.length()
    }

    // -------------------------------------------------
    // Certificate accessors
    // -------------------------------------------------

    pure def vqc_view(q: VQC): ViewNumber = q.leader_block.view

    pure def cert_view(cert: Certificate): ViewNumber = {
        match cert {
            | Notarization(q) => q.leader_block.view
            | Nullification(c) => c.view
        }
    }

    pure def cert_kind(cert: Certificate): Kind = {
        match cert {
            | Notarization(_) => NotarizationKind
            | Nullification(_) => NullificationKind
        }
    }

    pure def cert_signers(cert: Certificate): Set[Signature] = {
        match cert {
            | Notarization(q) => signers(q.votes).union(q.novotes).union(signers(q.other_votes))
            | Nullification(c) => c.signatures
        }
    }

    pure def cert_leader_block(cert: Certificate): Option[LeaderBlock] = {
        match cert {
            | Notarization(q) => Some(q.leader_block)
            | Nullification(_) => None
        }
    }

    pure def cert_ghost_sender(cert: Certificate): Signature = {
        match cert {
            | Notarization(q) => q.ghost_sender
            | Nullification(c) => c.ghost_sender
        }
    }

    // -------------------------------------------------
    // Quorum sizes
    // -------------------------------------------------

    // The threshold of the DA scheme: n - 2f (the paper's D).
    pure def da_quorum(p: Params): int = p.n - 2 * p.t

    // The threshold of the nullification scheme, the tally size of a
    // V-QC, and the extension carry threshold: 2f + 1 (minimmit: M).
    pure def null_quorum(p: Params): int = 2 * p.t + 1

    // n - t (minimmit: L). Named for the V-QC because that is the only
    // certificate the model stores, but it gates three things: the size
    // of a V-QC, the size of a finalising vote pool, and the endorsement
    // threshold of TipsF, where it means unanimity within the pool.
    pure def vqc_quorum(p: Params): int = p.n - p.t

    // -------------------------------------------------
    // Well-formedness of messages
    // -------------------------------------------------

    // A DA-certificate carries the (n-2f)-threshold signature on
    // (da, hd(b)).
    pure def da_cert_wellformed(c: DACert, p: Params): bool = {
        c.signatures.size() >= da_quorum(p)
    }

    // A nullification carries the (2f+1)-threshold signature on
    // (nullify, v).
    pure def nullification_wellformed(c: NullificationCert, p: Params): bool = {
        c.signatures.size() >= null_quorum(p)
    }

    // A vote's position/extension maps range over its leader block's
    // chains, its positions lie in [0, m_i], and its extensions carry at
    // most e payloads per chain.
    //
    // The upper bound on positions is where out-of-range positions are
    // discarded. Some such rule is required, and this is the paper's:
    // Tips must evaluate identically at every replica, and
    // since only f faulty votes can carry an out-of-range position, two
    // replicas treating such a vote differently can straddle the carry
    // threshold whenever the honest count sits in [f+1, 2f] -- giving
    // different tips, different orderings, and forked logs. Clamping to
    // m_i would be deterministic too, but strictly worse: it would let a
    // junk vote count towards the pool size and shrink settledness's
    // (n - |P|) slack.
    pure def vote_wellformed(v: NotarizeVote, p: Params): bool = and {
        vote_matches(v, v.leader_block),
        v.leader_block.proposal.keys().forall(i => and {
            v.positions.get(i) >= 0,
            v.positions.get(i) <= num_proposal_entries(v.leader_block.proposal, i),
            v.extensions.get(i).length() <= p.e,
        }),
    }

    // A V-QC certifies a set W of n-f view v messages by distinct
    // processors: well-formed votes for the designated proposal C (at
    // least 2f+1 of them, the tally), novote(v) messages (N), and
    // complete well-formed votes for other view v leader blocks (X),
    // with pairwise disjoint signer sets whose sizes sum to n-f.
    //
    // The `votes.size() == signers(votes).size()` conjuncts are what
    // make the tally a function on its signer set, as the paper's
    // (E*, P, D) encoding is by construction: a faulty processor may
    // sign two votes for one leader block, and at most one of them may
    // be accounted for.
    pure def vqc_wellformed(q: VQC, p: Params): bool = and {
        q.votes.forall(v => vote_matches(v, q.leader_block) and vote_wellformed(v, p)),
        q.votes.size() == signers(q.votes).size(),
        q.other_votes.forall(v => and {
            vote_wellformed(v, p),
            v.leader_block.view == q.leader_block.view,
            v.leader_block != q.leader_block,
        }),
        q.other_votes.size() == signers(q.other_votes).size(),
        signers(q.votes).intersect(q.novotes) == Set(),
        signers(q.votes).intersect(signers(q.other_votes)) == Set(),
        q.novotes.intersect(signers(q.other_votes)) == Set(),
        signers(q.votes).size() >= null_quorum(p),
        signers(q.votes).size() + q.novotes.size() + signers(q.other_votes).size()
            == vqc_quorum(p),
    }

    // A finalising pool: at least n-f votes for one leader block by
    // distinct processors, with at most one retained vote per signer.
    // The receive rule enforces this representation invariant; keeping
    // the check here prevents an unselected equivocation set from being
    // passed directly to extraction.
    pure def pool_finalizes(pool: Tally, lb: LeaderBlock, p: Params): bool = {
        val matching = pool.filter(v => vote_matches(v, lb))
        and {
            matching.size() == signers(matching).size(),
            signers(matching).size() >= vqc_quorum(p),
        }
    }

    // -------------------------------------------------
    // Leaders
    // -------------------------------------------------

    // lead(v) = p_{j+1}, where j = v mod n: the leader of view v, given
    // as a chain index (processor p_i owns chain i).
    pure def lead(v: ViewNumber, p: Params): ChainId = (v % p.n) + 1
}
