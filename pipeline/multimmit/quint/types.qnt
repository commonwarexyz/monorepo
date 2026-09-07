// Types for the basic formal model of the Multimmit protocol.
//
// The definitions follow the section "The formal specification" of the
// Multimmit paper (multimmit/multimmit.tex): the message types of the
// table "Messages", the local variables of the table "Local variables",
// and the genesis objects. The pure functions over these types (the
// extraction apparatus Prop/Tips/TipsF/Horiz/Ord/Emit and the
// well-formedness predicates) are in defs.qnt.
//
// Modelling conventions:
//  - Ordinary signatures, threshold shares, threshold signatures and
//    aggregates are modelled as (sets of) replica keys.
//  - The hash function H is perfect (collision resistant, and we restrict
//    attention to executions in which the adversary cannot break it), so a
//    hash is identified with the hashed content wherever this does not
//    make a type recursive:
//      * H(Tr) of a transaction sequence is an abstract PayloadId;
//      * a transaction block is identified with its chain and the sequence
//        of payloads of its ancestors (see Block below), so that H(b) is
//        b itself, and an anchor pair (H(b), height) is the block itself;
//      * H(ell) of a leader block is the leader block itself: votes embed
//        the leader block they vote for (the paper: possession of the
//        tuple (v, q, C) determines H(ell));
//      * H(Q) of a V-QC is an abstract VQcHash, since a V-QC contains a
//        leader block which contains the hash of its parent V-QC, which
//        would make the type recursive. Injectivity of the VQcHash
//        assignment is a model assumption maintained by the state machine.
//  - The protocol parameters n (processors), f (fault bound, n >= 5f+1),
//    d (pipelining depth) and e (extension bound) are constants of the
//    state machine; the pure modules take them as an explicit Params
//    argument (below), so that the extraction rules can be exercised at
//    parameters other than those of the instance under check.
//
// Module structure. The pure definitions are layered:
//    types -> blocks -> defs -> chainrules -> sweep
// where blocks.qnt is the block algebra (one chain, no messages),
// defs.qnt the message accessors, quorum sizes and well-formedness
// predicates, chainrules.qnt the per-chain extraction rules, and
// sweep.qnt the multichain sweep. The state machines (da.qnt for the
// chain layer, consensus.qnt for the consensus layer) sit on top.

module types {
    import option.* from "./option"

    // An ordinary signature, a threshold share, or a vote signature:
    // modelled as the key (identity) of the signing replica.
    type Signature = str

    type ViewNumber = int

    type Height = int

    // Chains are indexed 1..n, chain i belonging to processor p_i.
    // Integer indices are required by the horizontal order on positions
    // (offset first, then chain index) and by lead(v).
    type ChainId = int

    type ReplicaId = str

    // Each replica id has a private/public key pair assigned to it.
    // For testing purposes and for modeling byzantine behavior,
    // several replica ids may have the same private/public key pair.
    type ReplicaKey = str

    // The hash H(Tr) of a transaction block's transaction sequence. By
    // collision resistance it identifies that sequence -- hence "Id" --
    // so the model never represents transactions themselves. An int
    // rather than an abstract name, so that hash values are ordered: the
    // extraction rules break carry ties by least hash, and Quint has no
    // order on str.
    type PayloadId = int

    // Stands for the hash H(Q) of a V-QC (see the module comment). An
    // int: the state machine allocates a fresh one from 1..MAX_VQC_HASH
    // per distinct V-QC and keeps the assignment injective, which is the
    // model's stand-in for collision resistance.
    type VQcHash = int

    // Views start at 1; view 0 is the view of the genesis leader block
    // and of the distinguished initial V-QC Q_gen.
    pure val GENESIS_VIEW = 0

    // The parent reference of the genesis leader block ell_gen = (0, lambda, lambda)
    // (lambda, the empty sequence, in the paper).
    // It is not the hash of any V-QC, hence a value outside the
    // allocated range.
    pure val EMPTY_VQC_HASH = -1

    // The hash of the distinguished initial V-QC Q_gen.
    // Allocation starts at 1, so this never collides with a fresh one.
    pure val GENESIS_VQC_HASH = 0

    type Kind = str

    // The protocol parameters, passed explicitly to every pure
    // definition that needs one of them:
    //   n          -- the number of processors, and of chains,
    //   t          -- the fault bound assumed by the thresholds
    //                 (n >= 5t + 1),
    //   d          -- the pipelining depth,
    //   e          -- the extension bound.
    //
    // Three fault counts, not two. The paper writes f for the bound the
    // protocol's thresholds are computed from, and f_a for the number of
    // replicas that are actually faulty in a given execution. The model
    // keeps them apart as the state machine's constants N, T and F:
    //   N -- the number of processors, = n here,
    //   T -- the fault bound, the paper's f, = t here; every quorum size
    //        is computed from it, and the correctness assumption is
    //        N >= 5T + 1,
    //   F -- the number of processors actually faulty, the paper's f_a.
    // Normally F <= T; keeping F separate is what lets an instance be
    // checked with fewer faults than the bound (a smaller state space)
    // or, deliberately, with more (to confirm the invariants fail where
    // the analysis says they must). Only T appears below: the pure
    // definitions state the protocol's rules, and a replica computing a
    // threshold knows the bound, never the actual fault count.
    // The state machine holds these as constants and passes one record;
    // the pure modules never read a constant of their own, which is what
    // lets the extraction lemmas be checked at arbitrary parameters.
    type Params = {
        n: int,
        t: int,
        d: int,
        e: int,
    }

    // -------------------------------------------------
    // The chain layer
    // -------------------------------------------------

    // A transaction block b = (i, h, x, Tr), identified by its chain and
    // the payloads H(Tr) of all blocks on the path from the genesis block
    // of the chain up to b itself.
    //
    // Read the list as prefix plus last. The last entry is b's own
    // payload; the prefix before it identifies b's ancestors, one per
    // height in increasing order -- payloads[j] is the payload of the
    // ancestor at height j+1. So:
    //   the height of b   = length(payloads),
    //   the payload of b  = last(payloads),
    //   the parent of b   = the block with the last payload dropped,
    //   the ancestor at h = the list truncated to length h.
    // Ancestry is therefore exactly the prefix relation on these lists,
    // which is what makes does_extend_block a slice rather than a walk.
    // Since H is collision resistant, this path representation carries
    // exactly the information determined by H(b), and the blocks
    // specified by chain proposals and votes "form a chain by
    // construction" (entries specify blocks by payload alone, with chain,
    // height and parent supplied by context). The genesis block of chain
    // i is (i, 0, lambda, lambda), i.e. the empty path.
    type Block = {
        chain: ChainId,
        payloads: List[PayloadId],
    }

    pure def mkBlock(chain: ChainId, payloads: List[PayloadId]): Block = {
        { chain: chain, payloads: payloads }
    }

    // The genesis block g_i of chain i.
    pure def genesis_block(chain: ChainId): Block = mkBlock(chain, List())

    // A vector of tips: one transaction block per chain. This is the
    // type of the safe-to-extend tips Tips(Q) of a V-QC, of the
    // finalised tips TipsF(P) of a finalising vote pool, and of the
    // arguments T, T' of Horiz (the functions tips, tips_f and horiz
    // in sweep.qnt).
    type Tips = ChainId -> Block

    // A DA-vote (da, hd(b), rho) for the transaction block b: rho is the
    // sender's (n-2f)-threshold share on (da, hd(b)). The header hd(b) is
    // recoverable from b, so the model stores the block itself.
    type DAVote = {
        block: Block,
        sig: Signature,
    }

    pure def da_vote(block: Block, sig: Signature): DAVote = {
        { block: block, sig: sig }
    }

    // A DA-certificate (hd(b), tau) for the transaction block b: tau is
    // the (n-2f)-threshold signature on (da, hd(b)), modelled as the set
    // of contributed shares. Each genesis block is considered
    // DA-certified at the start of the protocol execution.
    type DACert = {
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature,
    }

    pure def da_cert(
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature
    ): DACert = {
        { block: block, signatures: signatures, ghost_sender: ghost_sender }
    }

    // -------------------------------------------------
    // The consensus layer: leader blocks
    // -------------------------------------------------

    // The anchor a_i of a chain proposal for chain i: either an explicit
    // (hash, height) pair -- which, H being collision resistant,
    // determines the base block, so the model stores the block itself --
    // or a DA-certificate for the base.
    type Anchor =
        | HashAnchor(Block)
        | CertAnchor(DACert)

    // The entry C(i) = (a_i, x_i) of a chain proposal: the anchor a_i and
    // a possibly empty sequence x_i of at most d payloads, position
    // k >= 1 specifying the block extending the base by the first k
    // payloads (see prop in defs.qnt).
    type ChainProposalEntry = {
        anchor: Anchor,
        payloads: List[PayloadId],
    }

    // A chain proposal C maps each chain to its entry C(i) = (a_i, x_i).
    type ChainProposal = ChainId -> ChainProposalEntry

    // A leader block ell = (v, H(Q), C), signed by lead(v), where Q is a
    // V-QC for an earlier view. The value parent_vqc stands for the hash
    // H(Q) of the referenced V-QC (the V-QC itself is not included in the
    // block; it is forwarded to all upon first receipt).
    type LeaderBlock = {
        view: ViewNumber,
        parent_vqc: VQcHash,
        proposal: ChainProposal,
    }

    // The genesis chain proposal: for each chain, the genesis block as an
    // explicit anchor, and no payload entries.
    pure def genesis_chain_proposal(chains: Set[ChainId]): ChainProposal = {
        chains.mapBy(i => { anchor: HashAnchor(genesis_block(i)), payloads: List() })
    }

    // The genesis leader block ell_gen = (0, lambda, lambda).
    pure def genesis_leader_block(chains: Set[ChainId]): LeaderBlock = {
        {
            view: GENESIS_VIEW,
            parent_vqc: EMPTY_VQC_HASH,
            proposal: genesis_chain_proposal(chains),
        }
    }

    // -------------------------------------------------
    // The consensus layer: votes
    // -------------------------------------------------

    // The position map pi of a vote: maps each chain i to a position in
    // {0, ..., m_i}.
    type Positions = ChainId -> int

    // The extension map eps of a vote: maps each chain i to a sequence
    // of at most e payloads, specifying consecutive blocks on chain i
    // extending the vote's position block Prop(C, i, pi(i)).
    type Extensions = ChainId -> List[PayloadId]

    // A vote (vote, v, H(ell), pi, eps, s) for the leader block
    // ell = (v, H(Q), C):
    //  - the leader block is embedded, standing for (v, H(ell));
    //  - the single signature s covers the entire content, so no party
    //    can exhibit a vote while withholding or altering (pi, eps).
    // The intended semantics, enforced for correct voters by the voting
    // rules: the voter has DA-voted for Prop(C, i, k) for every
    // k in [1, pi(i)] and for every block specified by eps(i).
    type NotarizeVote = {
        leader_block: LeaderBlock,
        positions: Positions,
        extensions: Extensions,
        sig: Signature,
    }

    // A tally T = (E*, P, D) for a leader block describes one vote per
    // processor in P: standard w.r.t. the reference extension vector E*
    // for processors outside the domain of D, and as given by the
    // deviation records D otherwise. Since a tally (however succinctly
    // encoded) always determines each constituent vote's full content,
    // the model stores the described vote set itself. A pool of votes
    // for a leader block, to which the finalisation rules TipsF,
    // settledness and Emit apply directly, is of the same type.
    type Tally = Set[NotarizeVote]

    // A novote(v) message (novote, v, s): s is an ordinary signature, as
    // novotes appear individually attributed inside V-QCs.
    type NovoteVote = {
        view: ViewNumber,
        sig: Signature,
    }

    // A nullify(v) message (nullify, v, rho): rho is the sender's
    // (2f+1)-threshold share on (nullify, v).
    type NullifyVote = {
        view: ViewNumber,
        sig: Signature,
    }

    // Correct processors never send both a vote for a view v leader block
    // and a novote(v) message; a correct processor that times out in view
    // v without voting sends both novote(v) and nullify(v), while one
    // that nullifies after voting sends only nullify(v).
    type Vote =
        | Notarize(NotarizeVote)
        | Novote(NovoteVote)
        | Nullify(NullifyVote)

    pure val NotarizeKind = "NOTARIZE_KIND"
    pure val NovoteKind = "NOVOTE_KIND"
    pure val NullifyKind = "NULLIFY_KIND"

    pure def notarize(
        leader_block: LeaderBlock,
        positions: Positions,
        extensions: Extensions,
        sig: Signature
    ): Vote = {
        Notarize({
            leader_block: leader_block,
            positions: positions,
            extensions: extensions,
            sig: sig,
        })
    }

    pure def novote(view: ViewNumber, sig: Signature): Vote = {
        Novote({ view: view, sig: sig })
    }

    pure def nullify(view: ViewNumber, sig: Signature): Vote = {
        Nullify({ view: view, sig: sig })
    }

    // -------------------------------------------------
    // The consensus layer: certificates
    // -------------------------------------------------

    // A nullification (nullification, v, tau) for view v: tau is the
    // (2f+1)-threshold signature on (nullify, v), modelled as the set of
    // contributed shares. A nullification certifies nothing about who
    // nullified.
    type NullificationCert = {
        view: ViewNumber,
        signatures: Set[Signature],
        ghost_sender: Signature,
    }

    // A V-QC Q = (ell, T, N, X, s) for view v, certifying a set W of n-f
    // view v messages by distinct processors (the paper identifies Q
    // with the pair (W, C)):
    //  - votes: the tally T, i.e. the votes for the designated proposal
    //    C in W, at least 2f+1 of them (see Tally above);
    //  - novotes: the signer set N of the novote(v) messages in W;
    //  - other_votes: the complete votes recorded by X, for view v leader
    //    blocks other than ell (possible only under an equivocating
    //    leader);
    //  - id stands for H(Q) and is referenced by child leader blocks.
    // V-QCs play the role of Minimmit's (M-)notarizations.
    type VQC = {
        id: VQcHash,
        leader_block: LeaderBlock,
        votes: Tally,
        novotes: Set[Signature],
        other_votes: Set[NotarizeVote],
        ghost_sender: Signature,
    }

    // There is deliberately no L-QC type. The paper lists L-QCs as a
    // message type but never instructs anyone to send one: finalisation
    // works directly off the vote pool, and the pool rules dominate the
    // rules for every individual L-QC assemblable from it (an L-QC being
    // the special case |P| = n-f). So finalisation here is "a pool of at
    // least n-f votes for one leader block", which is exactly what
    // tips_f, settledness and emit take. An implementation may still
    // ship L-QCs to help lagging replicas catch up; modelling that would
    // bring the type back.
    type Certificate =
        | Notarization(VQC)
        | Nullification(NullificationCert)

    pure val NotarizationKind = "NOTARIZATION_KIND"
    pure val NullificationKind = "NULLIFICATION_KIND"

    pure def notarization(
        id: VQcHash,
        leader_block: LeaderBlock,
        votes: Tally,
        novotes: Set[Signature],
        other_votes: Set[NotarizeVote],
        ghost_sender: Signature
    ): Certificate = {
        Notarization({
            id: id,
            leader_block: leader_block,
            votes: votes,
            novotes: novotes,
            other_votes: other_votes,
            ghost_sender: ghost_sender,
        })
    }

    pure def nullification(
        view: ViewNumber,
        signatures: Set[Signature],
        ghost_sender: Signature
    ): Certificate = {
        Nullification({
            view: view,
            signatures: signatures,
            ghost_sender: ghost_sender,
        })
    }

    // The distinguished initial V-QC Q_gen for view 0, considered
    // received by all processors at the start of the execution, with
    // Tips(Q_gen)_i = g_i for each chain i (see tips in defs.qnt).
    pure def genesis_vqc(chains: Set[ChainId]): VQC = {
        {
            id: GENESIS_VQC_HASH,
            leader_block: genesis_leader_block(chains),
            votes: Set(),
            novotes: Set(),
            other_votes: Set(),
            ghost_sender: "GENESIS",
        }
    }

    // -------------------------------------------------
    // Local state
    // -------------------------------------------------

    // Local state kept by each replica (the table "Local variables").
    // The variable State (all received messages, automatically updated)
    // is modelled by global store variables of the state machine;
    // the chain-layer history (blocks produced, DA-votes sent)
    // is likewise kept in global variables.
    type ReplicaState = {
        // Current protocol view v, initially 1.
        view: ViewNumber,
        // Whether this replica has sent nullify(v) in the current view,
        // initially false.
        nullified: bool,
        // Whether this replica has proposed a leader block for the
        // current view, initially false (the paper: proposed).
        propose_sent: bool,
        // Originally, the timer T reset upon entering each view. Here,
        // timer_cancelled <=> (T >= 2*Delta).
        timer_cancelled: bool,
        // The leader block voted for ("notarised"), per view; initially
        // None for every view. The paper keeps only the current view's
        // value and resets it on view entry; the model keeps the whole
        // history.
        notarized: ViewNumber -> Option[LeaderBlock],
        // The V-QC this replica forwarded when a view first became new,
        // per view; initially Some(Q_gen) for view 0 and None elsewhere.
        // SelectAnchor returns this value rather than recomputing a V-QC
        // from the messages held at proposal time, and that is a
        // liveness requirement, not a stylistic choice: a V-QC assembled
        // privately may contain a vote no other correct replica holds,
        // and since proposal validity requires the exact object
        // referenced, no correct replica could then vote. Note the value
        // is NOT recoverable from the messages held later, since further
        // V-QCs for the same view keep arriving.
        forwarded: ViewNumber -> Option[VQC],
        // Sequence of sent view messages per view: Some(ell) for a vote
        // for ell, None for a novote/nullify. Not in the original spec;
        // used by the no-vote-equivocation invariants.
        ghost_sent_votes: ViewNumber -> List[Option[LeaderBlock]],
        // The log log_i, at transaction-block granularity: the blocks
        // emitted so far, in order (see emit in defs.qnt). The paper's
        // log of transactions is the concatenation of the values b.Tr
        // over this sequence, with duplicates removed.
        ghost_log: List[Block],
    }
}
