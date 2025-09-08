// -*- mode: Bluespec; -*-

module types {
    import option.* from "./option"

    type Signature = str

    type Weight = int

    type ViewNumber = int

    type Block = str

    type Kind = str

    type ReplicaId = str

    // Each replica id has a private/public key pair assigned to it.
    // For testing purposes and for modeling byzantine behavior,
    // several replica ids may have the private/key pair.
    type ReplicaKey = str

    pure val GENESIS_BLOCK: Block = "GENESIS_BLOCK"
    pure val DUMMY_BLOCK: Block = "DUMMY_BLOCK"
    pure val EMPTY_BLOCK = "EMPTY_BLOCK"

    pure val GENESIS_VIEW = -1

    pure val NotarizeKind = "NOTARIZE_KIND"
    pure val EmptyKind = "EMPTY_KIND"
    pure val NullifyKind = "NULLIFY_KIND"

    pure val NotarizationKind = "NOTARIZATION_KIND"
    pure val NullificationKind = "NULLIFICATION_KIND"
    pure val FinalizationKind = "FINALIZATION_KIND"

    // Vote for a block at height h
    type Vote = {
        view: ViewNumber,
        block: Block,
        sig: Signature,
        kind: Kind
    }

    pure def nullify(v: ViewNumber,  id: Signature): Vote = {
        {
            view: v,
            sig: id,
            block: DUMMY_BLOCK,
            kind: NullifyKind
        }
    }

    pure def notarize(v: ViewNumber, id: Signature, block: Block): Vote = {
        {
            view: v,
            sig: id,
            block: block,
            kind: NotarizeKind
        }
    }

    type Certificate = {
        view: ViewNumber,
        kind: Kind,
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    // Leader-proposal message ⟨propose,h,b_0,…,b_h⟩
    type Proposal = {
        // proposed block
        block: Block,
        // The view in which this proposal is made
        view: ViewNumber,   
        // parent block
        block_parent: Block,  
        // The view of the parent proposal that this one builds upon
        view_parent: ViewNumber,  
        // Leader's identity
        sig: Signature
    }

    // Local state kept by each replica
    type ReplicaState = {
        // Current height (iteration), initially 0
        view: ViewNumber,
        // whether this replica has nullified this view, initially false
        nullified: bool,
        // originally, timer. Here, timer_cancelled <=> (timer >= 2Δ)
        timer_cancelled: bool,
        // NOTE: `proofs` are stored in a global variable `store_certificate`
        // NOTE: messages are stored in global variables `store_vote`

        // not in the original spec, the latest view that this replica has seen notarization votes for
        ghost_last_seen_notarization: ViewNumber,
        // sequence if the sent votes
        ghost_sent_votes: ViewNumber -> List[Block],
        // not in the original spec, the last view this replica has finalized
        last_finalized: ViewNumber,
        // not in the original spec, whether this replica has sent a proposal
        propose_sent: bool,
        // blocks that the replica notarized per view
        notarized: ViewNumber -> Block
    }
}
