// -*- mode: Bluespec; -*-

module types {
    import option.* from "./option"

    type ReplicaId = str

    type Signature = str

    type Weight = int

    type ViewNumber = int

    type BlockHash = str

    type Kind = str

    type Block = str

    pure val DUMMY_BLOCK_HASH: BlockHash = "DUMMY_BLOCK_HASH"
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

    // Get the "hash" of a string
    pure def hash(b: Block): BlockHash = b

    /// Vote for a block at height h
    type Vote = {
        view: ViewNumber,
        block_hash: BlockHash,
        sig: Signature,
        kind: Kind
    }

    pure def nullify(v: ViewNumber,  id: Signature): Vote = {
        {
            view: v,
            sig: id,
            block_hash: DUMMY_BLOCK_HASH,
            kind: NullifyKind
        }
    }

    pure def notarize(v: ViewNumber, id: Signature, block_hash: BlockHash): Vote = {
        {
            view: v,
            sig: id,
            block_hash: block_hash,
            kind: NotarizeKind
        }
    }

    type Certificate = {
        view: ViewNumber,
        kind: Kind,
        block_hash: BlockHash,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    /// Leader-proposal message ⟨propose,h,b_0,…,b_h⟩
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


    type Proof =
        Empty | Nullification(Certificate) | Notarization(Certificate) | Finalization(Certificate)

    /// Local state kept by each replica
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
        ghost_sent_votes: ViewNumber -> List[BlockHash],
        // not in the original spec, the last view this replica has finalized
        last_finalized: ViewNumber,
        // not in the original spec, whether this replica has sent a proposal
        propose_sent: bool,
        // blocks that the replica notarized per view
        notarized: ViewNumber -> BlockHash
    }
}
