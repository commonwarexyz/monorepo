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
    pure val EMPTY_BLOCK = "EMPTY_BLOCK"

    pure val GENESIS_VIEW = 0
    pure val FIRST_VIEW = 1

    pure val NotarizeKind = "NOTARIZE_KIND"
    pure val NullifyKind = "NULLIFY_KIND"
    pure val FinalizeKind = "FINALIZE_KIND"

    pure val NotarizationKind = "NOTARIZATION_KIND"
    pure val NullificationKind = "NULLIFICATION_KIND"
    pure val FinalizationKind = "FINALIZATION_KIND"

    type NotarizeVote = {
        view: ViewNumber,
        block: Block,
        sig: Signature
    }

    type NullifyVote = {
        view: ViewNumber,
        sig: Signature
    }

    type FinalizeVote = {
        view: ViewNumber,
        block: Block,
        sig: Signature
    }

    type Vote =
        | Notarize(NotarizeVote)
        | Nullify(NullifyVote)
        | Finalize(FinalizeVote)

    pure def nullify(v: ViewNumber, id: Signature): Vote = {
        Nullify({
            view: v,
            sig: id
        })
    }

    pure def notarize(v: ViewNumber, id: Signature, block: Block): Vote = {
        Notarize({
            view: v,
            sig: id,
            block: block
        })
    }

    pure def finalize(v: ViewNumber, id: Signature, block: Block): Vote = {
        Finalize({
            view: v,
            sig: id,
            block: block
        })
    }

    type NotarizationCert = {
        view: ViewNumber,
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    type NullificationCert = {
        view: ViewNumber,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    type FinalizationCert = {
        view: ViewNumber,
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    type Certificate =
        | Notarization(NotarizationCert)
        | Nullification(NullificationCert)
        | Finalization(FinalizationCert)

    pure def notarization(
        view: ViewNumber,
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature
    ): Certificate = {
        Notarization({
            view: view,
            block: block,
            signatures: signatures,
            ghost_sender: ghost_sender
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
            ghost_sender: ghost_sender
        })
    }

    pure def finalization(
        view: ViewNumber,
        block: Block,
        signatures: Set[Signature],
        ghost_sender: Signature
    ): Certificate = {
        Finalization({
            view: view,
            block: block,
            signatures: signatures,
            ghost_sender: ghost_sender
        })
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
        // Current view. Genesis is view 0, voting starts at view 1.
        view: ViewNumber,
        // whether this replica has nullified this view, initially false
        nullified: bool,
        // leader timeout (t_l) has been cancelled for current view.
        // Introduced to trigger early view transitions for unresponsive leaders.
        leader_timeout_cancelled: bool,
        // advance timeout (t_a) has been cancelled for current view
        advance_timeout_cancelled: bool,
        // NOTE: `proofs` are stored in a global variable `store_certificate`
        // NOTE: messages are stored in global variables `store_vote`

        // not in the original spec, the latest view that this replica has seen notarization votes for
        ghost_last_seen_notarization: ViewNumber,
        // sequence if the sent votes
        ghost_sent_votes: ViewNumber -> List[Kind],
        // not in the original spec, the last view this replica has finalized
        last_finalized: ViewNumber,
        // not in the original spec, whether this replica has sent a proposal
        propose_sent: bool,
        // block this replica has notarized per view
        notarized: ViewNumber -> Block,
        // block this replica has certified per view
        certified: ViewNumber -> Block
    }
}
