// -*- mode: Bluespec; -*-

module types {
    import option.* from "./option"

    type Signature = str

    type Weight = int

    type ViewNumber = int

    type Block = {
        id: str,
        ghost_height: int,
    }

    type Kind = str

    type ReplicaId = str

    // Each replica id has a private/public key pair assigned to it.
    // For testing purposes and for modeling byzantine behavior,
    // several replica ids may have the private/key pair.
    type ReplicaKey = str

    pure val GENESIS_VIEW = -1

    pure def mkBlock(id: str, ghost_height: int): Block = {
        { id: id, ghost_height: ghost_height }
    }

    pure val GENESIS_BLOCK: Block = mkBlock("GENESIS_BLOCK", GENESIS_VIEW)
    pure val DUMMY_BLOCK: Block = mkBlock("DUMMY_BLOCK", GENESIS_VIEW)
    pure val EMPTY_BLOCK: Block = mkBlock("EMPTY_BLOCK", GENESIS_VIEW)

    pure val NotarizeKind = "NOTARIZE_KIND"
    pure val EmptyKind = "EMPTY_KIND"
    pure val NullifyKind = "NULLIFY_KIND"

    pure val NotarizationKind = "NOTARIZATION_KIND"
    pure val NullificationKind = "NULLIFICATION_KIND"
    pure val FinalizationKind = "FINALIZATION_KIND"

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

    type NotarizeVote = {
        proposal: Proposal,
        sig: Signature,
    }

    type NullifyVote = {
        view: ViewNumber,
        sig: Signature,
    }

    type Vote =
        | Notarize(NotarizeVote)
        | Nullify(NullifyVote)

    pure def nullify(v: ViewNumber, id: Signature): Vote = {
        Nullify({
            view: v,
            sig: id,
        })
    }

    pure def notarize(proposal: Proposal, id: Signature): Vote = {
        Notarize({
            proposal: proposal,
            sig: id,
        })
    }

    type NotarizationCert = {
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature,
    }

    type NullificationCert = {
        view: ViewNumber,
        signatures: Set[Signature],
        ghost_sender: Signature,
    }

    type Certificate =
        | Notarization(NotarizationCert)
        | Nullification(NullificationCert)
        | Finalization(NotarizationCert)

    pure def notarization(
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature,
    ): Certificate = {
        Notarization({
            proposal: proposal,
            signatures: signatures,
            ghost_sender: ghost_sender,
        })
    }

    pure def nullification(
        view: ViewNumber,
        signatures: Set[Signature],
        ghost_sender: Signature,
    ): Certificate = {
        Nullification({
            view: view,
            signatures: signatures,
            ghost_sender: ghost_sender,
        })
    }

    pure def finalization(
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature,
    ): Certificate = {
        Finalization({
            proposal: proposal,
            signatures: signatures,
            ghost_sender: ghost_sender,
        })
    }

    // Local state kept by each replica
    type ReplicaState = {
        // Current protocol view, initially 0
        view: ViewNumber,
        // whether this replica has nullified this view, initially false
        nullified: bool,
        // originally, timer. Here, timer_cancelled <=> (timer >= 2Δ)
        timer_cancelled: bool,
        // NOTE: `proofs` are stored in a global variable `store_certificate`
        // NOTE: messages are stored in global variables `store_vote`

        // not in the original spec, the latest view that this replica has seen notarization votes for
        ghost_last_seen_notarization: ViewNumber,
        // sequence of sent votes: Some(proposal) for notarize, None for nullify
        ghost_sent_votes: ViewNumber -> List[Option[Proposal]],
        // not in the original spec, the last view this replica has finalized
        last_finalized: ViewNumber,
        // not in the original spec, whether this replica has sent a proposal
        propose_sent: bool,
        // proposal that the replica notarized per view
        notarized: ViewNumber -> Option[Proposal]
    }
}
