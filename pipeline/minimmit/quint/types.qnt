// -*- mode: Bluespec; -*-

module types {
    import option.* from "./option"

    type Signature = str

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

    pure val GENESIS_VIEW = -1

    pure val NotarizeKind = "NOTARIZE_KIND"
    pure val NullifyKind = "NULLIFY_KIND"

    pure val NotarizationKind = "NOTARIZATION_KIND"
    pure val NullificationKind = "NULLIFICATION_KIND"
    pure val FinalizationKind = "FINALIZATION_KIND"

    // Leader-proposal message ⟨propose,h,b_0,…,b_h⟩
    //
    // A proposal, not a block, is what the protocol votes on. `build(c')` produces a block
    // that commits to its parent and `verify(c, c')` checks that link, so the parent is part
    // of what a replica signs over. Carrying it here is what stops one block from having two
    // parents: a second proposal naming the same block with a different parent is a
    // different proposal, so votes for it never join the same quorum and it cannot rewrite
    // the first one's ancestry.
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

    // The root the committed chain is anchored at, finalized at view `< 0`.
    pure val GENESIS_PROPOSAL: Proposal = {
        block: GENESIS_BLOCK,
        view: GENESIS_VIEW,
        block_parent: GENESIS_BLOCK,
        view_parent: GENESIS_VIEW,
        sig: ""
    }

    // A notarize vote signs the complete proposal.
    type NotarizeVote = {
        proposal: Proposal,
        sig: Signature
    }

    // A nullify vote signs only a view.
    type NullifyVote = {
        view: ViewNumber,
        sig: Signature
    }

    type Vote =
        | Notarize(NotarizeVote)
        | Nullify(NullifyVote)

    pure def nullify(v: ViewNumber,  id: Signature): Vote = {
        Nullify({
            view: v,
            sig: id
        })
    }

    pure def notarize(p: Proposal, id: Signature): Vote = {
        Notarize({
            proposal: p,
            sig: id
        })
    }

    type NotarizationCert = {
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    type NullificationCert = {
        view: ViewNumber,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    type Certificate =
        | Notarization(NotarizationCert)
        | Nullification(NullificationCert)

    pure def notarization(
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature
    ): Certificate = {
        Notarization({
            proposal: proposal,
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
        // sequence of the sent votes: Some(p) for a notarize, None for a nullify
        ghost_sent_votes: ViewNumber -> List[Option[Proposal]],
        // not in the original spec, the last view this replica has finalized
        last_finalized: ViewNumber,
        // not in the original spec, whether this replica has sent a proposal
        propose_sent: bool,
        // the proposal this replica notarized per view, None if it has not notarized
        notarized: ViewNumber -> Option[Proposal]
    }
}
