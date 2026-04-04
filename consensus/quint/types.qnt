// -*- mode: Bluespec; -*-

module types {
    import option.* from "./option"

    type Signature = str

    type Weight = int

    type ViewNumber = int

    type Payload = str

    type Kind = str

    type ReplicaId = str

    // Each replica id has a private/public key pair assigned to it.
    // For testing purposes and for modeling byzantine behavior,
    // several replica ids may have the private/key pair.
    type ReplicaKey = str

    pure val GENESIS_PAYLOAD: Payload = "GENESIS_PAYLOAD"

    pure val GENESIS_VIEW = 0
    pure val FIRST_VIEW = 1

    pure val NotarizeKind = "NOTARIZE_KIND"
    pure val NullifyKind = "NULLIFY_KIND"
    pure val FinalizeKind = "FINALIZE_KIND"

    pure val NotarizationKind = "NOTARIZATION_KIND"
    pure val NullificationKind = "NULLIFICATION_KIND"
    pure val FinalizationKind = "FINALIZATION_KIND"

    type TimeoutKind = str

    pure val LeaderTimeoutKind = "LEADER_TIMEOUT_KIND"
    pure val CertificationTimeoutKind = "CERTIFICATION_TIMEOUT_KIND"

    type TimeoutReason = str

    pure val InactivityReason = "Inactivity"
    pure val LeaderNullifyReason = "LeaderNullify"
    pure val LeaderTimeoutReason = "LeaderTimeout"
    pure val CertificationTimeoutReason = "CertificationTimeout"
    pure val MissingProposalReason = "MissingProposal"
    pure val IgnoredProposalReason = "IgnoredProposal"
    pure val InvalidProposalReason = "InvalidProposal"
    pure val FailedCertificationReason = "FailedCertification"

    // Leader-proposal message
    type Proposal = {
        // proposed payload
        payload: Payload,
        // The view in which this proposal is made
        view: ViewNumber,
        // The view of the parent proposal that this one builds upon
        parent: ViewNumber,
    }

    type NotarizeVote = {
        proposal: Proposal,
        sig: Signature
    }

    type NullifyVote = {
        view: ViewNumber,
        sig: Signature
    }

    type FinalizeVote = {
        proposal: Proposal,
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

    pure def notarize(proposal: Proposal, id: Signature): Vote = {
        Notarize({
            proposal: proposal,
            sig: id
        })
    }

    pure def finalize(proposal: Proposal, id: Signature): Vote = {
        Finalize({
            proposal: proposal,
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

    type FinalizationCert = {
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature
    }

    type Certificate =
        | Notarization(NotarizationCert)
        | Nullification(NullificationCert)
        | Finalization(FinalizationCert)

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

    pure def finalization(
        proposal: Proposal,
        signatures: Set[Signature],
        ghost_sender: Signature
    ): Certificate = {
        Finalization({
            proposal: proposal,
            signatures: signatures,
            ghost_sender: ghost_sender
        })
    }

    // Parent pointer recorded from observed proposals.
    type ParentRef = {
        parent_view: ViewNumber
    }

    // Local state kept by each replica
    type ReplicaState = {
        // Current view. Genesis is view 0, voting starts at view 1.
        view: ViewNumber,
        // leader timeout state per view:
        // Some(false) = pending, Some(true) = expired, None = cancelled
        leader_timeout: ViewNumber -> Option[bool],
        // advance timeout state per view:
        // Some(false) = pending, Some(true) = expired, None = cancelled
        certification_timeout: ViewNumber -> Option[bool],
        // not in the original spec, the latest view that this replica has seen notarization votes for
        ghost_last_seen_notarization: ViewNumber,
        // not in the original spec, the last view this replica has finalized
        last_finalized: ViewNumber,
        // not in the original spec, whether this replica has sent a proposal
        propose_sent: bool,
        // round proposal currently remembered for each view
        proposal: ViewNumber -> Option[Proposal],
        // leader proposal learned for each view from leader vote/proposal or recovered certificates
        leader_proposal: ViewNumber -> Option[Proposal],
        // once a conflicting leader proposal is observed for a view, keep that fact forever
        leader_proposal_conflicted: ViewNumber -> bool,
        // local certification result for a view:
        // Some(true) = certified, Some(false) = certification failed, None = no result yet
        certify: ViewNumber -> Option[bool],
        // payload this replica has certified per view
        certified: ViewNumber -> Option[Payload]
    }
}
