module replica {
    import types.* from "./types"
    import defs.* from "./defs"
    import option.* from "./option"

    // Total number of replicas.
    const N: int
    // Maximum number of byzantine(faulty) replicas.
    const F: int
    // Quorum value according to the utils/src/faults.rs.
    const Q: int
    // Identities of the correct replicas.
    const CORRECT: Set[ReplicaId]
    // Identities of the byzantine replicas.
    const BYZANTINE: Set[ReplicaId]
    // The set of all views.
    const VIEWS: Set[ViewNumber]
    // the set of all valid payloads
    const VALID_PAYLOADS: Set[Payload]
    // externally invalid payloads (for adversarial tests)
    const INVALID_PAYLOADS: Set[Payload]
    // Matches activity_timeout in the implementation (Delta::new(10) in fuzz targets).
    const ACTIVITY_TIMEOUT: int
    // All replicas.
    pure val Replicas = CORRECT.union(BYZANTINE)
    // The keys of the replicas, normally, one unique key per replica.
    // For modeling byzantine behaviour via twin replicas use the same keys.
    const REPLICA_KEYS: ReplicaId -> ReplicaKey

    // Produce replica's signature
    pure def sig_of(id: ReplicaId): ReplicaKey = REPLICA_KEYS.get(id)

    pure val AllPayloads = VALID_PAYLOADS.union(Set(GENESIS_PAYLOAD)).union(INVALID_PAYLOADS)
    pure val CorrectSigs = CORRECT.map(id => sig_of(id))
    pure val ByzantineSigs = BYZANTINE.map(id => sig_of(id))
    pure val LEADER_INACTIVITY_WINDOW = 2

    // The states of the correct replicas
    var replica_state: ReplicaId -> ReplicaState
    // the leader function from the view to the replicas identities
    var leader: ViewNumber -> ReplicaId

    // votes sent by the replicas, correct and byzantine
    var sent_notarize_votes: Set[NotarizeVote]
    var sent_nullify_votes: Set[NullifyVote]
    var sent_finalize_votes: Set[FinalizeVote]
    // certificates sent by the replicas, correct and byzantine
    var sent_certificates: Set[Certificate]

    // votes received by the correct replicas
    var store_notarize_votes: ReplicaId -> Set[NotarizeVote]
    var store_nullify_votes: ReplicaId -> Set[NullifyVote]
    var store_finalize_votes: ReplicaId -> Set[FinalizeVote]
    // certificates received or assembled by the correct replicas
    var store_certificates: ReplicaId -> Set[Certificate]

    // Best locally reconstructible committed prefix for each correct replica.
    var ghost_committed_blocks: ReplicaId -> List[Proposal]
    // Replica-local deterministic certification policy from the application.
    var certify_policy: ReplicaId -> Set[Payload]
    // The last action taken, used for tracing and model-based testing.
    var lastAction: str

    // Filter votes by view and kind.
    pure def cert_view(c: Certificate): ViewNumber = {
        match (c) {
            | Notarization(n) => n.proposal.view
            | Nullification(n) => n.view
            | Finalization(f) => f.proposal.view
        }
    }

    pure def cert_signatures(c: Certificate): Set[Signature] = {
        match (c) {
            | Notarization(n) => n.signatures
            | Nullification(n) => n.signatures
            | Finalization(f) => f.signatures
        }
    }

    pure def cert_ghost_sender(c: Certificate): Signature = {
        match (c) {
            | Notarization(n) => n.ghost_sender
            | Nullification(n) => n.ghost_sender
            | Finalization(f) => f.ghost_sender
        }
    }

    pure def cert_payload(c: Certificate): Option[Payload] = {
        match (c) {
            | Notarization(n) => Some(n.proposal.payload)
            | Nullification(_) => None
            | Finalization(f) => Some(f.proposal.payload)
        }
    }

    pure def cert_proposal(c: Certificate): Option[Proposal] = {
        match (c) {
            | Notarization(n) => Some(n.proposal)
            | Nullification(_) => None
            | Finalization(f) => Some(f.proposal)
        }
    }

    pure def cert_kind(c: Certificate): Kind = {
        match (c) {
            | Notarization(_) => NotarizationKind
            | Nullification(_) => NullificationKind
            | Finalization(_) => FinalizationKind
        }
    }

    pure def is_notarization_cert(c: Certificate): bool = {
        match (c) {
            | Notarization(_) => true
            | _ => false
        }
    }

    pure def is_nullification_cert(c: Certificate): bool = {
        match (c) {
            | Nullification(_) => true
            | _ => false
        }
    }

    pure def is_finalization_cert(c: Certificate): bool = {
        match (c) {
            | Finalization(_) => true
            | _ => false
        }
    }

    def has_sent_vote(id: ReplicaId, view: ViewNumber, kind: Kind): bool = {
        if (kind == NotarizeKind) {
            sent_notarize_votes.exists(v => v.sig == sig_of(id) and v.proposal.view == view)
        } else if (kind == NullifyKind) {
            sent_nullify_votes.exists(v => v.sig == sig_of(id) and v.view == view)
        } else {
            sent_finalize_votes.exists(v => v.sig == sig_of(id) and v.proposal.view == view)
        }
    }

    def broadcast_notarize(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, NotarizeKind)
    }

    def broadcast_nullify(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, NullifyKind)
    }

    def broadcast_finalize(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, FinalizeKind)
    }

    pure def broadcast_finalize_in(
        sent_finalize: Set[FinalizeVote],
        id: ReplicaId,
        view: ViewNumber
    ): bool = {
        sent_finalize.exists(v => v.sig == sig_of(id) and v.proposal.view == view)
    }

    def broadcast_notarization(id: ReplicaId, view: ViewNumber): bool = {
        sent_certificates.exists(c => and {
            cert_ghost_sender(c) == sig_of(id),
            cert_kind(c) == NotarizationKind,
            cert_view(c) == view,
        })
    }

    def broadcast_nullification(id: ReplicaId, view: ViewNumber): bool = {
        sent_certificates.exists(c => and {
            cert_ghost_sender(c) == sig_of(id),
            cert_kind(c) == NullificationKind,
            cert_view(c) == view,
        })
    }

    def broadcast_finalization(id: ReplicaId, view: ViewNumber): bool = {
        sent_certificates.exists(c => and {
            cert_ghost_sender(c) == sig_of(id),
            cert_kind(c) == FinalizationKind,
            cert_view(c) == view,
        })
    }

    def has_participated_in_view(id: ReplicaId, view: ViewNumber): bool = or {
        sent_notarize_votes.exists(v => v.sig == sig_of(id) and v.proposal.view == view),
        sent_nullify_votes.exists(v => v.sig == sig_of(id) and v.view == view),
        sent_finalize_votes.exists(v => v.sig == sig_of(id) and v.proposal.view == view),
    }

    // The designated leader for `view` is considered inactive if they have not
    // participated in any of the previous `LEADER_INACTIVITY_WINDOW` views.
    def leader_inactive(view: ViewNumber): bool = {
        val designated = leader.get(view)
        val previous_views = VIEWS.filter(v => and {
            v < view,
            v >= view - LEADER_INACTIVITY_WINDOW,
        })
        and {
            previous_views.size() == LEADER_INACTIVITY_WINDOW,
            previous_views.forall(v => not(has_participated_in_view(designated, v)))
        }
    }

    // Returns Some(proposal) if a notarize vote should be constructed.
    def construct_notarize(
        id: ReplicaId,
        self: ReplicaState,
        view: ViewNumber,
        proposal: Proposal,
        is_verified: bool
    ): Option[Proposal] = {
        if (broadcast_notarize(id, view) or broadcast_nullify(id, view))
            None
        else if (not(is_verified))
            None
        else
            Some(proposal)
    }

    // Returns true if a nullify vote is not blocked by a prior finalize.
    def construct_nullify(
        id: ReplicaId,
        self: ReplicaState,
        view: ViewNumber
    ): bool = {
        not(broadcast_finalize(id, view))
    }

    // Returns Some(proposal) if a finalize vote should be constructed.
    // The proposal_conflicted parameter maps to !has_unequivocated_proposal()
    // in the implementation. The is_certified parameter represents the result
    // of application-level certification (asynchronous in the implementation,
    // atomic here).
    def construct_finalize(
        id: ReplicaId,
        self: ReplicaState,
        view: ViewNumber,
        proposal: Proposal,
        proposal_conflicted: bool,
        is_certified: bool
    ): Option[Proposal] = {
        if (broadcast_finalize(id, view) or broadcast_nullify(id, view))
            None
        else if (proposal_conflicted)
            None
        // If we haven't certified the proposal, return false.
        // Note, this does not require verification.
        else if (not(is_certified))
            None
        else
            Some(proposal)
    }

    pure def is_proposal_notarized_votes(proposal: Proposal, votes: Set[NotarizeVote]): bool = or {
        proposal.view == GENESIS_VIEW and proposal.payload == GENESIS_PAYLOAD,
        votes
            .filter(v => v.proposal == proposal)
            .map(v => v.sig)
            .size() >= Q
    }

    pure def is_proposal_finalized_votes(proposal: Proposal, votes: Set[FinalizeVote]): bool = or {
        proposal.view == GENESIS_VIEW and proposal.payload == GENESIS_PAYLOAD,
        votes
            .filter(v => v.proposal == proposal)
            .map(v => v.sig)
            .size() >= Q
    }

    pure def is_view_nullified(view: ViewNumber, certificates: Set[Certificate]): bool = or {
        view == GENESIS_VIEW,
        certificates.exists(c => is_nullification_cert(c) and cert_view(c) == view)
    }

    // Does a set of certificates contain nullification certificates for all views in (v1, v2)?
    pure def are_views_nullified(v1: ViewNumber, v2: ViewNumber, certificates: Set[Certificate]): bool = {
        VIEWS.filter(v => v > v1 and v < v2).forall(v => is_view_nullified(v, certificates))
    }

    pure def observe_leader_proposal(self: ReplicaState, proposal: Proposal): ReplicaState = {
        val known = self.leader_proposal.get(proposal.view)
        {
            ...self,
            leader_proposal: self.leader_proposal.put(
                proposal.view,
                match (known) {
                    | Some(p) => Some(p)
                    | None => Some(proposal)
                }
            ),
            leader_proposal_conflicted: self.leader_proposal_conflicted.put(
                proposal.view,
                self.leader_proposal_conflicted.get(proposal.view)
                    or option_has(known, p => p != proposal)
            )
        }
    }

    pure def record_local_proposal(self: ReplicaState, proposal: Proposal): ReplicaState = {
        if (self.proposal.get(proposal.view) == None)
            {
                ...self,
                proposal: self.proposal.set(proposal.view, Some(proposal))
            }
        else
            self
    }

    pure def observe_round_proposal(
        self: ReplicaState,
        proposal: Proposal,
        recovered: bool
    ): ReplicaState = {
        if (self.leader_proposal_conflicted.get(proposal.view))
            self
        else
            match (self.proposal.get(proposal.view)) {
                | None => {
                    ...self,
                    proposal: self.proposal.set(proposal.view, Some(proposal))
                }
                | Some(existing) =>
                    if (existing == proposal)
                        self
                    else if (recovered)
                        {
                            ...self,
                            proposal: self.proposal.set(proposal.view, Some(proposal))
                        }
                    else
                        self
            }
    }

    pure def has_leader_proposal_conflict(self: ReplicaState, proposal: Proposal): bool = {
        self.leader_proposal_conflicted.get(proposal.view)
            or option_has(self.leader_proposal.get(proposal.view), known => known != proposal)
    }

    pure def remember_timeout_reason(
        self: ReplicaState,
        view: ViewNumber,
        reason: TimeoutReason
    ): ReplicaState = {
        self
    }

    pure def same_certificate_subject(existing: Certificate, cert: Certificate): bool = {
        match (existing) {
            | Notarization(n1) =>
                match (cert) {
                    | Notarization(n2) => n1.proposal == n2.proposal
                    | _ => false
                }
            | Nullification(n1) =>
                match (cert) {
                    | Nullification(n2) => n1.view == n2.view
                    | _ => false
                }
            | Finalization(f1) =>
                match (cert) {
                    | Finalization(f2) => f1.proposal == f2.proposal
                    | _ => false
                }
        }
    }

    pure def same_certificate_kind_and_view(existing: Certificate, cert: Certificate): bool = {
        and {
            cert_kind(existing) == cert_kind(cert),
            cert_view(existing) == cert_view(cert),
        }
    }

    pure def cert_with_sender(cert: Certificate, sender: Signature): Certificate = {
        match (cert) {
            | Notarization(n) => Notarization({ ...n, ghost_sender: sender })
            | Nullification(n) => Nullification({ ...n, ghost_sender: sender })
            | Finalization(f) => Finalization({ ...f, ghost_sender: sender })
        }
    }

    pure def list_contains_proposal(chain: List[Proposal], proposal: Proposal): bool = {
        chain.indices().exists(i => chain[i] == proposal)
    }

    pure def finalized_proposal_at(
          view: ViewNumber,
          certificates: Set[Certificate]
      ): Option[Proposal] = {
          val proposals =
              certificates.fold(Set(), (acc, c) =>
                  if (is_finalization_cert(c) and cert_view(c) == view)
                      match (cert_proposal(c)) {
                          | Some(p) => acc.union(Set(p))
                          | None => acc
                      }
                  else
                      acc
              )

          if (proposals.size() == 1)
              proposals.fold(None, (_acc, p) => Some(p))
          else
              None
      }

    pure def finalized_payload_at(
          view: ViewNumber,
          certificates: Set[Certificate]
      ): Option[Payload] = {
          match (finalized_proposal_at(view, certificates)) {
              | Some(p) => Some(p.payload)
              | None => None
          }
      }

    // Returns the unique finalized child that can extend the committed chain
    // rooted at `parent_view`, if the skipped views are all nullified.
    pure def next_committable_proposal(
        parent_view: ViewNumber,
        certificates: Set[Certificate]
    ): Option[Proposal] = {
        val proposals =
            certificates.fold(Set(), (acc, c) =>
                if (is_finalization_cert(c))
                    match (cert_proposal(c)) {
                        | Some(p) =>
                            if (p.parent == parent_view and p.view > parent_view and are_views_nullified(parent_view, p.view, certificates))
                                acc.union(Set(p))
                            else
                                acc
                        | None => acc
                    }
                else
                    acc
            )

        if (proposals.size() == 1)
            proposals.fold(None, (_acc, p) => Some(p))
        else
            None
    }

    pure def extend_committed_chain_once(
        chain: List[Proposal],
        certificates: Set[Certificate]
    ): List[Proposal] = {
        val parent_view = if (chain.length() == 0) GENESIS_VIEW else chain[chain.length() - 1].view
        match (next_committable_proposal(parent_view, certificates)) {
            | Some(p) =>
                if (list_contains_proposal(chain, p))
                    chain
                else
                    chain.append(p)
            | None => chain
        }
    }

    // Rebuild the best connected committed prefix from locally stored
    // finalization/nullification certificates.
    pure def rebuild_committed_chain(certificates: Set[Certificate]): List[Proposal] = {
        VIEWS.fold(List(), (chain, _view) =>
            extend_committed_chain_once(chain, certificates)
        )
    }

      pure def parent_payload(
          self: ReplicaState,
          view: ViewNumber,
          parent_view: ViewNumber,
          certificates: Set[Certificate]
      ): Option[Payload] = {
          if (view <= parent_view)
              None
          else if (parent_view < self.last_finalized)
              None
          else if (not(are_views_nullified(parent_view, view, certificates)))
              None
          else if (parent_view == GENESIS_VIEW)
              Some(GENESIS_PAYLOAD)
          else
              match (finalized_payload_at(parent_view, certificates)) {
                  | Some(p) => Some(p)
                  | None =>
                      if (self.certified.get(parent_view) == Some(true))
                          match (self.proposal.get(parent_view)) {
                              | Some(proposal) => Some(proposal.payload)
                              | None => None
                          }
                      else
                          None
              }
      }

    // Certification is deterministic and may depend on replica id.
    def can_certify(id: ReplicaId, payload: Payload): bool = {
        certify_policy.get(id).contains(payload)
    }

    // Enter a new view, unless it is older than the current view or outside modeled bounds.
    pure def enter_view(self: ReplicaState, new_view: ViewNumber): ReplicaState = {
        if (not(VIEWS.contains(new_view)) or self.view >= new_view)
            self
        else
            {
                ...self,
                view: new_view,
                leader_timeout: self.leader_timeout,
                certification_timeout: self.certification_timeout
            }
    }

    pure def timeout_pending(timers: ViewNumber -> Option[bool], view: ViewNumber): bool = {
        timers.get(view) == Some(false)
    }

    pure def timeout_fired(timers: ViewNumber -> Option[bool], view: ViewNumber): bool = {
        timers.get(view) == Some(true)
    }

    pure def fire_all_timers(self: ReplicaState, view: ViewNumber): ReplicaState = {
        {
            ...self,
            leader_timeout: self.leader_timeout.set(view, Some(true)),
            certification_timeout: self.certification_timeout.set(view, Some(true))
        }
    }

    pure def cancel_all_timers(self: ReplicaState, view: ViewNumber): ReplicaState = {
        {
            ...self,
            leader_timeout: self.leader_timeout.set(view, None),
            certification_timeout: self.certification_timeout.set(view, None)
        }
    }

    type TimerExpired = {
        next_self: ReplicaState,
        next_sent_nullify: Set[NullifyVote],
        next_stored_nullify: Set[NullifyVote]
    }

    type NotarizeEffect = {
        next_self: ReplicaState,
        next_sent_nullify: Set[NullifyVote],
        next_sent_finalize: Set[FinalizeVote],
        next_stored_nullify: Set[NullifyVote],
        next_stored_finalize: Set[FinalizeVote],
    }

    pure def timer_expired(
        self: ReplicaState,
        id: ReplicaId,
        view: ViewNumber,
        expired: TimeoutKind,
        sent_nullify: Set[NullifyVote],
        sent_finalize: Set[FinalizeVote],
        stored_nullify: Set[NullifyVote]
    ): TimerExpired = {
        val local_nullify: NullifyVote = {
            view: view,
            sig: sig_of(id),
        }
        val leader_expired = expired == LeaderTimeoutKind
        val advance_expired = expired == CertificationTimeoutKind
        if (self.view != view) {
            next_self: self,
            next_sent_nullify: sent_nullify,
            next_stored_nullify: stored_nullify
        } else if (broadcast_finalize_in(sent_finalize, id, view)) {
            next_self: {
                ...self,
                leader_timeout: if (leader_expired) self.leader_timeout.set(view, Some(true)) else self.leader_timeout,
                certification_timeout: if (advance_expired) self.certification_timeout.set(view, Some(true)) else self.certification_timeout
            },
            next_sent_nullify: sent_nullify,
            next_stored_nullify: stored_nullify
        } else {
            val timeout_reason =
                if (leader_expired)
                    LeaderTimeoutReason
                else
                    CertificationTimeoutReason
            {
                next_self: {
                    ...remember_timeout_reason(self, view, timeout_reason),
                    leader_timeout: if (leader_expired) self.leader_timeout.set(view, Some(true)) else self.leader_timeout,
                    certification_timeout: if (advance_expired) self.certification_timeout.set(view, Some(true)) else self.certification_timeout
                },
                next_sent_nullify: sent_nullify.union(Set(local_nullify)),
                next_stored_nullify: stored_nullify.union(Set(local_nullify))
            }
        }
    }

    pure def forced_timeout_expired(
        self: ReplicaState,
        id: ReplicaId,
        view: ViewNumber,
        reason: TimeoutReason,
        sent_nullify: Set[NullifyVote],
        sent_finalize: Set[FinalizeVote],
        stored_nullify: Set[NullifyVote]
    ): TimerExpired = {
        val local_nullify: NullifyVote = {
            view: view,
            sig: sig_of(id),
        }
        if (self.view != view)
            {
                next_self: self,
                next_sent_nullify: sent_nullify,
                next_stored_nullify: stored_nullify
            }
        else if (broadcast_finalize_in(sent_finalize, id, view))
            {
                next_self: remember_timeout_reason({
                    ...self,
                    leader_timeout: self.leader_timeout.set(view, None),
                    certification_timeout: self.certification_timeout.set(view, None)
                }, view, reason),
                next_sent_nullify: sent_nullify,
                next_stored_nullify: stored_nullify
            }
        else
            {
                next_self: {
                    ...remember_timeout_reason(self, view, reason),
                    leader_timeout: self.leader_timeout.set(view, None),
                    certification_timeout: self.certification_timeout.set(view, None)
                },
                next_sent_nullify: sent_nullify.union(Set(local_nullify)),
                next_stored_nullify: stored_nullify.union(Set(local_nullify))
            }
    }

    pure def leader_nullify_expired(
        self: ReplicaState,
        id: ReplicaId,
        view: ViewNumber,
        sent_nullify: Set[NullifyVote],
        sent_finalize: Set[FinalizeVote],
        stored_nullify: Set[NullifyVote]
    ): TimerExpired = {
        val local_nullify: NullifyVote = {
            view: view,
            sig: sig_of(id),
        }
        if (self.view != view)
            {
                next_self: self,
                next_sent_nullify: sent_nullify,
                next_stored_nullify: stored_nullify
            }
        else if (broadcast_finalize_in(sent_finalize, id, view))
            {
                next_self: remember_timeout_reason(
                    fire_all_timers(self, view),
                    view,
                    LeaderNullifyReason
                ),
                next_sent_nullify: sent_nullify,
                next_stored_nullify: stored_nullify
            }
        else
            {
                next_self: {
                    ...remember_timeout_reason(
                        fire_all_timers(self, view),
                        view,
                        LeaderNullifyReason
                    )
                },
                next_sent_nullify: sent_nullify.union(Set(local_nullify)),
                next_stored_nullify: stored_nullify.union(Set(local_nullify))
            }
    }

    def create_nullification(id: ReplicaId, view: ViewNumber, votes: Set[NullifyVote]): Option[NullificationCert] = {
        val similar_votes = votes.filter(v => v.view == view)
        val signers = similar_votes.map(v => v.sig)

        if (signers.size() < Q)
            None
        else
            Some({
                view: view,
                signatures: signers,
                ghost_sender: sig_of(id)
            })
    }

    def create_notarization(id: ReplicaId, proposal: Proposal, votes: Set[NotarizeVote]): Option[NotarizationCert] = {
        val similar_votes: Set[NotarizeVote] = votes.filter(v => v.proposal == proposal)
        val signers = similar_votes.map(v => v.sig)

        if (signers.size() < Q)
            None
        else
            Some({
                proposal: proposal,
                signatures: signers,
                ghost_sender: sig_of(id)
            })
    }

    def create_finalization(id: ReplicaId, proposal: Proposal, votes: Set[FinalizeVote]): Option[FinalizationCert] = {
        val similar_votes: Set[FinalizeVote] = votes.filter(v => v.proposal == proposal)
        val signers = similar_votes.map(v => v.sig)

        if (signers.size() < Q)
            None
        else
            Some({
                proposal: proposal,
                signatures: signers,
                ghost_sender: sig_of(id)
            })
    }

    action init = {
        // Non-deterministically choose any total leader function (View -> ReplicaId)
        nondet l = VIEWS.setOfMaps(Replicas).oneOf()
        initWithLeader(l)
    }

    action initWithLeader(l: ViewNumber -> ReplicaId): bool = {
        val default_certify_policy = Replicas.mapBy(_ => AllPayloads)
        initWithLeaderAndCertify(l, default_certify_policy)
    }

    action initWithLeaderAndCertify(
        l: ViewNumber -> ReplicaId,
        certify: ReplicaId -> Set[Payload]
    ): bool = {
        all {
            replica_state' = CORRECT.mapBy(id => {
                view: FIRST_VIEW,
                ghost_last_seen_notarization: GENESIS_VIEW,
                last_finalized: GENESIS_VIEW,
                proposal: VIEWS.mapBy(_ => None),
                leader_proposal: VIEWS.mapBy(_ => None),
                leader_proposal_conflicted: VIEWS.mapBy(_ => false),
                certified: VIEWS.mapBy(_ => None),
                leader_timeout: VIEWS.mapBy(_ => Some(false)),
                certification_timeout: VIEWS.mapBy(_ => Some(false))
            }),
            sent_notarize_votes' = Set(),
            sent_nullify_votes' = Set(),
            sent_finalize_votes' = Set(),
            sent_certificates' = Set(),
            store_notarize_votes' = CORRECT.mapBy(_ => Set()),
            store_nullify_votes' = CORRECT.mapBy(_ => Set()),
            store_finalize_votes' = CORRECT.mapBy(_ => Set()),
            store_certificates' = CORRECT.mapBy(_ => Set()),
            ghost_committed_blocks' = CORRECT.mapBy(_ => List()),
            leader' = l,
            certify_policy' = certify,
            lastAction' = "init"
        }
    }

    // A step by a correct or byzantine replica.
    action step = {
        any {
            {
                correct_replica_step
            },
            all {
                nondet id = oneOf(CORRECT)
                nondet new_payload = oneOf(VALID_PAYLOADS)
                nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
                propose(id, new_payload, parent_view),
            },
            all {
                byzantine_replica_step,
                _unchanged_replica_state,
                lastAction' = "byzantine_step",
            }
        }
    }

    // A step by a correct replica, except for the proposer step.
    action correct_replica_step(): bool = all {
        nondet id = oneOf(CORRECT)
        val self = replica_state.get(id)
        val skip_timeout = and {
            id != leader.get(self.view),
            leader_inactive(self.view),
            not(broadcast_nullify(id, self.view)),
        }
        // Skip "leader timeout" and "certification timeout" if a designated leader hasn't participated in
        // some number of views (again to trigger early view transition for an unresponsive leader).
        if (skip_timeout) {
            on_timeout(id, LeaderTimeoutKind)
        } else {
            any {
                {
                    on_timeout(id, LeaderTimeoutKind)
                },
                {
                    on_timeout(id, CertificationTimeoutKind)
                },
                {
                    nondet vote = sent_notarize_votes.oneOf()
                    on_notarize(id, vote)
                },
                {
                    nondet vote = sent_finalize_votes.oneOf()
                    on_finalize(id, vote)
                },
                {
                    nondet vote = sent_nullify_votes.oneOf()
                    on_nullify(id, vote)
                },
                all {
                    nondet cert = oneOf(sent_certificates)
                    on_certificate(id, cert)
                },
            }
        }
    }

    // This action models only the successful leader proposal path:
    // find_parent must already have succeeded, and the application-level
    // propose(v, parent) must have returned Some(payload). Invalid parents
    // therefore disable this action rather than triggering nullify. The
    // missing-proposal case (propose returning None) is not modeled here.
    // Upon entering a view, the leader may propose and implicitly cast notarize(c, v).
    action propose(
        id: ReplicaId,
        new_payload: Payload,
        parent_view: ViewNumber
    ): bool = all {
        val store_notarize = store_notarize_votes.get(id)
        val store_nullify = store_nullify_votes.get(id)
        val self = replica_state.get(id)
        val certs = store_certificates.get(id)
        val proposal_ok = VALID_PAYLOADS.contains(new_payload) and is_some(parent_payload(self, self.view, parent_view, certs))
        val proposal: Proposal = {
            view: self.view,
            parent: parent_view,
            payload: new_payload,
        }
        val timer = forced_timeout_expired(
            self,
            id,
            self.view,
            InvalidProposalReason,
            sent_nullify_votes,
            sent_finalize_votes,
            store_nullify
        )
        all {
            id == leader.get(self.view),
            is_none(self.proposal.get(self.view)),
            not(broadcast_nullify(id, self.view)),
            proposal_ok,

            sent_notarize_votes' = sent_notarize_votes.union(Set({ proposal: proposal, sig: sig_of(id) })),
            sent_nullify_votes' = sent_nullify_votes,
            sent_finalize_votes' = sent_finalize_votes,
            store_notarize_votes' = store_notarize_votes.set(id, store_notarize.union(Set({ proposal: proposal, sig: sig_of(id) }))),
            store_nullify_votes' = store_nullify_votes,
            store_finalize_votes' = store_finalize_votes,
            replica_state' = replica_state.set(id,
               {
                    ...observe_leader_proposal(
                        record_local_proposal(self, proposal),
                        proposal
                    ),
                    leader_timeout: self.leader_timeout.set(self.view, None)
               }
            ),
            // unchanged
            sent_certificates' = sent_certificates,
            store_certificates' = store_certificates,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            certify_policy' = certify_policy,
            lastAction' = "propose"
        }
    }

    // Upon receiving a notarize vote:
    // - if from the leader: validate proposal and send notarize/nullify
    // - otherwise: collect vote, on 2f+1 create notarization cert
    action on_notarize(id: ReplicaId, vote: NotarizeVote): bool = all {
        sent_notarize_votes.contains(vote),
        val store_notarize = store_notarize_votes.get(id)
        val store_nullify = store_nullify_votes.get(id)
        val store_finalize = store_finalize_votes.get(id)
        val self = replica_state.get(id)
        val certs = store_certificates.get(id)
        val proposal = vote.proposal
        val view = proposal.view
        val payload = proposal.payload
        val parent_ok = is_some(parent_payload(self, proposal.view, proposal.parent, certs))
        val payload_ok = VALID_PAYLOADS.contains(payload)
        val is_leader_vote = (vote.sig == sig_of(leader.get(view)))
        val proposal_conflicted = has_leader_proposal_conflict(self, proposal)
        val can_process_as_proposal = and {
            is_leader_vote,
            view == self.view,
            not(broadcast_notarize(id, self.view)),
            not(broadcast_nullify(id, view)),
        }

        if (proposal_conflicted) {
            all {
                sent_notarize_votes' = sent_notarize_votes,
                sent_nullify_votes' = sent_nullify_votes,
                sent_finalize_votes' = sent_finalize_votes,
                sent_certificates' = sent_certificates,
                store_notarize_votes' = store_notarize_votes,
                store_nullify_votes' = store_nullify_votes,
                store_finalize_votes' = store_finalize_votes,
                store_certificates' = store_certificates,
                replica_state' = replica_state,
                ghost_committed_blocks' = ghost_committed_blocks,
                leader' = leader,
                certify_policy' = certify_policy,
                lastAction' = "on_notarize"
            }
        } else if (can_process_as_proposal) {
            val timer = forced_timeout_expired(
                self,
                id,
                view,
                InvalidProposalReason,
                sent_nullify_votes,
                sent_finalize_votes,
                store_nullify
            )
            // Proposal processing: validate the leader's proposal and vote
            val notarize_ok = is_some(construct_notarize(id, self, view, proposal, payload_ok and parent_ok))
            val new_store_notarize_p = if (notarize_ok)
                store_notarize.union(Set(vote, { proposal: proposal, sig: sig_of(id) }))
              else
                store_notarize
            val proposal_self = if (notarize_ok) {
                    ...observe_leader_proposal(
                        observe_round_proposal(self, proposal, false),
                        proposal
                    ),
                    leader_timeout: self.leader_timeout.set(self.view, None)
                } else
                    observe_leader_proposal(
                        observe_round_proposal(timer.next_self, proposal, false),
                        proposal
                    )
            // Build the certificate from the fullest available vote set.
            val maybe_not_cert_p = if (notarize_ok) create_notarization(id, proposal, new_store_notarize_p) else None
            val can_cert_p = can_certify(id, proposal.payload)
            val should_broadcast_not_p = not(broadcast_notarization(id, view))
            val effect_p = match maybe_not_cert_p {
                | Some(cert) => notarize_effect(proposal_self, id, cert, can_cert_p,
                    sent_nullify_votes, sent_finalize_votes,
                    store_nullify_votes.get(id), store_finalize_votes.get(id))
                | None => {
                    next_self: proposal_self,
                    next_sent_nullify: sent_nullify_votes,
                    next_sent_finalize: sent_finalize_votes,
                    next_stored_nullify: store_nullify_votes.get(id),
                    next_stored_finalize: store_finalize_votes.get(id),
                }
            }
            all {
                sent_notarize_votes' = if (notarize_ok)
                    sent_notarize_votes.union(Set({ proposal: proposal, sig: sig_of(id) }))
                  else
                    sent_notarize_votes,
                sent_nullify_votes' = if (notarize_ok) effect_p.next_sent_nullify else timer.next_sent_nullify,
                sent_finalize_votes' = effect_p.next_sent_finalize,
                store_notarize_votes' = store_notarize_votes.set(id, new_store_notarize_p),
                store_nullify_votes' = if (notarize_ok)
                    store_nullify_votes.set(id, effect_p.next_stored_nullify)
                  else
                    store_nullify_votes.set(id, timer.next_stored_nullify),
                store_finalize_votes' = store_finalize_votes.set(id, effect_p.next_stored_finalize),
                store_certificates' = match maybe_not_cert_p {
                    | Some(cert) =>
                        store_certificates.setBy(id, old => old.union(Set(Notarization(cert))))
                    | None => store_certificates
                },
                sent_certificates' = match maybe_not_cert_p {
                    | Some(cert) => if (should_broadcast_not_p)
                        sent_certificates.union(Set(Notarization(cert)))
                      else
                        sent_certificates
                    | None => sent_certificates
                },
                replica_state' = replica_state.set(id, effect_p.next_self),

                ghost_committed_blocks' = ghost_committed_blocks,

                // unchanged
                leader' = leader,
                certify_policy' = certify_policy,
                lastAction' = "on_notarize"
            }
        } else {
            // Vote aggregation: collect vote and check for notarization quorum
            val new_store_notarize = store_notarize.union(Set(vote))
            val had_notarization = certs.exists(c => and {
                is_notarization_cert(c),
                cert_proposal(c) == Some(proposal),
            })
            val now_notarized = is_proposal_notarized_votes(proposal, new_store_notarize)

            // Build the certificate from the fullest available vote
            // set (≥ Q).
            val maybe_not_cert = if (had_notarization) None
                else create_notarization(id, proposal, new_store_notarize)
            val can_cert = can_certify(id, proposal.payload)
            val is_new_cert = not(had_notarization)
            val should_broadcast_not = not(broadcast_notarization(id, view))
            val effect = match maybe_not_cert {
                | Some(cert) => notarize_effect(self, id, cert, can_cert,
                    sent_nullify_votes, sent_finalize_votes,
                    store_nullify_votes.get(id), store_finalize_votes.get(id))
                | None => {
                    next_self: self,
                    next_sent_nullify: sent_nullify_votes,
                    next_sent_finalize: sent_finalize_votes,
                    next_stored_nullify: store_nullify_votes.get(id),
                    next_stored_finalize: store_finalize_votes.get(id),
                }
            }
            // Matches Rust construct_notarize (round.rs:481-482): self-vote even
            // after seeing a notarization when a cert is first formed here.
            val can_self_notarize_agg = and {
                is_some(maybe_not_cert),
                not(broadcast_notarize(id, view)),
                not(broadcast_nullify(id, view)),
            }
            val self_vote_agg: NotarizeVote = { proposal: proposal, sig: sig_of(id) }
            all {
                is_none(maybe_not_cert) or now_notarized,
                store_notarize_votes' = store_notarize_votes.set(id,
                    if (can_self_notarize_agg) new_store_notarize.union(Set(self_vote_agg))
                    else new_store_notarize
                ),
                // Add the newly-constructed cert. `maybe_not_cert` is
                // `None` whenever `had_notarization` holds (see the gate
                // above), so this branch is a no-op in that case — the
                // store contains at most one notarization per (view,
                // proposal), matching Rust's one-shot assembly.
                store_certificates' = match maybe_not_cert {
                    | Some(cert) =>
                        store_certificates.setBy(id, old => old.union(Set(Notarization(cert))))
                    | None => store_certificates
                },
                // Re-broadcast is also one-per-view.
                sent_certificates' = match maybe_not_cert {
                    | Some(cert) => if (should_broadcast_not)
                        sent_certificates.union(Set(Notarization(cert)))
                      else
                        sent_certificates
                    | None => sent_certificates
                },
                sent_notarize_votes' = if (can_self_notarize_agg)
                    sent_notarize_votes.union(Set(self_vote_agg))
                  else
                    sent_notarize_votes,
                sent_nullify_votes' = effect.next_sent_nullify,
                sent_finalize_votes' = effect.next_sent_finalize,
                store_nullify_votes' = store_nullify_votes.set(id, effect.next_stored_nullify),
                store_finalize_votes' = store_finalize_votes.set(id, effect.next_stored_finalize),
                replica_state' = replica_state.set(id, effect.next_self),
                ghost_committed_blocks' = ghost_committed_blocks,

                // unchanged
                leader' = leader,
                certify_policy' = certify_policy,
                lastAction' = "on_notarize"
            }
        }
    }

    // Upon receiving votes for finalize(c, v):
    // - collect votes
    // - on 2f+1: create finalization cert and enter v+1
    action on_finalize(id: ReplicaId, vote: FinalizeVote): bool = all {
        sent_finalize_votes.contains(vote),
        val store_finalize = store_finalize_votes.get(id)
        val self = replica_state.get(id)
        val proposal = vote.proposal
        all {
            // Matches interesting() in implementation: min_active = last_finalized - activity_timeout
            proposal.view >= self.last_finalized - ACTIVITY_TIMEOUT,
            proposal.view <= self.view + 1,
            val conflict = has_leader_proposal_conflict(self, proposal)
            val new_store_finalize = store_finalize.union(Set(vote))
            // Build the certificate from the fullest available vote
            // set (≥ Q).
            val maybe_fin_cert = if (conflict) None
                else create_finalization(id, proposal, new_store_finalize)
            val is_new_cert = not(store_certificates.get(id).exists(c => and {
                is_finalization_cert(c),
                cert_proposal(c) == Some(proposal),
            }))
            match maybe_fin_cert {
                | Some(cert) => all {
                    store_finalize_votes' = if (conflict) store_finalize_votes else store_finalize_votes.set(id, new_store_finalize),
                    store_notarize_votes' = store_notarize_votes,
                    store_nullify_votes' = store_nullify_votes,
                    _add_finalization(id, cert, is_new_cert)
                }
                | None => all {
                    store_finalize_votes' = if (conflict) store_finalize_votes else store_finalize_votes.set(id, new_store_finalize),
                    store_certificates' = store_certificates,
                    sent_certificates' = sent_certificates,
                    sent_notarize_votes' = sent_notarize_votes,
                    sent_nullify_votes' = sent_nullify_votes,
                    sent_finalize_votes' = sent_finalize_votes,
                    store_notarize_votes' = store_notarize_votes,
                    store_nullify_votes' = store_nullify_votes,
                    replica_state' = replica_state,
                    ghost_committed_blocks' = ghost_committed_blocks,
                }
            },
            // unchanged
            leader' = leader,
            certify_policy' = certify_policy,
            lastAction' = "on_finalize"
        }
    }

    // Upon receiving votes for nullify(v):
    // - collect votes
    // - on 2f+1: create nullification cert and enter v+1
    //
    // Additional Simplex rule:
    // if a non-leader replica receives nullify(v) from the current leader of view v,
    // it treats this as immediate timeout expiry and broadcasts nullify(v) if it is allowed.
    action on_nullify(id: ReplicaId, vote: NullifyVote): bool = all {
        sent_nullify_votes.contains(vote),
        val store_nullify = store_nullify_votes.get(id)
        val self = replica_state.get(id)
        all {
            // Matches interesting() in implementation: min_active = last_finalized - activity_timeout
            vote.view >= self.last_finalized - ACTIVITY_TIMEOUT,
            vote.view <= self.view + 1,
            val new_nullify_votes = store_nullify.union(Set(vote))
            val leader_nullify_trigger = and {
                id != leader.get(vote.view),
                not(broadcast_nullify(id, vote.view)),
                vote.sig == sig_of(leader.get(vote.view)),
            }
            val timer = if (leader_nullify_trigger)
                leader_nullify_expired(self, id, vote.view, sent_nullify_votes, sent_finalize_votes, new_nullify_votes)
            else {
                next_self: self,
                next_sent_nullify: sent_nullify_votes,
                next_stored_nullify: new_nullify_votes
            }
            val certs = store_certificates.get(id)
            val had_nullification = certs.exists(c => is_nullification_cert(c) and cert_view(c) == vote.view)
            // Build the certificate from the fullest available vote
            // set (≥ Q).
            val maybe_null_cert = create_nullification(id, vote.view, timer.next_stored_nullify)
            match maybe_null_cert {
                | Some(cert) => all {
                    store_notarize_votes' = store_notarize_votes,
                    store_nullify_votes' = store_nullify_votes.set(id, timer.next_stored_nullify),
                    store_finalize_votes' = store_finalize_votes,
                    sent_nullify_votes' = timer.next_sent_nullify,
                    _add_nullification(id, cert, not(had_nullification), timer.next_self)
                }
                | None => all {
                    store_certificates' = store_certificates,
                    sent_certificates' = sent_certificates,
                    sent_notarize_votes' = sent_notarize_votes,
                    sent_nullify_votes' = timer.next_sent_nullify,
                    sent_finalize_votes' = sent_finalize_votes,
                    store_notarize_votes' = store_notarize_votes,
                    store_nullify_votes' = store_nullify_votes.set(id, timer.next_stored_nullify),
                    store_finalize_votes' = store_finalize_votes,
                    replica_state' = replica_state.set(id, timer.next_self),
                    ghost_committed_blocks' = ghost_committed_blocks,
                }
            },
            // unchanged
            leader' = leader,
            certify_policy' = certify_policy,
            lastAction' = "on_nullify"
        }
    }

    // Handle certificate message.
    action on_certificate(id: ReplicaId, cert: Certificate): bool = all {
        val certs = store_certificates.get(id)
        all {
            sent_certificates.contains(cert),
            cert_signatures(cert).size() >= Q,
            val duplicate = certs.exists(existing => same_certificate_subject(existing, cert))
            val seen_kind_and_view = certs.exists(existing => same_certificate_kind_and_view(existing, cert))

            if (duplicate) {
                all {
                    sent_notarize_votes' = sent_notarize_votes,
                    sent_nullify_votes' = sent_nullify_votes,
                    sent_finalize_votes' = sent_finalize_votes,
                    sent_certificates' = sent_certificates,
                    store_notarize_votes' = store_notarize_votes,
                    store_nullify_votes' = store_nullify_votes,
                    store_finalize_votes' = store_finalize_votes,
                    store_certificates' = store_certificates,
                    replica_state' = replica_state,
                    ghost_committed_blocks' = ghost_committed_blocks,
                }
            } else {
                match (cert) {
                    | Notarization(n) => all {
                        _add_notarization(id, n, not(seen_kind_and_view))
                    }
                    | Nullification(n) => all {
                        store_notarize_votes' = store_notarize_votes,
                        store_nullify_votes' = store_nullify_votes,
                        store_finalize_votes' = store_finalize_votes,
                        sent_nullify_votes' = sent_nullify_votes,
                        _add_nullification(id, n, not(seen_kind_and_view), replica_state.get(id))
                    }
                    | Finalization(f) => all {
                        store_notarize_votes' = store_notarize_votes,
                        store_nullify_votes' = store_nullify_votes,
                        store_finalize_votes' = store_finalize_votes,
                        _add_finalization(id, f, not(seen_kind_and_view))
                    }
                }
            },

            // unchanged
            leader' = leader,
            certify_policy' = certify_policy,
            lastAction' = "on_certificate"
        }
    }

    def notarize_effect(
        self: ReplicaState,
        id: ReplicaId,
        notarization: NotarizationCert,
        can_cert: bool,
        sent_nullify_votes: Set[NullifyVote],
        sent_finalize_votes: Set[FinalizeVote],
        stored_nullify: Set[NullifyVote],
        stored_finalize: Set[FinalizeVote]
    ): NotarizeEffect = {
        val cert: Certificate = Notarization(notarization)
        val cert_view_num = notarization.proposal.view
        val seen_notarization = if (self.ghost_last_seen_notarization < cert_view_num) cert_view_num else self.ghost_last_seen_notarization
        val cert_prop = notarization.proposal
        val proposal_conflicted = has_leader_proposal_conflict(self, cert_prop)
        val should_broadcast = not(broadcast_notarization(id, cert_view_num))
        val timer = forced_timeout_expired(
            self,
            id,
            cert_view_num,
            FailedCertificationReason,
            sent_nullify_votes,
            sent_finalize_votes,
            stored_nullify
        )
        val is_certified = and {
            can_cert,
            self.certified.get(cert_view_num) == None,
        }
        val finalize_result = construct_finalize(id, self, cert_view_num, cert_prop, proposal_conflicted, is_certified)
        val can_send_nullify = and {
            not(can_cert),
            self.view == cert_view_num,
            construct_nullify(id, self, cert_view_num),
            // NOTE: Model simplification: suppress nullify retries (single-shot nullify per view).
            not(broadcast_nullify(id, cert_view_num)),
        }
        val observed = observe_leader_proposal(observe_round_proposal(self, cert_prop, true), cert_prop)

        if (is_some(finalize_result))
            {
                next_self: enter_view({
                    ...observed,
                    // clear_deadlines: matches Rust round.clear_deadlines()
                    leader_timeout: self.leader_timeout.set(cert_view_num, None),
                    certification_timeout: self.certification_timeout.set(cert_view_num, None),
                    ghost_last_seen_notarization: seen_notarization,
                    certified: self.certified.put(cert_view_num, Some(true))
                }, cert_view_num + 1),
                next_sent_nullify: sent_nullify_votes,
                next_sent_finalize: sent_finalize_votes.union(Set({
                    proposal: cert_prop,
                    sig: sig_of(id),
                })),
                next_stored_nullify: stored_nullify,
                next_stored_finalize: stored_finalize.union(Set({
                    proposal: cert_prop,
                    sig: sig_of(id),
                })),
            }
        else if (is_certified)
            {
                // Certification succeeds but finalize is blocked
                // (equivocation detected or already broadcast finalize/nullify).
                next_self: enter_view({
                    ...observed,
                    // clear_deadlines: matches Rust round.clear_deadlines()
                    leader_timeout: self.leader_timeout.set(cert_view_num, None),
                    certification_timeout: self.certification_timeout.set(cert_view_num, None),
                    ghost_last_seen_notarization: seen_notarization,
                    certified: self.certified.put(cert_view_num, Some(true)),
                }, cert_view_num + 1),
                next_sent_nullify: sent_nullify_votes,
                next_sent_finalize: sent_finalize_votes,
                next_stored_nullify: stored_nullify,
                next_stored_finalize: stored_finalize,
            }
        else if (can_send_nullify)
            {
                next_self: {
                    ...observe_leader_proposal(
                        observe_round_proposal(timer.next_self, cert_prop, true),
                        cert_prop
                    ),
                    certified: timer.next_self.certified.set(cert_view_num, Some(false)),
                    ghost_last_seen_notarization: seen_notarization
                },
                next_sent_nullify: timer.next_sent_nullify,
                next_sent_finalize: sent_finalize_votes,
                next_stored_nullify: timer.next_stored_nullify,
                next_stored_finalize: stored_finalize,
            }
        else
            {
                next_self: {
                    ...observed,
                    ghost_last_seen_notarization: seen_notarization
                },
                next_sent_nullify: sent_nullify_votes,
                next_sent_finalize: sent_finalize_votes,
                next_stored_nullify: stored_nullify,
                next_stored_finalize: stored_finalize,
            }
    }

    action _add_notarization(id: ReplicaId, notarization: NotarizationCert, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        val cert: Certificate = Notarization(notarization)
        val should_broadcast_notarization = not(broadcast_notarization(id, notarization.proposal.view))
        val effect = notarize_effect(
            self, id, notarization,
            can_certify(id, notarization.proposal.payload),
            sent_nullify_votes, sent_finalize_votes,
            store_nullify_votes.get(id), store_finalize_votes.get(id)
        )
        // Matches Rust construct_notarize (round.rs:481-482): self-vote even after
        // seeing a notarization, "in case someone is recording our activity".
        val can_self_notarize = and {
            not(broadcast_notarize(id, notarization.proposal.view)),
            not(broadcast_nullify(id, notarization.proposal.view)),
        }
        val self_vote: NotarizeVote = { proposal: notarization.proposal, sig: sig_of(id) }
        all {
            notarization.signatures.size() >= Q,
            store_certificates' = if (is_new_cert)
                store_certificates.setBy(id, old => old.union(Set(cert)))
              else
                store_certificates,
            sent_certificates' = if (should_broadcast_notarization)
                sent_certificates.union(Set(cert_with_sender(cert, sig_of(id))))
              else
                sent_certificates,
            sent_notarize_votes' = if (can_self_notarize)
                sent_notarize_votes.union(Set(self_vote))
              else
                sent_notarize_votes,
            sent_nullify_votes' = effect.next_sent_nullify,
            sent_finalize_votes' = effect.next_sent_finalize,
            store_notarize_votes' = if (can_self_notarize)
                store_notarize_votes.setBy(id, old => old.union(Set(self_vote)))
              else
                store_notarize_votes,
            store_nullify_votes' = store_nullify_votes.set(id, effect.next_stored_nullify),
            store_finalize_votes' = store_finalize_votes.set(id, effect.next_stored_finalize),
            replica_state' = replica_state.set(id, effect.next_self),
            ghost_committed_blocks' = ghost_committed_blocks,
        }
    }

    action _add_nullification(id: ReplicaId, nullification: NullificationCert, is_new_cert: bool, base_self: ReplicaState): bool = all {
        val cert: Certificate = Nullification(nullification)
        val cert_view_num = nullification.view
        val should_broadcast_nullification = not(broadcast_nullification(id, cert_view_num))
        val next_certs = if (is_new_cert)
            store_certificates.get(id).union(Set(cert))
          else
            store_certificates.get(id)
        all {
            nullification.signatures.size() >= Q,

            store_certificates' = if (is_new_cert)
                store_certificates.set(id, next_certs)
              else
                store_certificates,
            sent_certificates' = if (should_broadcast_nullification)
                sent_certificates.union(Set(cert_with_sender(cert, sig_of(id))))
              else
                sent_certificates,

            sent_notarize_votes' = sent_notarize_votes,
            sent_finalize_votes' = sent_finalize_votes,
            replica_state' = replica_state.set(
                id,
                enter_view(
                    cancel_all_timers(base_self, cert_view_num),
                    cert_view_num + 1
                )
            ),
            ghost_committed_blocks' = if (is_new_cert)
                ghost_committed_blocks.set(id, rebuild_committed_chain(next_certs))
              else
                ghost_committed_blocks
        }
    }

    action _add_finalization(id: ReplicaId, finalization: FinalizationCert, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        val cert: Certificate = Finalization(finalization)
        val should_broadcast_finalization = not(broadcast_finalization(id, finalization.proposal.view))
        val cert_view_num = finalization.proposal.view
        val cert_prop = finalization.proposal
        val seen_notarization = if (self.ghost_last_seen_notarization < cert_view_num) cert_view_num else self.ghost_last_seen_notarization
        val newer = cert_view_num > self.last_finalized
        val next_certs = if (is_new_cert)
            store_certificates.get(id).union(Set(cert))
          else
            store_certificates.get(id)
        all {
            finalization.signatures.size() >= Q,

            store_certificates' = if (is_new_cert)
                store_certificates.set(id, next_certs)
              else
                store_certificates,
            sent_certificates' = if (should_broadcast_finalization)
                sent_certificates.union(Set(cert_with_sender(cert, sig_of(id))))
              else
                sent_certificates,
            ghost_committed_blocks' = if (is_new_cert)
                ghost_committed_blocks.set(id, rebuild_committed_chain(next_certs))
              else
                ghost_committed_blocks,

            sent_notarize_votes' = sent_notarize_votes,
            sent_nullify_votes' = sent_nullify_votes,
            sent_finalize_votes' = sent_finalize_votes,
            replica_state' = replica_state.set(id,
                enter_view({
                    ...observe_leader_proposal(
                        observe_round_proposal(
                            cancel_all_timers(self, cert_view_num),
                            cert_prop, true
                        ),
                        cert_prop
                    ),
                    last_finalized: if (newer) cert_view_num else self.last_finalized,
                    ghost_last_seen_notarization: seen_notarization
                }, cert_view_num + 1)
            )
        }
    }

    // On leader timeout or advance timeout firing, broadcast nullify(v).
    action on_timeout(id: ReplicaId, expired: TimeoutKind): bool = all {
        val self = replica_state.get(id)
        val leader_mode = and {
            expired == LeaderTimeoutKind,
            timeout_pending(self.leader_timeout, self.view)
        }
        val advance_mode = and {
            expired == CertificationTimeoutKind,
            timeout_fired(self.leader_timeout, self.view),
            timeout_pending(self.certification_timeout, self.view)
        }
        val timer = timer_expired(
            self,
            id,
            self.view,
            expired,
            sent_nullify_votes,
            sent_finalize_votes,
            store_nullify_votes.get(id)
        )
        all {
            not(broadcast_nullify(id, self.view)),
            or {
                leader_mode,
                advance_mode
            },
            sent_notarize_votes' = sent_notarize_votes,
            sent_nullify_votes' = timer.next_sent_nullify,
            sent_finalize_votes' = sent_finalize_votes,
            store_notarize_votes' = store_notarize_votes,
            store_nullify_votes' = store_nullify_votes.set(id, timer.next_stored_nullify),
            store_finalize_votes' = store_finalize_votes,
            replica_state' = replica_state.set(id, timer.next_self),

            // unchanged
            sent_certificates' = sent_certificates,
            store_certificates' = store_certificates,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            certify_policy' = certify_policy,
            lastAction' = "timeout"
        }
    }

    // Byzantine behavior (completely adversarial)
    action byzantine_replica_step: bool = all {
        BYZANTINE != Set(),

        // Adversary may inject arbitrary well-typed vote messages.
        all {
              nondet sender = BYZANTINE.oneOf()
              nondet view = VIEWS.oneOf()
              nondet payload = AllPayloads.oneOf()
              nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
              val p = {
                  view: view,
                  payload: payload,
                  parent: parent_view,
              }
              val vote = {
                  proposal: p,
                  sig: sig_of(sender)
              }

              sent_notarize_votes' = sent_notarize_votes.union(Set(vote)),
        },

        all {
              nondet sender = BYZANTINE.oneOf()
              nondet view = VIEWS.oneOf()

              val vote = {
                  view: view,
                  sig: sig_of(sender)
              }

              sent_nullify_votes' = sent_nullify_votes.union(Set(vote))
        },

        all {
              nondet sender = BYZANTINE.oneOf()
              nondet view = VIEWS.oneOf()
              nondet payload = AllPayloads.oneOf()
              nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()

              val p = {
                  view: view,
                  payload: payload,
                  parent: parent_view,
              }
              val vote = {
                  proposal: p,
                  sig: sig_of(sender)
              }

              sent_finalize_votes' = sent_finalize_votes.union(Set(vote))
        },

        // Adversary may inject arbitrary certificates.
        all {
            nondet sender = BYZANTINE.oneOf()
            nondet view = VIEWS.oneOf()
            nondet payload = AllPayloads.oneOf()
            nondet parent_view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            nondet kind = oneOf(Set(NotarizationKind, NullificationKind, FinalizationKind))

            val byz_proposal: Proposal = {
                view: view,
                payload: payload,
                parent: parent_view,
            }

            val vote_sigs = if (kind == NotarizationKind) {
                sent_notarize_votes.filter(v => and {
                    v.proposal == byz_proposal,
                }).map(v => v.sig)
            } else if (kind == NullificationKind) {
                sent_nullify_votes.filter(v => v.view == view).map(v => v.sig)
            } else {
                sent_finalize_votes.filter(v => and {
                    v.proposal == byz_proposal,
                }).map(v => v.sig)
            }
            nondet agg_sig = vote_sigs.union(ByzantineSigs).powerset().oneOf()
            val cert = if (kind == NotarizationKind) {
                notarization(byz_proposal, agg_sig, sig_of(sender))
            } else if (kind == NullificationKind) {
                nullification(view, agg_sig, sig_of(sender))
            } else {
                finalization(byz_proposal, agg_sig, sig_of(sender))
            }
            sent_certificates' = sent_certificates.union(Set(cert))
        },
    }

    // Part of the state not touched by byzantine validators.
    action _unchanged_replica_state = all {
        ghost_committed_blocks' = ghost_committed_blocks,
        replica_state' = replica_state,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        leader' = leader,
        certify_policy' = certify_policy
    }

    // -------------------------------------------------
    // Invariants
    // -------------------------------------------------

    // Assumptions and thresholds.
    val assumptions_valid = all {
        CORRECT.size() + BYZANTINE.size() == N,
        CORRECT.intersect(BYZANTINE) == Set(),
        N >= 3*F + 1,
        Q == N - F,
    }

    val agreement = tuples(CORRECT, CORRECT).forall(((id1, id2)) => {
        val blocks1 = ghost_committed_blocks.get(id1)
        val blocks2 = ghost_committed_blocks.get(id2)
        or {
            id1 == id2,
            // ignore this case, as there is a symmetric one
            blocks1.length() > blocks2.length(),
            // the shorter sequence is a prefix of the longer one
            blocks1.indices().forall(i => blocks1[i] == blocks2[i])
        }
    })

    // A correct replica cannot both nullify and finalize in the same view.
    // Notarize may coexist with either, matching the protocol's allowed patterns.
    val no_vote_equivocation_inv = CORRECT.forall(id => {
        VIEWS.forall(v =>
            not(broadcast_nullify(id, v) and broadcast_finalize(id, v))
        )
    })

    // No view may contain both nullification and finalization certificates.
    val nullified_views_seen = CORRECT.fold(Set(), (acc, id) =>
          acc.union(
              store_certificates.get(id)
                  .filter(c => is_nullification_cert(c))
                  .map(c => cert_view(c))
          )
      )

      val finalized_views_seen = CORRECT.fold(Set(), (acc, id) =>
          acc.union(
              store_certificates.get(id)
                  .filter(c => is_finalization_cert(c))
                  .map(c => cert_view(c))
          )
      )

      val no_nullification_and_finalization_in_the_same_view =
          nullified_views_seen.intersect(finalized_views_seen) == Set()

    val no_notarize_equivocation = CORRECT.forall(id =>
          VIEWS.forall(v =>
              sent_notarize_votes
                  .filter(vote => vote.sig == sig_of(id) and vote.proposal.view == v)
                  .map(vote => vote.proposal)
                  .size() <= 1
          )
      )

    val valid_last_finalized = CORRECT.forall(id => {
        val self = replica_state.get(id)
        self.last_finalized <= self.ghost_last_seen_notarization
    })

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v =>
            not(broadcast_notarize(id, v))
                or is_some(self.proposal.get(v))
        )
    })

    def finalized_payloads_seen(view: ViewNumber): Set[Payload] = {
        CORRECT.fold(Set(), (acc, id) =>
            acc.union(
                store_certificates.get(id).fold(Set(), (cert_acc, c) =>
                    if (is_finalization_cert(c) and cert_view(c) == view)
                        match (cert_proposal(c)) {
                            | Some(p) => cert_acc.union(Set(p.payload))
                            | None => cert_acc
                        }
                    else
                        cert_acc
                )
            )
        )
    }

    // If a payload B for view v is finalized, no other payload B' at v can be finalized.
    val validity = VIEWS.forall(v =>
        finalized_payloads_seen(v).size() <= 1
    )

    val unique_notarized_or_finalized_payload_per_view =
        tuples(CORRECT, VIEWS).forall(((id, v)) => {
            val certs = store_certificates.get(id)
            certs
                .filter(c => and {
                    cert_view(c) == v,
                    is_notarization_cert(c) or is_finalization_cert(c),
                })
                .map(c => cert_payload(c))
                .size() <= 1
        })

    val finalize_vote_requires_notarization_cert = CORRECT.forall(id => {
        val certs = store_certificates.get(id)
        sent_finalize_votes
            .filter(v => v.sig == sig_of(id))
            .forall(v =>
                certs.exists(c => and {
                    is_notarization_cert(c),
                    cert_proposal(c) == Some(v.proposal),
                })
            )
    })

    // A finalized view must not contain multiple finalized proposals.
    val finalized_views_have_unique_proposal = CORRECT.forall(id => {
        val certs = store_certificates.get(id)
        VIEWS.forall(v =>
            certs
                .filter(c => is_finalization_cert(c) and cert_view(c) == v)
                .map(c => cert_proposal(c))
                .size() <= 1
        )
    })

    // Every committed proposal must come from a locally stored finalization cert.
    val committed_blocks_are_finalized = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        val certs = store_certificates.get(id)
        chain.indices().forall(i =>
            certs.exists(c => is_finalization_cert(c) and cert_proposal(c) == Some(chain[i]))
        )
    })

    // The committed chain must follow parent pointers, allowing only nullified
    // gaps between consecutive finalized proposals.
    val committed_chain_is_connected = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        val certs = store_certificates.get(id)
        chain.indices().forall(i =>
            if (i == 0)
                and {
                    chain[i].parent == GENESIS_VIEW,
                    are_views_nullified(GENESIS_VIEW, chain[i].view, certs),
                }
            else
                and {
                    chain[i].parent == chain[i - 1].view,
                    are_views_nullified(chain[i - 1].view, chain[i].view, certs),
                }
        )
    })

    // With watermark-only finalization (no recursive ancestor walk),
    // committed payloads are not guaranteed to be consecutively parent-linked.
    // Instead, we verify the weaker property that every committed payload
    // is distinct (no duplicates).
    val committed_blocks_no_duplicates = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        chain.indices().forall(i =>
            chain.indices().forall(j =>
                (i == j) or (chain[i].view != chain[j].view)
            )
        )
    })

    // A correct replica only re-broadcasts certificates that it has stored locally.
    val certificates_require_sent_votes =
        sent_certificates
            .filter(cert => cert_ghost_sender(cert).in(CorrectSigs))
            .forall(cert =>
                CORRECT.exists(id => and {
                    sig_of(id) == cert_ghost_sender(cert),
                    store_certificates.get(id).exists(existing => same_certificate_subject(existing, cert)),
                })
            )

    val safe_invariants = all {
        no_notarize_equivocation,
        agreement,
        no_vote_equivocation_inv,
        no_nullification_and_finalization_in_the_same_view,
        validity,
        valid_last_finalized,
        notarized_consistency,
        unique_notarized_or_finalized_payload_per_view,
        finalize_vote_requires_notarization_cert,
        finalized_views_have_unique_proposal,
        committed_blocks_are_finalized,
        committed_chain_is_connected,
        committed_blocks_no_duplicates,
        certificates_require_sent_votes,
    }

    // Test invariants.

    val correct_nodes_sent_certificates_valid = sent_certificates
        .filter(cert => cert_ghost_sender(cert).in(CorrectSigs))
        .forall(cert => cert_signatures(cert).size() >= Q)

    val store_certificates_are_valid = CORRECT.forall(id => {
        val certs = store_certificates.get(id)
        certs.forall(cert => cert_signatures(cert).size() >= Q)
    })

    val certificates_are_valid = and {
        correct_nodes_sent_certificates_valid,
        store_certificates_are_valid
    }

    val test_invariants = all {
        safe_invariants,
        certificates_are_valid
    }

    // Examples.

    // Check this invariant to see an example of having a finalized payload.
    val block_example = not(CORRECT.exists(id => {
        ghost_committed_blocks.get(id).length() >= 1
    }))

    val finalized_example = not(CORRECT.exists(id => {
        replica_state.get(id).last_finalized >= FIRST_VIEW
    }))

    val notarized_example = not(CORRECT.exists(id => {
        replica_state.get(id).ghost_last_seen_notarization >= FIRST_VIEW
    }))

    val two_chained_blocks_example = not(CORRECT.exists(id => {
        ghost_committed_blocks.get(id).length() >= 2
    }))

    // Check this invariant to see an example of having at least one vote.
    val one_vote_example = CORRECT.forall(id => {
        and {
            store_notarize_votes.get(id).size() == 0,
            store_nullify_votes.get(id).size() == 0,
            store_finalize_votes.get(id).size() == 0,
        }
    })

    // Check this invariant to see an example of having a notarization certificate.
    val notarization_example = CORRECT.forall(id => {
        val certs = store_certificates.get(id)
        certs.filter(c => is_notarization_cert(c)).size()==0
    })

    // Check this invariant to see an example of having a finalization certificate.
    val finalization_example = CORRECT.forall(id => {
        val certs = store_certificates.get(id)
        certs.filter(c => is_finalization_cert(c)).size()==0
    })

    // Check this invariant to see an example of having a nullification certificate.
    val nullification_example = CORRECT.forall(id => {
        val certs = store_certificates.get(id)
        certs.filter(c => is_nullification_cert(c)).size()==0
    })

    // Check this invariant to see an example of a replica reaching view >= 2.
    val view = CORRECT.forall(id => {
        replica_state.get(id).view < 3
    })
}