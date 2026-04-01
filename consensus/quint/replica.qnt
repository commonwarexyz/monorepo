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

    // proposals sent by the replicas, correct and byzantine
    var sent_proposal: Set[(Signature, Proposal)]
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

    // history of received proposals
    var ghost_proposal: ReplicaId -> Set[Proposal]
    // sequence of finalized payloads observed by each correct replica
    var ghost_committed_blocks: ReplicaId -> List[Payload]
    // Replica-local deterministic certification policy from the application.
    var certify_policy: ReplicaId -> (Payload -> bool)
    // The last action taken (for IST assume_state).
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

    def has_sent_nullify(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, NullifyKind)
    }

    def has_sent_finalize(id: ReplicaId, view: ViewNumber): bool = {
        has_sent_vote(id, view, FinalizeKind)
    }

    def has_participated_in_view(id: ReplicaId, view: ViewNumber): bool = or {
        sent_notarize_votes.exists(v => v.sig == sig_of(id) and v.proposal.view == view),
        sent_nullify_votes.exists(v => v.sig == sig_of(id) and v.view == view),
        sent_finalize_votes.exists(v => v.sig == sig_of(id) and v.proposal.view == view),
        sent_proposal.exists(((s, p)) => s == sig_of(id) and p.view == view),
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
    pure def construct_notarize(
        self: ReplicaState,
        view: ViewNumber,
        proposal: Proposal,
        is_verified: bool
    ): Option[Proposal] = {
        if (self.broadcast_notarize.get(view) or self.broadcast_nullify.get(view))
            None
        else if (not(is_verified))
            None
        else
            Some(proposal)
    }

    // Returns true if a nullify vote is not blocked by a prior finalize.
    pure def construct_nullify(
        self: ReplicaState,
        view: ViewNumber
    ): bool = {
        not(self.broadcast_finalize.get(view))
    }

    // Returns Some(proposal) if a finalize vote should be constructed.
    // The proposal_conflicted parameter maps to !has_unequivocated_proposal()
    // in the implementation. The is_certified parameter represents the result
    // of application-level certification (asynchronous in the implementation,
    // atomic here).
    pure def construct_finalize(
        self: ReplicaState,
        view: ViewNumber,
        proposal: Proposal,
        proposal_conflicted: bool,
        is_certified: bool
    ): Option[Proposal] = {
        if (self.broadcast_finalize.get(view) or self.broadcast_nullify.get(view))
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
        if (self.timeout_reason.get(view) == None)
            {
                ...self,
                timeout_reason: self.timeout_reason.set(view, Some(reason))
            }
        else
            self
    }

    pure def mark_vote_broadcast(self: ReplicaState, view: ViewNumber, kind: Kind): ReplicaState = {
        if (kind == NotarizeKind)
            {
                ...self,
                broadcast_notarize: self.broadcast_notarize.set(view, true)
            }
        else if (kind == NullifyKind)
            {
                ...self,
                broadcast_nullify: self.broadcast_nullify.set(view, true)
            }
        else
            {
                ...self,
                broadcast_finalize: self.broadcast_finalize.set(view, true)
            }
    }

    pure def mark_certificate_broadcast(self: ReplicaState, cert: Certificate): ReplicaState = {
        match (cert) {
            | Notarization(n) => {
                ...self,
                broadcast_notarization: self.broadcast_notarization.set(n.proposal.view, true)
            }
            | Nullification(n) => {
                ...self,
                broadcast_nullification: self.broadcast_nullification.set(n.view, true)
            }
            | Finalization(f) => {
                ...self,
                broadcast_finalization: self.broadcast_finalization.set(f.proposal.view, true)
            }
        }
    }

    pure def remember_certificate(self: ReplicaState, cert: Certificate): ReplicaState = {
        match (cert) {
            | Notarization(n) => {
                if (is_some(self.notarization.get(n.proposal.view)))
                    self
                else
                    {
                        ...self,
                        notarization: self.notarization.set(n.proposal.view, Some(n))
                    }
            }
            | Nullification(n) => {
                if (is_some(self.nullification.get(n.view)))
                    self
                else
                    {
                        ...self,
                        nullification: self.nullification.set(n.view, Some(n))
                    }
            }
            | Finalization(f) => {
                if (is_some(self.finalization.get(f.proposal.view)))
                    self
                else
                    {
                        ...self,
                        finalization: self.finalization.set(f.proposal.view, Some(f))
                    }
            }
        }
    }

    pure def observe_certificate(self: ReplicaState, cert: Certificate, rebroadcast: bool): ReplicaState = {
        val remembered = remember_certificate(self, cert)
        if (rebroadcast)
            mark_certificate_broadcast(remembered, cert)
        else
            remembered
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

    pure def list_contains_payload(chain: List[Payload], payload: Payload): bool = {
        chain.indices().exists(i => chain[i] == payload)
    }

    pure def finalized_payload_at(
          view: ViewNumber,
          certificates: Set[Certificate]
      ): Option[Payload] = {
          val payloads =
              certificates.fold(Set(), (acc, c) =>
                  if (is_finalization_cert(c) and cert_view(c) == view)
                      match (cert_proposal(c)) {
                          | Some(p) => acc.union(Set(p.payload))
                          | None => acc
                      }
                  else
                      acc
              )

          if (payloads.size() == 1)
              payloads.fold(None, (_acc, p) => Some(p))
          else
              None
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
                  | None => self.certified.get(parent_view)
              }
      }

    // Certification is deterministic and may depend on replica id.
    def can_certify(id: ReplicaId, payload: Payload): bool = {
        certify_policy.get(id).get(payload)
    }

    // Enter a new view, unless it is older than the current view or outside modeled bounds.
    pure def enter_view(self: ReplicaState, new_view: ViewNumber): ReplicaState = {
        if (not(VIEWS.contains(new_view)) or self.view >= new_view)
            self
        else
            {
                ...self,
                view: new_view,
                propose_sent: false,
                broadcast_notarize: self.broadcast_notarize,
                broadcast_nullify: self.broadcast_nullify,
                broadcast_finalize: self.broadcast_finalize,
                broadcast_notarization: self.broadcast_notarization,
                broadcast_nullification: self.broadcast_nullification,
                broadcast_finalization: self.broadcast_finalization,
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
        } else if (self.broadcast_finalize.get(view)) {
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
                    ...mark_vote_broadcast(
                        remember_timeout_reason(self, view, timeout_reason),
                        view,
                        NullifyKind
                    ),
                    leader_timeout: if (leader_expired) self.leader_timeout.set(view, Some(true)) else self.leader_timeout,
                    certification_timeout: if (advance_expired) self.certification_timeout.set(view, Some(true)) else self.certification_timeout,
                    ghost_sent_votes: self.ghost_sent_votes.setBy(view, old => old.append(NullifyKind))
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
        else if (self.broadcast_finalize.get(view))
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
                    ...mark_vote_broadcast(
                        remember_timeout_reason(self, view, reason),
                        view,
                        NullifyKind
                    ),
                    leader_timeout: self.leader_timeout.set(view, None),
                    certification_timeout: self.certification_timeout.set(view, None),
                    ghost_sent_votes: self.ghost_sent_votes.setBy(view, old => old.append(NullifyKind))
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
        else if (self.broadcast_finalize.get(view))
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
                    ...mark_vote_broadcast(
                        remember_timeout_reason(
                            fire_all_timers(self, view),
                            view,
                            LeaderNullifyReason
                        ),
                        view,
                        NullifyKind
                    ),
                    ghost_sent_votes: self.ghost_sent_votes.setBy(view, old => old.append(NullifyKind))
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
        val default_payload_policy = AllPayloads.mapBy(_ => true)
        val default_certify_policy = Replicas.mapBy(_ => default_payload_policy)
        initWithLeaderAndCertify(l, default_certify_policy)
    }

    action initWithLeaderAndCertify(
        l: ViewNumber -> ReplicaId,
        certify: ReplicaId -> (Payload -> bool)
    ): bool = {
        all {
            replica_state' = CORRECT.mapBy(id => {
                view: FIRST_VIEW,
                ghost_last_seen_notarization: GENESIS_VIEW,
                last_finalized: GENESIS_VIEW,
                broadcast_notarize: VIEWS.mapBy(_ => false),
                broadcast_nullify: VIEWS.mapBy(_ => false),
                broadcast_finalize: VIEWS.mapBy(_ => false),
                broadcast_notarization: VIEWS.mapBy(_ => false),
                broadcast_nullification: VIEWS.mapBy(_ => false),
                broadcast_finalization: VIEWS.mapBy(_ => false),
                proposal: VIEWS.union(Set(GENESIS_VIEW)).mapBy(_ => None),
                timeout_reason: VIEWS.mapBy(_ => None),
                notarization: VIEWS.mapBy(_ => None),
                nullification: VIEWS.mapBy(_ => None),
                finalization: VIEWS.mapBy(_ => None),
                leader_proposal: VIEWS.union(Set(GENESIS_VIEW)).mapBy(_ => None),
                leader_proposal_conflicted: VIEWS.union(Set(GENESIS_VIEW)).mapBy(_ => false),
                certify: VIEWS.mapBy(_ => None),
                certified: VIEWS.mapBy(_ => None),
                propose_sent: false,
                leader_timeout: VIEWS.mapBy(_ => Some(false)),
                certification_timeout: VIEWS.mapBy(_ => Some(false)),
                ghost_sent_votes: VIEWS.mapBy(_ => List())
            }),
            sent_proposal' = Set(),
            sent_notarize_votes' = Set(),
            sent_nullify_votes' = Set(),
            sent_finalize_votes' = Set(),
            sent_certificates' = Set(),
            store_notarize_votes' = CORRECT.mapBy(_ => Set()),
            store_nullify_votes' = CORRECT.mapBy(_ => Set()),
            store_finalize_votes' = CORRECT.mapBy(_ => Set()),
            store_certificates' = CORRECT.mapBy(_ => Set()),
            ghost_committed_blocks' = CORRECT.mapBy(_ => List()),
            ghost_proposal' = CORRECT.mapBy(_ => Set()),
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
                lastAction' = "byzantine",
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
            not(self.broadcast_nullify.get(self.view)),
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
                    val notarize_votes = sent_notarize_votes
                    all {
                        notarize_votes != Set(),
                        nondet vote = notarize_votes.oneOf()
                        on_notarize(id, vote)
                    }
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
                    sent_certificates != Set(),
                    nondet cert = oneOf(sent_certificates)
                    on_certificate(id, cert)
                },
            }
        }
    }

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
            store_nullify
        )
        all {
            id == leader.get(self.view),
            not(self.propose_sent),
            not(self.broadcast_nullify.get(self.view)),
            sent_proposal' = if (proposal_ok)
                sent_proposal.union(Set((sig_of(id), proposal)))
              else
                sent_proposal,
            sent_notarize_votes' = if (proposal_ok)
                sent_notarize_votes.union(Set({ proposal: proposal, sig: sig_of(id) }))
              else
                sent_notarize_votes,
            sent_nullify_votes' = if (proposal_ok) sent_nullify_votes else timer.next_sent_nullify,
            sent_finalize_votes' = sent_finalize_votes,
            store_notarize_votes' = if (proposal_ok)
                store_notarize_votes.set(id, store_notarize.union(Set({ proposal: proposal, sig: sig_of(id) })))
              else
                store_notarize_votes,
            store_nullify_votes' = if (proposal_ok)
                store_nullify_votes
              else
                store_nullify_votes.set(id, timer.next_stored_nullify),
            store_finalize_votes' = store_finalize_votes,
            replica_state' = replica_state.set(id,
                if (proposal_ok) {
                    ...mark_vote_broadcast(
                        observe_leader_proposal(
                            record_local_proposal(self, proposal),
                            proposal
                        ),
                        self.view,
                        NotarizeKind
                    ),
                    propose_sent: true,
                    leader_timeout: self.leader_timeout.set(self.view, None),
                    ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NotarizeKind))
                } else
                    timer.next_self
            ),
            ghost_proposal' = if (proposal_ok)
                ghost_proposal.setBy(id, old => old.union(Set(proposal)))
              else
                ghost_proposal,

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
        val timer = forced_timeout_expired(
            self,
            id,
            view,
            InvalidProposalReason,
            sent_nullify_votes,
            store_nullify
        )
        val can_process_as_proposal = and {
            is_leader_vote,
            view == self.view,
            not(self.broadcast_notarize.get(self.view)),
            not(self.broadcast_nullify.get(view)),
        }

        if (proposal_conflicted) {
            all {
                sent_proposal' = sent_proposal,
                sent_notarize_votes' = sent_notarize_votes,
                sent_nullify_votes' = sent_nullify_votes,
                sent_finalize_votes' = sent_finalize_votes,
                sent_certificates' = sent_certificates,
                store_notarize_votes' = store_notarize_votes,
                store_nullify_votes' = store_nullify_votes,
                store_finalize_votes' = store_finalize_votes,
                store_certificates' = store_certificates,
                replica_state' = replica_state,
                ghost_proposal' = ghost_proposal,
                ghost_committed_blocks' = ghost_committed_blocks,
                leader' = leader,
                certify_policy' = certify_policy,
                lastAction' = "on_notarize"
            }
        } else if (can_process_as_proposal) {
            // Proposal processing: validate the leader's proposal and vote
            val notarize_ok = is_some(construct_notarize(self, view, proposal, payload_ok and parent_ok))
            all {
                sent_notarize_votes' = if (notarize_ok)
                    sent_notarize_votes.union(Set({ proposal: proposal, sig: sig_of(id) }))
                  else
                    sent_notarize_votes,
                sent_nullify_votes' = if (notarize_ok) sent_nullify_votes else timer.next_sent_nullify,
                sent_finalize_votes' = sent_finalize_votes,
                store_notarize_votes' = if (notarize_ok)
                    store_notarize_votes.set(id, store_notarize.union(Set(vote, { proposal: proposal, sig: sig_of(id) })))
                  else
                    store_notarize_votes,
                store_nullify_votes' = if (notarize_ok)
                    store_nullify_votes
                  else
                    store_nullify_votes.set(id, timer.next_stored_nullify),
                store_finalize_votes' = store_finalize_votes,
                replica_state' = replica_state.set(id,
                    if (notarize_ok) {
                        ...mark_vote_broadcast(
                            observe_leader_proposal(
                                observe_round_proposal(self, proposal, false),
                                proposal
                            ),
                            self.view,
                            NotarizeKind
                        ),
                        leader_timeout: self.leader_timeout.set(self.view, None),
                        ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(NotarizeKind))
                    } else
                        observe_leader_proposal(
                            observe_round_proposal(timer.next_self, proposal, false),
                            proposal
                        )
                ),

                ghost_proposal' = ghost_proposal.setBy(id, old => old.union(Set(proposal))),

                // unchanged
                sent_proposal' = sent_proposal,
                sent_certificates' = sent_certificates,
                store_certificates' = store_certificates,
                leader' = leader,
                ghost_committed_blocks' = ghost_committed_blocks,
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

            val maybe_not_cert = create_notarization(id, proposal, new_store_notarize)
            val can_cert = can_certify(id, proposal.payload)
            val is_new_cert = not(had_notarization)
            val should_broadcast_not = not(self.broadcast_notarization.get(view))
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
            all {
                is_none(maybe_not_cert) or now_notarized,
                store_notarize_votes' = store_notarize_votes.set(id, new_store_notarize),
                store_certificates' = match maybe_not_cert {
                    | Some(cert) => if (is_new_cert)
                        store_certificates.setBy(id, old => old.union(Set(Notarization(cert))))
                      else
                        store_certificates
                    | None => store_certificates
                },
                sent_certificates' = match maybe_not_cert {
                    | Some(cert) => if (should_broadcast_not)
                        sent_certificates.union(Set(Notarization(cert)))
                      else
                        sent_certificates
                    | None => sent_certificates
                },
                sent_notarize_votes' = sent_notarize_votes,
                sent_nullify_votes' = effect.next_sent_nullify,
                sent_finalize_votes' = effect.next_sent_finalize,
                store_nullify_votes' = store_nullify_votes.set(id, effect.next_stored_nullify),
                store_finalize_votes' = store_finalize_votes.set(id, effect.next_stored_finalize),
                replica_state' = replica_state.set(id, effect.next_self),
                ghost_committed_blocks' = ghost_committed_blocks,

                // unchanged
                sent_proposal' = sent_proposal,
                leader' = leader,
                ghost_proposal' = ghost_proposal,
                certify_policy' = certify_policy,
                lastAction' = "on_notarize"
            }
        }
    }

    // Upon receiving votes for finalize(c, v):
    // - collect votes
    // - on 2f+1: create finalization cert and enter v+1
    action on_finalize(id: ReplicaId, vote: FinalizeVote): bool = all {
        val store_finalize = store_finalize_votes.get(id)
        val self = replica_state.get(id)
        val proposal = vote.proposal
        all {
            // Matches interesting() in implementation: min_active = last_finalized - activity_timeout
            proposal.view >= self.last_finalized - ACTIVITY_TIMEOUT,
            proposal.view <= self.view + 1,
            val conflict = has_leader_proposal_conflict(self, proposal)
            val new_store_finalize = store_finalize.union(Set(vote))
            val maybe_fin_cert = if (conflict) None else create_finalization(id, proposal, new_store_finalize)
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
            sent_proposal' = sent_proposal,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
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
        val store_nullify = store_nullify_votes.get(id)
        val self = replica_state.get(id)
        all {
            // Matches interesting() in implementation: min_active = last_finalized - activity_timeout
            vote.view >= self.last_finalized - ACTIVITY_TIMEOUT,
            vote.view <= self.view + 1,
            val new_nullify_votes = store_nullify.union(Set(vote))
            val leader_nullify_trigger = and {
                id != leader.get(vote.view),
                not(self.broadcast_nullify.get(vote.view)),
                vote.sig == sig_of(leader.get(vote.view)),
            }
            val timer = if (leader_nullify_trigger)
                leader_nullify_expired(self, id, vote.view, sent_nullify_votes, new_nullify_votes)
            else {
                next_self: self,
                next_sent_nullify: sent_nullify_votes,
                next_stored_nullify: new_nullify_votes
            }
            val certs = store_certificates.get(id)
            val had_nullification = certs.exists(c => is_nullification_cert(c) and cert_view(c) == vote.view)
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
            sent_proposal' = sent_proposal,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
            certify_policy' = certify_policy,
            lastAction' = "on_nullify"
        }
    }

    // Handle certificate message.
    action on_certificate(id: ReplicaId, cert: Certificate): bool = all {
        val certs = store_certificates.get(id)
        all {
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
                        store_notarize_votes' = store_notarize_votes,
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
            sent_proposal' = sent_proposal,
            leader' = leader,
            ghost_proposal' = ghost_proposal,
            certify_policy' = certify_policy,
            lastAction' = "on_certificate"
        }
    }

    pure def notarize_effect(
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
        val cert_payload_val = notarization.proposal.payload
        val seen_notarization = if (self.ghost_last_seen_notarization < cert_view_num) cert_view_num else self.ghost_last_seen_notarization
        val cert_prop = notarization.proposal
        val proposal_conflicted = has_leader_proposal_conflict(self, cert_prop)
        val should_broadcast = not(self.broadcast_notarization.get(cert_view_num))
        val timer = forced_timeout_expired(
            self,
            id,
            cert_view_num,
            FailedCertificationReason,
            sent_nullify_votes,
            stored_nullify
        )
        val is_certified = and {
            can_cert,
            self.certified.get(cert_view_num) == None,
        }
        val finalize_result = construct_finalize(self, cert_view_num, cert_prop, proposal_conflicted, is_certified)
        val can_send_nullify = and {
            not(can_cert),
            self.view == cert_view_num,
            construct_nullify(self, cert_view_num),
            // NOTE: Model simplification: suppress nullify retries (single-shot nullify per view).
            not(self.broadcast_nullify.get(cert_view_num)),
        }
        val observed = observe_certificate(
            observe_leader_proposal(observe_round_proposal(self, cert_prop, true), cert_prop),
            cert,
            should_broadcast
        )

        if (is_some(finalize_result))
            {
                next_self: enter_view({
                    ...mark_vote_broadcast(observed, cert_view_num, FinalizeKind),
                    // clear_deadlines: matches Rust round.clear_deadlines()
                    leader_timeout: self.leader_timeout.set(cert_view_num, None),
                    certification_timeout: self.certification_timeout.set(cert_view_num, None),
                    ghost_last_seen_notarization: seen_notarization,
                    certify: self.certify.set(cert_view_num, Some(true)),
                    certified: self.certified.put(cert_view_num, Some(cert_payload_val)),
                    ghost_sent_votes: self.ghost_sent_votes.setBy(cert_view_num, old => old.append(FinalizeKind))
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
                    certify: self.certify.set(cert_view_num, Some(true)),
                    certified: self.certified.put(cert_view_num, Some(cert_payload_val)),
                }, cert_view_num + 1),
                next_sent_nullify: sent_nullify_votes,
                next_sent_finalize: sent_finalize_votes,
                next_stored_nullify: stored_nullify,
                next_stored_finalize: stored_finalize,
            }
        else if (can_send_nullify)
            {
                next_self: {
                    ...observe_certificate(
                        observe_leader_proposal(
                            observe_round_proposal(timer.next_self, cert_prop, true),
                            cert_prop
                        ),
                        cert,
                        should_broadcast
                    ),
                    certify: timer.next_self.certify.set(cert_view_num, Some(false)),
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
        val should_broadcast_notarization = not(self.broadcast_notarization.get(notarization.proposal.view))
        val effect = notarize_effect(
            self, id, notarization,
            can_certify(id, notarization.proposal.payload),
            sent_nullify_votes, sent_finalize_votes,
            store_nullify_votes.get(id), store_finalize_votes.get(id)
        )
        all {
            notarization.signatures.size() >= Q,
            store_certificates' = if (is_new_cert)
                store_certificates.setBy(id, old => old.union(Set(cert)))
              else
                store_certificates,
            sent_certificates' = if (should_broadcast_notarization)
                sent_certificates.union(Set(cert))
              else
                sent_certificates,
            sent_notarize_votes' = sent_notarize_votes,
            sent_nullify_votes' = effect.next_sent_nullify,
            sent_finalize_votes' = effect.next_sent_finalize,
            store_nullify_votes' = store_nullify_votes.set(id, effect.next_stored_nullify),
            store_finalize_votes' = store_finalize_votes.set(id, effect.next_stored_finalize),
            replica_state' = replica_state.set(id, effect.next_self),
            ghost_committed_blocks' = ghost_committed_blocks,
        }
    }

    action _add_nullification(id: ReplicaId, nullification: NullificationCert, is_new_cert: bool, base_self: ReplicaState): bool = all {
        val cert: Certificate = Nullification(nullification)
        val cert_view_num = nullification.view
        val should_broadcast_nullification = not(base_self.broadcast_nullification.get(cert_view_num))
        all {
            nullification.signatures.size() >= Q,

            store_certificates' = if (is_new_cert)
                store_certificates.setBy(id, old => old.union(Set(cert)))
              else
                store_certificates,
            sent_certificates' = if (should_broadcast_nullification)
                sent_certificates.union(Set(cert))
              else
                sent_certificates,

            sent_notarize_votes' = sent_notarize_votes,
            sent_finalize_votes' = sent_finalize_votes,
            replica_state' = replica_state.set(
                id,
                enter_view(
                    observe_certificate(
                        cancel_all_timers(base_self, cert_view_num),
                        cert,
                        should_broadcast_nullification
                    ),
                    cert_view_num + 1
                )
            ),
            ghost_committed_blocks' = ghost_committed_blocks
        }
    }

    action _add_finalization(id: ReplicaId, finalization: FinalizationCert, is_new_cert: bool): bool = all {
        val self = replica_state.get(id)
        val cert: Certificate = Finalization(finalization)
        val should_broadcast_finalization = not(self.broadcast_finalization.get(finalization.proposal.view))
        val cert_view_num = finalization.proposal.view
        val cert_payload_val = finalization.proposal.payload
        val cert_prop = finalization.proposal
        val seen_notarization = if (self.ghost_last_seen_notarization < cert_view_num) cert_view_num else self.ghost_last_seen_notarization
        val newer = cert_view_num > self.last_finalized
        all {
            finalization.signatures.size() >= Q,

            store_certificates' = if (is_new_cert)
                store_certificates.setBy(id, old => old.union(Set(cert)))
              else
                store_certificates,
            sent_certificates' = if (should_broadcast_finalization)
                sent_certificates.union(Set(cert))
              else
                sent_certificates,
            ghost_committed_blocks' = if (is_new_cert and newer)
                ghost_committed_blocks.setBy(id, old => old.append(cert_payload_val))
              else
                ghost_committed_blocks,

            sent_notarize_votes' = sent_notarize_votes,
            sent_nullify_votes' = sent_nullify_votes,
            sent_finalize_votes' = sent_finalize_votes,
            replica_state' = replica_state.set(id,
                enter_view({
                    ...observe_certificate(
                        observe_leader_proposal(
                            observe_round_proposal(
                                cancel_all_timers(self, cert_view_num),
                                cert_prop, true
                            ),
                            cert_prop
                        ),
                        cert,
                        should_broadcast_finalization
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
            store_nullify_votes.get(id)
        )
        all {
            not(self.broadcast_nullify.get(self.view)),
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
            sent_proposal' = sent_proposal,
            sent_certificates' = sent_certificates,
            store_certificates' = store_certificates,
            leader' = leader,
            ghost_committed_blocks' = ghost_committed_blocks,
            ghost_proposal' = ghost_proposal,
            certify_policy' = certify_policy,
            lastAction' = "timeout"
        }
    }

    action byzantine_votes(
        sender: ReplicaId,
        view: ViewNumber,
        payload: Payload,
        parent_view: ViewNumber,
        kinds: Set[Kind]
    ): bool = all {
        sent_notarize_votes' = sent_notarize_votes.union(
            kinds.filter(k => k == NotarizeKind).map(_ => {
                proposal: {
                    view: view,
                    payload: payload,
                    parent: parent_view,
                },
                sig: sig_of(sender),
            })
        ),
        sent_nullify_votes' = sent_nullify_votes.union(
            kinds.filter(k => k == NullifyKind).map(_ => {
                view: view,
                sig: sig_of(sender),
            })
        ),
        sent_finalize_votes' = sent_finalize_votes.union(
            kinds.filter(k => k == FinalizeKind).map(_ => {
                proposal: {
                    view: view,
                    payload: payload,
                    parent: parent_view,
                },
                sig: sig_of(sender),
            })
        )
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

              nondet base = Set(NotarizeKind, NullifyKind, FinalizeKind).powerset().oneOf()
              nondet kind = Set(NotarizeKind, NullifyKind, FinalizeKind).oneOf()
              val kinds = base.union(Set(kind))
              byzantine_votes(sender, view, payload, parent_view, kinds)
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

        // Adversary may inject arbitrary proposal.
        all {
            nondet parent = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            nondet view = VIEWS.union(Set(GENESIS_VIEW)).oneOf()
            nondet sig = BYZANTINE.oneOf()
            nondet payload = AllPayloads.oneOf()
            val proposal = {
                view: view,
                payload: payload,
                parent: parent,
            }
            sent_proposal' = sent_proposal.union(Set((sig_of(sig), proposal))),
        }
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
        ghost_proposal' = ghost_proposal,
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

    def votes_seq_correct(votes: List[Kind]): bool = or {
        votes == List(),
        and {
            votes.length() == 1,
            or {
                votes[0] == NotarizeKind,
                votes[0] == NullifyKind,
                votes[0] == FinalizeKind,
            }
        },
        and {
            votes.length() == 2,
            votes[0] == NotarizeKind,
            or {
                votes[1] == NullifyKind,
                votes[1] == FinalizeKind,
            }
        }
    }

    // A correct replica cannot equivocate in a view.
    // Allowed patterns: notarize->finalize, notarize->nullify, single vote.
    val no_vote_equivocation_inv = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v => votes_seq_correct(self.ghost_sent_votes.get(v)))
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

    val no_proposal_equivocation = CORRECT.forall(id => {
        or {
            sig_of(id).in(ByzantineSigs),
            VIEWS.forall(v =>
                sent_proposal
                    .filter(((s, p)) => s == sig_of(id) and p.view == v)
                    .size() <= 1
            )
        }
    })

    val valid_last_finalized = CORRECT.forall(id => {
        val self = replica_state.get(id)
        self.last_finalized <= self.ghost_last_seen_notarization
    })

    val notarized_consistency = CORRECT.forall(id => {
        val self = replica_state.get(id)
        VIEWS.forall(v =>
            self.broadcast_notarize.get(v)
                iff self.ghost_sent_votes.get(v).indices().exists(i =>
                    self.ghost_sent_votes.get(v)[i] == NotarizeKind
                )
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

    // Upon finalization, the finalized payload must appear in the committed chain.
    val finalized_certificates_are_committed = CORRECT.forall(id => {
        val self = replica_state.get(id)
        val chain = ghost_committed_blocks.get(id)
        val certs = store_certificates.get(id)
        certs
            .filter(c => is_finalization_cert(c) and cert_view(c) <= self.last_finalized)
            .forall(c => option_has(cert_payload(c), b => list_contains_payload(chain, b)))
    })

    // With watermark-only finalization (no recursive ancestor walk),
    // committed payloads are not guaranteed to be consecutively parent-linked.
    // Instead, we verify the weaker property that every committed payload
    // is distinct (no duplicates).
    val committed_blocks_no_duplicates = CORRECT.forall(id => {
        val chain = ghost_committed_blocks.get(id)
        chain.indices().forall(i =>
            chain.indices().forall(j =>
                (i == j) or (chain[i] != chain[j])
            )
        )
    })

     def supporting_vote_sigs(cert: Certificate): Set[Signature] = {
        match (cert) {
            | Notarization(n) =>
                sent_notarize_votes
                    .filter(v => v.proposal == n.proposal)
                    .map(v => v.sig)

            | Nullification(n) =>
                sent_nullify_votes
                    .filter(v => v.view == n.view)
                    .map(v => v.sig)

            | Finalization(f) =>
                sent_finalize_votes
                    .filter(v => v.proposal == f.proposal)
                    .map(v => v.sig)
        }
    }

    val certificates_require_sent_votes =
        sent_certificates
            .filter(cert => cert_ghost_sender(cert).in(CorrectSigs))
            .forall(cert =>
                cert_signatures(cert).subseteq(supporting_vote_sigs(cert))
            )

    val safe_invariants = all {
        no_proposal_equivocation,
        agreement,
        no_vote_equivocation_inv,
        no_nullification_and_finalization_in_the_same_view,
        validity,
        valid_last_finalized,
        notarized_consistency,
        unique_notarized_or_finalized_payload_per_view,
        finalize_vote_requires_notarization_cert,
        finalized_views_have_unique_proposal,
        finalized_certificates_are_committed,
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
