// Bounded executable model for the UNO protocol in uno-protocol-spec.tex.
//
// The model has three finite abstractions:
//
// 1. uno_group checks one-, two-, and three-participant atomic publication, arbitrary
//    per-participant prepare outcomes, code-last abort and final-root repair interrupted like any
//    other write, independent M/T finalization, and arbitrary crash-surviving deletion subsets
//    after all participants are independently final.
// 2. uno_slot checks exact-root provenance at byte-cell granularity. Every non-durable write may
//    retain an arbitrary powerset of addressed cells. initBuggy uses generation-independent state
//    spellings and admits the concrete old-M + torn-B + torn-A reconstruction. initFixed uses the
//    R14 generation-colored state byte and excludes any final state whose guarded write was not
//    issued.
// 3. uno_composed joins those concerns for exactly two participants. It represents each R14 root
//    header as all 112 offset-indexed bytes, keeps the adjacent ring witness and representative
//    payload as separate byte maps, and derives recovery, finalization, unlink, and observations
//    from those disk images. Ordered provenance masks compose B, ordinary R, abort, and M/T writes;
//    joint cuts let both participant writes tear in the same crash. beginRecoveryBuggyGeneration
//    deliberately omits generation byte 15, while initBuggyPayload omits append-payload validation.
//
// A cell is an equivalence class of addressed bytes whose distinction matters to decoding. The
// four CRC cells are separate because an arbitrary subset may take different checksum bytes from
// different writes. Choosing Cells.powerset().oneOf() is therefore a finite abstraction of the
// paper's arbitrary-subset addressed-byte fault model, not a prefix approximation.
//
// This is bounded model checking, not an unbounded proof, an ext4 model, or implementation
// refinement. The LaTeX argument supplies the unbounded proof obligations; concrete crash tests
// must establish that codecs and backend I/O refine these actions. In particular, group-level
// symbolic root classes rely on the byte-level provenance property checked separately by uno_slot.

module uno_group {
  type GLocal =
      GOld
    | GPrepared
    | GTornPrepare
    | GTornAbort
    | GAbortBody
    | GAborted
    | GTornFinal
    | GMaterialized
    | GTombstone
    | GMissing

  type GObservation = GNoObservation | GOldObservation | GNewObservation | GAbsentObservation
  type GOperation = GAppend | GRewind | GRemove
  type GGoal = GNoGoal | GRecoverOld | GRecoverNew
  type GPhase = GIdle | GPreparing | GActive | GRecovering | GFinalizing | GFinalized | GObserved
  type GWriteOutcome = GKeepWrite | GTornWrite | GExactWrite

  pure val AllParticipants: Set[int] = Set(0, 1, 2)
  pure val ParticipantSets: Set[Set[int]] = Set(Set(0), Set(0, 1), Set(0, 1, 2))
  pure val RetainedOperations: Set[GOperation] = Set(GAppend, GRewind)
  pure val WriteOutcomes: Set[GWriteOutcome] = Set(GKeepWrite, GTornWrite, GExactWrite)

  var members: Set[int]
  var removals: Set[int]
  var operations: int -> GOperation
  var local: int -> GLocal
  var linkOk: int -> bool
  var payloadOk: int -> bool
  var preparePending: Set[int]
  var prepareCrashed: bool
  var needsAbort: int -> bool
  var abortBodySynced: int -> bool
  var unlinkIssued: Set[int]
  var truncated: int -> bool
  var acknowledged: bool
  var decisionEstablished: bool
  var goal: GGoal
  var phase: GPhase
  var observation: int -> GObservation

  pure def oldAuthority(s: GLocal): bool = s == GOld or s == GAborted

  pure def retainedFinal(p: int, states: int -> GLocal, removed: Set[int]): bool =
    if (p.in(removed))
      states.get(p) == GTombstone or states.get(p) == GMissing
    else
      states.get(p) == GMaterialized

  // GTornFinal denotes a bytewise partial M/T overwrite whose adjacent prepared witness remains
  // exact. Before an exact A guard exists, a torn abort is likewise provisional: if its untouched
  // witness ring and payload validate, recovery may resolve the still-unacknowledged batch to new.
  // The slot model separately checks that an unissued generation-colored final guard cannot be
  // forged and that an exact A guard is published only over predecessor-equivalent bytes.
  pure def transitionRecognizable(s: GLocal): bool =
    s == GPrepared or s == GTornAbort or s == GAbortBody or
      s == GTornFinal or s == GMaterialized or s == GTombstone

  pure def completeTransitionRing(
      ps: Set[int],
      states: int -> GLocal,
      links: int -> bool
  ): bool = ps.forall(p => transitionRecognizable(states.get(p)) and links.get(p))

  pure def completePreparedRing(
      ps: Set[int],
      states: int -> GLocal,
      links: int -> bool,
      payload: int -> bool
  ): bool = completeTransitionRing(ps, states, links) and ps.forall(p => payload.get(p))

  // A final root is useful as a group certificate only while the complete group-bound witness
  // ring remains traversable. Once names are unlinked, independently final roots replace the ring.
  pure def hasReachableFinalCertificate(
      ps: Set[int],
      states: int -> GLocal,
      links: int -> bool
  ): bool = completeTransitionRing(ps, states, links) and
    ps.exists(p => states.get(p) == GMaterialized or states.get(p) == GTombstone)

  pure def independentlyFinal(ps: Set[int], states: int -> GLocal, removed: Set[int]): bool =
    ps.forall(p => retainedFinal(p, states, removed))

  pure def diskProvesNew(
      ps: Set[int],
      states: int -> GLocal,
      links: int -> bool,
      payload: int -> bool,
      removed: Set[int]
  ): bool = or {
    completePreparedRing(ps, states, links, payload),
    hasReachableFinalCertificate(ps, states, links),
    independentlyFinal(ps, states, removed),
  }

  pure def expectedNewObservation(p: int, removed: Set[int]): GObservation =
    if (p.in(removed)) GAbsentObservation else GNewObservation

  pure def decodeObservation(
      p: int,
      ps: Set[int],
      states: int -> GLocal,
      removed: Set[int]
  ): GObservation =
    if (not(p.in(ps)))
      GNoObservation
    else if (p.in(removed) and
        (states.get(p) == GTombstone or states.get(p) == GMissing))
      GAbsentObservation
    else if (not(p.in(removed)) and states.get(p) == GMaterialized)
      GNewObservation
    else if (oldAuthority(states.get(p)))
      GOldObservation
    else
      GNoObservation

  action init = {
    nondet chosenMembers = ParticipantSets.oneOf()
    nondet chosenRemovals = chosenMembers.powerset().oneOf()
    nondet retained0 = RetainedOperations.oneOf()
    nondet retained1 = RetainedOperations.oneOf()
    nondet retained2 = RetainedOperations.oneOf()
    val retainedOps = Map(0 -> retained0, 1 -> retained1, 2 -> retained2)
    val chosenOps = AllParticipants.mapBy(p =>
      if (p.in(chosenRemovals)) GRemove else retainedOps.get(p))
    all {
      members' = chosenMembers,
      removals' = chosenRemovals,
      operations' = chosenOps,
      local' = AllParticipants.mapBy(_ => GOld),
      linkOk' = AllParticipants.mapBy(_ => false),
      payloadOk' = AllParticipants.mapBy(p => chosenOps.get(p) != GAppend),
      preparePending' = Set(),
      prepareCrashed' = false,
      needsAbort' = AllParticipants.mapBy(_ => false),
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      unlinkIssued' = Set(),
      truncated' = AllParticipants.mapBy(_ => false),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = GNoGoal,
      phase' = GIdle,
      observation' = AllParticipants.mapBy(_ => GNoObservation),
    }
  }

  // Reachable cut points used to exhaust deeper recovery subprotocols at practical BMC depths.
  // They do not replace init: each is the projection of a prefix reachable from init.
  action initRejected = {
    nondet chosenMembers = ParticipantSets.oneOf()
    nondet chosenRemovals = chosenMembers.powerset().oneOf()
    nondet retained0 = RetainedOperations.oneOf()
    nondet retained1 = RetainedOperations.oneOf()
    nondet retained2 = RetainedOperations.oneOf()
    val retainedOps = Map(0 -> retained0, 1 -> retained1, 2 -> retained2)
    val chosenOps = AllParticipants.mapBy(p =>
      if (p.in(chosenRemovals)) GRemove else retainedOps.get(p))
    all {
      members' = chosenMembers,
      removals' = chosenRemovals,
      operations' = chosenOps,
      local' = AllParticipants.mapBy(p =>
        if (p.in(chosenMembers)) GTornPrepare else GOld),
      linkOk' = AllParticipants.mapBy(_ => false),
      payloadOk' = AllParticipants.mapBy(p => chosenOps.get(p) != GAppend),
      preparePending' = Set(),
      prepareCrashed' = false,
      needsAbort' = AllParticipants.mapBy(p => p.in(chosenMembers)),
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      unlinkIssued' = Set(),
      truncated' = AllParticipants.mapBy(_ => false),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = GRecoverOld,
      phase' = GRecovering,
      observation' = AllParticipants.mapBy(_ => GNoObservation),
    }
  }

  action initDecided = {
    nondet chosenMembers = ParticipantSets.oneOf()
    nondet chosenRemovals = chosenMembers.powerset().oneOf()
    nondet retained0 = RetainedOperations.oneOf()
    nondet retained1 = RetainedOperations.oneOf()
    nondet retained2 = RetainedOperations.oneOf()
    val retainedOps = Map(0 -> retained0, 1 -> retained1, 2 -> retained2)
    val chosenOps = AllParticipants.mapBy(p =>
      if (p.in(chosenRemovals)) GRemove else retainedOps.get(p))
    all {
      members' = chosenMembers,
      removals' = chosenRemovals,
      operations' = chosenOps,
      local' = AllParticipants.mapBy(p => if (p.in(chosenMembers)) GPrepared else GOld),
      linkOk' = AllParticipants.mapBy(p => p.in(chosenMembers)),
      payloadOk' = AllParticipants.mapBy(_ => true),
      preparePending' = Set(),
      prepareCrashed' = false,
      needsAbort' = AllParticipants.mapBy(p => p.in(chosenMembers)),
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      unlinkIssued' = Set(),
      truncated' = AllParticipants.mapBy(_ => false),
      acknowledged' = false,
      decisionEstablished' = true,
      goal' = GRecoverNew,
      phase' = GRecovering,
      observation' = AllParticipants.mapBy(_ => GNoObservation),
    }
  }

  action initFinalized = {
    nondet chosenMembers = ParticipantSets.oneOf()
    nondet chosenRemovals = chosenMembers.powerset().oneOf()
    nondet retained0 = RetainedOperations.oneOf()
    nondet retained1 = RetainedOperations.oneOf()
    nondet retained2 = RetainedOperations.oneOf()
    val retainedOps = Map(0 -> retained0, 1 -> retained1, 2 -> retained2)
    val chosenOps = AllParticipants.mapBy(p =>
      if (p.in(chosenRemovals)) GRemove else retainedOps.get(p))
    all {
      members' = chosenMembers,
      removals' = chosenRemovals,
      operations' = chosenOps,
      local' = AllParticipants.mapBy(p =>
        if (not(p.in(chosenMembers)))
          GOld
        else if (p.in(chosenRemovals))
          GTombstone
        else
          GMaterialized),
      linkOk' = AllParticipants.mapBy(p => p.in(chosenMembers)),
      payloadOk' = AllParticipants.mapBy(_ => true),
      preparePending' = Set(),
      prepareCrashed' = false,
      needsAbort' = AllParticipants.mapBy(_ => false),
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      unlinkIssued' = Set(),
      truncated' = AllParticipants.mapBy(_ => false),
      acknowledged' = false,
      decisionEstablished' = true,
      goal' = GNoGoal,
      phase' = GFinalized,
      observation' = AllParticipants.mapBy(_ => GNoObservation),
    }
  }

  action startPrepare = all {
    phase == GIdle,
    phase' = GPreparing,
    preparePending' = members,
    prepareCrashed' = false,
    members' = members,
    removals' = removals,
    operations' = operations,
    local' = local,
    linkOk' = linkOk,
    payloadOk' = payloadOk,
    needsAbort' = needsAbort,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    truncated' = truncated,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    observation' = observation,
  }

  // Once the first participant is sampled as a crash outcome, no later barrier may complete in
  // that execution. Other pending participants can still independently retain any write subset.
  action tearPrepare = {
    nondet p = preparePending.oneOf()
    nondet outcome = Set(GOld, GPrepared, GTornPrepare).oneOf()
    nondet linkSurvives = Set(false, true).oneOf()
    nondet payloadSurvives = Set(false, true).oneOf()
    all {
      phase == GPreparing,
      local' = local.set(p, outcome),
      linkOk' = linkOk.set(p, linkSurvives),
      payloadOk' = payloadOk.set(p,
        if (operations.get(p) == GAppend)
          payloadOk.get(p) or payloadSurvives
        else
          true),
      preparePending' = preparePending.exclude(Set(p)),
      prepareCrashed' = true,
      needsAbort' = needsAbort.set(p, true),
      members' = members,
      removals' = removals,
      operations' = operations,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation' = observation,
    }
  }

  action syncPrepare = {
    nondet p = preparePending.oneOf()
    all {
      phase == GPreparing,
      not(prepareCrashed),
      local' = local.set(p, GPrepared),
      linkOk' = linkOk.set(p, true),
      payloadOk' = payloadOk.set(p, true),
      preparePending' = preparePending.exclude(Set(p)),
      needsAbort' = needsAbort.set(p, true),
      members' = members,
      removals' = removals,
      operations' = operations,
      prepareCrashed' = prepareCrashed,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation' = observation,
    }
  }

  action acknowledge = all {
    phase == GPreparing,
    preparePending == Set(),
    not(prepareCrashed),
    members.forall(p => local.get(p) == GPrepared and linkOk.get(p) and payloadOk.get(p)),
    acknowledged' = true,
    decisionEstablished' = true,
    phase' = GActive,
    preparePending' = preparePending,
    members' = members,
    removals' = removals,
    operations' = operations,
    local' = local,
    linkOk' = linkOk,
    payloadOk' = payloadOk,
    prepareCrashed' = prepareCrashed,
    needsAbort' = needsAbort,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    truncated' = truncated,
    goal' = GNoGoal,
    observation' = observation,
  }

  // Rewind is a logical resize to a retained prefix. A physical truncate can become durable for
  // any subset of rewind participants, but only after the complete group decision exists.
  action truncateRewind = {
    nondet p = members.oneOf()
    all {
      decisionEstablished,
      operations.get(p) == GRewind,
      not(truncated.get(p)),
      members' = members,
      removals' = removals,
      operations' = operations,
      local' = local,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = preparePending,
      prepareCrashed' = prepareCrashed,
      needsAbort' = needsAbort,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated.set(p, true),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation' = observation,
    }
  }

  // Recovery uses only disk evidence. Volatile barrier credit and an unfinished prepare join are
  // discarded. The monotone decisionEstablished variable is a specification ghost, not an input.
  action beginRecovery = {
    val provesNew = diskProvesNew(members, local, linkOk, payloadOk, removals)
    all {
      phase != GRecovering,
      phase != GObserved,
      unlinkIssued == Set(),
      goal' = if (provesNew) GRecoverNew else GRecoverOld,
      phase' = GRecovering,
      preparePending' = Set(),
      prepareCrashed' = false,
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      decisionEstablished' = (decisionEstablished or provesNew),
      members' = members,
      removals' = removals,
      operations' = operations,
      local' = local,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      needsAbort' = needsAbort,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      observation' = observation,
    }
  }

  // The first abort phase writes all non-guard A bytes. An interrupted write can leave none, some,
  // or all of those bytes. It never grants the volatile barrier credit needed to issue the guard.
  action interruptAbortBody = {
    nondet p = members.oneOf()
    nondet outcome = WriteOutcomes.oneOf()
    val nextState = if (outcome == GKeepWrite)
      local.get(p)
    else if (outcome == GTornWrite)
      GTornAbort
    else
      GAbortBody
    all {
      phase == GRecovering,
      goal == GRecoverOld,
      needsAbort.get(p),
      local.get(p) != GMissing,
      local' = local.set(p, nextState),
      phase' = GActive,
      goal' = GNoGoal,
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = Set(),
      prepareCrashed' = false,
      needsAbort' = needsAbort,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      observation' = observation,
    }
  }

  action syncAbortBody = {
    nondet p = members.oneOf()
    all {
      phase == GRecovering,
      goal == GRecoverOld,
      needsAbort.get(p),
      local.get(p) != GMissing,
      local' = local.set(p, GAbortBody),
      abortBodySynced' = abortBodySynced.set(p, true),
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = preparePending,
      prepareCrashed' = prepareCrashed,
      needsAbort' = needsAbort,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation' = observation,
    }
  }

  // The one-byte guard is old or A after an interrupted write. All other A bytes were made durable
  // by syncAbortBody first. A surviving guard therefore yields an exact predecessor-equivalent A.
  action interruptAbortGuard = {
    nondet p = members.oneOf()
    nondet guardSurvives = Set(false, true).oneOf()
    all {
      phase == GRecovering,
      goal == GRecoverOld,
      abortBodySynced.get(p),
      local' = local.set(p, if (guardSurvives) GAborted else GAbortBody),
      needsAbort' = needsAbort.set(p, not(guardSurvives)),
      phase' = GActive,
      goal' = GNoGoal,
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = Set(),
      prepareCrashed' = false,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      observation' = observation,
    }
  }

  action syncAbortGuard = {
    nondet p = members.oneOf()
    all {
      phase == GRecovering,
      goal == GRecoverOld,
      abortBodySynced.get(p),
      local' = local.set(p, GAborted),
      needsAbort' = needsAbort.set(p, false),
      abortBodySynced' = abortBodySynced.set(p, false),
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = preparePending,
      prepareCrashed' = prepareCrashed,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation' = observation,
    }
  }

  // Final-root repair is no more atomic than initial publication. An interrupted M/T write starts
  // the next recovery from the exact byte-subset image represented by keep/torn/exact.
  action interruptFinal = {
    nondet p = members.oneOf()
    nondet outcome = WriteOutcomes.oneOf()
    val finalState = if (p.in(removals)) GTombstone else GMaterialized
    val nextState = if (outcome == GKeepWrite)
      local.get(p)
    else if (outcome == GTornWrite)
      GTornFinal
    else
      finalState
    all {
      decisionEstablished,
      or {
        phase == GActive,
        phase == GFinalizing,
        phase == GRecovering and goal == GRecoverNew,
      },
      local.get(p) != GMissing,
      local.get(p) != finalState,
      local' = local.set(p, nextState),
      needsAbort' = if (outcome == GExactWrite)
        needsAbort.set(p, false)
      else
        needsAbort,
      phase' = GActive,
      goal' = GNoGoal,
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = Set(),
      prepareCrashed' = false,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      observation' = observation,
    }
  }

  action syncFinal = {
    nondet p = members.oneOf()
    val finalState = if (p.in(removals)) GTombstone else GMaterialized
    all {
      decisionEstablished,
      or {
        phase == GActive,
        phase == GFinalizing,
        phase == GRecovering and goal == GRecoverNew,
      },
      local.get(p) != GMissing,
      local' = local.set(p, finalState),
      needsAbort' = needsAbort.set(p, false),
      phase' = GFinalizing,
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = preparePending,
      prepareCrashed' = prepareCrashed,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      observation' = observation,
    }
  }

  // This crash point covers interruption after any successful repair barrier but before the next
  // repair action. Durable roots remain; all process-local barrier credit and recovery intent die.
  action interruptRecovery = all {
    phase == GRecovering or phase == GFinalizing,
    phase' = GActive,
    goal' = GNoGoal,
    abortBodySynced' = AllParticipants.mapBy(_ => false),
    preparePending' = Set(),
    prepareCrashed' = false,
    members' = members,
    removals' = removals,
    operations' = operations,
    local' = local,
    linkOk' = linkOk,
    payloadOk' = payloadOk,
    needsAbort' = needsAbort,
    unlinkIssued' = unlinkIssued,
    truncated' = truncated,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    observation' = observation,
  }

  action markFinalized = all {
    decisionEstablished,
    independentlyFinal(members, local, removals),
    unlinkIssued == Set(),
    phase != GObserved,
    phase' = GFinalized,
    goal' = GNoGoal,
    abortBodySynced' = AllParticipants.mapBy(_ => false),
    members' = members,
    removals' = removals,
    operations' = operations,
    local' = local,
    linkOk' = linkOk,
    payloadOk' = payloadOk,
    preparePending' = preparePending,
    prepareCrashed' = prepareCrashed,
    needsAbort' = needsAbort,
    unlinkIssued' = unlinkIssued,
    truncated' = truncated,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    observation' = observation,
  }

  // unlink() changes the live namespace first. Before directory barriers, a crash may preserve any
  // subset of the issued removals. This models different parent directories as well as one crash
  // between two unlinks; it does not assume an ordinal-prefix deletion frontier.
  action issueUnlink = {
    nondet p = removals.oneOf()
    all {
      phase == GFinalized,
      independentlyFinal(members, local, removals),
      local.get(p) == GTombstone,
      not(p.in(unlinkIssued)),
      unlinkIssued' = unlinkIssued.union(Set(p)),
      members' = members,
      removals' = removals,
      operations' = operations,
      local' = local,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = preparePending,
      prepareCrashed' = prepareCrashed,
      needsAbort' = needsAbort,
      abortBodySynced' = abortBodySynced,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation' = observation,
    }
  }

  action crashDuringUnlink = {
    nondet survived = unlinkIssued.powerset().oneOf()
    all {
      phase == GFinalized,
      unlinkIssued != Set(),
      local' = AllParticipants.mapBy(p =>
        if (p.in(survived)) GMissing else local.get(p)),
      unlinkIssued' = Set(),
      phase' = GActive,
      members' = members,
      removals' = removals,
      operations' = operations,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = Set(),
      prepareCrashed' = false,
      needsAbort' = needsAbort,
      abortBodySynced' = AllParticipants.mapBy(_ => false),
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = GNoGoal,
      observation' = observation,
    }
  }

  action syncUnlinks = all {
    phase == GFinalized,
    unlinkIssued != Set(),
    local' = AllParticipants.mapBy(p =>
      if (p.in(unlinkIssued)) GMissing else local.get(p)),
    unlinkIssued' = Set(),
    members' = members,
    removals' = removals,
    operations' = operations,
    linkOk' = linkOk,
    payloadOk' = payloadOk,
    preparePending' = preparePending,
    prepareCrashed' = prepareCrashed,
    needsAbort' = needsAbort,
    abortBodySynced' = abortBodySynced,
    truncated' = truncated,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation' = observation,
  }

  action finishRecovery = {
    val oldReady = members.forall(p =>
      oldAuthority(local.get(p)) and not(needsAbort.get(p)) and not(truncated.get(p)))
    val newReady = independentlyFinal(members, local, removals)
    all {
      phase == GRecovering,
      (goal == GRecoverOld and oldReady) or (goal == GRecoverNew and newReady),
      observation' = AllParticipants.mapBy(p =>
        decodeObservation(p, members, local, removals)),
      phase' = GObserved,
      members' = members,
      removals' = removals,
      operations' = operations,
      local' = local,
      linkOk' = linkOk,
      payloadOk' = payloadOk,
      preparePending' = preparePending,
      prepareCrashed' = prepareCrashed,
      needsAbort' = needsAbort,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued,
      truncated' = truncated,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = GNoGoal,
    }
  }

  action stutter = all {
    members' = members,
    removals' = removals,
    operations' = operations,
    local' = local,
    linkOk' = linkOk,
    payloadOk' = payloadOk,
    preparePending' = preparePending,
    prepareCrashed' = prepareCrashed,
    needsAbort' = needsAbort,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    truncated' = truncated,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation' = observation,
  }

  action step = any {
    startPrepare,
    tearPrepare,
    syncPrepare,
    acknowledge,
    truncateRewind,
    beginRecovery,
    interruptAbortBody,
    syncAbortBody,
    interruptAbortGuard,
    syncAbortGuard,
    interruptFinal,
    syncFinal,
    interruptRecovery,
    markFinalized,
    issueUnlink,
    crashDuringUnlink,
    syncUnlinks,
    finishRecovery,
    stutter,
  }

  val oldVector = members.forall(p => observation.get(p) == GOldObservation)
  val newVector = members.forall(p => observation.get(p) == expectedNewObservation(p, removals))
  val groupAtomicity = phase == GObserved implies (oldVector or newVector)
  val acknowledgedDurability = (phase == GObserved and acknowledged) implies newVector
  val noPreparedVisibility = phase == GObserved implies
    members.forall(p => observation.get(p) != GNoObservation)
  val finalBeforeMissing = members.exists(p => local.get(p) == GMissing) implies
    decisionEstablished and independentlyFinal(members, local, removals)
  val exactFinalHasDecision = members.forall(p =>
    (local.get(p) == GMaterialized or local.get(p) == GTombstone or local.get(p) == GMissing)
      implies decisionEstablished)
  val decisionRetainsEvidence = decisionEstablished implies
    diskProvesNew(members, local, linkOk, payloadOk, removals)
  val truncateAfterDecision = members.forall(p =>
    truncated.get(p) implies decisionEstablished and operations.get(p) == GRewind)
  val noPayloadNeededForPrefixOperations = members.forall(p =>
    operations.get(p) != GAppend implies payloadOk.get(p))
  val oldObservationIsQuiescent = (phase == GObserved and oldVector) implies
    members.forall(p =>
      oldAuthority(local.get(p)) and not(needsAbort.get(p)) and not(truncated.get(p)))
  val abortDoesNotFollowDecision = members.exists(p => local.get(p) == GAborted) implies
    not(decisionEstablished)
  val typeOk = and {
    members.in(ParticipantSets),
    removals.subseteq(members),
    preparePending.subseteq(members),
    unlinkIssued.subseteq(removals),
    operations.keys() == AllParticipants,
    local.keys() == AllParticipants,
    linkOk.keys() == AllParticipants,
    payloadOk.keys() == AllParticipants,
    needsAbort.keys() == AllParticipants,
    abortBodySynced.keys() == AllParticipants,
    truncated.keys() == AllParticipants,
    observation.keys() == AllParticipants,
    members.forall(p => p.in(removals) == (operations.get(p) == GRemove)),
  }
  val safe = and {
    typeOk,
    groupAtomicity,
    acknowledgedDurability,
    noPreparedVisibility,
    finalBeforeMissing,
    exactFinalHasDecision,
    decisionRetainsEvidence,
    truncateAfterDecision,
    noPayloadNeededForPrefixOperations,
    oldObservationIsQuiescent,
    abortDoesNotFollowDecision,
  }
}

module uno_slot {
  type SCell =
      SGeneration
    | SStateGuard
    | SBody
    | SRootCrc0
    | SRootCrc1
    | SRootCrc2
    | SRootCrc3
    | SWitness

  type SByte =
      SZero
    | SOldGeneration
    | SNewGeneration
    | SOldBody
    | SNewBody
    | SOldFinalGuard
    | SCommonFinalGuard
    | SNewPreparedGuard
    | SNewAbortGuard
    | SNewFinalGuard
    | SOldCrc0
    | SOldCrc1
    | SOldCrc2
    | SOldCrc3
    | SPreparedCrc0
    | SPreparedCrc1
    | SPreparedCrc2
    | SPreparedCrc3
    | SAbortCrc0
    | SAbortCrc2
    | SFinalCrc0
    | SFinalCrc1
    | SFinalCrc2
    | SFinalCrc3
    | SGroupWitness

  type SPhase = SIdle | SOnDisk | SRejecting | SAbortGuard | SFinalizing | SComplete
  type SObservation = SNoObservation | SOldObservation | SNewObservation

  pure val Cells: Set[SCell] = Set(
    SGeneration,
    SStateGuard,
    SBody,
    SRootCrc0,
    SRootCrc1,
    SRootCrc2,
    SRootCrc3,
    SWitness
  )
  pure val HeaderCells: Set[SCell] = Cells.exclude(Set(SWitness))
  pure val AbortBodyCells: Set[SCell] = HeaderCells.exclude(Set(SStateGuard))

  pure def oldFinal(colored: bool): SCell -> SByte = Map(
    SGeneration -> SOldGeneration,
    SStateGuard -> (if (colored) SOldFinalGuard else SCommonFinalGuard),
    SBody -> SOldBody,
    SRootCrc0 -> SFinalCrc0,
    SRootCrc1 -> SOldCrc1,
    SRootCrc2 -> SFinalCrc2,
    SRootCrc3 -> SOldCrc3,
    SWitness -> SZero
  )

  pure def prepared(colored: bool): SCell -> SByte = Map(
    SGeneration -> SNewGeneration,
    SStateGuard -> SNewPreparedGuard,
    SBody -> SNewBody,
    SRootCrc0 -> SPreparedCrc0,
    SRootCrc1 -> SPreparedCrc1,
    SRootCrc2 -> SPreparedCrc2,
    SRootCrc3 -> SPreparedCrc3,
    SWitness -> SGroupWitness
  )

  // The abort CRC contributes bytes 1 and 3 of the never-issued final CRC. This is the concrete
  // non-prefix source shape found by adversarial review. The colored guard is the only intended
  // reason that the complete final image remains unreachable.
  pure def abortRoot(colored: bool): SCell -> SByte = Map(
    SGeneration -> SNewGeneration,
    SStateGuard -> SNewAbortGuard,
    SBody -> SOldBody,
    SRootCrc0 -> SAbortCrc0,
    SRootCrc1 -> SFinalCrc1,
    SRootCrc2 -> SAbortCrc2,
    SRootCrc3 -> SFinalCrc3,
    SWitness -> SGroupWitness
  )

  pure def newFinal(colored: bool): SCell -> SByte = Map(
    SGeneration -> SNewGeneration,
    SStateGuard -> (if (colored) SNewFinalGuard else SCommonFinalGuard),
    SBody -> SNewBody,
    SRootCrc0 -> SFinalCrc0,
    SRootCrc1 -> SFinalCrc1,
    SRootCrc2 -> SFinalCrc2,
    SRootCrc3 -> SFinalCrc3,
    SWitness -> SGroupWitness
  )

  pure def tear(
      base: SCell -> SByte,
      target: SCell -> SByte,
      survives: Set[SCell]
  ): SCell -> SByte =
    Cells.mapBy(c => if (c.in(survives)) target.get(c) else base.get(c))

  pure def exactOn(
      selected: Set[SCell],
      image: SCell -> SByte,
      target: SCell -> SByte
  ): bool = selected.forall(c => image.get(c) == target.get(c))

  pure def exactAbortHeader(image: SCell -> SByte, colored: bool): bool =
    exactOn(HeaderCells, image, abortRoot(colored))

  pure def installAbortBody(
      base: SCell -> SByte,
      colored: bool
  ): SCell -> SByte =
    Cells.mapBy(c =>
      if (c.in(AbortBodyCells)) abortRoot(colored).get(c) else base.get(c))

  var colored: bool
  var slot: SCell -> SByte
  var payloadValid: bool
  var decisionIssued: bool
  var mutable: bool
  var phase: SPhase
  var observation: SObservation

  action initFixed = all {
    colored' = true,
    slot' = oldFinal(true),
    payloadValid' = false,
    decisionIssued' = false,
    mutable' = false,
    phase' = SIdle,
    observation' = SNoObservation,
  }

  action initBuggy = all {
    colored' = false,
    slot' = oldFinal(false),
    payloadValid' = false,
    decisionIssued' = false,
    mutable' = false,
    phase' = SIdle,
    observation' = SNoObservation,
  }

  action crashDuringPrepare = {
    nondet survives = Cells.powerset().oneOf()
    nondet suffixIsValid = Set(false, true).oneOf()
    all {
      phase == SIdle,
      slot' = tear(slot, prepared(colored), survives),
      payloadValid' = suffixIsValid,
      phase' = SOnDisk,
      colored' = colored,
      decisionIssued' = decisionIssued,
      mutable' = false,
      observation' = observation,
    }
  }

  // Every restart discards volatile recovery intent and classifies only the recovered bytes. An
  // exact prepared image reconstructed by a partial abort is therefore reconsidered as a decision
  // candidate instead of being overwritten merely because the previous process was rejecting it.
  action classifyDisk = {
    val exactPrepared = slot == prepared(colored) and payloadValid
    val exactAbort = exactAbortHeader(slot, colored)
    val exactFinal = slot == newFinal(colored)
    val decisionNow = decisionIssued or exactPrepared
    all {
      phase == SOnDisk,
      decisionIssued' = decisionNow,
      phase' = if (exactAbort or exactFinal)
        SComplete
      else if (decisionNow)
        SFinalizing
      else
        SRejecting,
      colored' = colored,
      slot' = slot,
      payloadValid' = payloadValid,
      mutable' = exactAbort,
      observation' = if (exactFinal)
        SNewObservation
      else if (exactAbort)
        SOldObservation
      else
        SNoObservation,
    }
  }

  // An interrupted repair chooses a fresh arbitrary subset from the already recovered disk image,
  // then loses all volatile phase and barrier credit.
  action crashDuringAbortBody = {
    nondet survives = AbortBodyCells.powerset().oneOf()
    all {
      phase == SRejecting,
      slot' = tear(slot, abortRoot(colored), survives),
      colored' = colored,
      payloadValid' = payloadValid,
      decisionIssued' = decisionIssued,
      mutable' = false,
      phase' = SOnDisk,
      observation' = SNoObservation,
    }
  }

  // A successful first barrier makes every A body/checksum byte exact while deliberately leaving
  // the one-byte state guard untouched.
  action syncAbortBody = all {
    phase == SRejecting,
    colored' = colored,
    slot' = installAbortBody(slot, colored),
    payloadValid' = payloadValid,
    decisionIssued' = decisionIssued,
    mutable' = false,
    phase' = SAbortGuard,
    observation' = observation,
  }

  // Once the body barrier has succeeded, a crash during the one-byte guard write leaves either
  // the previous non-A guard or the complete predecessor-equivalent A root.
  action crashDuringAbortGuard = {
    nondet guardSurvives = Set(false, true).oneOf()
    all {
      phase == SAbortGuard,
      slot' = if (guardSurvives)
        slot.set(SStateGuard, abortRoot(colored).get(SStateGuard))
      else
        slot,
      colored' = colored,
      payloadValid' = payloadValid,
      decisionIssued' = decisionIssued,
      mutable' = false,
      phase' = SOnDisk,
      observation' = SNoObservation,
    }
  }

  action syncAbortGuard = all {
    phase == SAbortGuard,
    slot' = slot.set(SStateGuard, abortRoot(colored).get(SStateGuard)),
    colored' = colored,
    payloadValid' = payloadValid,
    decisionIssued' = decisionIssued,
    mutable' = true,
    phase' = SComplete,
    observation' = SOldObservation,
  }

  // A crash after the first barrier but before any guard write also loses the process-local proof
  // that the body barrier returned. Recovery reclassifies and repeats the body barrier.
  action crashAfterAbortBody = all {
    phase == SAbortGuard,
    colored' = colored,
    slot' = slot,
    payloadValid' = payloadValid,
    decisionIssued' = decisionIssued,
    mutable' = false,
    phase' = SOnDisk,
    observation' = SNoObservation,
  }

  action crashDuringFinal = {
    nondet survives = HeaderCells.powerset().oneOf()
    all {
      phase == SFinalizing,
      decisionIssued,
      slot' = tear(slot, newFinal(colored), survives),
      colored' = colored,
      payloadValid' = payloadValid,
      decisionIssued' = decisionIssued,
      mutable' = false,
      phase' = SOnDisk,
      observation' = SNoObservation,
    }
  }

  action syncFinal = all {
    phase == SFinalizing,
    decisionIssued,
    colored' = colored,
    slot' = newFinal(colored),
    payloadValid' = payloadValid,
    decisionIssued' = decisionIssued,
    mutable' = false,
    phase' = SComplete,
    observation' = SNewObservation,
  }

  action stutter = all {
    colored' = colored,
    slot' = slot,
    payloadValid' = payloadValid,
    decisionIssued' = decisionIssued,
    mutable' = mutable,
    phase' = phase,
    observation' = observation,
  }

  action step = any {
    crashDuringPrepare,
    classifyDisk,
    crashDuringAbortBody,
    syncAbortBody,
    crashDuringAbortGuard,
    syncAbortGuard,
    crashAfterAbortBody,
    crashDuringFinal,
    syncFinal,
    stutter,
  }

  val finalHasProvenance = (slot == newFinal(colored)) implies decisionIssued
  val rejectedNeverPublishes = (not(decisionIssued)) implies observation != SNewObservation
  val mutableOnlyAfterAbort = mutable implies
    exactAbortHeader(slot, colored) and observation == SOldObservation
  val typeOk = slot.keys() == Cells
  val safe = and {
    typeOk,
    finalHasProvenance,
    rejectedNeverPublishes,
    mutableOnlyAfterAbort,
  }
}


// Focused bounded-checking form of the composed model. Isolated cuts give one participant a
// symbolic write and swap the active ring ordinal; joint cuts carry independent survivor masks for
// both participants. Encoded stage/participant/offset provenance is applied in issue order, so
// abort and final writes overlay the actual recovered prepare/R image rather than an assumed exact
// B base. Full actions use every addressed offset; five-/71-byte projections are used only where
// changedOffsetQuotient checks source/target equality at every omitted offset.
//
// The 16-byte witness is one fixed, prevalidated reciprocal-ring interface, not the full L14 codec
// or a stale-group/incarnation adversary. Namespace absence is closed-world: only the modeled,
// exact-tombstone-authorized unlink actions can remove a name. Root bytes retained after unlink are
// proof-history ghosts and are not consulted by decode0/decode1 when the name is absent.
module uno_composed {
  type COperation = CAppend | CRewind | CRemove
  type CHeaderKind = CSameSlotOld | CPredecessor | CPrepared | CRecovered | CAbort | CFinal
  type CGoal = CNoGoal | CRecoverOld | CRecoverNew
  type CPhase = CIdle | COnDisk | CRecovering | CFinalized | CObserved
  type CObservation = CNoObservation | COldObservation | CNewObservation | CAbsentObservation

  pure val HeaderOffsets: Set[int] = 0.to(111)
  pure val LogicalOffsets: Set[int] = 16.to(107)
  pure val AbortBodyAddressedOffsets: Set[int] = HeaderOffsets.exclude(Set(7))
  // Survivor choices on an addressed byte whose source and target values are equal have no effect
  // on the recovered image. These exact changed-offset quotients still denote every concrete
  // arbitrary-subset outcome while avoiding inert powerset dimensions in Apalache.
  pure val PrepareChangedOffsets: Set[int] = Set(7, 15, 23).union(44.to(111))
  pure val AbortBodyOffsets: Set[int] = Set(23).union(44.to(111))
  pure val RecoveredChangedOffsets: Set[int] = Set(7, 108, 109, 110, 111)
  pure val FinalChangedOffsets: Set[int] = Set(7, 108, 109, 110, 111)
  pure val WitnessOffsets: Set[int] = 0.to(15)
  pure val PayloadOffsets: Set[int] = 0.to(6)
  pure val AppendOffsets: Set[int] = Set(5, 6)
  pure val Operations: Set[COperation] = Set(CAppend, CRewind, CRemove)
  pure def removalParticipants(op0: COperation, op1: COperation): Set[int] =
    (if (op0 == CRemove) Set(0) else Set())
      .union(if (op1 == CRemove) Set(1) else Set())
  pure def retainedParticipants(op0: COperation, op1: COperation): Set[int] =
    Set(0, 1).exclude(removalParticipants(op0, op1))
  pure val ScenarioPrepare: int = 0
  pure val ScenarioAbort: int = 1
  pure val ScenarioFinal: int = 2
  pure val ScenarioControl: int = 3
  pure val ScenarioJointPrepare: int = 4
  pure val ScenarioComposedAbort: int = 5
  pure val ScenarioComposedFinal: int = 6
  pure val EncodedStageStride: int = 224
  pure val EncodedParticipantStride: int = 112
  pure val EncodedPrepareStage: int = 0
  pure val EncodedRecoveredStage: int = 1
  pure val EncodedAbortStage: int = 2
  pure val EncodedFinalStage: int = 3
  pure val EncodedSurvivorOffsets: Set[int] = 0.to(895)
  pure val ModeOld: int = 0
  pure val ModePrepared: int = 1
  pure val ModeAbort: int = 2
  pure val ModeFinal: int = 3

  pure def rootCrc(
      p: int,
      op: COperation,
      kind: CHeaderKind
  ): int -> int =
    if (kind == CSameSlotOld)
      if (p == 0) Map(108 -> 206, 109 -> 89, 110 -> 138, 111 -> 39)
      else Map(108 -> 223, 109 -> 247, 110 -> 180, 111 -> 218)
    else if (kind == CPredecessor)
      if (p == 0) Map(108 -> 36, 109 -> 60, 110 -> 136, 111 -> 93)
      else Map(108 -> 53, 109 -> 146, 110 -> 182, 111 -> 160)
    else if (kind == CAbort)
      if (p == 0) Map(108 -> 132, 109 -> 68, 110 -> 9, 111 -> 4)
      else Map(108 -> 149, 109 -> 234, 110 -> 55, 111 -> 249)
    else if (kind == CPrepared)
      if (p == 0)
        if (op == CAppend) Map(108 -> 149, 109 -> 33, 110 -> 64, 111 -> 79)
        else if (op == CRewind) Map(108 -> 62, 109 -> 143, 110 -> 127, 111 -> 26)
        else Map(108 -> 10, 109 -> 55, 110 -> 217, 111 -> 168)
      else
        if (op == CAppend) Map(108 -> 161, 109 -> 230, 110 -> 220, 111 -> 178)
        else if (op == CRewind) Map(108 -> 38, 109 -> 48, 110 -> 231, 111 -> 49)
        else Map(108 -> 27, 109 -> 153, 110 -> 231, 111 -> 85)
    else if (kind == CRecovered)
      if (p == 0)
        if (op == CAppend) Map(108 -> 168, 109 -> 54, 110 -> 24, 111 -> 125)
        else if (op == CRewind) Map(108 -> 3, 109 -> 152, 110 -> 39, 111 -> 40)
        else Map(108 -> 55, 109 -> 32, 110 -> 129, 111 -> 154)
      else
        if (op == CAppend) Map(108 -> 156, 109 -> 241, 110 -> 132, 111 -> 128)
        else if (op == CRewind) Map(108 -> 27, 109 -> 39, 110 -> 191, 111 -> 3)
        else Map(108 -> 38, 109 -> 142, 110 -> 191, 111 -> 103)
    else
      if (p == 0)
        if (op == CAppend) Map(108 -> 38, 109 -> 69, 110 -> 200, 111 -> 209)
        else if (op == CRewind) Map(108 -> 141, 109 -> 235, 110 -> 247, 111 -> 132)
        else Map(108 -> 254, 109 -> 106, 110 -> 185, 111 -> 96)
      else
        if (op == CAppend) Map(108 -> 18, 109 -> 130, 110 -> 84, 111 -> 44)
        else if (op == CRewind) Map(108 -> 149, 109 -> 84, 110 -> 111, 111 -> 175)
        else Map(108 -> 239, 109 -> 196, 110 -> 135, 111 -> 157)

  pure def magicByte(offset: int): int =
    if (offset == 0) 67
    else if (offset == 1) 87
    else if (offset == 2) 85
    else if (offset == 3) 78
    else if (offset == 4) 79
    else if (offset == 5) 49
    else 52

  pure def generation(kind: CHeaderKind): int =
    if (kind == CSameSlotOld) 1 else if (kind == CPredecessor) 2 else 3

  pure def stateGuard(op: COperation, kind: CHeaderKind): int =
    if (kind == CSameSlotOld) 11
    else if (kind == CPredecessor) 15
    else if (kind == CPrepared) 2
    else if (kind == CRecovered) 3
    else if (kind == CAbort) 4
    else if (op == CRemove) 6
    else 5

  pure def logicalLength(op: COperation, kind: CHeaderKind): int =
    if (kind == CSameSlotOld or kind == CPredecessor or kind == CAbort) 5
    else if (op == CAppend) 7
    else if (op == CRewind) 2
    else 5

  pure def tagByte(p: int, op: COperation, kind: CHeaderKind, index: int): int =
    if (kind == CSameSlotOld or kind == CPredecessor or kind == CAbort or op == CRemove)
      (17 + 13 * p + 3 * index) % 256
    else if (op == CAppend)
      (91 + 13 * p + 5 * index) % 256
    else
      (121 + 13 * p + 5 * index) % 256

  pure def rootByte(p: int, op: COperation, kind: CHeaderKind, offset: int): int =
    if (offset < 7)
      magicByte(offset)
    else if (offset == 7)
      stateGuard(op, kind)
    else if (offset < 15)
      0
    else if (offset == 15)
      generation(kind)
    else if (offset < 23)
      0
    else if (offset == 23)
      logicalLength(op, kind)
    else if (offset < 44)
      0
    else if (offset < 108)
      tagByte(p, op, kind, offset - 44)
    else
      rootCrc(p, op, kind).get(offset)

  pure def rootHeader(p: int, op: COperation, kind: CHeaderKind): int -> int =
    HeaderOffsets.mapBy(offset => rootByte(p, op, kind, offset))

  pure def overlay(
      offsets: Set[int],
      base: int -> int,
      target: int -> int,
      survives: Set[int]
  ): int -> int =
    offsets.mapBy(offset => if (offset.in(survives)) target.get(offset) else base.get(offset))

  pure def operationCode(op: COperation): int =
    if (op == CAppend) 21 else if (op == CRewind) 22 else 23

  // Compact byte-level wrapper/link abstraction. It retains the marker/group, count, ordinal,
  // reciprocal successor, operation/removal, local/successor incarnation, base/candidate
  // generation, slot, and payload suffix range used by this model. It is not the complete L14
  // physical codec. Decoded fields grant authority only when the entire 16-byte vector is exact.
  pure def canonicalWitness(p: int, op: COperation): int -> int = Map(
    0 -> 82,
    1 -> 73,
    2 -> 78,
    3 -> 71,
    4 -> 67,
    5 -> 2,
    6 -> p,
    7 -> (1 - p),
    8 -> operationCode(op),
    9 -> (50 + p),
    10 -> (51 - p),
    11 -> 2,
    12 -> 3,
    13 -> 1,
    14 -> (if (op == CAppend) 5 else 0),
    15 -> (if (op == CAppend) 2 else 0)
  )
  pure def zeroWitness: int -> int = WitnessOffsets.mapBy(_ => 0)
  pure def decodeOperation(image: int -> int): COperation =
    if (image.get(8) == 21) CAppend
    else if (image.get(8) == 22) CRewind
    else CRemove
  pure def validWitness(p: int, image: int -> int): bool =
    Operations.exists(op => image == canonicalWitness(p, op))

  pure def oldPayloadByte(p: int, offset: int): int =
    (31 + 17 * p + 7 * offset) % 256
  pure def appendPayloadByte(p: int, offset: int): int =
    (211 + 19 * p + 11 * offset) % 256
  pure def oldPayload(p: int): int -> int =
    PayloadOffsets.mapBy(offset => if (offset < 5) oldPayloadByte(p, offset) else 0)
  pure def candidatePayload(p: int, op: COperation): int -> int =
    PayloadOffsets.mapBy(offset =>
      if (offset < 5) oldPayloadByte(p, offset)
      else if (op == CAppend) appendPayloadByte(p, offset)
      else 0)
  pure def payloadValid(
      p: int,
      op: COperation,
      image: int -> int,
      physicalLength: int
  ): bool =
    if (op == CAppend)
      physicalLength >= 7 and image == candidatePayload(p, op)
    else if (op == CRewind)
      physicalLength >= 2 and Set(0, 1).forall(offset =>
        image.get(offset) == oldPayloadByte(p, offset))
    else
      physicalLength >= 5 and 0.to(4).forall(offset =>
        image.get(offset) == oldPayloadByte(p, offset))

  var checkPayload: bool
  var operation0: COperation
  var operation1: COperation
  var activeParticipant: int
  var scenario: int
  var activeMode: int
  var peerMode: int
  var survivors: Set[int]
  var abortGuardSurvived: bool
  var witness0: Set[int]
  var witness1: Set[int]
  var payload0: Set[int]
  var payload1: Set[int]
  var physicalLength0: int
  var physicalLength1: int
  var names: Set[int]
  var abortBodySynced: bool
  var unlinkIssued: Set[int]
  var acknowledged: bool
  var decisionEstablished: bool
  var goal: CGoal
  var phase: CPhase
  var observation0: CObservation
  var observation1: CObservation

  def activeOperation: COperation =
    if (activeParticipant == 0) operation0 else operation1

  pure def encodedOffset(stage: int, p: int, offset: int): int =
    stage * EncodedStageStride + p * EncodedParticipantStride + offset

  pure def encodedStageOffsets(stage: int, p: int): Set[int] =
    encodedOffset(stage, p, 0).to(encodedOffset(stage, p, 111))

  pure def encodedPairStageOffsets(stage: int): Set[int] =
    encodedStageOffsets(stage, 0).union(encodedStageOffsets(stage, 1))

  pure val EncodedPrepareRecoveredOffsets: Set[int] =
    encodedPairStageOffsets(EncodedPrepareStage).union(
      encodedPairStageOffsets(EncodedRecoveredStage))

  pure def encodedAbortBodyOffsets(p: int): Set[int] =
    encodedStageOffsets(EncodedAbortStage, p).exclude(
      Set(encodedOffset(EncodedAbortStage, p, 7)))

  pure val EncodedAbortBody0: Set[int] = encodedAbortBodyOffsets(0)
  pure val EncodedAbortBody1: Set[int] = encodedAbortBodyOffsets(1)
  pure val EncodedAbortBodies: Set[int] = EncodedAbortBody0.union(EncodedAbortBody1)
  pure val EncodedAbortStage0: Set[int] = encodedStageOffsets(EncodedAbortStage, 0)
  pure val EncodedAbortStage1: Set[int] = encodedStageOffsets(EncodedAbortStage, 1)
  pure val EncodedAbortStages: Set[int] = EncodedAbortStage0.union(EncodedAbortStage1)
  pure val EncodedFinalStage0: Set[int] = encodedStageOffsets(EncodedFinalStage, 0)
  pure val EncodedFinalStage1: Set[int] = encodedStageOffsets(EncodedFinalStage, 1)

  def activeEncodedAbortBodyOffsets: Set[int] =
    if (activeParticipant == 0) EncodedAbortBody0 else EncodedAbortBody1

  pure def encodedAbortGuardOffset(p: int): int =
    encodedOffset(EncodedAbortStage, p, 7)

  def composedAbortBodySynced(p: int): bool =
    (if (p == 0) EncodedAbortBody0 else EncodedAbortBody1).subseteq(survivors)

  def composedAbortGuardSurvived(p: int): bool =
    encodedAbortGuardOffset(p).in(survivors)

  pure def encodedFinalChangedOffsets(p: int): Set[int] = Set(
    encodedOffset(EncodedFinalStage, p, 7),
    encodedOffset(EncodedFinalStage, p, 108),
    encodedOffset(EncodedFinalStage, p, 109),
    encodedOffset(EncodedFinalStage, p, 110),
    encodedOffset(EncodedFinalStage, p, 111)
  )

  pure def encodedRecoveredChangedOffsets(p: int): Set[int] = Set(
    encodedOffset(EncodedRecoveredStage, p, 7),
    encodedOffset(EncodedRecoveredStage, p, 108),
    encodedOffset(EncodedRecoveredStage, p, 109),
    encodedOffset(EncodedRecoveredStage, p, 110),
    encodedOffset(EncodedRecoveredStage, p, 111)
  )

  pure def canonicalModeKind(mode: int): CHeaderKind =
    if (mode == ModePrepared) CPrepared
    else if (mode == ModeAbort) CAbort
    else if (mode == ModeFinal) CFinal
    else CSameSlotOld

  pure def canonicalModeByte(p: int, op: COperation, mode: int, offset: int): int =
    rootByte(
      p,
      if (mode == ModeAbort or mode == ModeOld) CAppend else op,
      canonicalModeKind(mode),
      offset)

  pure def canonicalModeRoot(p: int, op: COperation, mode: int): int -> int =
    HeaderOffsets.mapBy(offset => canonicalModeByte(p, op, mode, offset))

  def activeBaseByte(offset: int): int =
    if (scenario == ScenarioPrepare)
      rootByte(activeParticipant, CAppend, CSameSlotOld, offset)
    else if (scenario == ScenarioAbort or scenario == ScenarioFinal)
      rootByte(activeParticipant, activeOperation, CPrepared, offset)
    else
      canonicalModeByte(activeParticipant, activeOperation, activeMode, offset)

  def activeTargetByte(offset: int): int =
    if (scenario == ScenarioPrepare)
      rootByte(activeParticipant, activeOperation, CPrepared, offset)
    else if (scenario == ScenarioAbort)
      rootByte(activeParticipant, CAppend, CAbort, offset)
    else if (scenario == ScenarioFinal)
      rootByte(activeParticipant, activeOperation, CFinal, offset)
    else
      activeBaseByte(offset)

  def activeByteWithoutGuard(offset: int): int =
    if (offset.in(survivors)) activeTargetByte(offset) else activeBaseByte(offset)

  def activeByte(offset: int): int =
    if (scenario == ScenarioAbort and abortGuardSurvived and offset == 7)
      rootByte(activeParticipant, CAppend, CAbort, offset)
    else
      activeByteWithoutGuard(offset)

  def preparedOverlayByte(p: int, offset: int): int =
    if (encodedOffset(EncodedPrepareStage, p, offset).in(survivors))
      rootByte(p, if (p == 0) operation0 else operation1, CPrepared, offset)
    else
      rootByte(p, CAppend, CSameSlotOld, offset)

  def recoveredOverlayByte(p: int, offset: int): int =
    if (encodedOffset(EncodedRecoveredStage, p, offset).in(survivors))
      rootByte(p, if (p == 0) operation0 else operation1, CRecovered, offset)
    else
      preparedOverlayByte(p, offset)

  def abortOverlayByte(p: int, offset: int): int =
    if (encodedOffset(EncodedAbortStage, p, offset).in(survivors))
      rootByte(p, CAppend, CAbort, offset)
    else
      recoveredOverlayByte(p, offset)

  def finalOverlayByte(p: int, offset: int): int =
    if (encodedOffset(EncodedFinalStage, p, offset).in(survivors))
      rootByte(p, if (p == 0) operation0 else operation1, CFinal, offset)
    else
      abortOverlayByte(p, offset)

  def participantByte(p: int, offset: int): int =
    if (scenario == ScenarioJointPrepare)
      recoveredOverlayByte(p, offset)
    else if (scenario == ScenarioComposedAbort)
      abortOverlayByte(p, offset)
    else if (scenario == ScenarioComposedFinal)
      finalOverlayByte(p, offset)
    else if (activeParticipant == p)
      activeByte(offset)
    else
      canonicalModeByte(p, if (p == 0) operation0 else operation1, peerMode, offset)

  def root0: int -> int = HeaderOffsets.mapBy(offset => participantByte(0, offset))
  def root1: int -> int = HeaderOffsets.mapBy(offset => participantByte(1, offset))

  // The mutable root maps above are the generation-3 candidate slots. The selected generation-2
  // predecessors live in the alternate slots, are durable before admission, and are not addressed
  // by any modeled group write.
  pure val Predecessor0: int -> int = rootHeader(0, CAppend, CPredecessor)
  pure val Predecessor1: int -> int = rootHeader(1, CAppend, CPredecessor)

  def witnessImage0: int -> int = overlay(
    WitnessOffsets, zeroWitness, canonicalWitness(0, operation0), witness0)
  def witnessImage1: int -> int = overlay(
    WitnessOffsets, zeroWitness, canonicalWitness(1, operation1), witness1)
  def payloadImage0: int -> int = overlay(
    PayloadOffsets, oldPayload(0), candidatePayload(0, operation0), payload0)
  def payloadImage1: int -> int = overlay(
    PayloadOffsets, oldPayload(1), candidatePayload(1, operation1), payload1)
  def witnessValid0: bool = validWitness(0, witnessImage0)
  def witnessValid1: bool = validWitness(1, witnessImage1)
  def decodedOperation0: COperation = decodeOperation(witnessImage0)
  def decodedOperation1: COperation = decodeOperation(witnessImage1)

  def rootMatches(p: int, op: COperation, kind: CHeaderKind): bool =
    HeaderOffsets.forall(offset =>
      participantByte(p, offset) == rootByte(p, op, kind, offset))

  def transitionByteAllowed(p: int, op: COperation, offset: int): bool = or {
    participantByte(p, offset) == rootByte(p, op, CPrepared, offset),
    participantByte(p, offset) == rootByte(p, op, CRecovered, offset),
    participantByte(p, offset) == rootByte(p, op, CAbort, offset),
    participantByte(p, offset) == rootByte(p, op, CFinal, offset),
  }

  def transition(p: int, op: COperation): bool = all {
    participantByte(p, 7) != rootByte(p, op, CAbort, 7),
    transitionByteAllowed(p, op, 7),
    transitionByteAllowed(p, op, 15),
    HeaderOffsets.exclude(Set(7, 15)).forall(offset =>
      transitionByteAllowed(p, op, offset)),
  }
  def exactRing: bool = and {
    names == Set(0, 1),
    witnessValid0,
    witnessValid1,
    witnessImage0.get(4) == witnessImage1.get(4),
    witnessImage0.get(5) == 2,
    witnessImage1.get(5) == 2,
    witnessImage0.get(6) == 0,
    witnessImage1.get(6) == 1,
    witnessImage0.get(7) == 1,
    witnessImage1.get(7) == 0,
    witnessImage0.get(9) == witnessImage1.get(10),
    witnessImage1.get(9) == witnessImage0.get(10),
  }
  def transitionRing: bool = and {
    exactRing,
    transition(0, decodedOperation0),
    transition(1, decodedOperation1),
  }
  def payloadValid0: bool = witnessValid0 and payloadValid(
    0, decodedOperation0, payloadImage0, physicalLength0)
  def payloadValid1: bool = witnessValid1 and payloadValid(
    1, decodedOperation1, payloadImage1, physicalLength1)
  def exactPrepared0: bool = witnessValid0 and
    rootMatches(0, decodedOperation0, CPrepared)
  def exactPrepared1: bool = witnessValid1 and
    rootMatches(1, decodedOperation1, CPrepared)
  def exactRecovered0: bool = witnessValid0 and
    participantByte(0, 7) == rootByte(0, decodedOperation0, CRecovered, 7) and
    rootMatches(0, decodedOperation0, CRecovered)
  def exactRecovered1: bool = witnessValid1 and
    participantByte(1, 7) == rootByte(1, decodedOperation1, CRecovered, 7) and
    rootMatches(1, decodedOperation1, CRecovered)
  def boundFinal0: bool = witnessValid0 and
    participantByte(0, 7) == rootByte(0, decodedOperation0, CFinal, 7) and
    rootMatches(0, decodedOperation0, CFinal)
  def boundFinal1: bool = witnessValid1 and
    participantByte(1, 7) == rootByte(1, decodedOperation1, CFinal, 7) and
    rootMatches(1, decodedOperation1, CFinal)
  def exactFinal0: bool = 0.in(names) and boundFinal0 and payloadValid0
  def exactFinal1: bool = 1.in(names) and boundFinal1 and payloadValid1
  // Before the A guard becomes exact, rejection is provisional: no predecessor mutation or
  // payload reuse is permitted. A B/R/A/M-or-T transition mixture with an exact ring and valid
  // payload may therefore be resolved to the all-new vector. The explicit A-guard exclusion in
  // transition gives an exact abort root precedence and makes old authority irreversible.
  def completeCandidateEvidence: bool = transitionRing and payloadValid0 and payloadValid1
  def finalCertificateEvidence: bool = transitionRing and (boundFinal0 or boundFinal1)
  def independentlyFinal: bool = and {
    if (0.in(names)) exactFinal0 else true,
    if (1.in(names)) exactFinal1 else true,
  }
  def removalNamesFromDisk: Set[int] =
    (if (boundFinal0 and decodedOperation0 == CRemove) Set(0) else Set())
      .union(if (boundFinal1 and decodedOperation1 == CRemove) Set(1) else Set())
  def retainedNamesFromDisk: Set[int] = Set(0, 1).exclude(removalNamesFromDisk)
  def diskProvesNew(validatePayload: bool): bool = or {
    transitionRing and (not(validatePayload) or (payloadValid0 and payloadValid1)),
    finalCertificateEvidence,
    independentlyFinal,
  }
  def fixedCandidateEvidence(expectedOp0: COperation, expectedOp1: COperation): bool = and {
    exactRing,
    decodedOperation0 == expectedOp0,
    decodedOperation1 == expectedOp1,
    transition(0, expectedOp0),
    transition(1, expectedOp1),
    payloadValid(0, expectedOp0, payloadImage0, physicalLength0),
    payloadValid(1, expectedOp1, payloadImage1, physicalLength1),
  }
  // The composed recovery action uses the same disk-decoded predicate for every ordered operation
  // pair. Pair-fixed wrappers below specialize operation0/1 for tractable Apalache runs.
  def composedCandidateEvidence: bool = completeCandidateEvidence
  def brokenTransitionWithoutGeneration(p: int, op: COperation): bool = all {
    participantByte(p, 7) != rootByte(p, op, CAbort, 7),
    transitionByteAllowed(p, op, 7),
    HeaderOffsets.exclude(Set(7, 15)).forall(offset =>
      transitionByteAllowed(p, op, offset)),
  }
  def fixedBrokenGenerationEvidence(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = and {
    exactRing,
    decodedOperation0 == expectedOp0,
    decodedOperation1 == expectedOp1,
    brokenTransitionWithoutGeneration(0, expectedOp0),
    brokenTransitionWithoutGeneration(1, expectedOp1),
    payloadValid(0, expectedOp0, payloadImage0, physicalLength0),
    payloadValid(1, expectedOp1, payloadImage1, physicalLength1),
  }
  def brokenGenerationEvidence: bool =
    if (operation0 == CAppend and operation1 == CRewind)
      fixedBrokenGenerationEvidence(CAppend, CRewind)
    else if (operation0 == CRewind and operation1 == CAppend)
      fixedBrokenGenerationEvidence(CRewind, CAppend)
    else
      false
  def exactAbort0: bool =
    participantByte(0, 7) == rootByte(0, CAppend, CAbort, 7) and
      rootMatches(0, CAppend, CAbort)
  def exactAbort1: bool =
    participantByte(1, 7) == rootByte(1, CAppend, CAbort, 7) and
      rootMatches(1, CAppend, CAbort)
  def quiescent0: bool =
    if (participantByte(0, 7) == rootByte(0, CAppend, CSameSlotOld, 7))
      rootMatches(0, CAppend, CSameSlotOld) and witnessImage0 == zeroWitness
    else if (participantByte(0, 7) == rootByte(0, CAppend, CAbort, 7))
      exactAbort0
    else
      false
  def quiescent1: bool =
    if (participantByte(1, 7) == rootByte(1, CAppend, CSameSlotOld, 7))
      rootMatches(1, CAppend, CSameSlotOld) and witnessImage1 == zeroWitness
    else if (participantByte(1, 7) == rootByte(1, CAppend, CAbort, 7))
      exactAbort1
    else
      false
  // Predecessor0/1 are fixed durable fixture images, so no action can make them noncanonical.
  def oldReady0: bool = 0.in(names) and physicalLength0 >= 5 and quiescent0
  def oldReady1: bool = 1.in(names) and physicalLength1 >= 5 and quiescent1
  def expected0: CObservation =
    if (operation0 == CRemove) CAbsentObservation else CNewObservation
  def expected1: CObservation =
    if (operation1 == CRemove) CAbsentObservation else CNewObservation
  def decode0: CObservation =
    if (not(0.in(names)))
      CAbsentObservation
    else if (participantByte(0, 7) == rootByte(0, decodedOperation0, CFinal, 7))
      if (exactFinal0)
        if (decodedOperation0 == CRemove) CAbsentObservation else CNewObservation
      else
        CNoObservation
    else if (oldReady0)
      COldObservation
    else
      CNoObservation
  def decode1: CObservation =
    if (not(1.in(names)))
      CAbsentObservation
    else if (participantByte(1, 7) == rootByte(1, decodedOperation1, CFinal, 7))
      if (exactFinal1)
        if (decodedOperation1 == CRemove) CAbsentObservation else CNewObservation
      else
        CNoObservation
    else if (oldReady1)
      COldObservation
    else
      CNoObservation

  // Focused initializers keep one 112-byte write symbolic at a time. Swapping the active
  // participant covers both ring positions without constructing an intractable Cartesian product
  // of two independent 112-byte powersets.
  action initPreparedPair(
      chosen0: COperation,
      chosen1: COperation,
      alreadyAcknowledged: bool
  ): bool = all {
    checkPayload' = true,
    operation0' = chosen0,
    operation1' = chosen1,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModePrepared,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
    payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
    physicalLength0' = if (chosen0 == CAppend) 7 else 5,
    physicalLength1' = if (chosen1 == CAppend) 7 else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = alreadyAcknowledged,
    // An acknowledged exact prepared ring is already a disk-derived decision even if the next
    // process must rediscover it. The unacknowledged wrappers exercise recovery establishment.
    decisionEstablished' = alreadyAcknowledged,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action init = {
    nondet chosen0 = Operations.oneOf()
    nondet chosen1 = Operations.oneOf()
    initPreparedPair(chosen0, chosen1, false)
  }
  action initAA = initPreparedPair(CAppend, CAppend, false)
  action initAR = initPreparedPair(CAppend, CRewind, false)
  action initAD = initPreparedPair(CAppend, CRemove, false)
  action initRA = initPreparedPair(CRewind, CAppend, false)
  action initRR = initPreparedPair(CRewind, CRewind, false)
  action initRD = initPreparedPair(CRewind, CRemove, false)
  action initDA = initPreparedPair(CRemove, CAppend, false)
  action initDR = initPreparedPair(CRemove, CRewind, false)
  action initDD = initPreparedPair(CRemove, CRemove, false)

  action initAckAA = initPreparedPair(CAppend, CAppend, true)
  action initAckAR = initPreparedPair(CAppend, CRewind, true)
  action initAckAD = initPreparedPair(CAppend, CRemove, true)
  action initAckRA = initPreparedPair(CRewind, CAppend, true)
  action initAckRR = initPreparedPair(CRewind, CRewind, true)
  action initAckRD = initPreparedPair(CRewind, CRemove, true)
  action initAckDA = initPreparedPair(CRemove, CAppend, true)
  action initAckDR = initPreparedPair(CRemove, CRewind, true)
  action initAckDD = initPreparedPair(CRemove, CRemove, true)

  action initPrepareTorn0 = {
    nondet rootLanded = PrepareChangedOffsets.powerset().oneOf()
    nondet witnessLanded = WitnessOffsets.powerset().oneOf()
    nondet payloadLanded = AppendOffsets.powerset().oneOf()
    nondet lengthLanded = Set(false, true).oneOf()
    all {
      checkPayload' = true,
      operation0' = CAppend,
      operation1' = CRewind,
      activeParticipant' = 0,
      scenario' = ScenarioPrepare,
      activeMode' = ModeOld,
      peerMode' = ModePrepared,
      survivors' = rootLanded,
      abortGuardSurvived' = false,
      witness0' = witnessLanded,
      witness1' = WitnessOffsets,
      payload0' = payloadLanded,
      payload1' = Set(),
      physicalLength0' = if (lengthLanded) 7 else 5,
      physicalLength1' = 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initPrepareTorn1 = {
    nondet rootLanded = PrepareChangedOffsets.powerset().oneOf()
    nondet witnessLanded = WitnessOffsets.powerset().oneOf()
    nondet payloadLanded = AppendOffsets.powerset().oneOf()
    nondet lengthLanded = Set(false, true).oneOf()
    all {
      checkPayload' = true,
      operation0' = CRewind,
      operation1' = CAppend,
      activeParticipant' = 1,
      scenario' = ScenarioPrepare,
      activeMode' = ModeOld,
      peerMode' = ModePrepared,
      survivors' = rootLanded,
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = witnessLanded,
      payload0' = Set(),
      payload1' = payloadLanded,
      physicalLength0' = 5,
      physicalLength1' = if (lengthLanded) 7 else 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  // Final-root provenance depends on the one generation-colored guard byte. Other prepare bytes
  // cannot compensate for a guard mismatch, so these focused initializers are a sound projection
  // of initPrepareTorn0/1 for prepareTear0NoFinal/prepareTear1NoFinal.
  action initPrepareGuardCut(active: int, guardLanded: bool): bool = all {
    active.in(Set(0, 1)),
    checkPayload' = true,
    operation0' = if (active == 0) CAppend else CRewind,
    operation1' = if (active == 1) CAppend else CRewind,
    activeParticipant' = active,
    scenario' = ScenarioPrepare,
    activeMode' = ModeOld,
    peerMode' = ModePrepared,
    survivors' = if (guardLanded) Set(7) else Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (active == 0) AppendOffsets else Set(),
    payload1' = if (active == 1) AppendOffsets else Set(),
    physicalLength0' = if (active == 0) 7 else 5,
    physicalLength1' = if (active == 1) 7 else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initPrepareGuardTorn0 = {
    nondet guardLanded = Set(false, true).oneOf()
    initPrepareGuardCut(0, guardLanded)
  }

  action initPrepareGuardTorn1 = {
    nondet guardLanded = Set(false, true).oneOf()
    initPrepareGuardCut(1, guardLanded)
  }

  // Exact two-participant prepare crash: both root writes, witnesses, append suffixes, and length
  // extensions independently retain arbitrary addressed subsets. The encoded survivor namespace
  // keeps participant and write-stage provenance distinct while participantByte decodes the actual
  // ordered disk image.
  action initJointPreparePair(chosen0: COperation, chosen1: COperation): bool = {
    nondet root0Landed = encodedStageOffsets(
      EncodedPrepareStage, 0).powerset().oneOf()
    nondet root1Landed = encodedStageOffsets(
      EncodedPrepareStage, 1).powerset().oneOf()
    nondet witness0Landed = WitnessOffsets.powerset().oneOf()
    nondet witness1Landed = WitnessOffsets.powerset().oneOf()
    nondet payload0Landed = AppendOffsets.powerset().oneOf()
    nondet payload1Landed = AppendOffsets.powerset().oneOf()
    nondet length0Landed = Set(false, true).oneOf()
    nondet length1Landed = Set(false, true).oneOf()
    all {
      checkPayload' = true,
      operation0' = chosen0,
      operation1' = chosen1,
      activeParticipant' = 0,
      scenario' = ScenarioJointPrepare,
      activeMode' = ModeOld,
      peerMode' = ModeOld,
      survivors' = root0Landed.union(root1Landed),
      abortGuardSurvived' = false,
      witness0' = witness0Landed,
      witness1' = witness1Landed,
      payload0' = if (chosen0 == CAppend) payload0Landed else Set(),
      payload1' = if (chosen1 == CAppend) payload1Landed else Set(),
      physicalLength0' = if (chosen0 == CAppend and length0Landed) 7 else 5,
      physicalLength1' = if (chosen1 == CAppend and length1Landed) 7 else 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initJointPrepareAA = initJointPreparePair(CAppend, CAppend)
  action initJointPrepareAR = initJointPreparePair(CAppend, CRewind)
  action initJointPrepareAD = initJointPreparePair(CAppend, CRemove)
  action initJointPrepareRA = initJointPreparePair(CRewind, CAppend)
  action initJointPrepareRR = initJointPreparePair(CRewind, CRewind)
  action initJointPrepareRD = initJointPreparePair(CRewind, CRemove)
  action initJointPrepareDA = initJointPreparePair(CRemove, CAppend)
  action initJointPrepareDR = initJointPreparePair(CRemove, CRewind)
  action initJointPrepareDD = initJointPreparePair(CRemove, CRemove)

  action initRecoveredMixedPair(chosen0: COperation, chosen1: COperation): bool = {
    nondet recovered0Landed = encodedRecoveredChangedOffsets(0).powerset().oneOf()
    nondet recovered1Landed = encodedRecoveredChangedOffsets(1).powerset().oneOf()
    all {
      checkPayload' = true,
      operation0' = chosen0,
      operation1' = chosen1,
      activeParticipant' = 0,
      scenario' = ScenarioJointPrepare,
      activeMode' = ModeOld,
      peerMode' = ModeOld,
      survivors' = encodedPairStageOffsets(EncodedPrepareStage)
        .union(recovered0Landed)
        .union(recovered1Landed),
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = WitnessOffsets,
      payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
      payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
      physicalLength0' = if (chosen0 == CAppend) 7 else 5,
      physicalLength1' = if (chosen1 == CAppend) 7 else 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initRecoveredMixedAA = initRecoveredMixedPair(CAppend, CAppend)
  action initRecoveredMixedAR = initRecoveredMixedPair(CAppend, CRewind)
  action initRecoveredMixedAD = initRecoveredMixedPair(CAppend, CRemove)
  action initRecoveredMixedRA = initRecoveredMixedPair(CRewind, CAppend)
  action initRecoveredMixedRR = initRecoveredMixedPair(CRewind, CRewind)
  action initRecoveredMixedRD = initRecoveredMixedPair(CRewind, CRemove)
  action initRecoveredMixedDA = initRecoveredMixedPair(CRemove, CAppend)
  action initRecoveredMixedDR = initRecoveredMixedPair(CRemove, CRewind)
  action initRecoveredMixedDD = initRecoveredMixedPair(CRemove, CRemove)

  // Reachable cut after both prepared roots omitted generation byte 15, recovery selected the old
  // vector, both A-body writes were issued, and one crash retained independent addressed-byte
  // subsets. No guard byte is included: guard publication is a later, separately ordered write.
  action initJointAbortBodiesPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = {
    nondet abort0Landed = EncodedAbortBody0.powerset().oneOf()
    nondet abort1Landed = EncodedAbortBody1.powerset().oneOf()
    all {
      checkPayload' = true,
      operation0' = chosen0,
      operation1' = chosen1,
      activeParticipant' = 0,
      scenario' = ScenarioComposedAbort,
      activeMode' = ModeOld,
      peerMode' = ModeOld,
      survivors' = encodedStageOffsets(EncodedPrepareStage, 0)
        .exclude(Set(encodedOffset(EncodedPrepareStage, 0, 15)))
        .union(encodedStageOffsets(EncodedPrepareStage, 1)
          .exclude(Set(encodedOffset(EncodedPrepareStage, 1, 15))))
        .union(abort0Landed)
        .union(abort1Landed),
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = WitnessOffsets,
      payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
      payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
      physicalLength0' = if (chosen0 == CAppend) 7 else 5,
      physicalLength1' = if (chosen1 == CAppend) 7 else 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = false,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initJointAbortBodiesAA = initJointAbortBodiesPair(CAppend, CAppend)
  action initJointAbortBodiesAR = initJointAbortBodiesPair(CAppend, CRewind)
  action initJointAbortBodiesAD = initJointAbortBodiesPair(CAppend, CRemove)
  action initJointAbortBodiesRA = initJointAbortBodiesPair(CRewind, CAppend)
  action initJointAbortBodiesRR = initJointAbortBodiesPair(CRewind, CRewind)
  action initJointAbortBodiesRD = initJointAbortBodiesPair(CRewind, CRemove)
  action initJointAbortBodiesDA = initJointAbortBodiesPair(CRemove, CAppend)
  action initJointAbortBodiesDR = initJointAbortBodiesPair(CRemove, CRewind)
  action initJointAbortBodiesDD = initJointAbortBodiesPair(CRemove, CRemove)

  action initComposedAbortedPairState(
      chosen0: COperation,
      chosen1: COperation,
      recoveryReady: bool
  ): bool = all {
    checkPayload' = true,
    operation0' = chosen0,
    operation1' = chosen1,
    activeParticipant' = 0,
    scenario' = ScenarioComposedAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = encodedPairStageOffsets(EncodedPrepareStage)
      .union(EncodedAbortStages),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
    payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
    physicalLength0' = if (chosen0 == CAppend) 7 else 5,
    physicalLength1' = if (chosen1 == CAppend) 7 else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = if (recoveryReady) CRecoverOld else CNoGoal,
    phase' = if (recoveryReady) CRecovering else COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initComposedAbortedPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = initComposedAbortedPairState(chosen0, chosen1, false)

  action initComposedAbortedRecoveringPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = initComposedAbortedPairState(chosen0, chosen1, true)

  action initComposedAbortedAA = initComposedAbortedPair(CAppend, CAppend)
  action initComposedAbortedAR = initComposedAbortedPair(CAppend, CRewind)
  action initComposedAbortedAD = initComposedAbortedPair(CAppend, CRemove)
  action initComposedAbortedRA = initComposedAbortedPair(CRewind, CAppend)
  action initComposedAbortedRR = initComposedAbortedPair(CRewind, CRewind)
  action initComposedAbortedRD = initComposedAbortedPair(CRewind, CRemove)
  action initComposedAbortedDA = initComposedAbortedPair(CRemove, CAppend)
  action initComposedAbortedDR = initComposedAbortedPair(CRemove, CRewind)
  action initComposedAbortedDD = initComposedAbortedPair(CRemove, CRemove)

  action initComposedAbortedRecoveringAA =
    initComposedAbortedRecoveringPair(CAppend, CAppend)
  action initComposedAbortedRecoveringAR =
    initComposedAbortedRecoveringPair(CAppend, CRewind)
  action initComposedAbortedRecoveringAD =
    initComposedAbortedRecoveringPair(CAppend, CRemove)
  action initComposedAbortedRecoveringRA =
    initComposedAbortedRecoveringPair(CRewind, CAppend)
  action initComposedAbortedRecoveringRR =
    initComposedAbortedRecoveringPair(CRewind, CRewind)
  action initComposedAbortedRecoveringRD =
    initComposedAbortedRecoveringPair(CRewind, CRemove)
  action initComposedAbortedRecoveringDA =
    initComposedAbortedRecoveringPair(CRemove, CAppend)
  action initComposedAbortedRecoveringDR =
    initComposedAbortedRecoveringPair(CRemove, CRewind)
  action initComposedAbortedRecoveringDD =
    initComposedAbortedRecoveringPair(CRemove, CRemove)

  action initJointRejectedOnDisk(active: int): bool = all {
    active.in(Set(0, 1)),
    checkPayload' = true,
    operation0' = if (active == 0) CAppend else CRewind,
    operation1' = if (active == 1) CAppend else CRewind,
    activeParticipant' = active,
    scenario' = ScenarioJointPrepare,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = if (active == 0)
      encodedStageOffsets(EncodedPrepareStage, 0)
        .exclude(Set(encodedOffset(EncodedPrepareStage, 0, 15)))
        .union(encodedStageOffsets(EncodedPrepareStage, 1))
    else
      encodedStageOffsets(EncodedPrepareStage, 0)
        .union(encodedStageOffsets(EncodedPrepareStage, 1)
          .exclude(Set(encodedOffset(EncodedPrepareStage, 1, 15)))),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (active == 0) AppendOffsets else Set(),
    payload1' = if (active == 1) AppendOffsets else Set(),
    physicalLength0' = if (active == 0) 7 else 5,
    physicalLength1' = if (active == 1) 7 else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initJointRejectedOnDisk0 = initJointRejectedOnDisk(0)
  action initJointRejectedOnDisk1 = initJointRejectedOnDisk(1)

  // Reachable cuts after a joint prepare crash and a disk-derived old verdict. The active root is
  // exact B except for generation byte 15; the peer and ring are exact. A later abort-body write
  // may supply that shared B/A byte and legitimately make the provisional verdict resolve new.
  action initComposedRejected0 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 0,
    scenario' = ScenarioComposedAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = encodedStageOffsets(EncodedPrepareStage, 0)
      .exclude(Set(encodedOffset(EncodedPrepareStage, 0, 15)))
      .union(encodedStageOffsets(EncodedPrepareStage, 1)),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CRecoverOld,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initComposedRejected1 = all {
    checkPayload' = true,
    operation0' = CRewind,
    operation1' = CAppend,
    activeParticipant' = 1,
    scenario' = ScenarioComposedAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = encodedStageOffsets(EncodedPrepareStage, 0)
      .union(encodedStageOffsets(EncodedPrepareStage, 1)
        .exclude(Set(encodedOffset(EncodedPrepareStage, 1, 15)))),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CRecoverOld,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initComposedDecidedMixture0 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 0,
    scenario' = ScenarioComposedFinal,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = encodedStageOffsets(EncodedPrepareStage, 0)
      .exclude(Set(encodedOffset(EncodedPrepareStage, 0, 15)))
      .union(encodedStageOffsets(EncodedPrepareStage, 1))
      .union(Set(
        encodedOffset(EncodedAbortStage, 0, 15),
        encodedOffset(EncodedAbortStage, 0, 108))),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initComposedSharedGeneration(active: int): bool = all {
    active.in(Set(0, 1)),
    checkPayload' = true,
    operation0' = if (active == 0) CAppend else CRewind,
    operation1' = if (active == 1) CAppend else CRewind,
    activeParticipant' = active,
    scenario' = ScenarioComposedAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = if (active == 0)
      encodedStageOffsets(EncodedPrepareStage, 0)
        .exclude(Set(encodedOffset(EncodedPrepareStage, 0, 15)))
        .union(encodedStageOffsets(EncodedPrepareStage, 1))
        .union(Set(encodedOffset(EncodedAbortStage, 0, 15)))
    else
      encodedStageOffsets(EncodedPrepareStage, 0)
        .union(encodedStageOffsets(EncodedPrepareStage, 1)
          .exclude(Set(encodedOffset(EncodedPrepareStage, 1, 15))))
        .union(Set(encodedOffset(EncodedAbortStage, 1, 15))),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (active == 0) AppendOffsets else Set(),
    payload1' = if (active == 1) AppendOffsets else Set(),
    physicalLength0' = if (active == 0) 7 else 5,
    physicalLength1' = if (active == 1) 7 else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initComposedSharedGeneration0 = initComposedSharedGeneration(0)
  action initComposedSharedGeneration1 = initComposedSharedGeneration(1)

  action initComposedDecidedMixture1 = all {
    checkPayload' = true,
    operation0' = CRewind,
    operation1' = CAppend,
    activeParticipant' = 1,
    scenario' = ScenarioComposedFinal,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = encodedStageOffsets(EncodedPrepareStage, 0)
      .union(encodedStageOffsets(EncodedPrepareStage, 1)
        .exclude(Set(encodedOffset(EncodedPrepareStage, 1, 15))))
      .union(Set(
        encodedOffset(EncodedAbortStage, 1, 15),
        encodedOffset(EncodedAbortStage, 1, 108))),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initComposedJointFinalTorn0 = {
    nondet final0Landed = encodedFinalChangedOffsets(0).powerset().oneOf()
    nondet final1Landed = encodedFinalChangedOffsets(1).powerset().oneOf()
    all {
      checkPayload' = true,
      operation0' = CAppend,
      operation1' = CRewind,
      activeParticipant' = 0,
      scenario' = ScenarioComposedFinal,
      activeMode' = ModeOld,
      peerMode' = ModeOld,
      survivors' = encodedStageOffsets(EncodedPrepareStage, 0)
        .exclude(Set(encodedOffset(EncodedPrepareStage, 0, 15)))
        .union(encodedStageOffsets(EncodedPrepareStage, 1))
        .union(Set(
          encodedOffset(EncodedAbortStage, 0, 15),
          encodedOffset(EncodedAbortStage, 0, 108)))
        .union(final0Landed)
        .union(final1Landed),
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = WitnessOffsets,
      payload0' = AppendOffsets,
      payload1' = Set(),
      physicalLength0' = 7,
      physicalLength1' = 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = true,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  // Exact prepared pair with a previously established disk decision, followed by independently
  // torn final-root writes. Sampling only B-to-M/T changed offsets is exact for this initializer;
  // the ordered B/A-mixture predecessor is covered separately by initComposedJointFinalTorn0.
  action initJointFinalPair(chosen0: COperation, chosen1: COperation): bool = {
    nondet final0Landed = encodedFinalChangedOffsets(0).powerset().oneOf()
    nondet final1Landed = encodedFinalChangedOffsets(1).powerset().oneOf()
    all {
      checkPayload' = true,
      operation0' = chosen0,
      operation1' = chosen1,
      activeParticipant' = 0,
      scenario' = ScenarioComposedFinal,
      activeMode' = ModeOld,
      peerMode' = ModeOld,
      survivors' = encodedPairStageOffsets(EncodedPrepareStage)
        .union(final0Landed)
        .union(final1Landed),
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = WitnessOffsets,
      payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
      payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
      physicalLength0' = if (chosen0 == CAppend) 7 else 5,
      physicalLength1' = if (chosen1 == CAppend) 7 else 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = true,
      decisionEstablished' = true,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initJointFinalAA = initJointFinalPair(CAppend, CAppend)
  action initJointFinalAR = initJointFinalPair(CAppend, CRewind)
  action initJointFinalAD = initJointFinalPair(CAppend, CRemove)
  action initJointFinalRA = initJointFinalPair(CRewind, CAppend)
  action initJointFinalRR = initJointFinalPair(CRewind, CRewind)
  action initJointFinalRD = initJointFinalPair(CRewind, CRemove)
  action initJointFinalDA = initJointFinalPair(CRemove, CAppend)
  action initJointFinalDR = initJointFinalPair(CRemove, CRewind)
  action initJointFinalDD = initJointFinalPair(CRemove, CRemove)

  action initRejected0 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 0,
    scenario' = ScenarioAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = Set(),
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CRecoverOld,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initRejected1 = all {
    checkPayload' = true,
    operation0' = CRewind,
    operation1' = CAppend,
    activeParticipant' = 1,
    scenario' = ScenarioAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = Set(),
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CRecoverOld,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initAbortGuardReady0 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 0,
    scenario' = ScenarioAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = AbortBodyOffsets,
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = Set(),
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = true,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CRecoverOld,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initAbortGuardReady1 = all {
    checkPayload' = true,
    operation0' = CRewind,
    operation1' = CAppend,
    activeParticipant' = 1,
    scenario' = ScenarioAbort,
    activeMode' = ModeOld,
    peerMode' = ModeOld,
    survivors' = AbortBodyOffsets,
    abortGuardSurvived' = false,
    witness0' = Set(),
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(0, 1),
    abortBodySynced' = true,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CRecoverOld,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initDecided0 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRemove,
    activeParticipant' = 0,
    scenario' = ScenarioFinal,
    activeMode' = ModeOld,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initDecided1 = all {
    checkPayload' = true,
    operation0' = CRemove,
    operation1' = CAppend,
    activeParticipant' = 1,
    scenario' = ScenarioFinal,
    activeMode' = ModeOld,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initDecidedRewind0 = all {
    checkPayload' = true,
    operation0' = CRewind,
    operation1' = CAppend,
    activeParticipant' = 0,
    scenario' = ScenarioFinal,
    activeMode' = ModeOld,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initDecidedRewind1 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 1,
    scenario' = ScenarioFinal,
    activeMode' = ModeOld,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  // Crash cut immediately after the normal all-participant prepare join returned success.
  action initAcknowledged = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRemove,
    activeParticipant' = 0,
    scenario' = ScenarioFinal,
    activeMode' = ModeOld,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = true,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  // Reachable cut after both final roots of an acknowledged append/remove pair are durable.
  action initAcknowledgedFinalized = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRemove,
    activeParticipant' = 0,
    scenario' = ScenarioFinal,
    activeMode' = ModeOld,
    peerMode' = ModeFinal,
    survivors' = FinalChangedOffsets,
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = true,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initFinalTorn0 = {
    nondet landed = FinalChangedOffsets.powerset().oneOf()
    all {
      checkPayload' = true,
      operation0' = CAppend,
      operation1' = CRemove,
      activeParticipant' = 0,
      scenario' = ScenarioFinal,
      activeMode' = ModeOld,
      peerMode' = ModePrepared,
      survivors' = landed,
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = WitnessOffsets,
      payload0' = AppendOffsets,
      payload1' = Set(),
      physicalLength0' = 7,
      physicalLength1' = 5,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = true,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initFinalTorn1 = {
    nondet landed = FinalChangedOffsets.powerset().oneOf()
    all {
      checkPayload' = true,
      operation0' = CRemove,
      operation1' = CAppend,
      activeParticipant' = 1,
      scenario' = ScenarioFinal,
      activeMode' = ModeOld,
      peerMode' = ModePrepared,
      survivors' = landed,
      abortGuardSurvived' = false,
      witness0' = WitnessOffsets,
      witness1' = WitnessOffsets,
      payload0' = Set(),
      payload1' = AppendOffsets,
      physicalLength0' = 5,
      physicalLength1' = 7,
      names' = Set(0, 1),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = false,
      decisionEstablished' = true,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = CNoObservation,
      observation1' = CNoObservation,
    }
  }

  action initFinalized = all {
    checkPayload' = true,
    operation0' = CRewind,
    operation1' = CRemove,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = Set(),
    physicalLength0' = 2,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initPartialUnlink0 = all {
    checkPayload' = true,
    operation0' = CRemove,
    operation1' = CAppend,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = AppendOffsets,
    physicalLength0' = 5,
    physicalLength1' = 7,
    names' = Set(1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initPartialUnlink1 = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRemove,
    activeParticipant' = 1,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = AppendOffsets,
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  // Reachable cut after both exact tombstones were independently finalized and both unlink
  // syscalls were issued. A crash may persist any subset of the two namespace removals.
  action initBothRemovalsIssued = all {
    checkPayload' = true,
    operation0' = CRemove,
    operation1' = CRemove,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(),
    payload1' = Set(),
    physicalLength0' = 5,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(0, 1),
    acknowledged' = false,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initBuggyPayload = all {
    checkPayload' = false,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModePrepared,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(5),
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initPayloadRejected = all {
    checkPayload' = true,
    operation0' = CAppend,
    operation1' = CRewind,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModePrepared,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = Set(5),
    payload1' = Set(),
    physicalLength0' = 7,
    physicalLength1' = 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = false,
    decisionEstablished' = false,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action applyRecoveryVerdict(provesNew: bool): bool = all {
    phase == COnDisk,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    // Joint prepare/R and every interrupted composed repair share one ordered byte image. Route
    // the disk verdict without discarding its survivor provenance.
    scenario' = if (scenario.in(Set(
        ScenarioJointPrepare,
        ScenarioComposedAbort,
        ScenarioComposedFinal)))
      if (provesNew) ScenarioComposedFinal else ScenarioComposedAbort
    else
      scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = acknowledged,
    decisionEstablished' = (decisionEstablished or provesNew),
    goal' = if (provesNew) CRecoverNew else CRecoverOld,
    phase' = CRecovering,
    observation0' = observation0,
    observation1' = observation1,
  }

  action beginRecoveryComposed = all {
    scenario.in(Set(
      ScenarioJointPrepare,
      ScenarioComposedAbort,
      ScenarioComposedFinal)),
    unlinkIssued == Set(),
    applyRecoveryVerdict(composedCandidateEvidence),
  }

  // Pair-fixed actions are exact specializations of completeCandidateEvidence once the exact
  // witnesses decode the named operations. They avoid translating all three operation branches
  // inside every one of the 224 root-byte comparisons.
  action beginRecoveryFixed(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = all {
    operation0 == expectedOp0,
    operation1 == expectedOp1,
    unlinkIssued == Set(),
    applyRecoveryVerdict(fixedCandidateEvidence(expectedOp0, expectedOp1)),
  }

  action beginRecoveryAA = beginRecoveryFixed(CAppend, CAppend)
  action beginRecoveryAR = beginRecoveryFixed(CAppend, CRewind)
  action beginRecoveryAD = beginRecoveryFixed(CAppend, CRemove)
  action beginRecoveryRA = beginRecoveryFixed(CRewind, CAppend)
  action beginRecoveryRR = beginRecoveryFixed(CRewind, CRewind)
  action beginRecoveryRD = beginRecoveryFixed(CRewind, CRemove)
  action beginRecoveryDA = beginRecoveryFixed(CRemove, CAppend)
  action beginRecoveryDR = beginRecoveryFixed(CRemove, CRewind)
  action beginRecoveryDD = beginRecoveryFixed(CRemove, CRemove)

  // Deliberately broken control: byte 15 is omitted from transition validation.
  action beginRecoveryBuggyGeneration = all {
    scenario.in(Set(ScenarioJointPrepare, ScenarioComposedAbort)),
    unlinkIssued == Set(),
    applyRecoveryVerdict(brokenGenerationEvidence),
  }

  action beginRecovery = {
    val provesNew = diskProvesNew(checkPayload)
    all {
      phase == COnDisk,
      unlinkIssued == Set(),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = (decisionEstablished or provesNew),
      goal' = if (provesNew) CRecoverNew else CRecoverOld,
      phase' = CRecovering,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action beginRecoveryCanonical = all {
    scenario == ScenarioControl,
    activeMode == ModePrepared,
    peerMode == ModePrepared,
    beginRecovery,
  }

  action beginRecoveryIndependent = {
    val provesNew = and {
      scenario == ScenarioControl,
      activeMode == ModeFinal,
      peerMode == ModeFinal,
      independentlyFinal,
    }
    all {
      phase == COnDisk,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = (decisionEstablished or provesNew),
      goal' = if (provesNew) CRecoverNew else CRecoverOld,
      phase' = CRecovering,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  // Deliberately broken control: exact canonical prepared modes and an exact ring are accepted
  // without the append suffix check. Keeping this predicate narrow makes the counterexample say
  // exactly which validation was removed.
  action beginRecoveryBuggyPayload = {
    val provesNew = and {
      scenario == ScenarioControl,
      activeMode == ModePrepared,
      peerMode == ModePrepared,
      exactRing,
    }
    all {
      phase == COnDisk,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = (decisionEstablished or provesNew),
      goal' = if (provesNew) CRecoverNew else CRecoverOld,
      phase' = CRecovering,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action applyAbortBodyCrash(landed: Set[int]): bool = all {
      scenario == ScenarioAbort,
      phase == CRecovering,
      goal == CRecoverOld,
      not(decisionEstablished),
      not(abortGuardSurvived),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors.union(landed),
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
  }

  action crashDuringAbortBody = {
    nondet landed = AbortBodyOffsets.powerset().oneOf()
    applyAbortBodyCrash(landed)
  }

  // The abort-order invariant depends only on whether the body barrier returned and whether the
  // separately addressed guard was issued. None, one representative changed byte, and all changed
  // bytes are the exact dependency projection of arbitrary body subsets for that obligation.
  action crashDuringAbortBodyGuardProjection = {
    nondet outcome = Set(0, 1, 2).oneOf()
    val landed = if (outcome == 0) Set()
      else if (outcome == 1) Set(23)
      else AbortBodyOffsets
    applyAbortBodyCrash(landed)
  }

  action syncAbortBody = all {
    scenario == ScenarioAbort,
    phase == CRecovering,
    goal == CRecoverOld,
    not(decisionEstablished),
    not(abortGuardSurvived),
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = AbortBodyOffsets,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = true,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  // Focused successful-barrier path for the nine fixed operation pairs. Torn final roots and torn
  // rewind truncates are checked by separate byte-level actions; this action joins their completed
  // postconditions so each mixed pair reaches the actual disk decoder.
  action applyCanonicalFinals(evidence: bool): bool = all {
    scenario == ScenarioControl,
    activeMode == ModePrepared,
    peerMode == ModePrepared,
    phase == CRecovering,
    goal == CRecoverNew,
    decisionEstablished,
    // The preceding beginRecovery transition evaluated diskProvesNew. This success refinement
    // evaluates it once more only as the current durable-evidence guard; exact root decoding is
    // checked separately from the post-state so the same 112-byte formula is not duplicated.
    evidence,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = if (decodedOperation0 == CRewind) 2
      else if (decodedOperation0 == CAppend) 7
      else 5,
    physicalLength1' = if (decodedOperation1 == CRewind) 2
      else if (decodedOperation1 == CAppend) 7
      else 5,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = observation0,
    observation1' = observation1,
  }

  action completeCanonicalFinals = applyCanonicalFinals(diskProvesNew(true))
  action completeCanonicalFinalsFromDisk = completeCanonicalFinals

  action completeCanonicalFinalsFixed(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = all {
    operation0 == expectedOp0,
    operation1 == expectedOp1,
    applyCanonicalFinals(fixedCandidateEvidence(expectedOp0, expectedOp1)),
  }

  action completeCanonicalFinalsAA = completeCanonicalFinalsFixed(CAppend, CAppend)
  action completeCanonicalFinalsAR = completeCanonicalFinalsFixed(CAppend, CRewind)
  action completeCanonicalFinalsAD = completeCanonicalFinalsFixed(CAppend, CRemove)
  action completeCanonicalFinalsRA = completeCanonicalFinalsFixed(CRewind, CAppend)
  action completeCanonicalFinalsRR = completeCanonicalFinalsFixed(CRewind, CRewind)
  action completeCanonicalFinalsRD = completeCanonicalFinalsFixed(CRewind, CRemove)
  action completeCanonicalFinalsDA = completeCanonicalFinalsFixed(CRemove, CAppend)
  action completeCanonicalFinalsDR = completeCanonicalFinalsFixed(CRemove, CRewind)
  action completeCanonicalFinalsDD = completeCanonicalFinalsFixed(CRemove, CRemove)

  // Staged exact-success cuts keep the disk-derived lifecycle non-vacuous without asking
  // Apalache to translate the depth-three product of all root maps in one run. Every constructor
  // is the explicit postcondition of the preceding successful barrier stage.
  action initCanonicalDecidedPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = all {
    checkPayload' = true,
    operation0' = chosen0,
    operation1' = chosen1,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModePrepared,
    peerMode' = ModePrepared,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
    payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
    physicalLength0' = if (chosen0 == CAppend) 7 else 5,
    physicalLength1' = if (chosen1 == CAppend) 7 else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = true,
    decisionEstablished' = true,
    goal' = CRecoverNew,
    phase' = CRecovering,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initCanonicalDecidedAA = initCanonicalDecidedPair(CAppend, CAppend)
  action initCanonicalDecidedAR = initCanonicalDecidedPair(CAppend, CRewind)
  action initCanonicalDecidedAD = initCanonicalDecidedPair(CAppend, CRemove)
  action initCanonicalDecidedRA = initCanonicalDecidedPair(CRewind, CAppend)
  action initCanonicalDecidedRR = initCanonicalDecidedPair(CRewind, CRewind)
  action initCanonicalDecidedRD = initCanonicalDecidedPair(CRewind, CRemove)
  action initCanonicalDecidedDA = initCanonicalDecidedPair(CRemove, CAppend)
  action initCanonicalDecidedDR = initCanonicalDecidedPair(CRemove, CRewind)
  action initCanonicalDecidedDD = initCanonicalDecidedPair(CRemove, CRemove)

  action initCanonicalFinalizedPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = all {
    checkPayload' = true,
    operation0' = chosen0,
    operation1' = chosen1,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
    payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
    physicalLength0' = if (chosen0 == CRewind) 2
      else if (chosen0 == CAppend) 7
      else 5,
    physicalLength1' = if (chosen1 == CRewind) 2
      else if (chosen1 == CAppend) 7
      else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = true,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initCanonicalFinalizedAA = initCanonicalFinalizedPair(CAppend, CAppend)
  action initCanonicalFinalizedAR = initCanonicalFinalizedPair(CAppend, CRewind)
  action initCanonicalFinalizedAD = initCanonicalFinalizedPair(CAppend, CRemove)
  action initCanonicalFinalizedRA = initCanonicalFinalizedPair(CRewind, CAppend)
  action initCanonicalFinalizedRR = initCanonicalFinalizedPair(CRewind, CRewind)
  action initCanonicalFinalizedRD = initCanonicalFinalizedPair(CRewind, CRemove)
  action initCanonicalFinalizedDA = initCanonicalFinalizedPair(CRemove, CAppend)
  action initCanonicalFinalizedDR = initCanonicalFinalizedPair(CRemove, CRewind)
  action initCanonicalFinalizedDD = initCanonicalFinalizedPair(CRemove, CRemove)

  action applyCanonicalUnlinks(authorized: Set[int]): bool = all {
    scenario == ScenarioControl,
    phase == CFinalized,
    names == Set(0, 1),
    authorized != Set(),
    authorized.subseteq(names),
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = authorized,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  action issueCanonicalUnlinks = all {
    independentlyFinal,
    removalNamesFromDisk == removalParticipants(operation0, operation1),
    applyCanonicalUnlinks(removalNamesFromDisk),
  }

  action issueCanonicalUnlinksFixed(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = all {
    operation0 == expectedOp0,
    operation1 == expectedOp1,
    removalParticipants(expectedOp0, expectedOp1) != Set(),
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    decisionEstablished,
    acknowledged,
    exactRing,
    decodedOperation0 == expectedOp0,
    decodedOperation1 == expectedOp1,
    participantByte(0, 7) == rootByte(0, expectedOp0, CFinal, 7),
    participantByte(1, 7) == rootByte(1, expectedOp1, CFinal, 7),
    applyCanonicalUnlinks(removalParticipants(expectedOp0, expectedOp1)),
  }

  action issueCanonicalUnlinksAD = issueCanonicalUnlinksFixed(CAppend, CRemove)
  action issueCanonicalUnlinksRD = issueCanonicalUnlinksFixed(CRewind, CRemove)
  action issueCanonicalUnlinksDA = issueCanonicalUnlinksFixed(CRemove, CAppend)
  action issueCanonicalUnlinksDR = issueCanonicalUnlinksFixed(CRemove, CRewind)
  action issueCanonicalUnlinksDD = issueCanonicalUnlinksFixed(CRemove, CRemove)

  action initCanonicalUnlinksIssuedPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = all {
    removalParticipants(chosen0, chosen1) != Set(),
    checkPayload' = true,
    operation0' = chosen0,
    operation1' = chosen1,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
    payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
    physicalLength0' = if (chosen0 == CRewind) 2
      else if (chosen0 == CAppend) 7
      else 5,
    physicalLength1' = if (chosen1 == CRewind) 2
      else if (chosen1 == CAppend) 7
      else 5,
    names' = Set(0, 1),
    abortBodySynced' = false,
    unlinkIssued' = removalParticipants(chosen0, chosen1),
    acknowledged' = true,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initCanonicalUnlinksIssuedAD =
    initCanonicalUnlinksIssuedPair(CAppend, CRemove)
  action initCanonicalUnlinksIssuedRD =
    initCanonicalUnlinksIssuedPair(CRewind, CRemove)
  action initCanonicalUnlinksIssuedDA =
    initCanonicalUnlinksIssuedPair(CRemove, CAppend)
  action initCanonicalUnlinksIssuedDR =
    initCanonicalUnlinksIssuedPair(CRemove, CRewind)
  action initCanonicalUnlinksIssuedDD =
    initCanonicalUnlinksIssuedPair(CRemove, CRemove)

  action initCanonicalCleanPair(
      chosen0: COperation,
      chosen1: COperation
  ): bool = all {
    checkPayload' = true,
    operation0' = chosen0,
    operation1' = chosen1,
    activeParticipant' = 0,
    scenario' = ScenarioControl,
    activeMode' = ModeFinal,
    peerMode' = ModeFinal,
    survivors' = Set(),
    abortGuardSurvived' = false,
    witness0' = WitnessOffsets,
    witness1' = WitnessOffsets,
    payload0' = if (chosen0 == CAppend) AppendOffsets else Set(),
    payload1' = if (chosen1 == CAppend) AppendOffsets else Set(),
    physicalLength0' = if (chosen0 == CRewind) 2
      else if (chosen0 == CAppend) 7
      else 5,
    physicalLength1' = if (chosen1 == CRewind) 2
      else if (chosen1 == CAppend) 7
      else 5,
    names' = retainedParticipants(chosen0, chosen1),
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = true,
    decisionEstablished' = true,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = CNoObservation,
    observation1' = CNoObservation,
  }

  action initCanonicalCleanAA = initCanonicalCleanPair(CAppend, CAppend)
  action initCanonicalCleanAR = initCanonicalCleanPair(CAppend, CRewind)
  action initCanonicalCleanAD = initCanonicalCleanPair(CAppend, CRemove)
  action initCanonicalCleanRA = initCanonicalCleanPair(CRewind, CAppend)
  action initCanonicalCleanRR = initCanonicalCleanPair(CRewind, CRewind)
  action initCanonicalCleanRD = initCanonicalCleanPair(CRewind, CRemove)
  action initCanonicalCleanDA = initCanonicalCleanPair(CRemove, CAppend)
  action initCanonicalCleanDR = initCanonicalCleanPair(CRemove, CRewind)
  action initCanonicalCleanDD = initCanonicalCleanPair(CRemove, CRemove)

  action crashDuringAbortGuard = {
    nondet guardLanded = Set(false, true).oneOf()
    all {
      scenario == ScenarioAbort,
      phase == CRecovering,
      goal == CRecoverOld,
      abortBodySynced,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      // abortBodySynced can only be established while the guard is still absent.
      abortGuardSurvived' = guardLanded,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action syncAbortGuard = all {
    scenario == ScenarioAbort,
    phase == CRecovering,
    goal == CRecoverOld,
    abortBodySynced,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = true,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  action applyComposedAbortBodyCrash(landed: Set[int]): bool = all {
    landed.subseteq(EncodedAbortBodies),
    scenario == ScenarioComposedAbort,
    phase == CRecovering,
    goal == CRecoverOld,
    not(decisionEstablished),
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors.union(landed),
    abortGuardSurvived' = false,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = observation0,
    observation1' = observation1,
  }

  action crashDuringComposedAbortBody = {
    nondet p = Set(0, 1).oneOf()
    nondet landed = (if (p == 0) EncodedAbortBody0 else EncodedAbortBody1)
      .powerset().oneOf()
    applyComposedAbortBodyCrash(landed)
  }

  // Both participant writes may be outstanding at one crash. Their addressed-byte survivor sets
  // are independent; this is the Cartesian fault case that symmetric one-active cuts omit.
  action crashDuringJointComposedAbortBodies = {
    nondet landed0 = EncodedAbortBody0.powerset().oneOf()
    nondet landed1 = EncodedAbortBody1.powerset().oneOf()
    applyComposedAbortBodyCrash(landed0.union(landed1))
  }

  action crashComposedAbortSharedGeneration =
    applyComposedAbortBodyCrash(Set(encodedOffset(
      EncodedAbortStage, activeParticipant, 15)))

  action syncComposedAbortBody = {
    nondet p = Set(0, 1).oneOf()
    val body = if (p == 0) EncodedAbortBody0 else EncodedAbortBody1
    all {
      scenario == ScenarioComposedAbort,
      phase == CRecovering,
      goal == CRecoverOld,
      not(decisionEstablished),
      not(composedAbortGuardSurvived(p)),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors.union(body),
      abortGuardSurvived' = false,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = unlinkIssued,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action crashDuringComposedAbortGuard = {
    nondet p = Set(0, 1).oneOf()
    nondet guardLanded = Set(false, true).oneOf()
    all {
      scenario == ScenarioComposedAbort,
      phase == CRecovering,
      goal == CRecoverOld,
      not(decisionEstablished),
      composedAbortBodySynced(p),
      not(composedAbortGuardSurvived(p)),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = if (guardLanded)
        survivors.union(Set(encodedAbortGuardOffset(p)))
      else
        survivors,
      abortGuardSurvived' = false,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action syncComposedAbortGuard = {
    nondet p = Set(0, 1).oneOf()
    all {
      scenario == ScenarioComposedAbort,
      phase == CRecovering,
      goal == CRecoverOld,
      not(decisionEstablished),
      composedAbortBodySynced(p),
      not(composedAbortGuardSurvived(p)),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors.union(Set(encodedAbortGuardOffset(p))),
      abortGuardSurvived' = false,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = unlinkIssued,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action enterComposedFinal = all {
    scenario == ScenarioComposedAbort,
    phase == CRecovering,
    goal == CRecoverNew,
    decisionEstablished,
    not(composedAbortGuardSurvived(0)),
    not(composedAbortGuardSurvived(1)),
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = ScenarioComposedFinal,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = false,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  action crashDuringComposedFinal = {
    nondet p = Set(0, 1).oneOf()
    nondet landed = (if (p == 0) EncodedFinalStage0 else EncodedFinalStage1)
      .powerset().oneOf()
    all {
      scenario == ScenarioComposedFinal,
      phase == CRecovering,
      goal == CRecoverNew,
      decisionEstablished,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors.union(landed),
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action syncComposedFinal = {
    nondet p = Set(0, 1).oneOf()
    all {
      scenario == ScenarioComposedFinal,
      phase == CRecovering,
      goal == CRecoverNew,
      decisionEstablished,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors.union(
        if (p == 0) EncodedFinalStage0 else EncodedFinalStage1),
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = unlinkIssued,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action stutter = all {
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  action finishOld = all {
    phase == CRecovering,
    goal == CRecoverOld,
    not(decisionEstablished),
    oldReady0,
    oldReady1,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = CNoGoal,
    phase' = CObserved,
    observation0' = decode0,
    observation1' = decode1,
  }

  action markFinalized = all {
    phase == CRecovering,
    goal == CRecoverNew,
    decisionEstablished,
    independentlyFinal,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = Set(),
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = CNoGoal,
    phase' = CFinalized,
    observation0' = observation0,
    observation1' = observation1,
  }

  action issueUnlink = {
    nondet p = Set(0, 1).oneOf()
    val isFinal = if (p == 0) boundFinal0 else boundFinal1
    val decoded = if (p == 0) decodedOperation0 else decodedOperation1
    all {
      phase == CFinalized,
      independentlyFinal,
      p.in(names),
      isFinal,
      decoded == CRemove,
      not(p.in(unlinkIssued)),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued.union(Set(p)),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action crashDuringUnlink = {
    nondet survived = unlinkIssued.powerset().oneOf()
    all {
      phase == CFinalized,
      unlinkIssued != Set(),
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names.exclude(survived),
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action syncUnlinks = all {
    phase == CFinalized,
    unlinkIssued != Set(),
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names.exclude(unlinkIssued),
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = Set(),
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  action applyObservation(
      decoded0: CObservation,
      decoded1: CObservation
  ): bool = all {
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = CNoGoal,
    phase' = CObserved,
    observation0' = decoded0,
    observation1' = decoded1,
  }

  action observeFinalized = all {
    phase == CFinalized,
    unlinkIssued == Set(),
    independentlyFinal,
    applyObservation(decode0, decode1),
  }

  action observeCanonicalCleaned = all {
    scenario == ScenarioControl,
    names == retainedNamesFromDisk,
    observeFinalized,
  }

  action observeCanonicalCleanedFixed(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = all {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == CFinalized,
    unlinkIssued == Set(),
    operation0 == expectedOp0,
    operation1 == expectedOp1,
    names == retainedParticipants(expectedOp0, expectedOp1),
    decisionEstablished,
    acknowledged,
    witnessValid0,
    witnessValid1,
    decodedOperation0 == expectedOp0,
    decodedOperation1 == expectedOp1,
    payloadValid(0, expectedOp0, payloadImage0, physicalLength0),
    payloadValid(1, expectedOp1, payloadImage1, physicalLength1),
    participantByte(0, 7) == rootByte(0, expectedOp0, CFinal, 7),
    participantByte(1, 7) == rootByte(1, expectedOp1, CFinal, 7),
    applyObservation(decode0, decode1),
  }

  action observeCanonicalCleanedAA = observeCanonicalCleanedFixed(CAppend, CAppend)
  action observeCanonicalCleanedAR = observeCanonicalCleanedFixed(CAppend, CRewind)
  action observeCanonicalCleanedAD = observeCanonicalCleanedFixed(CAppend, CRemove)
  action observeCanonicalCleanedRA = observeCanonicalCleanedFixed(CRewind, CAppend)
  action observeCanonicalCleanedRR = observeCanonicalCleanedFixed(CRewind, CRewind)
  action observeCanonicalCleanedRD = observeCanonicalCleanedFixed(CRewind, CRemove)
  action observeCanonicalCleanedDA = observeCanonicalCleanedFixed(CRemove, CAppend)
  action observeCanonicalCleanedDR = observeCanonicalCleanedFixed(CRemove, CRewind)
  action observeCanonicalCleanedDD = observeCanonicalCleanedFixed(CRemove, CRemove)
  action crashRecovery = all {
    phase == CRecovering,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = Set(),
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = CNoGoal,
    phase' = COnDisk,
    observation0' = observation0,
    observation1' = observation1,
  }

  action crashDuringFinal = {
    nondet landed = FinalChangedOffsets.powerset().oneOf()
    all {
      scenario == ScenarioFinal,
      phase == CRecovering,
      goal == CRecoverNew,
      decisionEstablished,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors.union(landed),
      abortGuardSurvived' = false,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = physicalLength0,
      physicalLength1' = physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action syncFinal = all {
    scenario == ScenarioFinal,
    phase == CRecovering,
    goal == CRecoverNew,
    decisionEstablished,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = peerMode,
    survivors' = FinalChangedOffsets,
    abortGuardSurvived' = false,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = false,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  // The symmetric active-participant cut checks the peer's torn write.
  action syncPeerFinal = all {
    scenario == ScenarioFinal,
    phase == CRecovering,
    goal == CRecoverNew,
    decisionEstablished,
    peerMode == ModePrepared,
    checkPayload' = checkPayload,
    operation0' = operation0,
    operation1' = operation1,
    activeParticipant' = activeParticipant,
    scenario' = scenario,
    activeMode' = activeMode,
    peerMode' = ModeFinal,
    survivors' = survivors,
    abortGuardSurvived' = abortGuardSurvived,
    witness0' = witness0,
    witness1' = witness1,
    payload0' = payload0,
    payload1' = payload1,
    physicalLength0' = physicalLength0,
    physicalLength1' = physicalLength1,
    names' = names,
    abortBodySynced' = abortBodySynced,
    unlinkIssued' = unlinkIssued,
    acknowledged' = acknowledged,
    decisionEstablished' = decisionEstablished,
    goal' = goal,
    phase' = phase,
    observation0' = observation0,
    observation1' = observation1,
  }

  action crashDuringRewindTruncate = {
    nondet p = Set(0, 1).oneOf()
    nondet lengthLanded = Set(false, true).oneOf()
    val decoded = if (p == 0) decodedOperation0 else decodedOperation1
    val currentLength = if (p == 0) physicalLength0 else physicalLength1
    all {
      phase == CRecovering,
      goal == CRecoverNew,
      decisionEstablished,
      decoded == CRewind,
      currentLength > 2,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = if (p == 0 and lengthLanded) 2 else physicalLength0,
      physicalLength1' = if (p == 1 and lengthLanded) 2 else physicalLength1,
      names' = names,
      abortBodySynced' = false,
      unlinkIssued' = Set(),
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = CNoGoal,
      phase' = COnDisk,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  action syncRewindTruncate = {
    nondet p = Set(0, 1).oneOf()
    val decoded = if (p == 0) decodedOperation0 else decodedOperation1
    val currentLength = if (p == 0) physicalLength0 else physicalLength1
    all {
      phase == CRecovering,
      goal == CRecoverNew,
      decisionEstablished,
      decoded == CRewind,
      currentLength > 2,
      checkPayload' = checkPayload,
      operation0' = operation0,
      operation1' = operation1,
      activeParticipant' = activeParticipant,
      scenario' = scenario,
      activeMode' = activeMode,
      peerMode' = peerMode,
      survivors' = survivors,
      abortGuardSurvived' = abortGuardSurvived,
      witness0' = witness0,
      witness1' = witness1,
      payload0' = payload0,
      payload1' = payload1,
      physicalLength0' = if (p == 0) 2 else physicalLength0,
      physicalLength1' = if (p == 1) 2 else physicalLength1,
      names' = names,
      abortBodySynced' = abortBodySynced,
      unlinkIssued' = unlinkIssued,
      acknowledged' = acknowledged,
      decisionEstablished' = decisionEstablished,
      goal' = goal,
      phase' = phase,
      observation0' = observation0,
      observation1' = observation1,
    }
  }

  // Focused transition sets keep Apalache from translating unrelated large powersets while
  // preserving every action that can affect the stated recovery cut.
  action abortOrderingStep = any {
    crashDuringAbortBodyGuardProjection,
    syncAbortBody,
    crashDuringAbortGuard,
    syncAbortGuard,
    stutter,
  }

  action abortStep = any {
    beginRecovery,
    crashDuringAbortBodyGuardProjection,
    syncAbortBody,
    crashDuringAbortGuard,
    syncAbortGuard,
    crashRecovery,
    finishOld,
    stutter,
  }

  action finalStep = any {
    beginRecovery,
    crashDuringFinal,
    syncFinal,
    syncPeerFinal,
    crashRecovery,
    crashDuringRewindTruncate,
    syncRewindTruncate,
    markFinalized,
    issueUnlink,
    crashDuringUnlink,
    syncUnlinks,
    observeFinalized,
    stutter,
  }

  action finalWriteStep = any {
    crashDuringFinal,
    syncFinal,
    syncPeerFinal,
    crashDuringRewindTruncate,
    syncRewindTruncate,
    stutter,
  }

  action canonicalLifecycleStep = any {
    beginRecoveryCanonical,
    completeCanonicalFinals,
    issueCanonicalUnlinks,
    crashDuringUnlink,
    syncUnlinks,
    observeCanonicalCleaned,
    stutter,
  }

  action composedReconsiderationStep = any {
    crashComposedAbortSharedGeneration,
    beginRecoveryComposed,
    enterComposedFinal,
    stutter,
  }

  action buggyGenerationStep = any {
    crashRecovery,
    beginRecoveryBuggyGeneration,
    stutter,
  }

  action correctedGenerationStep = any {
    crashRecovery,
    beginRecoveryComposed,
    stutter,
  }

  action composedRepairStep = any {
    beginRecoveryComposed,
    crashDuringComposedAbortBody,
    crashDuringJointComposedAbortBodies,
    syncComposedAbortBody,
    crashDuringComposedAbortGuard,
    syncComposedAbortGuard,
    enterComposedFinal,
    crashDuringComposedFinal,
    syncComposedFinal,
    crashRecovery,
    finishOld,
    markFinalized,
    observeFinalized,
    stutter,
  }

  action cleanupStep = any {
    beginRecoveryIndependent,
    markFinalized,
    issueUnlink,
    crashDuringUnlink,
    syncUnlinks,
    observeFinalized,
    stutter,
  }

  action step = any {
    beginRecovery,
    beginRecoveryComposed,
    beginRecoveryCanonical,
    beginRecoveryIndependent,
    crashDuringAbortBody,
    syncAbortBody,
    crashDuringAbortGuard,
    syncAbortGuard,
    crashDuringComposedAbortBody,
    crashDuringJointComposedAbortBodies,
    syncComposedAbortBody,
    crashDuringComposedAbortGuard,
    syncComposedAbortGuard,
    enterComposedFinal,
    crashRecovery,
    crashDuringFinal,
    syncFinal,
    syncPeerFinal,
    crashDuringComposedFinal,
    syncComposedFinal,
    crashDuringRewindTruncate,
    syncRewindTruncate,
    finishOld,
    markFinalized,
    completeCanonicalFinals,
    issueUnlink,
    issueCanonicalUnlinks,
    crashDuringUnlink,
    syncUnlinks,
    observeFinalized,
    observeCanonicalCleaned,
    stutter,
  }

  val oldVector = observation0 == COldObservation and observation1 == COldObservation
  val newVector = observation0 == expected0 and observation1 == expected1
  val changedOffsetQuotient = and {
    HeaderOffsets.size() == 112,
    LogicalOffsets.size() == 92,
    AbortBodyAddressedOffsets.size() == 111,
    PrepareChangedOffsets.size() == 71,
    AbortBodyOffsets.size() == 69,
    RecoveredChangedOffsets.size() == 5,
    FinalChangedOffsets.size() == 5,
    Set(0, 1).forall(p => HeaderOffsets.forall(offset =>
      offset.in(PrepareChangedOffsets) iff
        rootByte(p, CAppend, CSameSlotOld, offset) !=
          rootByte(p, CAppend, CPrepared, offset))),
    Set(0, 1).forall(p => AbortBodyAddressedOffsets.forall(offset =>
      offset.in(AbortBodyOffsets) iff
        rootByte(p, CAppend, CPrepared, offset) !=
          rootByte(p, CAppend, CAbort, offset))),
    Set(0, 1).forall(p => Operations.forall(op => HeaderOffsets.forall(offset =>
      offset.in(RecoveredChangedOffsets) iff
        rootByte(p, op, CPrepared, offset) !=
          rootByte(p, op, CRecovered, offset)))),
    Set(0, 1).forall(p => Operations.forall(op => HeaderOffsets.forall(offset =>
      offset.in(FinalChangedOffsets) iff
        rootByte(p, op, CPrepared, offset) !=
          rootByte(p, op, CFinal, offset)))),
    Set(0, 1).forall(p => and {
      rootByte(p, CAppend, CSameSlotOld, 15) == 1,
      rootByte(p, CAppend, CPredecessor, 15) == 2,
      rootByte(p, CAppend, CPrepared, 15) == 3,
      rootByte(p, CAppend, CPredecessor, 7) == 15,
      (if (p == 0)
        and {
          rootByte(p, CAppend, CPredecessor, 108) == 36,
          rootByte(p, CAppend, CPredecessor, 109) == 60,
          rootByte(p, CAppend, CPredecessor, 110) == 136,
          rootByte(p, CAppend, CPredecessor, 111) == 93,
        }
      else
        and {
          rootByte(p, CAppend, CPredecessor, 108) == 53,
          rootByte(p, CAppend, CPredecessor, 109) == 146,
          rootByte(p, CAppend, CPredecessor, 110) == 182,
          rootByte(p, CAppend, CPredecessor, 111) == 160,
        }),
      LogicalOffsets.forall(offset =>
        rootByte(p, CAppend, CPredecessor, offset) ==
          rootByte(p, CAppend, CAbort, offset)),
    }),
  }
  val groupAtomicity = phase == CObserved implies (oldVector or newVector)
  val acknowledgedDurability = (phase == CObserved and acknowledged) implies newVector
  val observationsAreDecoded = phase == CObserved implies and {
    observation0 == decode0,
    observation1 == decode1,
    observation0 != CNoObservation,
    observation1 != CNoObservation,
  }
  val acknowledgedObservationSound = phase == CObserved implies and {
    acknowledged,
    observation0 == decode0,
    observation1 == decode1,
    observation0 == expected0,
    observation1 == expected1,
  }
  val witnessMatchesIntent = and {
    witnessValid0 implies decodedOperation0 == operation0,
    witnessValid1 implies decodedOperation1 == operation1,
  }
  val rawFinal0 = Operations.exists(op => rootMatches(0, op, CFinal))
  val rawFinal1 = Operations.exists(op => rootMatches(1, op, CFinal))
  val finalHasDecision = (rawFinal0 or rawFinal1) implies decisionEstablished
  // An exact final root requires its guard byte. The prepared-write target has a distinct guard,
  // so this one-byte mismatch proves that no arbitrary subset of the addressed root bytes can
  // decode as final; expanding equality over all 112 bytes only obscures this discriminating-byte
  // argument and exhausts Apalache's heap.
  val prepareTear0NoFinal = and {
    scenario == ScenarioPrepare,
    activeParticipant == 0,
    operation0 == CAppend,
    not(decisionEstablished),
  } implies participantByte(0, 7) != rootByte(0, CAppend, CFinal, 7)
  val prepareTear1NoFinal = and {
    scenario == ScenarioPrepare,
    activeParticipant == 1,
    operation1 == CAppend,
    not(decisionEstablished),
  } implies participantByte(1, 7) != rootByte(1, CAppend, CFinal, 7)
  val jointPrepareHasNoFinalGuard = scenario == ScenarioJointPrepare implies and {
    participantByte(0, 7) != rootByte(0, operation0, CFinal, 7),
    participantByte(1, 7) != rootByte(1, operation1, CFinal, 7),
  }
  val composedFinalWriteIssued = encodedPairStageOffsets(EncodedFinalStage)
    .exists(offset => offset.in(survivors))
  val finalWriteFollowsDecision = and {
    (scenario == ScenarioFinal and survivors != Set()) implies decisionEstablished,
    (scenario == ScenarioComposedFinal and composedFinalWriteIssued) implies
      decisionEstablished,
    (scenario == ScenarioControl and activeMode == ModeFinal) implies decisionEstablished,
    peerMode == ModeFinal implies decisionEstablished,
  }
  val decisionRetainsEvidence = decisionEstablished implies diskProvesNew(true)
  val decisionPayloadSound = decisionEstablished implies and {
    payloadValid(0, operation0, payloadImage0, physicalLength0),
    payloadValid(1, operation1, payloadImage1, physicalLength1),
  }
  val canonicalRecoverySound = phase == CRecovering implies and {
    decisionEstablished,
    goal == CRecoverNew,
    decisionPayloadSound,
  }
  val incompletePayloadRejected = and {
    phase == CRecovering,
    not(payloadValid0 and payloadValid1),
  } implies and {
    not(decisionEstablished),
    goal == CRecoverOld,
  }
  val abortBodyCannotInstallGuard = and {
    and {
      scenario == ScenarioAbort,
      not(abortGuardSurvived),
    } implies participantByte(activeParticipant, 7) !=
      rootByte(activeParticipant, CAppend, CAbort, 7),
    Set(0, 1).forall(p => not(composedAbortGuardSurvived(p)) implies
      participantByte(p, 7) != rootByte(p, CAppend, CAbort, 7)),
  }
  val abortDiskDecodesOld = and {
    scenario == ScenarioAbort,
    abortGuardSurvived,
  } implies and {
    decode0 == COldObservation,
    decode1 == COldObservation,
  }
  val abortGuardIsCodeLast = and {
    abortGuardSurvived implies and {
      scenario == ScenarioAbort,
      survivors == AbortBodyOffsets,
      not(decisionEstablished),
    },
    Set(0, 1).forall(p => composedAbortGuardSurvived(p) implies and {
      composedAbortBodySynced(p),
      not(decisionEstablished),
    }),
  }
  val finalBeforeMissing = names != Set(0, 1) implies and {
    decisionEstablished,
    boundFinal0,
    boundFinal1,
    not(0.in(names)) implies operation0 == CRemove,
    not(1.in(names)) implies operation1 == CRemove,
  }
  val unlinkIsAuthorized = unlinkIssued.forall(p => and {
    p.in(names),
    if (p == 0) operation0 == CRemove and boundFinal0
    else operation1 == CRemove and boundFinal1,
  }) and (unlinkIssued != Set() implies independentlyFinal)
  val truncateAfterDecision = and {
    physicalLength0 < 5 implies decisionEstablished and operation0 == CRewind,
    physicalLength1 < 5 implies decisionEstablished and operation1 == CRewind,
  }
  val stableRecoveryDecision = and {
    phase == CRecovering,
    decisionEstablished,
  } implies goal == CRecoverNew
  val completedPairIsIndependent = and {
    or {
      and {
        scenario == ScenarioFinal,
        survivors == FinalChangedOffsets,
        peerMode == ModeFinal,
      },
      and {
        scenario == ScenarioComposedFinal,
        encodedPairStageOffsets(EncodedFinalStage).subseteq(survivors),
      },
    },
  } implies independentlyFinal
  val removalUnlinkCrashDecodesAbsent = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    operation0 == CRemove,
    operation1 == CRemove,
    decisionEstablished,
  } implies and {
    decode0 == CAbsentObservation,
    decode1 == CAbsentObservation,
  }
  val ordinaryRecoveredIsNotFinal = and {
    exactRecovered0 implies not(boundFinal0),
    exactRecovered1 implies not(boundFinal1),
  }
  val recoveredPairHasNoFinalCertificate = and {
    exactRecovered0,
    exactRecovered1,
  } implies not(finalCertificateEvidence)
  val composedRejectedCutIsOld = and {
    scenario == ScenarioComposedAbort,
    participantByte(activeParticipant, 15) ==
      rootByte(activeParticipant, CAppend, CSameSlotOld, 15),
    phase == CRecovering,
  } implies and {
    not(decisionEstablished),
    goal == CRecoverOld,
    not(composedCandidateEvidence),
  }
  val composedRejectedDiscriminator = and {
    scenario == ScenarioComposedAbort,
    participantByte(activeParticipant, 15) ==
      rootByte(activeParticipant, CAppend, CSameSlotOld, 15),
  } implies not(transitionByteAllowed(
    activeParticipant, activeOperation, 15))
  val sharedGenerationRepairReconsiders = and {
    scenario == ScenarioComposedFinal,
    encodedOffset(EncodedAbortStage, activeParticipant, 15).in(survivors),
    phase == CRecovering,
  } implies and {
    decisionEstablished,
    goal == CRecoverNew,
    composedCandidateEvidence,
  }
  val composedDecisionRetainsEvidence = and {
    scenario == ScenarioComposedFinal,
    decisionEstablished,
  } implies composedCandidateEvidence
  val generationDecisionSound = and {
    scenario.in(Set(ScenarioComposedAbort, ScenarioComposedFinal)),
    decisionEstablished,
  } implies composedCandidateEvidence
  val sharedGenerationDiscriminator = and {
    scenario.in(Set(ScenarioComposedAbort, ScenarioComposedFinal)),
    encodedOffset(EncodedAbortStage, activeParticipant, 15).in(survivors),
  } implies and {
    participantByte(activeParticipant, 15) ==
      rootByte(activeParticipant, activeOperation, CPrepared, 15),
    transitionByteAllowed(activeParticipant, activeOperation, 15),
  }
  def fixedRecoveryClassification(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = and {
    operation0 == expectedOp0,
    operation1 == expectedOp1,
    phase == CRecovering,
    scenario.in(Set(ScenarioComposedAbort, ScenarioComposedFinal)),
  } implies
    if (fixedCandidateEvidence(expectedOp0, expectedOp1)) and {
      scenario == ScenarioComposedFinal,
      decisionEstablished,
      goal == CRecoverNew,
    } else and {
      scenario == ScenarioComposedAbort,
      not(decisionEstablished),
      goal == CRecoverOld,
    }
  val fixedRecoveryClassificationAA = fixedRecoveryClassification(CAppend, CAppend)
  val fixedRecoveryClassificationAR = fixedRecoveryClassification(CAppend, CRewind)
  val fixedRecoveryClassificationAD = fixedRecoveryClassification(CAppend, CRemove)
  val fixedRecoveryClassificationRA = fixedRecoveryClassification(CRewind, CAppend)
  val fixedRecoveryClassificationRR = fixedRecoveryClassification(CRewind, CRewind)
  val fixedRecoveryClassificationRD = fixedRecoveryClassification(CRewind, CRemove)
  val fixedRecoveryClassificationDA = fixedRecoveryClassification(CRemove, CAppend)
  val fixedRecoveryClassificationDR = fixedRecoveryClassification(CRemove, CRewind)
  val fixedRecoveryClassificationDD = fixedRecoveryClassification(CRemove, CRemove)
  val composedOldObservationSound = and {
    scenario == ScenarioComposedAbort,
    phase == CObserved,
  } implies and {
    observation0 == decode0,
    observation1 == decode1,
    oldVector,
  }
  val composedOldObservedScalarSound = and {
    scenario == ScenarioComposedAbort,
    phase == CObserved,
  } implies oldVector
  val composedAbortRouteUnreached = not(and {
    scenario == ScenarioComposedAbort,
    phase == CRecovering,
    goal == CRecoverOld,
    not(decisionEstablished),
  })
  val composedFinalRouteUnreached = not(and {
    scenario == ScenarioComposedFinal,
    phase == CRecovering,
    goal == CRecoverNew,
    decisionEstablished,
  })
  val composedOldObservedUnreached = not(and {
    scenario == ScenarioComposedAbort,
    phase == CObserved,
    oldVector,
  })
  val canonicalLifecycleObservationSound = and {
    scenario == ScenarioControl,
    phase == CObserved,
  } implies and {
    observation0 == decode0,
    observation1 == decode1,
    newVector,
  }
  val canonicalPreparedOnDisk = and {
    scenario == ScenarioControl,
    activeMode == ModePrepared,
    peerMode == ModePrepared,
    exactRing,
    exactPrepared0,
    exactPrepared1,
    payloadValid0,
    payloadValid1,
    diskProvesNew(true),
  }
  val canonicalDecisionFromDisk = and {
    scenario == ScenarioControl,
    activeMode == ModePrepared,
    peerMode == ModePrepared,
    phase == CRecovering,
  } implies and {
    decisionEstablished,
    goal == CRecoverNew,
    payloadValid0,
    payloadValid1,
  }
  val canonicalFinalScalarSound = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == CFinalized,
  } implies and {
    decisionEstablished,
    participantByte(0, 7) == rootByte(0, decodedOperation0, CFinal, 7),
    participantByte(1, 7) == rootByte(1, decodedOperation1, CFinal, 7),
    physicalLength0 == (if (decodedOperation0 == CRewind) 2
      else if (decodedOperation0 == CAppend) 7
      else 5),
    physicalLength1 == (if (decodedOperation1 == CRewind) 2
      else if (decodedOperation1 == CAppend) 7
      else 5),
  }
  val canonicalFinalAndTruncateSound = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == CFinalized,
  } implies and {
    decisionEstablished,
    boundFinal0,
    boundFinal1,
    payloadValid0,
    payloadValid1,
    physicalLength0 == (if (decodedOperation0 == CRewind) 2
      else if (decodedOperation0 == CAppend) 7
      else 5),
    physicalLength1 == (if (decodedOperation1 == CRewind) 2
      else if (decodedOperation1 == CAppend) 7
      else 5),
  }
  val canonicalUnlinkIssueSound = and {
    scenario == ScenarioControl,
    phase == CFinalized,
    unlinkIssued != Set(),
  } implies and {
    independentlyFinal,
    unlinkIssued == removalNamesFromDisk,
    unlinkIssued == removalParticipants(operation0, operation1),
    retainedNamesFromDisk == retainedParticipants(operation0, operation1),
  }
  val canonicalUnlinkIssueScalarSound = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == CFinalized,
    unlinkIssued != Set(),
    acknowledged,
  } implies and {
    decisionEstablished,
    unlinkIssued == removalParticipants(operation0, operation1),
    participantByte(0, 7) == rootByte(0, operation0, CFinal, 7),
    participantByte(1, 7) == rootByte(1, operation1, CFinal, 7),
  }
  val canonicalUnlinkCrashSound = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == COnDisk,
    decisionEstablished,
  } implies and {
    boundFinal0,
    boundFinal1,
    retainedParticipants(operation0, operation1).subseteq(names),
    Set(0, 1).exclude(names).subseteq(removalParticipants(operation0, operation1)),
    decode0 == expected0,
    decode1 == expected1,
  }
  val canonicalUnlinkCrashScalarSound = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == COnDisk,
    acknowledged,
  } implies and {
    decisionEstablished,
    retainedParticipants(operation0, operation1).subseteq(names),
    Set(0, 1).exclude(names).subseteq(removalParticipants(operation0, operation1)),
    unlinkIssued == Set(),
  }
  val canonicalCleanupSound = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == CFinalized,
    names == retainedParticipants(operation0, operation1),
  } implies and {
    independentlyFinal,
    unlinkIssued == Set(),
    decode0 == expected0,
    decode1 == expected1,
  }
  val canonicalObservedFromDisk = and {
    scenario == ScenarioControl,
    phase == CObserved,
    acknowledged,
  } implies and {
    observation0 == decode0,
    observation1 == decode1,
    observation0 == expected0,
    observation1 == expected1,
  }
  def cleanDiskDecodesFixed(
      expectedOp0: COperation,
      expectedOp1: COperation
  ): bool = and {
    scenario == ScenarioControl,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
    phase == CFinalized,
    operation0 == expectedOp0,
    operation1 == expectedOp1,
    names == retainedParticipants(expectedOp0, expectedOp1),
    witnessValid0,
    witnessValid1,
    decodedOperation0 == expectedOp0,
    decodedOperation1 == expectedOp1,
  } implies and {
    decode0 == (if (expectedOp0 == CRemove) CAbsentObservation else CNewObservation),
    decode1 == (if (expectedOp1 == CRemove) CAbsentObservation else CNewObservation),
  }
  val cleanDiskDecodesAA = cleanDiskDecodesFixed(CAppend, CAppend)
  val cleanDiskDecodesAR = cleanDiskDecodesFixed(CAppend, CRewind)
  val cleanDiskDecodesAD = cleanDiskDecodesFixed(CAppend, CRemove)
  val cleanDiskDecodesRA = cleanDiskDecodesFixed(CRewind, CAppend)
  val cleanDiskDecodesRR = cleanDiskDecodesFixed(CRewind, CRewind)
  val cleanDiskDecodesRD = cleanDiskDecodesFixed(CRewind, CRemove)
  val cleanDiskDecodesDA = cleanDiskDecodesFixed(CRemove, CAppend)
  val cleanDiskDecodesDR = cleanDiskDecodesFixed(CRemove, CRewind)
  val cleanDiskDecodesDD = cleanDiskDecodesFixed(CRemove, CRemove)
  val canonicalObservedScalarSound = and {
    scenario == ScenarioControl,
    phase == CObserved,
    acknowledged,
  } implies and {
    decisionEstablished,
    observation0 == expected0,
    observation1 == expected1,
  }
  // Deliberately negated cover predicates. Their focused depth-one checks must return violations,
  // proving that each staged action and each double-remove namespace outcome is reachable.
  val canonicalRecoveryUnreached = not(and {
    scenario == ScenarioControl,
    phase == CRecovering,
    decisionEstablished,
    goal == CRecoverNew,
  })
  val canonicalFinalizedUnreached = not(and {
    scenario == ScenarioControl,
    phase == CFinalized,
    activeMode == ModeFinal,
    peerMode == ModeFinal,
  })
  val canonicalObservedUnreached = not(and {
    scenario == ScenarioControl,
    phase == CObserved,
  })
  val ddPostUnlinkNames01Unreached = not(and {
    phase == COnDisk,
    operation0 == CRemove,
    operation1 == CRemove,
    names == Set(0, 1),
  })
  val ddPostUnlinkNames0Unreached = not(and {
    phase == COnDisk,
    operation0 == CRemove,
    operation1 == CRemove,
    names == Set(0),
  })
  val ddPostUnlinkNames1Unreached = not(and {
    phase == COnDisk,
    operation0 == CRemove,
    operation1 == CRemove,
    names == Set(1),
  })
  val ddPostUnlinkNamesEmptyUnreached = not(and {
    phase == COnDisk,
    operation0 == CRemove,
    operation1 == CRemove,
    names == Set(),
  })
  val abortDoesNotFollowDecision = (exactAbort0 or exactAbort1) implies
    not(decisionEstablished)
  val oldObservationIsQuiescent = (phase == CObserved and oldVector) implies
    oldReady0 and oldReady1
  val typeOk = and {
    operation0.in(Operations),
    operation1.in(Operations),
    activeParticipant.in(Set(0, 1)),
    scenario.in(Set(
      ScenarioPrepare,
      ScenarioAbort,
      ScenarioFinal,
      ScenarioControl,
      ScenarioJointPrepare,
      ScenarioComposedAbort,
      ScenarioComposedFinal)),
    activeMode.in(Set(ModeOld, ModePrepared, ModeAbort, ModeFinal)),
    peerMode.in(Set(ModeOld, ModePrepared, ModeAbort, ModeFinal)),
    survivors.subseteq(
      if (scenario == ScenarioPrepare) PrepareChangedOffsets
      else if (scenario == ScenarioAbort) AbortBodyOffsets
      else if (scenario == ScenarioFinal) FinalChangedOffsets
      else if (scenario == ScenarioJointPrepare) EncodedPrepareRecoveredOffsets
      else if (scenario == ScenarioComposedAbort)
        EncodedPrepareRecoveredOffsets.union(EncodedAbortStages)
      else if (scenario == ScenarioComposedFinal) EncodedSurvivorOffsets
      else Set()),
    scenario == ScenarioControl implies survivors == Set(),
    abortGuardSurvived implies scenario == ScenarioAbort,
    abortBodySynced implies and {
      scenario == ScenarioAbort,
      survivors == AbortBodyOffsets,
      phase == CRecovering,
      goal == CRecoverOld,
    },
    witness0.subseteq(WitnessOffsets),
    witness1.subseteq(WitnessOffsets),
    payload0.subseteq(AppendOffsets),
    payload1.subseteq(AppendOffsets),
    physicalLength0.in(Set(2, 5, 7)),
    physicalLength1.in(Set(2, 5, 7)),
    names.subseteq(Set(0, 1)),
    unlinkIssued.subseteq(Set(0, 1)),
    witnessImage0.keys() == WitnessOffsets,
    witnessImage1.keys() == WitnessOffsets,
    payloadImage0.keys() == PayloadOffsets,
    payloadImage1.keys() == PayloadOffsets,
  }
  val codecSafe = and {
    typeOk,
    changedOffsetQuotient,
    witnessMatchesIntent,
    finalHasDecision,
    jointPrepareHasNoFinalGuard,
    finalWriteFollowsDecision,
    abortBodyCannotInstallGuard,
    abortGuardIsCodeLast,
    abortDoesNotFollowDecision,
    ordinaryRecoveredIsNotFinal,
    recoveredPairHasNoFinalCertificate,
  }
  val controlSafe = and {
    typeOk,
    witnessMatchesIntent,
    decisionRetainsEvidence,
    decisionPayloadSound,
    finalBeforeMissing,
    unlinkIsAuthorized,
    truncateAfterDecision,
    composedRejectedDiscriminator,
    sharedGenerationDiscriminator,
    generationDecisionSound,
    canonicalDecisionFromDisk,
    canonicalFinalAndTruncateSound,
    canonicalUnlinkCrashSound,
    canonicalCleanupSound,
  }
  val observationSafe = and {
    typeOk,
    groupAtomicity,
    acknowledgedDurability,
    observationsAreDecoded,
    oldObservationIsQuiescent,
    canonicalLifecycleObservationSound,
    canonicalObservedFromDisk,
    composedOldObservationSound,
  }
  val abortSafe = and {
    typeOk,
    abortBodyCannotInstallGuard,
    abortGuardIsCodeLast,
    abortDoesNotFollowDecision,
    observationSafe,
  }
  val abortOrderingSafe = and {
    abortBodyCannotInstallGuard,
    abortGuardIsCodeLast,
    abortDoesNotFollowDecision,
  }
  val finalRepairSafe = and {
    typeOk,
    finalHasDecision,
    finalWriteFollowsDecision,
    decisionRetainsEvidence,
    decisionPayloadSound,
    finalBeforeMissing,
    unlinkIsAuthorized,
    truncateAfterDecision,
    observationSafe,
  }
  val finalOrderingSafe = and {
    finalWriteFollowsDecision,
    completedPairIsIndependent,
    truncateAfterDecision,
  }
  val safe = and { codecSafe, controlSafe, observationSafe }
}
