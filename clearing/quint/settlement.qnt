// Certification, FIFO settlement, faults, claims, and terminal recovery.
module settlement {
    import types.* from "./types"

    const ACCOUNTS: Set[Account]
    const ACCOUNT_INDEX: Account -> int
    const ACCOUNT_SLICE: Account -> SliceId
    const BATCHES: Set[BatchId]
    const VALID_BATCHES: Set[BatchId]
    const CANDIDATES: BatchId -> Candidate
    const REGISTRATIONS: RegistrationId -> Registration
    const SLICE_IDS: Set[SliceId]
    const STATE_CONTENT: RootId -> (Account -> AccountState)
    const DEPOSIT_CONTENT: RootId -> (Account -> int)
    const WITHDRAWAL_CONTENT: RootId -> (Account -> WithdrawalSlot)
    const OUTPUT_CONTENT: RootId -> Set[PositionedWithdrawalOutput]
    const COVERAGE_CONTENT: RootId -> (int -> Boundary)
    const CREDIT_TIP_CONTENT: RootId -> Set[ShardHead]
    const CHANGE_OWNER: RootId -> BatchId
    import transition(
        ACCOUNTS = ACCOUNTS,
        ACCOUNT_INDEX = ACCOUNT_INDEX,
        ACCOUNT_SLICE = ACCOUNT_SLICE,
        BATCHES = BATCHES,
        CANDIDATES = CANDIDATES,
        REGISTRATIONS = REGISTRATIONS,
        SLICE_IDS = SLICE_IDS,
        STATE_CONTENT = STATE_CONTENT,
        DEPOSIT_CONTENT = DEPOSIT_CONTENT,
        WITHDRAWAL_CONTENT = WITHDRAWAL_CONTENT,
        OUTPUT_CONTENT = OUTPUT_CONTENT,
        COVERAGE_CONTENT = COVERAGE_CONTENT,
        CREDIT_TIP_CONTENT = CREDIT_TIP_CONTENT,
        CHANGE_OWNER = CHANGE_OWNER,
    ) as proof from "./transition"

    const VALIDATORS: Set[Validator]
    const HONEST: Set[Validator]
    const BYZANTINE: Set[Validator]
    const HOLDERS: SliceId -> Set[Validator]
    const QUORUM: int
    const MAX_PENDING: int
    const PIPELINE_SLOTS: Set[int]
    const FINALIZED_SLOTS: Set[int]
    const MAX_ADMISSION_DELAY: int
    const MIN_CHALLENGE_DURATION: int
    const MAX_CHALLENGE_DURATION: int
    const DEPOSIT_TIMEOUT: int
    const MIN_WITHDRAWAL_NOTICE: int
    const MAX_WITHDRAWAL_NOTICE: int
    const TIMES: Set[int]
    const TIME_HORIZON: int
    const DEPOSIT_EVENTS: Set[DepositEvent]
    const WITHDRAWALS: Set[Withdrawal]
    const EVIDENCE: Set[ChallengeEvidence]
    const WITHDRAWAL_CLAIMS: Set[WithdrawalClaim]
    const PAYOUT_CLAIMS: Set[PayoutClaim]
    const INITIAL_EPOCH: int
    const INITIAL_ROOT: TypedRoot
    const INITIAL_STATE: Account -> AccountState
    const EMPTY_STATE_ROOT: TypedRoot

    pure val NO_DEADLINE = -1
    pure val NO_FENCE = -1
    pure val NEVER = 1000000

    var chain: ChainState
    var certification: CertificationState

    pure def healthy(fault: Fault): bool =
        match fault {
            | Healthy => true
            | ProvenChallenge(_) => false
            | ExpiredDeposit => false
            | ExpiredWithdrawal => false
            | ExpiredRegistration(_) => false
        }

    pure def dormant(terminal: Terminal): bool =
        match terminal {
            | Dormant => true
            | Claiming(_) => false
            | Settled => false
        }

    pure def settled(terminal: Terminal): bool =
        match terminal {
            | Dormant => false
            | Claiming(_) => false
            | Settled => true
        }

    def is_registered(batch: BatchId): bool =
        match chain.registered {
            | NoRegistration => false
            | SomeRegistration(registration) => and {
                CANDIDATES.get(batch).registration == registration,
                proof::registration_holds(CANDIDATES.get(batch)),
            }
        }

    def unfinalized_deposit_total(): int =
        ACCOUNTS.fold(0, (total, account) => total + chain.unfinalized_deposits.get(account))

    def refund_total(): int =
        ACCOUNTS.fold(0, (total, account) => total + chain.refunded_deposits.get(account))

    def recovered_state_total(): int =
        ACCOUNTS.fold(0, (total, account) => total + chain.recovered_state.get(account))

    def reserve_total(): int =
        BATCHES.fold(0, (total, batch) =>
            total
                + chain.withdrawal_reserve.get(batch)
                + chain.payout_reserve.get(batch))

    def occupied_pipeline_slots(): Set[int] =
        PIPELINE_SLOTS.filter(slot => slot < chain.pipeline.length())

    def finalized_slots(): Set[int] =
        FINALIZED_SLOTS.filter(slot => slot < chain.finalized_epochs.length())

    def pipeline_contains(batch: BatchId): bool =
        occupied_pipeline_slots.exists(slot => chain.pipeline[slot] == batch)

    def pipeline_has_duplicates(): bool =
        tuples(occupied_pipeline_slots, occupied_pipeline_slots).exists(((left, right)) => and {
            left != right,
            chain.pipeline[left] == chain.pipeline[right],
        })

    def pipeline_descends_from(ancestor: BatchId, batch: BatchId): bool =
        tuples(occupied_pipeline_slots, occupied_pipeline_slots).exists(((left, right)) => and {
            left < right,
            chain.pipeline[left] == ancestor,
            chain.pipeline[right] == batch,
        })

    def next_admission_epoch(): int =
        if (chain.pipeline.length() == 0)
            chain.expected_epoch
        else
            CANDIDATES.get(chain.pipeline[chain.pipeline.length() - 1]).context.epoch + 1

    def head_root(): TypedRoot =
        if (chain.pipeline.length() == 0)
            chain.current_root
        else
            CANDIDATES.get(chain.pipeline[chain.pipeline.length() - 1]).roots.successor

    def head_state(): Account -> AccountState =
        if (chain.pipeline.length() == 0)
            chain.current_state
        else
            CANDIDATES.get(chain.pipeline[chain.pipeline.length() - 1]).successor_state

    def head_liability(): int = proof::state_liability(head_state)

    pure def withdrawal_defers_deposit(slot: WithdrawalSlot, deposit: int): bool =
        match slot {
            | NoWithdrawal => false
            | Requested(request) => match request.withdrawal_action {
                | Amount(amount) => amount == deposit
                | Close => false
            }
        }

    def boundary_deposits(): Account -> int = ACCOUNTS.mapBy(account => {
        val deposit = chain.pending_deposits.get(account)
        if (withdrawal_defers_deposit(chain.pending_withdrawals.get(account), deposit))
            0
        else
            deposit
    })

    def registration_inputs_match(registration: Registration): bool = and {
        registration.deposits == boundary_deposits,
        registration.withdrawals == chain.pending_withdrawals,
    }

    def deadline_policy_holds(registration: Registration): bool = {
        val base = if (chain.pipeline.length() == 0)
            chain.now
        else
            CANDIDATES.get(chain.pipeline[chain.pipeline.length() - 1])
                .context.admission_deadline
        val duration = registration.context.challenge_deadline
            - registration.context.admission_deadline
        and {
            if (chain.pipeline.length() == 0)
                registration.context.admission_deadline >= base
            else
                registration.context.admission_deadline > base,
            registration.context.admission_deadline <= base + MAX_ADMISSION_DELAY,
            duration >= MIN_CHALLENGE_DURATION,
            duration <= MAX_CHALLENGE_DURATION,
        }
    }

    pure def withdrawal_affordable(request: Withdrawal, state: AccountState): bool = and {
        state.active,
        match request.withdrawal_action {
            | Amount(amount) => amount > 0 and amount <= state.balance
            | Close => true
        },
    }

    def withdrawal_safe(request: Withdrawal): bool = and {
        request.context_root == chain.current_root.digest,
        withdrawal_affordable(request, chain.current_state.get(request.account)),
        occupied_pipeline_slots.forall(index =>
            withdrawal_affordable(
                request,
                CANDIDATES.get(chain.pipeline[index]).successor_state.get(request.account))),
    }

    pure def exact_delivery(batch: BatchId, validator: Validator): DeliveryKey = {
        batch: batch,
        validator: validator,
    }

    pure def assigned_slices(batch: BatchId, validator: Validator): Set[SliceRef] =
        SLICE_IDS
            .filter(index => validator.in(HOLDERS.get(index)))
            .map(index => { batch: batch, slice: index })

    pure def assigned_slice_ids(validator: Validator): Set[SliceId] =
        SLICE_IDS.filter(index => validator.in(HOLDERS.get(index)))

    def certified(batch: BatchId): bool = batch.in(certification.certificates)

    def can_record_deposit(event: DepositEvent): bool = and {
        healthy(chain.fault),
        dormant(chain.terminal),
        chain.registered == NoRegistration,
        event.account.in(ACCOUNTS),
        event.amount > 0,
        not(event.id.in(chain.consumed_deposits)),
        chain.now + DEPOSIT_TIMEOUT <= TIME_HORIZON,
    }

    def can_register(id: RegistrationId): bool =
        if (not(id.in(REGISTRATIONS.keys())))
            false
        else {
            val registration = REGISTRATIONS.get(id)
            and {
                healthy(chain.fault),
                dormant(chain.terminal),
                chain.registered == NoRegistration,
                chain.pipeline.length() < MAX_PENDING,
                chain.now <= registration.context.admission_deadline,
                registration.context.epoch == next_admission_epoch,
                registration.context.predecessor == head_root,
                registration.predecessor_state == head_state,
                registration.context.predecessor_liability == head_liability,
                proof::registration_roots_hold(registration),
                registration_inputs_match(registration),
                deadline_policy_holds(registration),
            }
        }

    def can_seal(batch: BatchId, validator: Validator): bool = {
        val candidate = CANDIDATES.get(batch)
        val slices = assigned_slice_ids(validator)
        and {
            validator.in(HONEST),
            is_registered(batch),
            exact_delivery(batch, validator).in(certification.exact_deliveries),
            proof::header_holds(candidate),
            slices.forall(index => proof::slice_holds(candidate, index)),
            proof::dealing_signatures_hold(candidate, slices),
            not(validator.in(certification.votes.get(batch))),
            certification.votes.get(batch).size() < QUORUM,
        }
    }

    action init = all {
        chain' = {
            now: 0,
            expected_epoch: INITIAL_EPOCH,
            current_root: INITIAL_ROOT,
            current_state: INITIAL_STATE,
            current_liability: proof::state_liability(INITIAL_STATE),
            custody: proof::state_liability(INITIAL_STATE),
            claimable: 0,
            total_in: proof::state_liability(INITIAL_STATE),
            released: 0,
            clean_claim_paid: 0,
            pending_deposits: ACCOUNTS.mapBy(_ => 0),
            deposit_deadlines: ACCOUNTS.mapBy(_ => NO_DEADLINE),
            unfinalized_deposits: ACCOUNTS.mapBy(_ => 0),
            pending_withdrawals: ACCOUNTS.mapBy(_ => NoWithdrawal),
            outstanding_withdrawals: ACCOUNTS.mapBy(_ => NoWithdrawal),
            registered: NoRegistration,
            pipeline: List(),
            status: BATCHES.mapBy(_ => Inactive),
            fault: Healthy,
            fault_history: Set(),
            admission_fence_epoch: NO_FENCE,
            invalid_from: NoBatch,
            terminal: Dormant,
            withdrawal_reserve: BATCHES.mapBy(_ => 0),
            payout_reserve: BATCHES.mapBy(_ => 0),
            consumed_claims: Set(),
            consumed_state: Set(),
            consumed_deposits: Set(),
            consumed_withdrawals: Set(),
            finalized_batches: Set(),
            invalidated_batches: Set(),
            finalized_epochs: List(),
            refunded_deposits: ACCOUNTS.mapBy(_ => 0),
            recovered_state: ACCOUNTS.mapBy(_ => 0),
            terminal_withdrawals: ACCOUNTS.mapBy(_ => 0),
            terminal_residuals: ACCOUNTS.mapBy(_ => 0),
        },
        certification' = {
            prepared: Set(),
            dealt: Set(),
            exact_deliveries: Set(),
            votes: BATCHES.mapBy(_ => Set()),
            retained: VALIDATORS.mapBy(_ => Set()),
            certificates: Set(),
        },
    }

    action record_deposit(event: DepositEvent): bool = all {
        can_record_deposit(event),

        val old_amount = chain.pending_deposits.get(event.account)
        val old_deadline = chain.deposit_deadlines.get(event.account)
        val deadline = chain.now + DEPOSIT_TIMEOUT
        val next_deadline = if (old_amount == 0)
            deadline
        else
            proof::minimum(old_deadline, deadline)

        chain' = {
            ...chain,
            custody: chain.custody + event.amount,
            total_in: chain.total_in + event.amount,
            pending_deposits: chain.pending_deposits
                .set(event.account, old_amount + event.amount),
            deposit_deadlines: chain.deposit_deadlines
                .set(event.account, next_deadline),
            unfinalized_deposits: chain.unfinalized_deposits.setBy(
                event.account,
                amount => amount + event.amount),
            consumed_deposits: chain.consumed_deposits.union(Set(event.id)),
        },
        certification' = certification,
    }

    action queue_withdrawal(request: Withdrawal): bool = all {
        healthy(chain.fault),
        dormant(chain.terminal),
        chain.registered == NoRegistration,
        request.in(WITHDRAWALS),
        request.account.in(ACCOUNTS),
        not(request.id.in(chain.consumed_withdrawals)),
        chain.pending_withdrawals.get(request.account) == NoWithdrawal,
        chain.outstanding_withdrawals.get(request.account) == NoWithdrawal,
        request.deadline >= chain.now + MIN_WITHDRAWAL_NOTICE,
        request.deadline <= chain.now + MAX_WITHDRAWAL_NOTICE,
        request.deadline <= TIME_HORIZON,
        request.signature_valid,
        request.destination_eligible,
        withdrawal_safe(request),

        chain' = {
            ...chain,
            pending_withdrawals: chain.pending_withdrawals
                .set(request.account, Requested(request)),
            outstanding_withdrawals: chain.outstanding_withdrawals
                .set(request.account, Requested(request)),
            consumed_withdrawals: chain.consumed_withdrawals.union(Set(request.id)),
        },
        certification' = certification,
    }

    action register(id: RegistrationId): bool = all {
        can_register(id),
        chain' = { ...chain, registered: SomeRegistration(id) },
        certification' = certification,
    }

    action prepare(batch: BatchId): bool = all {
        is_registered(batch),
        not(batch.in(certification.prepared)),
        chain' = chain,
        certification' = {
            ...certification,
            prepared: certification.prepared.union(Set(batch)),
        },
    }

    action deal(batch: BatchId): bool = all {
        is_registered(batch),
        batch.in(certification.prepared),
        not(batch.in(certification.dealt)),
        chain' = chain,
        certification' = {
            ...certification,
            dealt: certification.dealt.union(Set(batch)),
        },
    }

    action deliver_exact(batch: BatchId, validator: Validator): bool = all {
        is_registered(batch),
        batch.in(certification.dealt),
        validator.in(VALIDATORS),
        not(exact_delivery(batch, validator).in(certification.exact_deliveries)),
        chain' = chain,
        certification' = {
            ...certification,
            exact_deliveries: certification.exact_deliveries
                .union(Set(exact_delivery(batch, validator))),
        },
    }

    action seal(batch: BatchId, validator: Validator): bool = all {
        can_seal(batch, validator),

        chain' = chain,
        certification' = {
            ...certification,
            votes: certification.votes.setBy(
                batch,
                signers => signers.union(Set(validator))),
            retained: certification.retained.setBy(
                validator,
                retained => retained.union(assigned_slices(batch, validator))),
        },
    }

    action byzantine_vote(batch: BatchId, validator: Validator): bool = all {
        validator.in(BYZANTINE),
        is_registered(batch),
        batch.in(certification.dealt),
        not(validator.in(certification.votes.get(batch))),
        certification.votes.get(batch).size() < QUORUM,

        chain' = chain,
        certification' = {
            ...certification,
            votes: certification.votes.setBy(
                batch,
                signers => signers.union(Set(validator))),
        },
    }

    action form_certificate(batch: BatchId): bool = all {
        is_registered(batch),
        certification.votes.get(batch).size() == QUORUM,
        not(batch.in(certification.certificates)),
        chain' = chain,
        certification' = {
            ...certification,
            certificates: certification.certificates.union(Set(batch)),
        },
    }

    action admit(batch: BatchId): bool = {
        val candidate = CANDIDATES.get(batch)
        all {
            healthy(chain.fault),
            dormant(chain.terminal),
            is_registered(batch),
            certified(batch),
            proof::public_relation_holds(batch),
            chain.now <= candidate.context.admission_deadline,
            chain.pipeline.length() < MAX_PENDING,

            chain' = {
                ...chain,
                registered: NoRegistration,
                pipeline: chain.pipeline.append(batch),
                status: chain.status.set(batch, Pending),
                pending_deposits: ACCOUNTS.mapBy(account =>
                    chain.pending_deposits.get(account) - candidate.deposits.get(account)),
                deposit_deadlines: ACCOUNTS.mapBy(account =>
                    if (chain.pending_deposits.get(account) == candidate.deposits.get(account))
                        NO_DEADLINE
                    else
                        chain.deposit_deadlines.get(account)),
                pending_withdrawals: ACCOUNTS.mapBy(_ => NoWithdrawal),
            },
            certification' = certification,
        }
    }

    // Endpoint transition for lifecycle model checking. Proof and certification
    // soundness are exercised by the full actions and scenario suite.
    action admit_valid(batch: BatchId): bool = {
        val candidate = CANDIDATES.get(batch)
        all {
            batch.in(VALID_BATCHES),
            healthy(chain.fault),
            dormant(chain.terminal),
            is_registered(batch),
            chain.now <= candidate.context.admission_deadline,
            chain.pipeline.length() < MAX_PENDING,

            chain' = {
                ...chain,
                registered: NoRegistration,
                pipeline: chain.pipeline.append(batch),
                status: chain.status.set(batch, Pending),
                pending_deposits: ACCOUNTS.mapBy(account =>
                    chain.pending_deposits.get(account) - candidate.deposits.get(account)),
                deposit_deadlines: ACCOUNTS.mapBy(account =>
                    if (chain.pending_deposits.get(account) == candidate.deposits.get(account))
                        NO_DEADLINE
                    else
                        chain.deposit_deadlines.get(account)),
                pending_withdrawals: ACCOUNTS.mapBy(_ => NoWithdrawal),
            },
            certification' = certification,
        }
    }

    def registration_expiry(): int =
        match chain.registered {
            | NoRegistration => NEVER
            | SomeRegistration(id) => REGISTRATIONS.get(id).context.admission_deadline + 1
        }

    def deposit_expiry(): int =
        ACCOUNTS
            .filter(account => chain.pending_deposits.get(account) > 0)
            .fold(NEVER, (earliest, account) =>
                proof::minimum(earliest, chain.deposit_deadlines.get(account)))

    def withdrawal_expiry(): int =
        ACCOUNTS
            .filter(account => proof::is_requested(chain.outstanding_withdrawals.get(account)))
            .fold(NEVER, (earliest, account) =>
                match chain.outstanding_withdrawals.get(account) {
                    | NoWithdrawal => earliest
                    | Requested(request) => proof::minimum(earliest, request.deadline)
                })

    def observed_fault(at: int): Fault = {
        val registration = registration_expiry
        val withdrawal = withdrawal_expiry
        val deposit = deposit_expiry
        val first = proof::minimum(registration, proof::minimum(withdrawal, deposit))
        if (first > at)
            Healthy
        else if (registration == first)
            match chain.registered {
                | NoRegistration => Healthy
                | SomeRegistration(id) => ExpiredRegistration({
                    anchor: REGISTRATIONS.get(id).context.anchor,
                    epoch: REGISTRATIONS.get(id).context.epoch,
                    expired_at: REGISTRATIONS.get(id).context.admission_deadline,
                })
            }
        else if (withdrawal == first)
            ExpiredWithdrawal
        else
            ExpiredDeposit
    }

    action observe_time(at: int): bool = {
        val newly_observed = if (healthy(chain.fault)) observed_fault(at) else chain.fault
        val newly_faulted = healthy(chain.fault) and not(healthy(newly_observed))
        all {
            at.in(TIMES),
            at >= chain.now,
            chain' = {
                ...chain,
                now: at,
                fault: newly_observed,
                fault_history: if (newly_faulted)
                    chain.fault_history.union(Set(newly_observed))
                else
                    chain.fault_history,
                admission_fence_epoch: if (newly_faulted)
                    next_admission_epoch
                else
                    chain.admission_fence_epoch,
                registered: if (newly_faulted) NoRegistration else chain.registered,
            },
            certification' = certification,
        }
    }

    action rejected_call: bool = all {
        chain' = chain,
        certification' = certification,
    }

    action challenge(target: BatchId, evidence: ChallengeEvidence): bool = all {
        dormant(chain.terminal),
        pipeline_contains(target),
        chain.status.get(target) == Pending,
        chain.now <= CANDIDATES.get(target).context.challenge_deadline,

        if (proof::evidence_proves(target, evidence)) {
            val newly_faulted = healthy(chain.fault)
            val fence_epoch = next_admission_epoch
            chain' = {
                ...chain,
                status: BATCHES.mapBy(batch =>
                    if (batch == target)
                        Challenged(proof::evidence_kind(evidence))
                    else if (pipeline_descends_from(target, batch))
                        Invalidated(target)
                    else
                        chain.status.get(batch)),
                fault: if (newly_faulted)
                    ProvenChallenge({
                        batch: target,
                        kind: proof::evidence_kind(evidence),
                    })
                else
                    chain.fault,
                fault_history: if (newly_faulted)
                    chain.fault_history.union(Set(ProvenChallenge({
                        batch: target,
                        kind: proof::evidence_kind(evidence),
                    })))
                else
                    chain.fault_history,
                admission_fence_epoch: if (newly_faulted)
                    fence_epoch
                else
                    chain.admission_fence_epoch,
                registered: if (newly_faulted) NoRegistration else chain.registered,
                invalid_from: SomeBatch(target),
                invalidated_batches: chain.invalidated_batches.union(
                    BATCHES.filter(batch =>
                        batch == target or pipeline_descends_from(target, batch))),
            }
        } else {
            chain' = chain
        },
        certification' = certification,
    }

    // Contradiction endpoint for lifecycle checking after evidence adjudication.
    action challenge_proven(target: BatchId, kind: ChallengeKind): bool = all {
        dormant(chain.terminal),
        pipeline_contains(target),
        chain.status.get(target) == Pending,
        chain.now <= CANDIDATES.get(target).context.challenge_deadline,

        val newly_faulted = healthy(chain.fault)
        val proven = ProvenChallenge({ batch: target, kind: kind })
        chain' = {
            ...chain,
            status: BATCHES.mapBy(batch =>
                if (batch == target)
                    Challenged(kind)
                else if (pipeline_descends_from(target, batch))
                    Invalidated(target)
                else
                    chain.status.get(batch)),
            fault: if (newly_faulted) proven else chain.fault,
            fault_history: if (newly_faulted)
                chain.fault_history.union(Set(proven))
            else
                chain.fault_history,
            admission_fence_epoch: if (newly_faulted)
                next_admission_epoch
            else
                chain.admission_fence_epoch,
            registered: if (newly_faulted) NoRegistration else chain.registered,
            invalid_from: SomeBatch(target),
            invalidated_batches: chain.invalidated_batches.union(
                BATCHES.filter(batch =>
                    batch == target or pipeline_descends_from(target, batch))),
        },
        certification' = certification,
    }

    action finalize: bool =
        if (chain.pipeline.length() == 0)
            all {
                false,
                chain' = chain,
                certification' = certification,
            }
        else {
            val batch = chain.pipeline[0]
            val candidate = CANDIDATES.get(batch)
            val prefix = proof::terminal_prefix(candidate)
            val reserve = prefix.withdrawal + prefix.payout
            all {
                dormant(chain.terminal),
                chain.status.get(batch) == Pending,
                chain.now > candidate.context.challenge_deadline,
                candidate.context.epoch == chain.expected_epoch,
                chain.custody >= reserve,
                chain.unfinalized_deposits.keys() == ACCOUNTS,

                chain' = {
                    ...chain,
                    expected_epoch: chain.expected_epoch + 1,
                    current_root: candidate.roots.successor,
                    current_state: candidate.successor_state,
                    current_liability: proof::state_liability(candidate.successor_state),
                    custody: chain.custody - reserve,
                    claimable: chain.claimable + reserve,
                    unfinalized_deposits: ACCOUNTS.mapBy(account =>
                        chain.unfinalized_deposits.get(account)
                            - candidate.deposits.get(account)),
                    outstanding_withdrawals: ACCOUNTS.mapBy(account =>
                        if (proof::is_requested(candidate.withdrawals.get(account)))
                            NoWithdrawal
                        else
                            chain.outstanding_withdrawals.get(account)),
                    pipeline: chain.pipeline.tail(),
                    status: chain.status.set(batch, Finalized),
                    withdrawal_reserve: chain.withdrawal_reserve
                        .setBy(batch, amount => amount + prefix.withdrawal),
                    payout_reserve: chain.payout_reserve
                        .setBy(batch, amount => amount + prefix.payout),
                    finalized_batches: chain.finalized_batches.union(Set(batch)),
                    finalized_epochs: chain.finalized_epochs.append(candidate.context.epoch),
                },
                certification' = certification,
            }
        }

    action claim_withdrawal(target: BatchId, claim: WithdrawalClaim): bool = {
        val amount = claim.output.output.amount
        val key: ClaimKey = {
            kind: WithdrawalClaimKind,
            batch: target,
            position: claim.output.position,
        }
        all {
            target.in(chain.finalized_batches),
            proof::withdrawal_claim_holds(target, claim),
            not(key.in(chain.consumed_claims)),
            amount <= chain.withdrawal_reserve.get(target),

            chain' = {
                ...chain,
                claimable: chain.claimable - amount,
                released: chain.released + amount,
                clean_claim_paid: chain.clean_claim_paid + amount,
                withdrawal_reserve: chain.withdrawal_reserve
                    .setBy(target, remaining => remaining - amount),
                consumed_claims: chain.consumed_claims.union(Set(key)),
            },
            certification' = certification,
        }
    }

    action claim_payout(target: BatchId, claim: PayoutClaim): bool = {
        val amount = claim.output.amount
        val key: ClaimKey = {
            kind: PayoutClaimKind,
            batch: target,
            position: claim.output.position,
        }
        all {
            target.in(chain.finalized_batches),
            proof::payout_claim_holds(target, claim),
            not(key.in(chain.consumed_claims)),
            amount <= chain.payout_reserve.get(target),

            chain' = {
                ...chain,
                claimable: chain.claimable - amount,
                released: chain.released + amount,
                clean_claim_paid: chain.clean_claim_paid + amount,
                payout_reserve: chain.payout_reserve
                    .setBy(target, remaining => remaining - amount),
                consumed_claims: chain.consumed_claims.union(Set(key)),
            },
            certification' = certification,
        }
    }

    def deposit_claim_amount(account: Account): int =
        match chain.terminal {
            | Dormant => chain.pending_deposits.get(account)
            | Claiming(_) => chain.unfinalized_deposits.get(account)
            | Settled => 0
        }

    action claim_deposit(account: Account): bool = {
        val amount = deposit_claim_amount(account)
        val next_unfinalized = chain.unfinalized_deposits.get(account) - amount
        val next_terminal = match chain.terminal {
            | Dormant => Dormant
            | Claiming(claims) => {
                val remaining = claims.remaining_deposits - amount
                if (claims.remaining_state == 0 and remaining == 0)
                    Settled
                else
                    Claiming({ ...claims, remaining_deposits: remaining })
            }
            | Settled => Settled
        }
        val finishes = settled(next_terminal)
        all {
            not(healthy(chain.fault)),
            not(settled(chain.terminal)),
            account.in(ACCOUNTS),
            amount > 0,
            amount <= chain.custody,

            chain' = {
                ...chain,
                current_root: if (finishes) EMPTY_STATE_ROOT else chain.current_root,
                current_state: if (finishes)
                    ACCOUNTS.mapBy(_ => proof::zero_state)
                else
                    chain.current_state,
                current_liability: if (finishes) 0 else chain.current_liability,
                custody: chain.custody - amount,
                released: chain.released + amount,
                pending_deposits: chain.pending_deposits.set(account, 0),
                deposit_deadlines: chain.deposit_deadlines.set(account, NO_DEADLINE),
                unfinalized_deposits: chain.unfinalized_deposits
                    .set(account, next_unfinalized),
                terminal: next_terminal,
                refunded_deposits: chain.refunded_deposits
                    .setBy(account, refunded => refunded + amount),
            },
            certification' = certification,
        }
    }

    def terminal_can_begin(): bool =
        if (chain.pipeline.length() == 0)
            true
        else
            chain.status.get(chain.pipeline[0]) != Pending

    action begin_terminal: bool = {
        val deposits = unfinalized_deposit_total
        val liability = chain.current_liability
        val immediately_settled = liability == 0 and deposits == 0
        all {
            not(healthy(chain.fault)),
            dormant(chain.terminal),
            terminal_can_begin,
            chain.custody == liability + deposits,

            chain' = {
                ...chain,
                current_root: if (immediately_settled) EMPTY_STATE_ROOT else chain.current_root,
                current_state: if (immediately_settled)
                    ACCOUNTS.mapBy(_ => proof::zero_state)
                else
                    chain.current_state,
                current_liability: if (immediately_settled) 0 else chain.current_liability,
                custody: if (immediately_settled) 0 else chain.custody,
                registered: NoRegistration,
                pipeline: List(),
                pending_deposits: ACCOUNTS.mapBy(_ => 0),
                deposit_deadlines: ACCOUNTS.mapBy(_ => NO_DEADLINE),
                pending_withdrawals: ACCOUNTS.mapBy(_ => NoWithdrawal),
                terminal: if (immediately_settled)
                    Settled
                else
                    Claiming({
                        frozen_root: chain.current_root,
                        frozen_state: chain.current_state,
                        remaining_state: liability,
                        remaining_deposits: deposits,
                    }),
            },
            certification' = certification,
        }
    }

    def terminal_split(account: Account, balance: int): { withdrawal: int, residual: int } =
        match chain.outstanding_withdrawals.get(account) {
            | NoWithdrawal => { withdrawal: 0, residual: balance }
            | Requested(request) => match request.withdrawal_action {
                | Amount(amount) => { withdrawal: amount, residual: balance - amount }
                | Close => { withdrawal: balance, residual: 0 }
            }
        }

    action claim_state(account: Account): bool = {
        val claims = match chain.terminal {
            | Dormant => {
                frozen_root: EMPTY_STATE_ROOT,
                frozen_state: ACCOUNTS.mapBy(_ => proof::zero_state),
                remaining_state: 0,
                remaining_deposits: 0,
            }
            | Claiming(active) => active
            | Settled => {
                frozen_root: EMPTY_STATE_ROOT,
                frozen_state: ACCOUNTS.mapBy(_ => proof::zero_state),
                remaining_state: 0,
                remaining_deposits: 0,
            }
        }
        val state = claims.frozen_state.get(account)
        val balance = state.balance
        val split = terminal_split(account, balance)
        val remaining = claims.remaining_state - balance
        val finishes = remaining == 0 and claims.remaining_deposits == 0
        all {
            match chain.terminal {
                | Dormant => false
                | Claiming(_) => true
                | Settled => false
            },
            account.in(ACCOUNTS),
            state.active,
            balance > 0,
            not(account.in(chain.consumed_state)),
            split.withdrawal >= 0,
            split.residual >= 0,
            split.withdrawal + split.residual == balance,

            chain' = {
                ...chain,
                current_root: if (finishes) EMPTY_STATE_ROOT else chain.current_root,
                current_state: if (finishes)
                    ACCOUNTS.mapBy(_ => proof::zero_state)
                else
                    chain.current_state,
                current_liability: if (finishes) 0 else chain.current_liability,
                custody: chain.custody - balance,
                released: chain.released + balance,
                outstanding_withdrawals: chain.outstanding_withdrawals
                    .set(account, NoWithdrawal),
                terminal: if (finishes)
                    Settled
                else
                    Claiming({ ...claims, remaining_state: remaining }),
                consumed_state: chain.consumed_state.union(Set(account)),
                recovered_state: chain.recovered_state
                    .setBy(account, recovered => recovered + balance),
                terminal_withdrawals: chain.terminal_withdrawals
                    .setBy(account, paid => paid + split.withdrawal),
                terminal_residuals: chain.terminal_residuals
                    .setBy(account, paid => paid + split.residual),
            },
            certification' = certification,
        }
    }

    pure val quorum_assumptions = and {
        HONEST.union(BYZANTINE) == VALIDATORS,
        HONEST.intersect(BYZANTINE) == Set(),
        BYZANTINE.size() * 3 + 1 == VALIDATORS.size(),
        QUORUM == BYZANTINE.size() * 2 + 1,
        SLICE_IDS.forall(index => and {
            HOLDERS.get(index).size() == QUORUM,
            HOLDERS.get(index).subseteq(VALIDATORS),
        }),
        ACCOUNTS.forall(account => ACCOUNT_SLICE.get(account).in(SLICE_IDS)),
        tuples(ACCOUNTS, ACCOUNTS).forall(((left, right)) =>
            (ACCOUNT_INDEX.get(left) < ACCOUNT_INDEX.get(right)) implies
                ACCOUNT_SLICE.get(left) <= ACCOUNT_SLICE.get(right)),
        PIPELINE_SLOTS.size() == MAX_PENDING,
        PIPELINE_SLOTS.forall(slot => slot >= 0 and slot < MAX_PENDING),
        FINALIZED_SLOTS.size() == BATCHES.size(),
        FINALIZED_SLOTS.forall(slot => slot >= 0 and slot < BATCHES.size()),
        0.in(TIMES),
        TIME_HORIZON.in(TIMES),
        TIMES.forall(at => at >= 0 and at <= TIME_HORIZON),
    }

    val certification_sound = certification.certificates.forall(batch => and {
        certification.votes.get(batch).size() == QUORUM,
        proof::public_relation_holds(batch),
    })

    val certified_slice_coverage = certification.certificates.forall(batch =>
        SLICE_IDS.forall(index => HONEST.exists(validator => and {
            validator.in(certification.votes.get(batch)),
            validator.in(HOLDERS.get(index)),
            { batch: batch, slice: index }.in(certification.retained.get(validator)),
        })))

    val root_role_position_binding = certification.certificates.forall(batch =>
        proof::roots_hold(CANDIDATES.get(batch)))

    val coverage_continuity_and_terminal_exactness =
        certification.certificates.forall(batch =>
            proof::coverage_holds(CANDIDATES.get(batch)))

    val both_payment_signatures_and_linkage =
        certification.certificates.forall(batch => and {
            proof::payment_structure_holds(CANDIDATES.get(batch)),
            proof::signature_batch_holds(CANDIDATES.get(batch)),
        })

    val withdrawal_request_output_position_link =
        certification.certificates.forall(batch =>
            proof::withdrawal_outputs_hold(CANDIDATES.get(batch)))

    val fifo_pipeline = and {
        chain.pipeline.length() <= MAX_PENDING,
        not(pipeline_has_duplicates),
        occupied_pipeline_slots.forall(index => {
            val candidate = CANDIDATES.get(chain.pipeline[index])
            and {
                candidate.context.epoch == chain.expected_epoch + index,
                candidate.context.predecessor == if (index == 0)
                    chain.current_root
                else
                    CANDIDATES.get(chain.pipeline[index - 1]).roots.successor,
                candidate.predecessor_state == if (index == 0)
                    chain.current_state
                else
                    CANDIDATES.get(chain.pipeline[index - 1]).successor_state,
                chain.status.get(candidate.id) == Pending
                    or match chain.status.get(candidate.id) {
                        | Challenged(_) => true
                        | Invalidated(_) => true
                        | Inactive => false
                        | Pending => true
                        | Finalized => false
                    },
            }
        }),
        finalized_slots.forall(index =>
            chain.finalized_epochs[index] == INITIAL_EPOCH + index),
        chain.expected_epoch == INITIAL_EPOCH + chain.finalized_epochs.length(),
    }

    val challenge_invalidates_suffix =
        match chain.invalid_from {
            | NoBatch => true
            | SomeBatch(target) => and {
                target.in(chain.invalidated_batches),
                match chain.status.get(target) {
                    | Challenged(_) => true
                    | Inactive => false
                    | Pending => false
                    | Invalidated(_) => false
                    | Finalized => false
                },
                BATCHES.forall(batch => pipeline_descends_from(target, batch) implies
                    chain.status.get(batch) == Invalidated(target)),
            }
        }

    val no_invalid_finalization =
        chain.finalized_batches.intersect(chain.invalidated_batches) == Set()

    val claim_replay_scoped_by_kind_batch_position =
        chain.consumed_claims.forall(key => and {
            key.batch.in(chain.finalized_batches),
            key.position >= 0,
            match key.kind {
                | WithdrawalClaimKind => CANDIDATES.get(key.batch).withdrawal_outputs
                    .exists(output => output.position == key.position)
                | PayoutClaimKind => CANDIDATES.get(key.batch).payout_outputs
                    .exists(output => output.position == key.position)
            },
        })

    def unclaimed_withdrawal_total(batch: BatchId): int =
        if (not(batch.in(chain.finalized_batches)))
            0
        else
            CANDIDATES.get(batch).withdrawal_outputs
                .filter(positioned => not({
                    kind: WithdrawalClaimKind,
                    batch: batch,
                    position: positioned.position,
                }.in(chain.consumed_claims)))
                .fold(0, (total, positioned) => total + positioned.output.amount)

    def unclaimed_payout_total(batch: BatchId): int =
        if (not(batch.in(chain.finalized_batches)))
            0
        else
            CANDIDATES.get(batch).payout_outputs
                .filter(output => not({
                    kind: PayoutClaimKind,
                    batch: batch,
                    position: output.position,
                }.in(chain.consumed_claims)))
                .fold(0, (total, output) => total + output.amount)

    val claim_reserves_are_exact = BATCHES.forall(batch => and {
        chain.withdrawal_reserve.get(batch) == unclaimed_withdrawal_total(batch),
        chain.payout_reserve.get(batch) == unclaimed_payout_total(batch),
    })

    val claim_material_is_available = BATCHES.forall(batch => and {
        CANDIDATES.get(batch).withdrawal_outputs.forall(output =>
            WITHDRAWAL_CLAIMS.exists(claim => and {
                claim.output == output,
                proof::withdrawal_claim_holds(batch, claim),
            })),
        CANDIDATES.get(batch).payout_outputs.forall(output =>
            PAYOUT_CLAIMS.exists(claim => and {
                claim.output == output,
                proof::payout_claim_holds(batch, claim),
            })),
    })

    val every_live_deadline_is_observable = and {
        ACCOUNTS.forall(account => and {
            (chain.pending_deposits.get(account) > 0) implies
                chain.deposit_deadlines.get(account).in(TIMES),
            match chain.outstanding_withdrawals.get(account) {
                | NoWithdrawal => true
                | Requested(request) => request.deadline.in(TIMES)
            },
        }),
        match chain.registered {
            | NoRegistration => true
            | SomeRegistration(id) =>
                (REGISTRATIONS.get(id).context.admission_deadline + 1).in(TIMES)
        },
        occupied_pipeline_slots.forall(slot =>
            (CANDIDATES.get(chain.pipeline[slot]).context.challenge_deadline + 1).in(TIMES)),
    }

    val hard_fault_recovery_has_progress =
        if (healthy(chain.fault))
            true
        else match chain.terminal {
            | Settled => true
            | Dormant =>
                if (terminal_can_begin)
                    true
                else and {
                    chain.status.get(chain.pipeline[0]) == Pending,
                    (CANDIDATES.get(chain.pipeline[0]).context.challenge_deadline + 1)
                        .in(TIMES),
                }
            | Claiming(claims) => and {
                (claims.remaining_state > 0) implies ACCOUNTS.exists(account => and {
                    not(account.in(chain.consumed_state)),
                    claims.frozen_state.get(account).active,
                    claims.frozen_state.get(account).balance > 0,
                }),
                (claims.remaining_deposits > 0) implies ACCOUNTS.exists(account =>
                    chain.unfinalized_deposits.get(account) > 0),
            }
        }

    val custody_conservation = and {
        chain.custody >= 0,
        chain.claimable >= 0,
        chain.released >= 0,
        chain.custody + chain.claimable + chain.released == chain.total_in,
        chain.claimable == reserve_total,
        chain.released == chain.clean_claim_paid + refund_total + recovered_state_total,
    }

    val active_custody_backing = match chain.terminal {
        | Dormant => chain.custody
            == chain.current_liability + unfinalized_deposit_total
        | Claiming(claims) => chain.custody
            == claims.remaining_state + claims.remaining_deposits
        | Settled => chain.custody == 0 and chain.current_liability == 0
    }

    val state_and_recovery_exact = and {
        chain.current_liability == proof::state_liability(chain.current_state),
        ACCOUNTS.forall(account => and {
            chain.pending_deposits.get(account) >= 0,
            chain.unfinalized_deposits.get(account) >= chain.pending_deposits.get(account),
            chain.recovered_state.get(account)
                == chain.terminal_withdrawals.get(account)
                    + chain.terminal_residuals.get(account),
        }),
        match chain.terminal {
            | Dormant => true
            | Claiming(claims) => and {
                claims.frozen_root == chain.current_root,
                claims.remaining_state == ACCOUNTS
                    .filter(account => not(account.in(chain.consumed_state)))
                    .fold(0, (total, account) =>
                        total + claims.frozen_state.get(account).balance),
                claims.remaining_deposits == unfinalized_deposit_total,
            }
            | Settled => and {
                chain.current_root == EMPTY_STATE_ROOT,
                chain.current_state == ACCOUNTS.mapBy(_ => proof::zero_state),
                unfinalized_deposit_total == 0,
            }
        },
    }

    val fault_fence_is_permanent = and {
        if (healthy(chain.fault)) and {
            chain.admission_fence_epoch == NO_FENCE,
            dormant(chain.terminal),
            chain.fault_history == Set(),
        } else and {
            chain.admission_fence_epoch >= INITIAL_EPOCH,
            chain.registered == NoRegistration,
            chain.fault_history == Set(chain.fault),
        },
        settled(chain.terminal) implies not(healthy(chain.fault)),
    }

    val registered_context_is_exact =
        match chain.registered {
            | NoRegistration => true
            | SomeRegistration(id) => {
                val registration = REGISTRATIONS.get(id)
                and {
                    healthy(chain.fault),
                    registration.context.epoch == next_admission_epoch,
                    registration.context.predecessor == head_root,
                    registration.predecessor_state == head_state,
                    registration_inputs_match(registration),
                }
            }
        }

    val all_invariants = and {
        quorum_assumptions,
        certification_sound,
        certified_slice_coverage,
        root_role_position_binding,
        coverage_continuity_and_terminal_exactness,
        both_payment_signatures_and_linkage,
        withdrawal_request_output_position_link,
        fifo_pipeline,
        challenge_invalidates_suffix,
        no_invalid_finalization,
        claim_replay_scoped_by_kind_batch_position,
        claim_reserves_are_exact,
        claim_material_is_available,
        every_live_deadline_is_observable,
        hard_fault_recovery_has_progress,
        custody_conservation,
        active_custody_backing,
        state_and_recovery_exact,
        fault_fence_is_permanent,
        registered_context_is_exact,
    }

    val lifecycle_invariants = and {
        fifo_pipeline,
        challenge_invalidates_suffix,
        no_invalid_finalization,
        claim_replay_scoped_by_kind_batch_position,
        claim_reserves_are_exact,
        every_live_deadline_is_observable,
        hard_fault_recovery_has_progress,
        custody_conservation,
        active_custody_backing,
        state_and_recovery_exact,
        fault_fence_is_permanent,
        registered_context_is_exact,
    }

    action step = any {
        all {
            nondet at = TIMES.oneOf()
            observe_time(at)
        },
        all {
            nondet event = DEPOSIT_EVENTS.oneOf()
            record_deposit(event)
        },
        all {
            nondet request = WITHDRAWALS.oneOf()
            queue_withdrawal(request)
        },
        all {
            nondet id = REGISTRATIONS.keys().oneOf()
            register(id)
        },
        all {
            nondet batch = BATCHES.oneOf()
            prepare(batch)
        },
        all {
            nondet batch = BATCHES.oneOf()
            deal(batch)
        },
        all {
            nondet batch = BATCHES.oneOf()
            nondet validator = VALIDATORS.oneOf()
            deliver_exact(batch, validator)
        },
        all {
            nondet batch = BATCHES.oneOf()
            nondet validator = HONEST.oneOf()
            seal(batch, validator)
        },
        all {
            nondet batch = BATCHES.oneOf()
            nondet validator = BYZANTINE.oneOf()
            byzantine_vote(batch, validator)
        },
        all {
            nondet batch = BATCHES.oneOf()
            form_certificate(batch)
        },
        all {
            nondet batch = BATCHES.oneOf()
            admit(batch)
        },
        all {
            nondet target = BATCHES.oneOf()
            nondet evidence = EVIDENCE.oneOf()
            challenge(target, evidence)
        },
        finalize,
        all {
            nondet target = BATCHES.oneOf()
            nondet claim = WITHDRAWAL_CLAIMS.oneOf()
            claim_withdrawal(target, claim)
        },
        all {
            nondet target = BATCHES.oneOf()
            nondet claim = PAYOUT_CLAIMS.oneOf()
            claim_payout(target, claim)
        },
        all {
            nondet account = ACCOUNTS.oneOf()
            claim_deposit(account)
        },
        begin_terminal,
        all {
            nondet account = ACCOUNTS.oneOf()
            claim_state(account)
        },
        rejected_call,
    }

    // State-reduced transition relation for bounded exhaustive checking.
    action bounded_step = any {
        all {
            nondet at = TIMES.oneOf()
            observe_time(at)
        },
        all {
            nondet event = DEPOSIT_EVENTS.oneOf()
            record_deposit(event)
        },
        all {
            nondet request = WITHDRAWALS.oneOf()
            queue_withdrawal(request)
        },
        all {
            nondet id = REGISTRATIONS.keys().oneOf()
            register(id)
        },
        all {
            nondet batch = BATCHES.oneOf()
            admit_valid(batch)
        },
        all {
            nondet target = BATCHES.oneOf()
            nondet kind = Set(
                LatestAcknowledgedSend,
                HigherShardTip,
                InconsistentReceiptRange,
                ReceiptFork).oneOf()
            challenge_proven(target, kind)
        },
        finalize,
        all {
            nondet target = BATCHES.oneOf()
            nondet claim = WITHDRAWAL_CLAIMS.oneOf()
            claim_withdrawal(target, claim)
        },
        all {
            nondet target = BATCHES.oneOf()
            nondet claim = PAYOUT_CLAIMS.oneOf()
            claim_payout(target, claim)
        },
        all {
            nondet account = ACCOUNTS.oneOf()
            claim_deposit(account)
        },
        begin_terminal,
        all {
            nondet account = ACCOUNTS.oneOf()
            claim_state(account)
        },
    }
}
