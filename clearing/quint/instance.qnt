// One shared finite instantiation for executable checks and scenarios.
module instance {
    import types.* from "./types"
    import fixtures.* from "./fixtures"
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
    import settlement(
        ACCOUNTS = ACCOUNTS,
        ACCOUNT_INDEX = ACCOUNT_INDEX,
        ACCOUNT_SLICE = ACCOUNT_SLICE,
        BATCHES = BATCHES,
        VALID_BATCHES = VALID_BATCHES,
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
        VALIDATORS = VALIDATORS,
        HONEST = HONEST,
        BYZANTINE = BYZANTINE,
        HOLDERS = HOLDERS,
        QUORUM = QUORUM,
        MAX_PENDING = MAX_PENDING,
        PIPELINE_SLOTS = PIPELINE_SLOTS,
        FINALIZED_SLOTS = FINALIZED_SLOTS,
        MAX_ADMISSION_DELAY = MAX_ADMISSION_DELAY,
        MIN_CHALLENGE_DURATION = MIN_CHALLENGE_DURATION,
        MAX_CHALLENGE_DURATION = MAX_CHALLENGE_DURATION,
        DEPOSIT_TIMEOUT = DEPOSIT_TIMEOUT,
        MIN_WITHDRAWAL_NOTICE = MIN_WITHDRAWAL_NOTICE,
        MAX_WITHDRAWAL_NOTICE = MAX_WITHDRAWAL_NOTICE,
        TIMES = TIMES,
        TIME_HORIZON = TIME_HORIZON,
        DEPOSIT_EVENTS = DEPOSIT_EVENTS,
        WITHDRAWALS = WITHDRAWALS,
        EVIDENCE = EVIDENCE,
        WITHDRAWAL_CLAIMS = WITHDRAWAL_CLAIMS,
        PAYOUT_CLAIMS = PAYOUT_CLAIMS,
        INITIAL_EPOCH = INITIAL_EPOCH,
        INITIAL_ROOT = INITIAL_ROOT,
        INITIAL_STATE = INITIAL_STATE,
        EMPTY_STATE_ROOT = EMPTY_STATE_ROOT,
    ) as model from "./settlement"

    def chain_state(): ChainState = model::chain
    def certification_state(): CertificationState = model::certification

    action init = model::init
    action step = model::step
    action record_deposit(event: DepositEvent): bool = model::record_deposit(event)
    action queue_withdrawal(request: Withdrawal): bool = model::queue_withdrawal(request)
    action register(id: RegistrationId): bool = model::register(id)
    action prepare(batch: BatchId): bool = model::prepare(batch)
    action deal(batch: BatchId): bool = model::deal(batch)
    action deliver_exact(batch: BatchId, validator: Validator): bool =
        model::deliver_exact(batch, validator)
    action seal(batch: BatchId, validator: Validator): bool = model::seal(batch, validator)
    action byzantine_vote(batch: BatchId, validator: Validator): bool =
        model::byzantine_vote(batch, validator)
    action form_certificate(batch: BatchId): bool = model::form_certificate(batch)
    action admit(batch: BatchId): bool = model::admit(batch)
    action observe_time(at: int): bool = model::observe_time(at)
    action rejected_call = model::rejected_call
    action challenge(target: BatchId, evidence: ChallengeEvidence): bool =
        model::challenge(target, evidence)
    action finalize = model::finalize
    action claim_withdrawal(target: BatchId, claim: WithdrawalClaim): bool =
        model::claim_withdrawal(target, claim)
    action claim_payout(target: BatchId, claim: PayoutClaim): bool =
        model::claim_payout(target, claim)
    action claim_deposit(account: Account): bool = model::claim_deposit(account)
    action begin_terminal = model::begin_terminal
    action claim_state(account: Account): bool = model::claim_state(account)
    action bounded_step = model::bounded_step
    def can_record_deposit(event: DepositEvent): bool = model::can_record_deposit(event)
    def can_register(id: RegistrationId): bool = model::can_register(id)
    def can_seal(batch: BatchId, validator: Validator): bool = model::can_seal(batch, validator)

    pure def public_relation_holds(batch: BatchId): bool =
        proof::public_relation_holds(batch)
    pure def roots_hold(batch: BatchId): bool = proof::roots_hold(CANDIDATES.get(batch))
    pure def candidate_roots_hold(candidate: Candidate): bool = proof::roots_hold(candidate)
    pure def payments_hold(batch: BatchId): bool =
        proof::payment_structure_holds(CANDIDATES.get(batch))
    pure def rows_hold(batch: BatchId): bool =
        ACCOUNTS.forall(account => proof::row_holds(CANDIDATES.get(batch), account))
    pure def row_holds(batch: BatchId, account: Account): bool =
        proof::row_holds(CANDIDATES.get(batch), account)
    pure def signatures_hold(batch: BatchId): bool =
        proof::signature_batch_holds(CANDIDATES.get(batch))
    pure def outputs_hold(batch: BatchId): bool = and {
        proof::withdrawal_outputs_hold(CANDIDATES.get(batch)),
        proof::payout_outputs_hold(CANDIDATES.get(batch)),
    }
    pure def coverage_holds(batch: BatchId): bool =
        proof::coverage_holds(CANDIDATES.get(batch))
    pure def withdrawal_claim_holds(target: BatchId, claim: WithdrawalClaim): bool =
        proof::withdrawal_claim_holds(target, claim)

    val all_invariants = model::all_invariants
    val lifecycle_invariants = model::lifecycle_invariants
    pure val quorum_assumptions = model::quorum_assumptions
    val certification_sound = model::certification_sound
    val certified_slice_coverage = model::certified_slice_coverage
    val root_role_position_binding = model::root_role_position_binding
    val coverage_continuity_and_terminal_exactness =
        model::coverage_continuity_and_terminal_exactness
    val both_payment_signatures_and_linkage = model::both_payment_signatures_and_linkage
    val withdrawal_request_output_position_link =
        model::withdrawal_request_output_position_link
    val fifo_pipeline = model::fifo_pipeline
    val challenge_invalidates_suffix = model::challenge_invalidates_suffix
    val no_invalid_finalization = model::no_invalid_finalization
    val claim_replay_scoped_by_kind_batch_position =
        model::claim_replay_scoped_by_kind_batch_position
    val claim_reserves_are_exact = model::claim_reserves_are_exact
    val claim_material_is_available = model::claim_material_is_available
    val every_live_deadline_is_observable = model::every_live_deadline_is_observable
    val hard_fault_recovery_has_progress = model::hard_fault_recovery_has_progress
    val custody_conservation = model::custody_conservation
    val active_custody_backing = model::active_custody_backing
    val state_and_recovery_exact = model::state_and_recovery_exact
    val fault_fence_is_permanent = model::fault_fence_is_permanent
    val registered_context_is_exact = model::registered_context_is_exact
    val hard_fault_reached = not(model::healthy(chain_state.fault))
    val terminal_settled = model::settled(chain_state.terminal)
}
