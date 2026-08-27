// Branch-complete finite instance used by scenarios, simulation, and checking.
module fixtures {
    import types.* from "./types"

    pure val ALICE: Account = "alice"
    pure val BOB: Account = "bob"
    pure val CAROL: Account = "carol"
    pure val ACCOUNTS = Set(ALICE, BOB, CAROL)
    pure val ACCOUNT_INDEX = Map(ALICE -> 0, BOB -> 1, CAROL -> 2)
    pure val ACCOUNT_SLICE = Map(ALICE -> 0, BOB -> 1, CAROL -> 1)

    pure val B0: BatchId = "b0"
    pure val B1: BatchId = "b1"
    pure val B2: BatchId = "b2"
    pure val B3: BatchId = "b3"
    pure val BOFF: BatchId = "b-offset"
    pure val BAD: BatchId = "bad"
    pure val BATCHES = Set(B0, B1, B2, B3, BOFF, BAD)
    pure val VALID_BATCHES = Set(B0, B1, B2, B3, BOFF)

    pure val REG0: RegistrationId = "reg-0"
    pure val REG1: RegistrationId = "reg-1"
    pure val REG2: RegistrationId = "reg-2"
    pure val REG3: RegistrationId = "reg-3"
    pure val REGOFF: RegistrationId = "reg-offset"

    pure val V0: Validator = "v0"
    pure val V1: Validator = "v1"
    pure val V2: Validator = "v2"
    pure val V3: Validator = "v3"
    pure val VALIDATORS = Set(V0, V1, V2, V3)
    pure val HONEST = Set(V0, V1, V2)
    pure val BYZANTINE = Set(V3)
    pure val SLICE_IDS = Set(0, 1)
    pure val HOLDERS = Map(
        0 -> Set(V0, V1, V3),
        1 -> Set(V0, V2, V3))
    pure val CERTIFICATE_QUORUMS = Set(
        Set(V0, V1, V2),
        Set(V0, V1, V3),
        Set(V0, V2, V3),
        Set(V1, V2, V3))

    pure val QUORUM = 3
    pure val MAX_PENDING = 3
    pure val PIPELINE_SLOTS = Set(0, 1, 2)
    pure val FINALIZED_SLOTS = Set(0, 1, 2, 3, 4, 5)
    pure val MAX_ADMISSION_DELAY = 3
    pure val MIN_CHALLENGE_DURATION = 2
    pure val MAX_CHALLENGE_DURATION = 2
    pure val DEPOSIT_TIMEOUT = 8
    pure val MIN_WITHDRAWAL_NOTICE = 2
    pure val MAX_WITHDRAWAL_NOTICE = 20
    pure val TIMES = 0.to(12)
    pure val TIME_HORIZON = 12
    pure val INITIAL_EPOCH = 0

    pure def state(
        active: bool,
        balance: int,
        debit: int,
        credit: int,
        receipts: int,
    ): AccountState = {
        active: active,
        balance: balance,
        cumulative_debit: debit,
        cumulative_credit: credit,
        receipt_count: receipts,
    }

    pure val ZERO_STATE = state(false, 0, 0, 0, 0)

    pure def root(kind: VectorKind, digest: RootId, vector_length: int): TypedRoot = {
        kind: kind,
        digest: digest,
        length: vector_length,
    }

    pure val R0 = root(StateRole, "state-0", 2)
    pure val R1 = root(StateRole, "state-1", 2)
    pure val R2 = root(StateRole, "state-2", 2)
    pure val R3 = root(StateRole, "state-3", 2)
    pure val R4 = root(StateRole, "state-4", 1)
    pure val ROFF = root(StateRole, "state-offset", 2)
    pure val EMPTY_STATE_ROOT = root(StateRole, "state-empty", 0)
    pure val EMPTY_CREDIT_TIP_ROOT = root(CreditTipRole, "credit-tip-empty", 0)
    pure val B0_BOB_CREDIT_TIP_ROOT = root(CreditTipRole, "credit-tip-0-bob", 1)
    pure val B1_CAROL_CREDIT_TIP_ROOT = root(CreditTipRole, "credit-tip-1-carol", 1)

    pure val S0 = Map(
        ALICE -> state(true, 10, 0, 0, 0),
        BOB -> state(true, 5, 0, 0, 0),
        CAROL -> ZERO_STATE)
    pure val S1 = Map(
        ALICE -> state(true, 8, 2, 0, 0),
        BOB -> state(true, 9, 0, 2, 1),
        CAROL -> ZERO_STATE)
    pure val S2 = Map(
        ALICE -> state(true, 7, 3, 0, 0),
        BOB -> state(true, 9, 0, 2, 1),
        CAROL -> ZERO_STATE)
    pure val S3 = Map(
        ALICE -> state(true, 7, 3, 0, 0),
        BOB -> state(true, 7, 0, 2, 1),
        CAROL -> ZERO_STATE)
    pure val S4 = Map(
        ALICE -> ZERO_STATE,
        BOB -> state(true, 7, 0, 2, 1),
        CAROL -> ZERO_STATE)
    pure val SOFF = Map(
        ALICE -> state(true, 10, 0, 0, 0),
        BOB -> state(true, 3, 0, 0, 0),
        CAROL -> ZERO_STATE)

    pure val INITIAL_ROOT = R0
    pure val INITIAL_STATE = S0

    pure val NO_WITHDRAWALS = ACCOUNTS.mapBy(_ => NoWithdrawal)
    pure val NO_DEPOSITS = ACCOUNTS.mapBy(_ => 0)
    pure val NO_OUTGOING = ACCOUNTS.mapBy(_ => NoPayment)

    pure val W_AMOUNT: Withdrawal = {
        id: "withdraw-bob-2",
        account: BOB,
        destination: "bank-bob",
        withdrawal_action: Amount(2),
        deadline: 10,
        context_root: R0.digest,
        signature_valid: true,
        destination_eligible: true,
    }
    pure val W_CLOSE: Withdrawal = {
        id: "close-alice",
        account: ALICE,
        destination: "bank-alice",
        withdrawal_action: Close,
        deadline: 11,
        context_root: R1.digest,
        signature_valid: true,
        destination_eligible: true,
    }
    pure val W_CLOSE_EXIT: Withdrawal = {
        id: "close-alice-after-fault",
        account: ALICE,
        destination: "bank-alice",
        withdrawal_action: Close,
        deadline: 11,
        context_root: R0.digest,
        signature_valid: true,
        destination_eligible: true,
    }
    pure val W_OFFSET: Withdrawal = {
        id: "withdraw-offset-bob-2",
        account: BOB,
        destination: "bank-bob",
        withdrawal_action: Amount(2),
        deadline: 2,
        context_root: R0.digest,
        signature_valid: true,
        destination_eligible: true,
    }
    pure val WITHDRAWALS = Set(W_AMOUNT, W_CLOSE, W_CLOSE_EXIT, W_OFFSET)

    pure val P0: Payment = {
        id: "payment-0",
        payer: ALICE,
        recipient: BOB,
        amount: 2,
        cumulative_debit: 2,
        shard: 0,
        cumulative_shard_credit: 2,
        index: 1,
        external: false,
    }
    pure val P1: Payment = {
        id: "payment-1",
        payer: ALICE,
        recipient: CAROL,
        amount: 1,
        cumulative_debit: 3,
        shard: 0,
        cumulative_shard_credit: 1,
        index: 1,
        external: true,
    }

    pure def checks(context: RegistrationId, payment: Payment): Set[SignatureCheck] = Set(
        { context: context, payment: payment.id, kind: PayerSignature, valid: true },
        { context: context, payment: payment.id, kind: OperatorSignature, valid: true })

    pure def prefix(
        debit: int,
        credit: int,
        payout: int,
        deposit: int,
        withdrawal: int,
        withdrawal_count: int,
        shard_count: int,
    ): Prefix = {
        debit: debit,
        credit: credit,
        payout: payout,
        deposit: deposit,
        withdrawal: withdrawal,
        withdrawal_count: withdrawal_count,
        shard_count: shard_count,
    }

    pure val ZERO_PREFIX = prefix(0, 0, 0, 0, 0, 0, 0)

    pure def boundary(
        predecessor: int,
        change: int,
        successor: int,
        cumulative: Prefix,
    ): Boundary = {
        predecessor: predecessor,
        change: change,
        successor: successor,
        prefix: cumulative,
    }

    pure val ZERO_BOUNDARY = boundary(0, 0, 0, ZERO_PREFIX)

    pure def proof_slice(index: int, left: Boundary, right: Boundary): ProofSlice = {
        index: index,
        left: left,
        right: right,
        typed_openings: true,
        ordered_guards: true,
        exact_ranges: true,
    }

    pure val B0_PREFIX_A = prefix(2, 0, 0, 0, 0, 0, 0)
    pure val B0_PREFIX_Z = prefix(2, 2, 0, 2, 0, 0, 1)
    pure val B0_BOUNDARY_1 = boundary(1, 1, 1, B0_PREFIX_A)
    pure val B0_BOUNDARY_2 = boundary(2, 2, 2, B0_PREFIX_Z)
    pure val B0_ROOTS: RootBundle = {
        change: root(ChangeRole, "change-0", 2),
        withdrawal_outputs: root(WithdrawalOutputRole, "output-empty", 0),
        successor: R1,
        coverage: root(CoverageRole, "coverage-0", 3),
    }
    pure val B0_CONTEXT: CloseContext = {
        anchor: "anchor-0",
        epoch: 0,
        predecessor: R0,
        predecessor_liability: 15,
        deposit_root: root(DepositRole, "deposit-0", 1),
        withdrawal_root: root(WithdrawalRole, "withdrawal-empty", 0),
        admission_deadline: 2,
        challenge_deadline: 4,
    }
    pure val C0: Candidate = {
        id: B0,
        registration: REG0,
        context: B0_CONTEXT,
        roots: B0_ROOTS,
        header: { context_anchor: B0_CONTEXT.anchor, roots: B0_ROOTS },
        predecessor_state: S0,
        successor_state: S1,
        row_predecessors: S0,
        row_successors: S1,
        deposits: Map(ALICE -> 0, BOB -> 2, CAROL -> 0),
        withdrawals: NO_WITHDRAWALS,
        payments: Set(P0),
        outgoing: Map(
            ALICE -> TerminalPayment(P0),
            BOB -> NoPayment,
            CAROL -> NoPayment),
        shard_heads: Set({ recipient: BOB, shard: 0, payment: P0 }),
        credit_tip_roots: Map(
            ALICE -> EMPTY_CREDIT_TIP_ROOT,
            BOB -> B0_BOB_CREDIT_TIP_ROOT,
            CAROL -> EMPTY_CREDIT_TIP_ROOT),
        row_prefixes: Map(
            ALICE -> B0_PREFIX_A,
            BOB -> B0_PREFIX_Z,
            CAROL -> ZERO_PREFIX),
        signature_batch: checks(REG0, P0),
        withdrawal_outputs: Set(),
        withdrawal_links: Set(),
        payout_outputs: Set(),
        coverage_boundaries: Map(
            0 -> ZERO_BOUNDARY,
            1 -> B0_BOUNDARY_1,
            2 -> B0_BOUNDARY_2),
        slices: Map(
            0 -> proof_slice(0, ZERO_BOUNDARY, B0_BOUNDARY_1),
            1 -> proof_slice(1, B0_BOUNDARY_1, B0_BOUNDARY_2)),
    }

    pure val B1_PREFIX_A = prefix(1, 0, 0, 0, 0, 0, 0)
    pure val B1_PREFIX_Z = prefix(1, 1, 1, 0, 0, 0, 1)
    pure val B1_BOUNDARY_1 = boundary(1, 1, 1, B1_PREFIX_A)
    pure val B1_BOUNDARY_2 = boundary(2, 2, 2, B1_PREFIX_Z)
    pure val B1_ROOTS: RootBundle = {
        change: root(ChangeRole, "change-1", 2),
        withdrawal_outputs: root(WithdrawalOutputRole, "output-empty", 0),
        successor: R2,
        coverage: root(CoverageRole, "coverage-1", 3),
    }
    pure val B1_CONTEXT: CloseContext = {
        anchor: "anchor-1",
        epoch: 1,
        predecessor: R1,
        predecessor_liability: 17,
        deposit_root: root(DepositRole, "deposit-empty", 0),
        withdrawal_root: root(WithdrawalRole, "withdrawal-empty", 0),
        admission_deadline: 3,
        challenge_deadline: 5,
    }
    pure val B1_ROW_SUCCESSORS = Map(
        ALICE -> S2.get(ALICE),
        BOB -> S1.get(BOB),
        CAROL -> state(false, 0, 0, 1, 1))
    pure val C1: Candidate = {
        id: B1,
        registration: REG1,
        context: B1_CONTEXT,
        roots: B1_ROOTS,
        header: { context_anchor: B1_CONTEXT.anchor, roots: B1_ROOTS },
        predecessor_state: S1,
        successor_state: S2,
        row_predecessors: S1,
        row_successors: B1_ROW_SUCCESSORS,
        deposits: NO_DEPOSITS,
        withdrawals: NO_WITHDRAWALS,
        payments: Set(P1),
        outgoing: Map(
            ALICE -> TerminalPayment(P1),
            BOB -> NoPayment,
            CAROL -> NoPayment),
        shard_heads: Set({ recipient: CAROL, shard: 0, payment: P1 }),
        credit_tip_roots: Map(
            ALICE -> EMPTY_CREDIT_TIP_ROOT,
            BOB -> EMPTY_CREDIT_TIP_ROOT,
            CAROL -> B1_CAROL_CREDIT_TIP_ROOT),
        row_prefixes: Map(
            ALICE -> B1_PREFIX_A,
            BOB -> ZERO_PREFIX,
            CAROL -> B1_PREFIX_Z),
        signature_batch: checks(REG1, P1),
        withdrawal_outputs: Set(),
        withdrawal_links: Set(),
        payout_outputs: Set({ position: 1, recipient: CAROL, amount: 1 }),
        coverage_boundaries: Map(
            0 -> ZERO_BOUNDARY,
            1 -> B1_BOUNDARY_1,
            2 -> B1_BOUNDARY_2),
        slices: Map(
            0 -> proof_slice(0, ZERO_BOUNDARY, B1_BOUNDARY_1),
            1 -> proof_slice(1, B1_BOUNDARY_1, B1_BOUNDARY_2)),
    }

    pure val B2_PREFIX_Z = prefix(0, 0, 0, 0, 2, 1, 0)
    pure val B2_BOUNDARY_1 = boundary(1, 0, 1, ZERO_PREFIX)
    pure val B2_BOUNDARY_2 = boundary(2, 1, 2, B2_PREFIX_Z)
    pure val B2_ROOTS: RootBundle = {
        change: root(ChangeRole, "change-2", 1),
        withdrawal_outputs: root(WithdrawalOutputRole, "output-2", 1),
        successor: R3,
        coverage: root(CoverageRole, "coverage-2", 3),
    }
    pure val B2_CONTEXT: CloseContext = {
        anchor: "anchor-2",
        epoch: 2,
        predecessor: R2,
        predecessor_liability: 16,
        deposit_root: root(DepositRole, "deposit-empty", 0),
        withdrawal_root: root(WithdrawalRole, "withdrawal-2", 1),
        admission_deadline: 4,
        challenge_deadline: 6,
    }
    pure val B2_WITHDRAWALS = Map(
        ALICE -> NoWithdrawal,
        BOB -> Requested(W_AMOUNT),
        CAROL -> NoWithdrawal)
    pure val B2_OUTPUT: PositionedWithdrawalOutput = {
        position: 0,
        output: { destination: W_AMOUNT.destination, amount: 2 },
    }
    pure val C2: Candidate = {
        id: B2,
        registration: REG2,
        context: B2_CONTEXT,
        roots: B2_ROOTS,
        header: { context_anchor: B2_CONTEXT.anchor, roots: B2_ROOTS },
        predecessor_state: S2,
        successor_state: S3,
        row_predecessors: S2,
        row_successors: S3,
        deposits: NO_DEPOSITS,
        withdrawals: B2_WITHDRAWALS,
        payments: Set(),
        outgoing: NO_OUTGOING,
        shard_heads: Set(),
        credit_tip_roots: ACCOUNTS.mapBy(_ => EMPTY_CREDIT_TIP_ROOT),
        row_prefixes: Map(
            ALICE -> ZERO_PREFIX,
            BOB -> B2_PREFIX_Z,
            CAROL -> ZERO_PREFIX),
        signature_batch: Set(),
        withdrawal_outputs: Set(B2_OUTPUT),
        withdrawal_links: Set({
            account: BOB,
            request: W_AMOUNT.id,
            position: 0,
        }),
        payout_outputs: Set(),
        coverage_boundaries: Map(
            0 -> ZERO_BOUNDARY,
            1 -> B2_BOUNDARY_1,
            2 -> B2_BOUNDARY_2),
        slices: Map(
            0 -> proof_slice(0, ZERO_BOUNDARY, B2_BOUNDARY_1),
            1 -> proof_slice(1, B2_BOUNDARY_1, B2_BOUNDARY_2)),
    }

    pure val B3_PREFIX_Z = prefix(0, 0, 0, 0, 7, 1, 0)
    pure val B3_BOUNDARY_1 = boundary(1, 1, 0, B3_PREFIX_Z)
    pure val B3_BOUNDARY_2 = boundary(2, 1, 1, B3_PREFIX_Z)
    pure val B3_ROOTS: RootBundle = {
        change: root(ChangeRole, "change-3", 1),
        withdrawal_outputs: root(WithdrawalOutputRole, "output-3", 1),
        successor: R4,
        coverage: root(CoverageRole, "coverage-3", 3),
    }
    pure val B3_CONTEXT: CloseContext = {
        anchor: "anchor-3",
        epoch: 3,
        predecessor: R3,
        predecessor_liability: 14,
        deposit_root: root(DepositRole, "deposit-empty", 0),
        withdrawal_root: root(WithdrawalRole, "withdrawal-3", 1),
        admission_deadline: 6,
        challenge_deadline: 8,
    }
    pure val B3_WITHDRAWALS = Map(
        ALICE -> Requested(W_CLOSE),
        BOB -> NoWithdrawal,
        CAROL -> NoWithdrawal)
    pure val B3_ROW_SUCCESSORS = Map(
        ALICE -> state(false, 0, 3, 0, 0),
        BOB -> S3.get(BOB),
        CAROL -> ZERO_STATE)
    pure val B3_OUTPUT: PositionedWithdrawalOutput = {
        position: 0,
        output: { destination: W_CLOSE.destination, amount: 7 },
    }
    pure val C3: Candidate = {
        id: B3,
        registration: REG3,
        context: B3_CONTEXT,
        roots: B3_ROOTS,
        header: { context_anchor: B3_CONTEXT.anchor, roots: B3_ROOTS },
        predecessor_state: S3,
        successor_state: S4,
        row_predecessors: S3,
        row_successors: B3_ROW_SUCCESSORS,
        deposits: NO_DEPOSITS,
        withdrawals: B3_WITHDRAWALS,
        payments: Set(),
        outgoing: NO_OUTGOING,
        shard_heads: Set(),
        credit_tip_roots: ACCOUNTS.mapBy(_ => EMPTY_CREDIT_TIP_ROOT),
        row_prefixes: Map(
            ALICE -> B3_PREFIX_Z,
            BOB -> ZERO_PREFIX,
            CAROL -> ZERO_PREFIX),
        signature_batch: Set(),
        withdrawal_outputs: Set(B3_OUTPUT),
        withdrawal_links: Set({
            account: ALICE,
            request: W_CLOSE.id,
            position: 0,
        }),
        payout_outputs: Set(),
        coverage_boundaries: Map(
            0 -> ZERO_BOUNDARY,
            1 -> B3_BOUNDARY_1,
            2 -> B3_BOUNDARY_2),
        slices: Map(
            0 -> proof_slice(0, ZERO_BOUNDARY, B3_BOUNDARY_1),
            1 -> proof_slice(1, B3_BOUNDARY_1, B3_BOUNDARY_2)),
    }

    pure val OFF_PREFIX_Z = prefix(0, 0, 0, 0, 2, 1, 0)
    pure val OFF_BOUNDARY_1 = boundary(1, 0, 1, ZERO_PREFIX)
    pure val OFF_BOUNDARY_2 = boundary(2, 1, 2, OFF_PREFIX_Z)
    pure val OFF_ROOTS: RootBundle = {
        change: root(ChangeRole, "change-offset", 1),
        withdrawal_outputs: root(WithdrawalOutputRole, "output-offset", 1),
        successor: ROFF,
        coverage: root(CoverageRole, "coverage-offset", 3),
    }
    pure val OFF_CONTEXT: CloseContext = {
        anchor: "anchor-offset",
        epoch: 0,
        predecessor: R0,
        predecessor_liability: 15,
        deposit_root: root(DepositRole, "deposit-empty", 0),
        withdrawal_root: root(WithdrawalRole, "withdrawal-offset", 1),
        admission_deadline: 1,
        challenge_deadline: 3,
    }
    pure val OFF_WITHDRAWALS = Map(
        ALICE -> NoWithdrawal,
        BOB -> Requested(W_OFFSET),
        CAROL -> NoWithdrawal)
    pure val OFF_OUTPUT: PositionedWithdrawalOutput = {
        position: 0,
        output: { destination: W_OFFSET.destination, amount: 2 },
    }
    pure val C_OFF: Candidate = {
        id: BOFF,
        registration: REGOFF,
        context: OFF_CONTEXT,
        roots: OFF_ROOTS,
        header: { context_anchor: OFF_CONTEXT.anchor, roots: OFF_ROOTS },
        predecessor_state: S0,
        successor_state: SOFF,
        row_predecessors: S0,
        row_successors: SOFF,
        deposits: NO_DEPOSITS,
        withdrawals: OFF_WITHDRAWALS,
        payments: Set(),
        outgoing: NO_OUTGOING,
        shard_heads: Set(),
        credit_tip_roots: ACCOUNTS.mapBy(_ => EMPTY_CREDIT_TIP_ROOT),
        row_prefixes: Map(
            ALICE -> ZERO_PREFIX,
            BOB -> OFF_PREFIX_Z,
            CAROL -> ZERO_PREFIX),
        signature_batch: Set(),
        withdrawal_outputs: Set(OFF_OUTPUT),
        withdrawal_links: Set({
            account: BOB,
            request: W_OFFSET.id,
            position: 0,
        }),
        payout_outputs: Set(),
        coverage_boundaries: Map(
            0 -> ZERO_BOUNDARY,
            1 -> OFF_BOUNDARY_1,
            2 -> OFF_BOUNDARY_2),
        slices: Map(
            0 -> proof_slice(0, ZERO_BOUNDARY, OFF_BOUNDARY_1),
            1 -> proof_slice(1, OFF_BOUNDARY_1, OFF_BOUNDARY_2)),
    }

    pure val BAD_ROOTS: RootBundle = {
        change: root(ChangeRole, "change-bad", 2),
        withdrawal_outputs: root(WithdrawalOutputRole, "output-empty", 0),
        successor: root(StateRole, "state-bad", 2),
        coverage: root(CoverageRole, "coverage-bad", 3),
    }
    pure val C_BAD: Candidate = {
        ...C0,
        id: BAD,
        roots: BAD_ROOTS,
        header: { context_anchor: B0_CONTEXT.anchor, roots: BAD_ROOTS },
        slices: Map(
            0 -> proof_slice(0, ZERO_BOUNDARY, B0_BOUNDARY_1),
            1 -> proof_slice(1, ZERO_BOUNDARY, B0_BOUNDARY_2)),
    }

    pure val CANDIDATES = Map(
        B0 -> C0,
        B1 -> C1,
        B2 -> C2,
        B3 -> C3,
        BOFF -> C_OFF,
        BAD -> C_BAD)

    pure val REGISTRATIONS = Map(
        REG0 -> {
            id: REG0,
            context: B0_CONTEXT,
            predecessor_state: S0,
            deposits: C0.deposits,
            withdrawals: C0.withdrawals,
        },
        REG1 -> {
            id: REG1,
            context: B1_CONTEXT,
            predecessor_state: S1,
            deposits: C1.deposits,
            withdrawals: C1.withdrawals,
        },
        REG2 -> {
            id: REG2,
            context: B2_CONTEXT,
            predecessor_state: S2,
            deposits: C2.deposits,
            withdrawals: C2.withdrawals,
        },
        REG3 -> {
            id: REG3,
            context: B3_CONTEXT,
            predecessor_state: S3,
            deposits: C3.deposits,
            withdrawals: C3.withdrawals,
        },
        REGOFF -> {
            id: REGOFF,
            context: OFF_CONTEXT,
            predecessor_state: S0,
            deposits: C_OFF.deposits,
            withdrawals: C_OFF.withdrawals,
        })

    pure val STATE_CONTENT = Map(
        R0.digest -> S0,
        R1.digest -> S1,
        R2.digest -> S2,
        R3.digest -> S3,
        R4.digest -> S4,
        ROFF.digest -> SOFF,
        "state-bad" -> S1,
        EMPTY_STATE_ROOT.digest -> ACCOUNTS.mapBy(_ => ZERO_STATE))
    pure val DEPOSIT_CONTENT = Map(
        "deposit-empty" -> NO_DEPOSITS,
        "deposit-0" -> C0.deposits)
    pure val WITHDRAWAL_CONTENT = Map(
        "withdrawal-empty" -> NO_WITHDRAWALS,
        "withdrawal-2" -> B2_WITHDRAWALS,
        "withdrawal-3" -> B3_WITHDRAWALS,
        "withdrawal-offset" -> OFF_WITHDRAWALS)
    pure val OUTPUT_CONTENT = Map(
        "output-empty" -> Set(),
        "output-2" -> Set(B2_OUTPUT),
        "output-3" -> Set(B3_OUTPUT),
        "output-offset" -> Set(OFF_OUTPUT))
    pure val COVERAGE_CONTENT = Map(
        "coverage-0" -> C0.coverage_boundaries,
        "coverage-1" -> C1.coverage_boundaries,
        "coverage-2" -> C2.coverage_boundaries,
        "coverage-3" -> C3.coverage_boundaries,
        "coverage-offset" -> C_OFF.coverage_boundaries,
        "coverage-bad" -> C_BAD.coverage_boundaries)
    pure val CREDIT_TIP_CONTENT = Map(
        EMPTY_CREDIT_TIP_ROOT.digest -> Set(),
        B0_BOB_CREDIT_TIP_ROOT.digest -> C0.shard_heads,
        B1_CAROL_CREDIT_TIP_ROOT.digest -> C1.shard_heads)
    pure val CHANGE_OWNER = Map(
        C0.roots.change.digest -> B0,
        C1.roots.change.digest -> B1,
        C2.roots.change.digest -> B2,
        C3.roots.change.digest -> B3,
        C_OFF.roots.change.digest -> BOFF,
        C_BAD.roots.change.digest -> BAD)

    pure val C_ALIAS: Candidate = {
        ...C0,
        roots: { ...C0.roots, successor: R0 },
        header: {
            context_anchor: C0.context.anchor,
            roots: { ...C0.roots, successor: R0 },
        },
    }

    pure val D0: DepositEvent = { id: "deposit-bob-2", account: BOB, amount: 2 }
    pure val D1: DepositEvent = { id: "deposit-alice-1", account: ALICE, amount: 1 }
    pure val D2: DepositEvent = { id: "deposit-bob-1", account: BOB, amount: 1 }
    pure val DEPOSIT_EVENTS = Set(D0, D1, D2)

    pure def witness(payment: Payment): PaymentWitness = {
        payment: payment,
        payer_signature: true,
        operator_signature: true,
        exact_link: true,
        context_bound: true,
    }

    pure val P_LATEST: Payment = {
        id: "private-latest",
        payer: ALICE,
        recipient: BOB,
        amount: 1,
        cumulative_debit: 4,
        shard: 0,
        cumulative_shard_credit: 3,
        index: 2,
        external: false,
    }
    pure val P_HIGHER: Payment = {
        id: "private-higher",
        payer: BOB,
        recipient: CAROL,
        amount: 1,
        cumulative_debit: 1,
        shard: 0,
        cumulative_shard_credit: 2,
        index: 2,
        external: true,
    }
    pure val P_RANGE_LOWER: Payment = {
        id: "private-range-lower",
        payer: ALICE,
        recipient: BOB,
        amount: 1,
        cumulative_debit: 1,
        shard: 1,
        cumulative_shard_credit: 1,
        index: 1,
        external: false,
    }
    pure val P_RANGE_UPPER: Payment = {
        id: "private-range-upper",
        payer: ALICE,
        recipient: BOB,
        amount: 2,
        cumulative_debit: 3,
        shard: 1,
        cumulative_shard_credit: 2,
        index: 2,
        external: false,
    }
    pure val P_FORK_LEFT: Payment = {
        id: "private-fork-left",
        payer: ALICE,
        recipient: BOB,
        amount: 1,
        cumulative_debit: 1,
        shard: 2,
        cumulative_shard_credit: 1,
        index: 1,
        external: false,
    }
    pure val P_FORK_RIGHT: Payment = {
        id: "private-fork-right",
        payer: BOB,
        recipient: BOB,
        amount: 2,
        cumulative_debit: 2,
        shard: 2,
        cumulative_shard_credit: 2,
        index: 1,
        external: false,
    }

    pure val E_LATEST = LatestEvidence({
        origin: B1,
        payment: witness(P_LATEST),
        typed_openings: true,
    })
    pure val E_HIGHER = HigherShardTipEvidence({
        origin: B1,
        payment: witness(P_HIGHER),
        typed_openings: true,
    })
    pure val E_RANGE = ReceiptRangeEvidence({
        origin: B1,
        upper: witness(P_RANGE_UPPER),
        lower: LowerPayment(witness(P_RANGE_LOWER)),
    })
    pure val E_FORK = ReceiptForkEvidence({
        origin: B1,
        left: witness(P_FORK_LEFT),
        right: witness(P_FORK_RIGHT),
        canonical: true,
    })
    pure val E_NO_PAYER = ReceiptForkEvidence({
        origin: B1,
        left: { ...witness(P_FORK_LEFT), payer_signature: false },
        right: witness(P_FORK_RIGHT),
        canonical: true,
    })
    pure val E_NO_OPERATOR = ReceiptForkEvidence({
        origin: B1,
        left: witness(P_FORK_LEFT),
        right: { ...witness(P_FORK_RIGHT), operator_signature: false },
        canonical: true,
    })
    pure val E_BAD_LINK = ReceiptForkEvidence({
        origin: B1,
        left: { ...witness(P_FORK_LEFT), exact_link: false },
        right: witness(P_FORK_RIGHT),
        canonical: true,
    })
    pure val E_BAD_OPENING = LatestEvidence({
        origin: B1,
        payment: witness(P_LATEST),
        typed_openings: false,
    })
    pure val E_BAD_CONTEXT = LatestEvidence({
        origin: B1,
        payment: { ...witness(P_LATEST), context_bound: false },
        typed_openings: true,
    })
    pure val E_NO_CONTRADICTION = LatestEvidence({
        origin: B1,
        payment: witness(P1),
        typed_openings: true,
    })
    pure def fork_for(origin: BatchId): ChallengeEvidence = ReceiptForkEvidence({
        origin: origin,
        left: witness(P_FORK_LEFT),
        right: witness(P_FORK_RIGHT),
        canonical: true,
    })
    pure val E_B0_FORK = fork_for(B0)
    pure val E_B2_FORK = fork_for(B2)
    pure val E_B3_FORK = fork_for(B3)
    pure val E_OFFSET_FORK = fork_for(BOFF)
    pure val EVIDENCE = Set(
        E_LATEST,
        E_HIGHER,
        E_RANGE,
        E_FORK,
        E_NO_PAYER,
        E_NO_OPERATOR,
        E_BAD_LINK,
        E_BAD_OPENING,
        E_BAD_CONTEXT,
        E_NO_CONTRADICTION,
        E_B0_FORK,
        E_B2_FORK,
        E_B3_FORK,
        E_OFFSET_FORK)

    pure val B2_WITHDRAWAL_CLAIM: WithdrawalClaim = {
        output: B2_OUTPUT,
        opening: { root: B2_ROOTS.withdrawal_outputs, position: 0 },
    }
    pure val B3_WITHDRAWAL_CLAIM: WithdrawalClaim = {
        output: B3_OUTPUT,
        opening: { root: B3_ROOTS.withdrawal_outputs, position: 0 },
    }
    pure val OFF_WITHDRAWAL_CLAIM: WithdrawalClaim = {
        output: OFF_OUTPUT,
        opening: { root: OFF_ROOTS.withdrawal_outputs, position: 0 },
    }
    pure val WITHDRAWAL_CLAIMS = Set(
        B2_WITHDRAWAL_CLAIM,
        B3_WITHDRAWAL_CLAIM,
        OFF_WITHDRAWAL_CLAIM)

    pure val B1_PAYOUT: PayoutOutput = { position: 1, recipient: CAROL, amount: 1 }
    pure val B1_PAYOUT_CLAIM: PayoutClaim = {
        output: B1_PAYOUT,
        opening: { root: B1_ROOTS.change, position: 1 },
    }
    pure val PAYOUT_CLAIMS = Set(B1_PAYOUT_CLAIM)
}
