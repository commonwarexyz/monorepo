// Finite, ideal-cryptography types for the Bajillion protocol model.
module types {
    type Account = str
    type BatchId = str
    type DepositId = str
    type Destination = str
    type PaymentId = str
    type RegistrationId = str
    type RequestId = str
    type RootId = str
    type Validator = str
    type SliceId = int

    type VectorKind =
        | StateRole
        | ChangeRole
        | CreditTipRole
        | DepositRole
        | WithdrawalRole
        | CoverageRole
        | WithdrawalOutputRole

    type TypedRoot = {
        kind: VectorKind,
        digest: RootId,
        length: int,
    }

    type RootBundle = {
        change: TypedRoot,
        withdrawal_outputs: TypedRoot,
        successor: TypedRoot,
        coverage: TypedRoot,
    }

    type CloseContext = {
        anchor: str,
        epoch: int,
        predecessor: TypedRoot,
        predecessor_liability: int,
        deposit_root: TypedRoot,
        withdrawal_root: TypedRoot,
        admission_deadline: int,
        challenge_deadline: int,
    }

    type AccountState = {
        active: bool,
        balance: int,
        cumulative_debit: int,
        cumulative_credit: int,
        receipt_count: int,
    }

    type Header = {
        context_anchor: str,
        roots: RootBundle,
    }

    type WithdrawalAction =
        | Amount(int)
        | Close

    type Withdrawal = {
        id: RequestId,
        account: Account,
        destination: Destination,
        withdrawal_action: WithdrawalAction,
        deadline: int,
        context_root: RootId,
        signature_valid: bool,
        destination_eligible: bool,
    }

    type WithdrawalSlot =
        | NoWithdrawal
        | Requested(Withdrawal)

    type Payment = {
        id: PaymentId,
        payer: Account,
        recipient: Account,
        amount: int,
        cumulative_debit: int,
        shard: int,
        cumulative_shard_credit: int,
        index: int,
        external: bool,
    }

    type SignatureKind =
        | PayerSignature
        | OperatorSignature

    type SignatureCheck = {
        context: RegistrationId,
        payment: PaymentId,
        kind: SignatureKind,
        valid: bool,
    }

    type PaymentSlot =
        | NoPayment
        | TerminalPayment(Payment)

    type ShardHead = {
        recipient: Account,
        shard: int,
        payment: Payment,
    }

    // The request identity and account are ghost fields used only to state the
    // semantic derivation. The wire output is exactly destination plus amount.
    type WithdrawalOutput = {
        destination: Destination,
        amount: int,
    }

    type PositionedWithdrawalOutput = {
        position: int,
        output: WithdrawalOutput,
    }

    type WithdrawalOutputLink = {
        account: Account,
        request: RequestId,
        position: int,
    }

    type PayoutOutput = {
        position: int,
        recipient: Account,
        amount: int,
    }

    type Prefix = {
        debit: int,
        credit: int,
        payout: int,
        deposit: int,
        withdrawal: int,
        withdrawal_count: int,
        shard_count: int,
    }

    type Boundary = {
        predecessor: int,
        change: int,
        successor: int,
        prefix: Prefix,
    }

    type ProofSlice = {
        index: SliceId,
        left: Boundary,
        right: Boundary,
        typed_openings: bool,
        ordered_guards: bool,
        exact_ranges: bool,
    }

    type Registration = {
        id: RegistrationId,
        context: CloseContext,
        predecessor_state: Account -> AccountState,
        deposits: Account -> int,
        withdrawals: Account -> WithdrawalSlot,
    }

    type ChallengeKind =
        | LatestAcknowledgedSend
        | HigherShardTip
        | InconsistentReceiptRange
        | ReceiptFork

    type PaymentWitness = {
        payment: Payment,
        payer_signature: bool,
        operator_signature: bool,
        exact_link: bool,
        context_bound: bool,
    }

    type RangeLower =
        | ShardStart
        | LowerPayment(PaymentWitness)

    // Each `origin` is ghost context, not an embedded wire BatchId. Settlement
    // supplies the target batch separately and reconstructs against that context.
    type ChallengeEvidence =
        | LatestEvidence({
            origin: BatchId,
            payment: PaymentWitness,
            typed_openings: bool,
        })
        | HigherShardTipEvidence({
            origin: BatchId,
            payment: PaymentWitness,
            typed_openings: bool,
        })
        | ReceiptRangeEvidence({
            origin: BatchId,
            upper: PaymentWitness,
            lower: RangeLower,
        })
        | ReceiptForkEvidence({
            origin: BatchId,
            left: PaymentWitness,
            right: PaymentWitness,
            canonical: bool,
        })

    type Candidate = {
        id: BatchId,
        registration: RegistrationId,
        context: CloseContext,
        roots: RootBundle,
        header: Header,
        predecessor_state: Account -> AccountState,
        successor_state: Account -> AccountState,
        row_predecessors: Account -> AccountState,
        row_successors: Account -> AccountState,
        deposits: Account -> int,
        withdrawals: Account -> WithdrawalSlot,
        payments: Set[Payment],
        outgoing: Account -> PaymentSlot,
        shard_heads: Set[ShardHead],
        credit_tip_roots: Account -> TypedRoot,
        row_prefixes: Account -> Prefix,
        signature_batch: Set[SignatureCheck],
        withdrawal_outputs: Set[PositionedWithdrawalOutput],
        withdrawal_links: Set[WithdrawalOutputLink],
        payout_outputs: Set[PayoutOutput],
        coverage_boundaries: int -> Boundary,
        slices: SliceId -> ProofSlice,
    }

    type TypedOpening = {
        root: TypedRoot,
        position: int,
    }

    type WithdrawalClaim = {
        output: PositionedWithdrawalOutput,
        opening: TypedOpening,
    }

    type PayoutClaim = {
        output: PayoutOutput,
        opening: TypedOpening,
    }

    type BatchStatus =
        | Inactive
        | Pending
        | Challenged(ChallengeKind)
        | Invalidated(BatchId)
        | Finalized

    type ProvenFault = {
        batch: BatchId,
        kind: ChallengeKind,
    }

    type RegistrationFault = {
        anchor: str,
        epoch: int,
        expired_at: int,
    }

    type Fault =
        | Healthy
        | ProvenChallenge(ProvenFault)
        | ExpiredDeposit
        | ExpiredWithdrawal
        | ExpiredRegistration(RegistrationFault)

    type MaybeBatch =
        | NoBatch
        | SomeBatch(BatchId)

    type MaybeRegistration =
        | NoRegistration
        | SomeRegistration(RegistrationId)

    type ClaimKind =
        | WithdrawalClaimKind
        | PayoutClaimKind

    type ClaimKey = {
        kind: ClaimKind,
        batch: BatchId,
        position: int,
    }

    type ClaimingState = {
        frozen_root: TypedRoot,
        frozen_state: Account -> AccountState,
        remaining_state: int,
        remaining_deposits: int,
    }

    type Terminal =
        | Dormant
        | Claiming(ClaimingState)
        | Settled

    type DepositEvent = {
        id: DepositId,
        account: Account,
        amount: int,
    }

    type DeliveryKey = {
        batch: BatchId,
        validator: Validator,
    }

    type SliceRef = {
        batch: BatchId,
        slice: SliceId,
    }

    type CertificationState = {
        prepared: Set[BatchId],
        dealt: Set[BatchId],
        exact_deliveries: Set[DeliveryKey],
        votes: BatchId -> Set[Validator],
        retained: Validator -> Set[SliceRef],
        certificates: Set[BatchId],
    }

    type ChainState = {
        now: int,
        expected_epoch: int,
        current_root: TypedRoot,
        current_state: Account -> AccountState,
        current_liability: int,
        custody: int,
        claimable: int,
        total_in: int,
        released: int,
        clean_claim_paid: int,
        pending_deposits: Account -> int,
        deposit_deadlines: Account -> int,
        unfinalized_deposits: Account -> int,
        pending_withdrawals: Account -> WithdrawalSlot,
        outstanding_withdrawals: Account -> WithdrawalSlot,
        registered: MaybeRegistration,
        pipeline: List[BatchId],
        status: BatchId -> BatchStatus,
        fault: Fault,
        fault_history: Set[Fault],
        admission_fence_epoch: int,
        invalid_from: MaybeBatch,
        terminal: Terminal,
        withdrawal_reserve: BatchId -> int,
        payout_reserve: BatchId -> int,
        consumed_claims: Set[ClaimKey],
        consumed_state: Set[Account],
        consumed_deposits: Set[DepositId],
        consumed_withdrawals: Set[RequestId],
        finalized_batches: Set[BatchId],
        invalidated_batches: Set[BatchId],
        finalized_epochs: List[int],
        refunded_deposits: Account -> int,
        recovered_state: Account -> int,
        terminal_withdrawals: Account -> int,
        terminal_residuals: Account -> int,
    }
}
