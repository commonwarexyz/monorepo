// Idealized close construction, proof-slice continuity, and claim relations.
module transition {
    import types.* from "./types"

    const ACCOUNTS: Set[Account]
    const ACCOUNT_INDEX: Account -> int
    const ACCOUNT_SLICE: Account -> SliceId
    const BATCHES: Set[BatchId]
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

    pure val zero_state: AccountState = {
        active: false,
        balance: 0,
        cumulative_debit: 0,
        cumulative_credit: 0,
        receipt_count: 0,
    }

    pure val zero_prefix: Prefix = {
        debit: 0,
        credit: 0,
        payout: 0,
        deposit: 0,
        withdrawal: 0,
        withdrawal_count: 0,
        shard_count: 0,
    }

    pure def minimum(left: int, right: int): int =
        if (left < right) left else right

    pure def state_liability(state: Account -> AccountState): int =
        ACCOUNTS.fold(0, (total, account) => total + state.get(account).balance)

    pure def live_state_count(state: Account -> AccountState): int =
        ACCOUNTS.filter(account => state.get(account).active).size()

    pure def deposit_total(candidate: Candidate): int =
        ACCOUNTS.fold(0, (total, account) => total + candidate.deposits.get(account))

    pure def is_requested(slot: WithdrawalSlot): bool =
        match slot {
            | NoWithdrawal => false
            | Requested(_) => true
        }

    pure def withdrawal_count(candidate: Candidate): int =
        ACCOUNTS.filter(account => is_requested(candidate.withdrawals.get(account))).size()

    pure def debit_delta(candidate: Candidate, account: Account): int =
        candidate.row_successors.get(account).cumulative_debit
            - candidate.row_predecessors.get(account).cumulative_debit

    pure def credit_delta(candidate: Candidate, account: Account): int =
        candidate.row_successors.get(account).cumulative_credit
            - candidate.row_predecessors.get(account).cumulative_credit

    pure def receipt_delta(candidate: Candidate, account: Account): int =
        candidate.row_successors.get(account).receipt_count
            - candidate.row_predecessors.get(account).receipt_count

    pure def registered_account(candidate: Candidate, account: Account): bool =
        candidate.row_predecessors.get(account).active
            or candidate.deposits.get(account) > 0

    pure def payout_amount(candidate: Candidate, account: Account): int =
        if (registered_account(candidate, account)) 0 else credit_delta(candidate, account)

    pure def tail_before_withdrawal(candidate: Candidate, account: Account): int =
        candidate.row_predecessors.get(account).balance
            + candidate.deposits.get(account)
            + credit_delta(candidate, account)
            - debit_delta(candidate, account)
            - payout_amount(candidate, account)

    pure def withdrawal_amount(candidate: Candidate, account: Account): int =
        match candidate.withdrawals.get(account) {
            | NoWithdrawal => 0
            | Requested(request) => match request.withdrawal_action {
                | Amount(amount) => amount
                | Close => tail_before_withdrawal(candidate, account)
            }
        }

    pure def prefix_add(left: Prefix, right: Prefix): Prefix = {
        debit: left.debit + right.debit,
        credit: left.credit + right.credit,
        payout: left.payout + right.payout,
        deposit: left.deposit + right.deposit,
        withdrawal: left.withdrawal + right.withdrawal,
        withdrawal_count: left.withdrawal_count + right.withdrawal_count,
        shard_count: left.shard_count + right.shard_count,
    }

    pure def row_prefix(candidate: Candidate, account: Account): Prefix = {
        debit: debit_delta(candidate, account),
        credit: credit_delta(candidate, account),
        payout: payout_amount(candidate, account),
        deposit: candidate.deposits.get(account),
        withdrawal: withdrawal_amount(candidate, account),
        withdrawal_count: if (is_requested(candidate.withdrawals.get(account))) 1 else 0,
        shard_count: candidate.shard_heads
            .filter(tip => tip.recipient == account)
            .size(),
    }

    pure def terminal_prefix(candidate: Candidate): Prefix =
        ACCOUNTS.fold(zero_prefix, (prefix, account) =>
            prefix_add(prefix, row_prefix(candidate, account)))

    pure def cumulative_prefix(candidate: Candidate, account: Account): Prefix =
        ACCOUNTS
            .filter(other => ACCOUNT_INDEX.get(other) <= ACCOUNT_INDEX.get(account))
            .fold(zero_prefix, (prefix, other) =>
                prefix_add(prefix, row_prefix(candidate, other)))

    pure def row_has_effect(candidate: Candidate, account: Account): bool = {
        val prefix = row_prefix(candidate, account)
        or {
            prefix.debit > 0,
            prefix.credit > 0,
            prefix.deposit > 0,
            prefix.withdrawal_count == 1,
            prefix.shard_count > 0,
        }
    }

    pure def change_count(candidate: Candidate): int =
        ACCOUNTS.filter(account => row_has_effect(candidate, account)).size()

    pure def withdrawal_position(candidate: Candidate, account: Account): int =
        ACCOUNTS.filter(other => and {
            ACCOUNT_INDEX.get(other) < ACCOUNT_INDEX.get(account),
            is_requested(candidate.withdrawals.get(other)),
        }).size()

    pure def change_position(candidate: Candidate, account: Account): int =
        ACCOUNTS.filter(other => and {
            ACCOUNT_INDEX.get(other) < ACCOUNT_INDEX.get(account),
            row_has_effect(candidate, other),
        }).size()

    pure def canonical_predecessor(state: AccountState): bool =
        if (state.active) state.balance > 0 else state == zero_state

    pure def canonical_successor(state: AccountState): bool =
        state.active == (state.balance > 0)

    pure def payment_ids_unique(candidate: Candidate): bool =
        tuples(candidate.payments, candidate.payments).forall(((left, right)) =>
            (left.id == right.id) implies left == right)

    pure def head_keys_unique(candidate: Candidate): bool =
        tuples(candidate.shard_heads, candidate.shard_heads).forall(((left, right)) =>
            (left.recipient == right.recipient and left.shard == right.shard) implies left == right)

    pure def payment_holds(candidate: Candidate, payment: Payment): bool = and {
        payment.payer.in(ACCOUNTS),
        payment.recipient.in(ACCOUNTS),
        payment.amount > 0,
        payment.cumulative_debit > 0,
        payment.shard >= 0,
        payment.cumulative_shard_credit > 0,
        payment.index > 0,
        payment.external == not(registered_account(candidate, payment.recipient)),
        or {
            candidate.shard_heads.exists(tip => tip.payment == payment),
            ACCOUNTS.exists(account => match candidate.outgoing.get(account) {
                | NoPayment => false
                | TerminalPayment(outgoing) => outgoing == payment
            }),
        },
    }

    pure def head_holds(candidate: Candidate, tip: ShardHead): bool = and {
        tip.payment.in(candidate.payments),
        tip.recipient == tip.payment.recipient,
        tip.shard == tip.payment.shard,
    }

    pure def payment_structure_holds(candidate: Candidate): bool = and {
        payment_ids_unique(candidate),
        head_keys_unique(candidate),
        candidate.payments.forall(payment => payment_holds(candidate, payment)),
        candidate.shard_heads.forall(tip => head_holds(candidate, tip)),
    }

    pure def outgoing_holds(candidate: Candidate, account: Account): bool = {
        val debit = debit_delta(candidate, account)
        match candidate.outgoing.get(account) {
            | NoPayment => debit == 0
            | TerminalPayment(payment) => and {
                debit > 0,
                payment.in(candidate.payments),
                payment.payer == account,
                payment.cumulative_debit
                    == candidate.row_successors.get(account).cumulative_debit,
                payment.amount <= debit,
            }
        }
    }

    pure def credit_heads_hold(candidate: Candidate, account: Account): bool = {
        val heads = candidate.shard_heads.filter(tip => tip.recipient == account)
        and {
            heads.fold(0, (total, tip) =>
                total + tip.payment.cumulative_shard_credit)
                == credit_delta(candidate, account),
            heads.fold(0, (total, tip) => total + tip.payment.index)
                == receipt_delta(candidate, account),
        }
    }

    pure def withdrawal_request_holds(candidate: Candidate, account: Account): bool =
        match candidate.withdrawals.get(account) {
            | NoWithdrawal => true
            | Requested(request) => and {
                request.account == account,
                request.signature_valid,
                request.destination_eligible,
                match request.withdrawal_action {
                    | Amount(amount) => amount > 0
                    | Close => true
                },
            }
        }

    pure def row_holds(candidate: Candidate, account: Account): bool = {
        val predecessor = candidate.row_predecessors.get(account)
        val successor = candidate.row_successors.get(account)
        val debit = debit_delta(candidate, account)
        val credit = credit_delta(candidate, account)
        val receipts = receipt_delta(candidate, account)
        val deposit = candidate.deposits.get(account)
        val withdrawal = withdrawal_amount(candidate, account)
        val payout = payout_amount(candidate, account)
        val effect = row_has_effect(candidate, account)
        and {
            canonical_predecessor(predecessor),
            canonical_successor(successor),
            debit >= 0,
            credit >= 0,
            receipts >= 0,
            deposit >= 0,
            withdrawal >= 0,
            withdrawal_request_holds(candidate, account),
            outgoing_holds(candidate, account),
            credit_heads_hold(candidate, account),
            successor.balance + debit + withdrawal + payout
                == predecessor.balance + credit + deposit,
            if (not(effect))
                true
            else if (registered_account(candidate, account))
                payout == 0
            else and {
                    not(successor.active),
                    debit == 0,
                    credit > 0,
                    not(is_requested(candidate.withdrawals.get(account))),
                },
            match candidate.withdrawals.get(account) {
                | NoWithdrawal => true
                | Requested(request) => match request.withdrawal_action {
                    | Amount(_) => true
                    | Close => not(successor.active) and successor.balance == 0
                }
            },
            effect implies and {
                predecessor == candidate.predecessor_state.get(account),
                if (successor.active)
                    successor == candidate.successor_state.get(account)
                else
                    candidate.successor_state.get(account) == zero_state,
                candidate.row_prefixes.get(account) == cumulative_prefix(candidate, account),
                or {
                    predecessor != successor,
                    not(predecessor.active) and not(successor.active),
                },
            },
            not(effect) implies and {
                candidate.predecessor_state.get(account)
                    == candidate.successor_state.get(account),
                predecessor == candidate.predecessor_state.get(account),
                successor == candidate.successor_state.get(account),
            },
        }
    }

    pure def expected_signature_batch(candidate: Candidate): Set[SignatureCheck] =
        candidate.payments.map(payment => {
            context: candidate.registration,
            payment: payment.id,
            kind: PayerSignature,
            valid: true,
        }).union(candidate.payments.map(payment => {
            context: candidate.registration,
            payment: payment.id,
            kind: OperatorSignature,
            valid: true,
        }))

    pure def signature_batch_holds(candidate: Candidate): bool =
        candidate.signature_batch == expected_signature_batch(candidate)

    pure def registration_roots_hold(registration: Registration): bool = and {
        registration.context.predecessor.kind == StateRole,
        registration.context.predecessor.digest.in(STATE_CONTENT.keys()),
        STATE_CONTENT.get(registration.context.predecessor.digest)
            == registration.predecessor_state,
        registration.context.predecessor.length
            == live_state_count(registration.predecessor_state),
        registration.context.predecessor_liability
            == state_liability(registration.predecessor_state),
        registration.context.deposit_root.kind == DepositRole,
        registration.context.deposit_root.digest.in(DEPOSIT_CONTENT.keys()),
        DEPOSIT_CONTENT.get(registration.context.deposit_root.digest) == registration.deposits,
        registration.context.withdrawal_root.kind == WithdrawalRole,
        registration.context.withdrawal_root.digest.in(WITHDRAWAL_CONTENT.keys()),
        WITHDRAWAL_CONTENT.get(registration.context.withdrawal_root.digest)
            == registration.withdrawals,
    }

    pure def registration_holds(candidate: Candidate): bool =
        if (not(candidate.registration.in(REGISTRATIONS.keys())))
            false
        else {
            val registration = REGISTRATIONS.get(candidate.registration)
            and {
                registration_roots_hold(registration),
                candidate.context == registration.context,
                candidate.predecessor_state == registration.predecessor_state,
                candidate.deposits == registration.deposits,
                candidate.withdrawals == registration.withdrawals,
            }
        }

    pure def slice_accounts(index: SliceId): Set[Account] =
        ACCOUNTS.filter(account => ACCOUNT_SLICE.get(account) == index)

    pure def accounts_before(index: SliceId): Set[Account] =
        ACCOUNTS.filter(account => ACCOUNT_SLICE.get(account) < index)

    pure def expected_boundary(candidate: Candidate, index: SliceId): Boundary = {
        val before = accounts_before(index)
        {
            predecessor: before
                .filter(account => candidate.predecessor_state.get(account).active)
                .size(),
            change: before.filter(account => row_has_effect(candidate, account)).size(),
            successor: before
                .filter(account => candidate.successor_state.get(account).active)
                .size(),
            prefix: before.fold(zero_prefix, (prefix, account) =>
                prefix_add(prefix, row_prefix(candidate, account))),
        }
    }

    pure def payments_in_slices(
        candidate: Candidate,
        slices: Set[SliceId],
    ): Set[Payment] = candidate.payments.filter(payment => or {
        ACCOUNT_SLICE.get(payment.payer).in(slices),
        ACCOUNT_SLICE.get(payment.recipient).in(slices),
    })

    pure def expected_dealing_signatures(
        candidate: Candidate,
        slices: Set[SliceId],
    ): Set[SignatureCheck] = {
        val payments = payments_in_slices(candidate, slices)
        payments.map(payment => {
            context: candidate.registration,
            payment: payment.id,
            kind: PayerSignature,
            valid: true,
        }).union(payments.map(payment => {
            context: candidate.registration,
            payment: payment.id,
            kind: OperatorSignature,
            valid: true,
        }))
    }

    // Set equality states the one aggregate batch over every distinct send and
    // receipt envelope disclosed by this validator's exact dealing.
    pure def dealing_signatures_hold(
        candidate: Candidate,
        slices: Set[SliceId],
    ): bool = {
        val payment_ids = payments_in_slices(candidate, slices).map(payment => payment.id)
        candidate.signature_batch
            .filter(check => check.payment.in(payment_ids))
            == expected_dealing_signatures(candidate, slices)
    }

    pure def withdrawal_outputs_hold(candidate: Candidate): bool = and {
        candidate.withdrawal_outputs.size() == withdrawal_count(candidate),
        candidate.withdrawal_links.size() == withdrawal_count(candidate),
        candidate.withdrawal_outputs.forall(positioned => and {
            positioned.position >= 0,
            positioned.position < candidate.withdrawal_outputs.size(),
        }),
        candidate.withdrawal_outputs
            .map(positioned => positioned.position)
            .size() == candidate.withdrawal_outputs.size(),
        ACCOUNTS.forall(account => match candidate.withdrawals.get(account) {
            | NoWithdrawal => not(candidate.withdrawal_links.exists(link => link.account == account))
            | Requested(request) => candidate.withdrawal_links.exists(link => and {
                link.account == account,
                link.request == request.id,
                link.position == withdrawal_position(candidate, account),
                candidate.withdrawal_outputs.exists(positioned => and {
                    positioned.position == link.position,
                    positioned.output.destination == request.destination,
                    positioned.output.amount == withdrawal_amount(candidate, account),
                }),
            })
        }),
        candidate.withdrawal_links.forall(link =>
            match candidate.withdrawals.get(link.account) {
                | NoWithdrawal => false
                | Requested(request) => and {
                    link.request == request.id,
                    link.position == withdrawal_position(candidate, link.account),
                }
            }),
    }

    pure def payout_outputs_hold(candidate: Candidate): bool = {
        val recipients = ACCOUNTS.filter(account => payout_amount(candidate, account) > 0)
        and {
            candidate.payout_outputs.size() == recipients.size(),
            candidate.payout_outputs.forall(output => and {
                output.recipient.in(recipients),
                output.amount == payout_amount(candidate, output.recipient),
                output.position == change_position(candidate, output.recipient),
            }),
            recipients.forall(account => candidate.payout_outputs.exists(output => and {
                output.recipient == account,
                output.amount == payout_amount(candidate, account),
                output.position == change_position(candidate, account),
            })),
        }
    }

    pure def state_root_holds(root: TypedRoot, state: Account -> AccountState): bool = and {
        root.kind == StateRole,
        root.length == live_state_count(state),
        root.digest.in(STATE_CONTENT.keys()),
        STATE_CONTENT.get(root.digest) == state,
    }

    pure def boundary_roots_hold(candidate: Candidate): bool = and {
        candidate.context.deposit_root.kind == DepositRole,
        candidate.context.deposit_root.length
            == ACCOUNTS.filter(account => candidate.deposits.get(account) > 0).size(),
        candidate.context.deposit_root.digest.in(DEPOSIT_CONTENT.keys()),
        DEPOSIT_CONTENT.get(candidate.context.deposit_root.digest) == candidate.deposits,
        candidate.context.withdrawal_root.kind == WithdrawalRole,
        candidate.context.withdrawal_root.length == withdrawal_count(candidate),
        candidate.context.withdrawal_root.digest.in(WITHDRAWAL_CONTENT.keys()),
        WITHDRAWAL_CONTENT.get(candidate.context.withdrawal_root.digest) == candidate.withdrawals,
    }

    pure def credit_tip_roots_hold(candidate: Candidate): bool =
        ACCOUNTS.forall(account => {
            val root = candidate.credit_tip_roots.get(account)
            val tips = candidate.shard_heads.filter(tip => tip.recipient == account)
            and {
                root.kind == CreditTipRole,
                root.length == tips.size(),
                root.digest.in(CREDIT_TIP_CONTENT.keys()),
                CREDIT_TIP_CONTENT.get(root.digest) == tips,
            }
        })

    pure def header_holds(candidate: Candidate): bool = and {
        registration_holds(candidate),
        candidate.context.epoch >= 0,
        candidate.context.admission_deadline >= 0,
        candidate.context.challenge_deadline > candidate.context.admission_deadline,
        candidate.header.context_anchor == candidate.context.anchor,
        candidate.header.roots == candidate.roots,
        boundary_roots_hold(candidate),
    }

    pure def roots_hold(candidate: Candidate): bool = and {
        ACCOUNTS.forall(account => and {
            canonical_predecessor(candidate.predecessor_state.get(account)),
            canonical_predecessor(candidate.successor_state.get(account)),
        }),
        state_root_holds(candidate.context.predecessor, candidate.predecessor_state),
        candidate.context.predecessor_liability == state_liability(candidate.predecessor_state),
        candidate.roots.change.kind == ChangeRole,
        candidate.roots.change.length == change_count(candidate),
        candidate.roots.change.digest.in(CHANGE_OWNER.keys()),
        CHANGE_OWNER.get(candidate.roots.change.digest) == candidate.id,
        candidate.roots.withdrawal_outputs.kind == WithdrawalOutputRole,
        candidate.roots.withdrawal_outputs.length == withdrawal_count(candidate),
        candidate.roots.withdrawal_outputs.digest.in(OUTPUT_CONTENT.keys()),
        OUTPUT_CONTENT.get(candidate.roots.withdrawal_outputs.digest)
            == candidate.withdrawal_outputs,
        state_root_holds(candidate.roots.successor, candidate.successor_state),
        candidate.roots.coverage.kind == CoverageRole,
        candidate.roots.coverage.length == SLICE_IDS.size() + 1,
        candidate.roots.coverage.digest.in(COVERAGE_CONTENT.keys()),
        COVERAGE_CONTENT.get(candidate.roots.coverage.digest)
            == candidate.coverage_boundaries,
        credit_tip_roots_hold(candidate),
        header_holds(candidate),
    }

    pure def prefix_monotonic(left: Prefix, right: Prefix): bool = and {
        left.debit <= right.debit,
        left.credit <= right.credit,
        left.payout <= right.payout,
        left.deposit <= right.deposit,
        left.withdrawal <= right.withdrawal,
        left.withdrawal_count <= right.withdrawal_count,
        left.shard_count <= right.shard_count,
    }

    pure def boundary_monotonic(left: Boundary, right: Boundary): bool = and {
        left.predecessor <= right.predecessor,
        left.change <= right.change,
        left.successor <= right.successor,
        prefix_monotonic(left.prefix, right.prefix),
    }

    pure def zero_boundary(boundary: Boundary): bool = and {
        boundary.predecessor == 0,
        boundary.change == 0,
        boundary.successor == 0,
        boundary.prefix == zero_prefix,
    }

    pure def terminal_boundary_holds(candidate: Candidate, boundary: Boundary): bool = and {
        boundary.predecessor == live_state_count(candidate.predecessor_state),
        boundary.change == change_count(candidate),
        boundary.successor == live_state_count(candidate.successor_state),
        boundary.prefix == terminal_prefix(candidate),
        boundary.prefix.withdrawal_count == candidate.withdrawal_outputs.size(),
        candidate.context.predecessor_liability
            + boundary.prefix.deposit
            - boundary.prefix.withdrawal
            - boundary.prefix.payout
            == state_liability(candidate.successor_state),
        boundary.prefix.debit == boundary.prefix.credit,
    }

    pure def slice_holds(candidate: Candidate, index: SliceId): bool = {
        val proof_slice = candidate.slices.get(index)
        val accounts = slice_accounts(index)
        val left = expected_boundary(candidate, index)
        val right = expected_boundary(candidate, index + 1)
        val output_start = left.prefix.withdrawal_count
        val output_end = right.prefix.withdrawal_count
        val outputs = candidate.withdrawal_outputs.filter(positioned => and {
            positioned.position >= output_start,
            positioned.position < output_end,
        })
        and {
            index.in(SLICE_IDS),
            proof_slice.index == index,
            proof_slice.left == left,
            proof_slice.right == right,
            proof_slice.typed_openings,
            proof_slice.ordered_guards,
            proof_slice.exact_ranges,
            candidate.coverage_boundaries.get(index) == left,
            candidate.coverage_boundaries.get(index + 1) == right,
            COVERAGE_CONTENT.get(candidate.roots.coverage.digest).get(index) == left,
            COVERAGE_CONTENT.get(candidate.roots.coverage.digest).get(index + 1) == right,
            accounts.forall(account => and {
                row_holds(candidate, account),
                STATE_CONTENT.get(candidate.context.predecessor.digest).get(account)
                    == candidate.predecessor_state.get(account),
                STATE_CONTENT.get(candidate.roots.successor.digest).get(account)
                    == candidate.successor_state.get(account),
                CREDIT_TIP_CONTENT.get(candidate.credit_tip_roots.get(account).digest)
                    == candidate.shard_heads.filter(tip => tip.recipient == account),
            }),
            payments_in_slices(candidate, Set(index))
                .forall(payment => payment_holds(candidate, payment)),
            candidate.shard_heads
                .filter(tip => tip.recipient.in(accounts))
                .forall(tip => head_holds(candidate, tip)),
            dealing_signatures_hold(candidate, Set(index)),
            OUTPUT_CONTENT.get(candidate.roots.withdrawal_outputs.digest)
                .filter(positioned => and {
                    positioned.position >= output_start,
                    positioned.position < output_end,
                }) == outputs,
            boundary_monotonic(left, right),
        }
    }

    pure def coverage_holds(candidate: Candidate): bool = {
        val last = SLICE_IDS.size()
        and {
            SLICE_IDS.forall(index => index >= 0 and index < last),
            candidate.coverage_boundaries.keys()
                == SLICE_IDS.map(index => index + 1).union(Set(0)),
            candidate.slices.keys() == SLICE_IDS,
            zero_boundary(candidate.coverage_boundaries.get(0)),
            terminal_boundary_holds(candidate, candidate.coverage_boundaries.get(last)),
            SLICE_IDS.forall(index => slice_holds(candidate, index)),
        }
    }

    pure def public_relation_holds(batch: BatchId): bool = {
        val candidate = CANDIDATES.get(batch)
        and {
            candidate.id == batch,
            candidate.context.epoch >= 0,
            candidate.context.admission_deadline >= 0,
            candidate.context.challenge_deadline > candidate.context.admission_deadline,
            roots_hold(candidate),
            payment_structure_holds(candidate),
            ACCOUNTS.forall(account => row_holds(candidate, account)),
            terminal_prefix(candidate).debit == terminal_prefix(candidate).credit,
            signature_batch_holds(candidate),
            withdrawal_outputs_hold(candidate),
            payout_outputs_hold(candidate),
            coverage_holds(candidate),
        }
    }

    pure def evidence_kind(evidence: ChallengeEvidence): ChallengeKind =
        match evidence {
            | LatestEvidence(_) => LatestAcknowledgedSend
            | HigherShardTipEvidence(_) => HigherShardTip
            | ReceiptRangeEvidence(_) => InconsistentReceiptRange
            | ReceiptForkEvidence(_) => ReceiptFork
        }

    pure def evidence_origin(evidence: ChallengeEvidence): BatchId =
        match evidence {
            | LatestEvidence(value) => value.origin
            | HigherShardTipEvidence(value) => value.origin
            | ReceiptRangeEvidence(value) => value.origin
            | ReceiptForkEvidence(value) => value.origin
        }

    pure def witness_holds(witness: PaymentWitness): bool = {
        val payment = witness.payment
        and {
            witness.payer_signature,
            witness.operator_signature,
            witness.exact_link,
            witness.context_bound,
            payment.payer.in(ACCOUNTS),
            payment.recipient.in(ACCOUNTS),
            payment.amount > 0,
            payment.cumulative_debit > 0,
            payment.shard >= 0,
            payment.cumulative_shard_credit > 0,
            payment.index > 0,
        }
    }

    pure def public_tip_credit(
        candidate: Candidate,
        recipient: Account,
        shard: int,
    ): int = candidate.shard_heads
        .filter(tip => tip.recipient == recipient and tip.shard == shard)
        .fold(0, (credit, tip) => credit + tip.payment.cumulative_shard_credit)

    pure def public_tip_index(
        candidate: Candidate,
        recipient: Account,
        shard: int,
    ): int = candidate.shard_heads
        .filter(tip => tip.recipient == recipient and tip.shard == shard)
        .fold(0, (index, tip) => index + tip.payment.index)

    pure def range_feasible(
        lower_credit: int,
        lower_index: int,
        upper: Payment,
    ): bool = {
        val distance = upper.index - lower_index
        val explicit_credit = lower_credit + upper.amount
        and {
            upper.amount > 0,
            distance > 0,
            if (distance == 1)
                upper.cumulative_shard_credit == explicit_credit
            else
                upper.cumulative_shard_credit >= explicit_credit + distance - 1,
        }
    }

    pure def receipt_equal(left: Payment, right: Payment): bool = and {
        left.id == right.id,
        left.recipient == right.recipient,
        left.shard == right.shard,
        left.cumulative_shard_credit == right.cumulative_shard_credit,
        left.index == right.index,
    }

    pure def evidence_proves(
        target: BatchId,
        evidence: ChallengeEvidence,
    ): bool = {
        val candidate = CANDIDATES.get(target)
        and {
            target == evidence_origin(evidence),
            match evidence {
                | LatestEvidence(value) => {
                    val payment = value.payment.payment
                    val committed = candidate.row_successors
                        .get(payment.payer).cumulative_debit
                    val outgoing_matches = candidate.outgoing.get(payment.payer)
                        == TerminalPayment(payment)
                    and {
                        value.typed_openings,
                        witness_holds(value.payment),
                        payment.cumulative_debit > committed
                            or payment.cumulative_debit == committed
                                and not(outgoing_matches),
                    }
                }
                | HigherShardTipEvidence(value) => {
                    val payment = value.payment.payment
                    val credit = public_tip_credit(
                        candidate, payment.recipient, payment.shard)
                    val index = public_tip_index(
                        candidate, payment.recipient, payment.shard)
                    and {
                        value.typed_openings,
                        witness_holds(value.payment),
                        payment.cumulative_shard_credit > credit
                            or payment.index > index,
                    }
                }
                | ReceiptRangeEvidence(value) => {
                    val upper = value.upper.payment
                    match value.lower {
                        | ShardStart => and {
                            witness_holds(value.upper),
                            not(range_feasible(0, 0, upper)),
                        }
                        | LowerPayment(lower_witness) => {
                            val lower = lower_witness.payment
                            and {
                                witness_holds(value.upper),
                                witness_holds(lower_witness),
                                upper.recipient == lower.recipient,
                                upper.shard == lower.shard,
                                upper.index > lower.index,
                                not(range_feasible(
                                    lower.cumulative_shard_credit,
                                    lower.index,
                                    upper)),
                            }
                        }
                    }
                }
                | ReceiptForkEvidence(value) => {
                    val left = value.left.payment
                    val right = value.right.payment
                    val same_index = left.recipient == right.recipient
                        and left.shard == right.shard
                        and left.index == right.index
                    val same_transaction = left.id == right.id
                    and {
                        value.canonical,
                        witness_holds(value.left),
                        witness_holds(value.right),
                        not(receipt_equal(left, right)),
                        same_index or same_transaction,
                    }
                }
            },
        }
    }

    pure def withdrawal_claim_holds(
        target: BatchId,
        claim: WithdrawalClaim,
    ): bool = {
        val candidate = CANDIDATES.get(target)
        and {
            claim.output.in(candidate.withdrawal_outputs),
            claim.opening.root == candidate.roots.withdrawal_outputs,
            claim.opening.root.kind == WithdrawalOutputRole,
            claim.opening.position == claim.output.position,
            claim.opening.position >= 0,
            claim.opening.position < claim.opening.root.length,
        }
    }

    pure def payout_claim_holds(target: BatchId, claim: PayoutClaim): bool = {
        val candidate = CANDIDATES.get(target)
        and {
            claim.output.in(candidate.payout_outputs),
            claim.opening.root == candidate.roots.change,
            claim.opening.root.kind == ChangeRole,
            claim.opening.position == claim.output.position,
            claim.opening.position >= 0,
            claim.opening.position < claim.opening.root.length,
        }
    }
}
