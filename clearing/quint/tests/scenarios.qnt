module scenarios {
    import types.* from "../types"
    import fixtures.* from "../fixtures"
    import instance.* from "../instance"

    action certify(batch: BatchId): bool =
        prepare(batch)
            .then(deal(batch))
            .then(deliver_exact(batch, V0))
            .then(deliver_exact(batch, V1))
            .then(seal(batch, V0))
            .then(seal(batch, V1))
            .then(byzantine_vote(batch, V3))
            .then(form_certificate(batch))

    action certify_and_admit(batch: BatchId): bool =
        register(CANDIDATES.get(batch).registration)
            .then(certify(batch))
            .then(admit(batch))

    action admit_first_two: bool =
        record_deposit(D0)
            .then(certify_and_admit(B0))
            .then(certify_and_admit(B1))

    action admit_first_three: bool =
        admit_first_two
            .then(queue_withdrawal(W_AMOUNT))
            .then(certify_and_admit(B2))

    run publicRelationTest = init
        .then(all {
            assert(public_relation_holds(B0)),
            assert(public_relation_holds(B1)),
            assert(public_relation_holds(B2)),
            assert(public_relation_holds(B3)),
            assert(public_relation_holds(BOFF)),
            assert(not(public_relation_holds(BAD))),
            assert(not(candidate_roots_hold(C_ALIAS))),
            rejected_call,
        })

    run invalidProofCannotBeCertifiedTest = init
        .then(record_deposit(D0))
        .then(register(REG0))
        .then(prepare(BAD))
        .then(deal(BAD))
        .then(deliver_exact(BAD, V0))
        .then(deliver_exact(BAD, V1))
        .then(deliver_exact(BAD, V2))
        .then(seal(BAD, V1))
        .then(byzantine_vote(BAD, V3))
        .then(all {
            assert(not(public_relation_holds(BAD))),
            assert(not(can_seal(BAD, V0))),
            assert(not(can_seal(BAD, V2))),
            rejected_call,
        })
        .then(all {
            assert(certification_state.votes.get(BAD) == Set(V1, V3)),
            assert(not(BAD.in(certification_state.certificates))),
            rejected_call,
        })
        .then(certify(B0))
        .then(admit(B0))
        .then(all {
            assert(chain_state.pipeline == List(B0)),
            assert(chain_state.registered == NoRegistration),
            rejected_call,
        })
        .expect(all_invariants)

    run certificateRetainsEverySliceTest = init
        .then(record_deposit(D0))
        .then(register(REG0))
        .then(certify(B0))
        .then(all {
            assert(certification_state.votes.get(B0) == Set(V0, V1, V3)),
            assert({ batch: B0, slice: 0 }.in(certification_state.retained.get(V0))),
            assert({ batch: B0, slice: 1 }.in(certification_state.retained.get(V0))),
            assert(certified_slice_coverage),
            assert(certification_sound),
            rejected_call,
        })
        .expect(all_invariants)

    run everyCertificateQuorumIntersectsEverySliceHonestlyTest = init
        .then(all {
            assert(CERTIFICATE_QUORUMS.forall(signers => and {
                signers.size() == QUORUM,
                SLICE_IDS.forall(index => HONEST.exists(validator => and {
                    validator.in(signers),
                    validator.in(HOLDERS.get(index)),
                })),
            })),
            rejected_call,
        })
        .expect(all_invariants)

    run fifoRejectsSkippedEpochTest = init
        .then(all {
            assert(not(can_register(REG1))),
            rejected_call,
        })
        .then(record_deposit(D0))
        .then(certify_and_admit(B0))
        .then(all {
            assert(not(can_register(REG2))),
            assert(can_register(REG1)),
            assert(chain_state.pipeline == List(B0)),
            rejected_call,
        })
        .expect(all_invariants)

    run fifoFinalizationAndScopedClaimsTest = init
        .then(admit_first_three)
        .then(all {
            assert(chain_state.pipeline == List(B0, B1, B2)),
            assert(chain_state.expected_epoch == 0),
            rejected_call,
        })
        .then(observe_time(5))
        .then(finalize)
        .then(queue_withdrawal(W_CLOSE))
        .then(certify_and_admit(B3))
        .then(all {
            assert(chain_state.pipeline == List(B1, B2, B3)),
            assert(chain_state.expected_epoch == 1),
            rejected_call,
        })
        .then(all {
            assert(chain_state.now <= CANDIDATES.get(B1).context.challenge_deadline),
            rejected_call,
        })
        .then(observe_time(6))
        .then(finalize)
        .then(observe_time(7))
        .then(finalize)
        .then(observe_time(9))
        .then(finalize)
        .then(all {
            assert(chain_state.finalized_epochs == List(0, 1, 2, 3)),
            assert(chain_state.claimable == 10),
            assert(chain_state.custody == 7),
            rejected_call,
        })
        .then(all {
            assert(not(withdrawal_claim_holds(B2, B3_WITHDRAWAL_CLAIM))),
            rejected_call,
        })
        .then(claim_withdrawal(B2, B2_WITHDRAWAL_CLAIM))
        .then(all {
            assert({
                kind: WithdrawalClaimKind,
                batch: B2,
                position: 0,
            }.in(chain_state.consumed_claims)),
            rejected_call,
        })
        .then(claim_withdrawal(B3, B3_WITHDRAWAL_CLAIM))
        .then(claim_payout(B1, B1_PAYOUT_CLAIM))
        .then(all {
            assert(chain_state.claimable == 0),
            assert(chain_state.released == 10),
            assert(chain_state.custody == 7),
            rejected_call,
        })
        .expect(all_invariants)

    run middleChallengePreservesOnlyEarlierPrefixTest = init
        .then(admit_first_three)
        .then(challenge(B1, E_FORK))
        .then(all {
            assert(chain_state.status.get(B0) == Pending),
            assert(chain_state.status.get(B1) == Challenged(ReceiptFork)),
            assert(chain_state.status.get(B2) == Invalidated(B1)),
            assert(chain_state.invalid_from == SomeBatch(B1)),
            rejected_call,
        })
        .then(all {
            assert(chain_state.status.get(B0) == Pending),
            rejected_call,
        })
        .then(observe_time(5))
        .then(finalize)
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.terminal == Settled),
            assert(chain_state.terminal_withdrawals.get(BOB) == 2),
            assert(chain_state.terminal_residuals.get(BOB) == 7),
            assert(chain_state.terminal_residuals.get(ALICE) == 8),
            assert(chain_state.released == 17),
            rejected_call,
        })
        .expect(all_invariants)

    run malformedAndWrongBatchChallengesStutterTest = init
        .then(admit_first_two)
        .then(challenge(B1, E_NO_PAYER))
        .then(challenge(B1, E_NO_OPERATOR))
        .then(challenge(B1, E_BAD_LINK))
        .then(challenge(B1, E_BAD_OPENING))
        .then(challenge(B1, E_BAD_CONTEXT))
        .then(challenge(B1, E_NO_CONTRADICTION))
        .then(challenge(B0, E_FORK))
        .then(all {
            assert(chain_state.fault == Healthy),
            assert(chain_state.status.get(B0) == Pending),
            assert(chain_state.status.get(B1) == Pending),
            rejected_call,
        })
        .then(challenge(B1, E_FORK))
        .then(all {
            assert(chain_state.fault == ProvenChallenge({ batch: B1, kind: ReceiptFork })),
            rejected_call,
        })
        .expect(all_invariants)

    run latestAcknowledgedSendChallengeTest = init
        .then(admit_first_two)
        .then(challenge(B1, E_LATEST))
        .then(all {
            assert(chain_state.fault == ProvenChallenge({
                batch: B1,
                kind: LatestAcknowledgedSend,
            })),
            rejected_call,
        })
        .expect(all_invariants)

    run higherShardTipChallengeTest = init
        .then(admit_first_two)
        .then(challenge(B1, E_HIGHER))
        .then(all {
            assert(chain_state.fault == ProvenChallenge({ batch: B1, kind: HigherShardTip })),
            rejected_call,
        })
        .expect(all_invariants)

    run inconsistentReceiptRangeChallengeTest = init
        .then(admit_first_two)
        .then(challenge(B1, E_RANGE))
        .then(all {
            assert(chain_state.fault == ProvenChallenge({
                batch: B1,
                kind: InconsistentReceiptRange,
            })),
            rejected_call,
        })
        .expect(all_invariants)

    run receiptForkChallengeTest = init
        .then(admit_first_two)
        .then(challenge(B1, E_FORK))
        .then(all {
            assert(chain_state.fault == ProvenChallenge({ batch: B1, kind: ReceiptFork })),
            rejected_call,
        })
        .expect(all_invariants)

    run expiredRegistrationIsPermanentAndFullyRecoverableTest = init
        .then(record_deposit(D0))
        .then(register(REG0))
        .then(observe_time(3))
        .then(all {
            assert(chain_state.fault == ExpiredRegistration({
                anchor: B0_CONTEXT.anchor,
                epoch: 0,
                expired_at: B0_CONTEXT.admission_deadline,
            })),
            assert(chain_state.registered == NoRegistration),
            assert(chain_state.admission_fence_epoch == 0),
            rejected_call,
        })
        .then(all {
            assert(chain_state.fault != Healthy),
            assert(chain_state.registered == NoRegistration),
            rejected_call,
        })
        .then(claim_deposit(BOB))
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.terminal == Settled),
            assert(chain_state.refunded_deposits.get(BOB) == 2),
            assert(chain_state.released == 17),
            rejected_call,
        })
        .expect(all_invariants)

    run expiredDepositNeedsNoOperatorOrStateOpeningTest = init
        .then(record_deposit(D1))
        .then(observe_time(8))
        .then(all {
            assert(chain_state.fault == ExpiredDeposit),
            rejected_call,
        })
        .then(claim_deposit(ALICE))
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.refunded_deposits.get(ALICE) == 1),
            assert(chain_state.released == 16),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run expiredAmountWithdrawalReturnsAmountAndResidualTest = init
        .then(queue_withdrawal(W_AMOUNT))
        .then(observe_time(10))
        .then(all {
            assert(chain_state.fault == ExpiredWithdrawal),
            rejected_call,
        })
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.terminal_withdrawals.get(BOB) == 2),
            assert(chain_state.terminal_residuals.get(BOB) == 3),
            assert(chain_state.released == 15),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run expiredCloseWithdrawalSweepsTailTest = init
        .then(queue_withdrawal(W_CLOSE_EXIT))
        .then(observe_time(11))
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.terminal_withdrawals.get(ALICE) == 10),
            assert(chain_state.terminal_residuals.get(ALICE) == 0),
            assert(chain_state.released == 15),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run finalizedReservesSurviveDescendantFaultTest = init
        .then(admit_first_three)
        .then(observe_time(5))
        .then(finalize)
        .then(queue_withdrawal(W_CLOSE))
        .then(certify_and_admit(B3))
        .then(observe_time(6))
        .then(finalize)
        .then(observe_time(7))
        .then(finalize)
        .then(all {
            assert(chain_state.claimable == 3),
            assert(chain_state.custody == 14),
            rejected_call,
        })
        .then(challenge(B3, E_B3_FORK))
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.terminal == Settled),
            assert(chain_state.claimable == 3),
            assert(chain_state.terminal_withdrawals.get(ALICE) == 7),
            assert(chain_state.custody == 0),
            rejected_call,
        })
        .then(claim_payout(B1, B1_PAYOUT_CLAIM))
        .then(claim_withdrawal(B2, B2_WITHDRAWAL_CLAIM))
        .then(all {
            assert(chain_state.claimable == 0),
            assert(chain_state.released == 17),
            rejected_call,
        })
        .expect(all_invariants)

    run sameAccountDepositsKeepEarliestDeadlineAndFullyRefundTest = init
        .then(record_deposit(D0))
        .then(observe_time(2))
        .then(record_deposit(D2))
        .then(all {
            assert(chain_state.pending_deposits.get(BOB) == 3),
            assert(chain_state.deposit_deadlines.get(BOB) == 8),
            rejected_call,
        })
        .then(observe_time(8))
        .then(claim_deposit(BOB))
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.refunded_deposits.get(BOB) == 3),
            assert(chain_state.released == 18),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run finiteHorizonRejectsUnobservableObligationTest = init
        .then(observe_time(TIME_HORIZON))
        .then(all {
            assert(not(can_record_deposit(D0))),
            assert(chain_state.custody == 15),
            assert(chain_state.fault == Healthy),
            rejected_call,
        })
        .expect(all_invariants)

    run frontChallengeRecoversEveryUnfinalizedSenderValueTest = init
        .then(admit_first_three)
        .then(challenge(B0, E_B0_FORK))
        .then(all {
            assert(chain_state.status.get(B0) == Challenged(ReceiptFork)),
            assert(chain_state.status.get(B1) == Invalidated(B0)),
            assert(chain_state.status.get(B2) == Invalidated(B0)),
            rejected_call,
        })
        .then(begin_terminal)
        .then(claim_deposit(BOB))
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.terminal_withdrawals.get(BOB) == 2),
            assert(chain_state.terminal_residuals.get(BOB) == 3),
            assert(chain_state.refunded_deposits.get(BOB) == 2),
            assert(chain_state.released == 17),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run tailChallengeDrainsCleanPrefixAndPreservesPayoutReserveTest = init
        .then(admit_first_three)
        .then(challenge(B2, E_B2_FORK))
        .then(observe_time(5))
        .then(finalize)
        .then(observe_time(6))
        .then(finalize)
        .then(all {
            assert(chain_state.finalized_epochs == List(0, 1)),
            assert(chain_state.payout_reserve.get(B1) == 1),
            rejected_call,
        })
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(claim_payout(B1, B1_PAYOUT_CLAIM))
        .then(all {
            assert(chain_state.terminal_withdrawals.get(BOB) == 2),
            assert(chain_state.terminal_residuals.get(BOB) == 7),
            assert(chain_state.released == 17),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run expiredRegistrationDrainsEarlierPrefixAndPreservesReserveTest = init
        .then(admit_first_two)
        .then(queue_withdrawal(W_AMOUNT))
        .then(register(REG2))
        .then(observe_time(5))
        .then(all {
            assert(chain_state.fault == ExpiredRegistration({
                anchor: B2_CONTEXT.anchor,
                epoch: 2,
                expired_at: B2_CONTEXT.admission_deadline,
            })),
            rejected_call,
        })
        .then(finalize)
        .then(observe_time(6))
        .then(finalize)
        .then(begin_terminal)
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(claim_payout(B1, B1_PAYOUT_CLAIM))
        .then(all {
            assert(chain_state.finalized_epochs == List(0, 1)),
            assert(chain_state.terminal_withdrawals.get(BOB) == 2),
            assert(chain_state.released == 17),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run admittedWithdrawalExpiryCanInvalidateChallengeableCloseTest = init
        .then(record_deposit(D0))
        .then(queue_withdrawal(W_OFFSET))
        .then(certify_and_admit(BOFF))
        .then(all {
            assert(chain_state.pending_deposits.get(BOB) == 2),
            assert(chain_state.pipeline == List(BOFF)),
            rejected_call,
        })
        .then(observe_time(2))
        .then(all {
            assert(chain_state.fault == ExpiredWithdrawal),
            assert(chain_state.now <= OFF_CONTEXT.challenge_deadline),
            rejected_call,
        })
        .then(challenge(BOFF, E_OFFSET_FORK))
        .then(begin_terminal)
        .then(claim_deposit(BOB))
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(all {
            assert(chain_state.refunded_deposits.get(BOB) == 2),
            assert(chain_state.terminal_withdrawals.get(BOB) == 2),
            assert(chain_state.terminal_residuals.get(BOB) == 3),
            assert(chain_state.released == 17),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)

    run admittedWithdrawalExpiryCanFinalizeCleanCloseTest = init
        .then(record_deposit(D0))
        .then(queue_withdrawal(W_OFFSET))
        .then(certify_and_admit(BOFF))
        .then(observe_time(2))
        .then(observe_time(4))
        .then(finalize)
        .then(all {
            assert(chain_state.withdrawal_reserve.get(BOFF) == 2),
            assert(chain_state.pending_deposits.get(BOB) == 2),
            rejected_call,
        })
        .then(begin_terminal)
        .then(claim_deposit(BOB))
        .then(claim_state(ALICE))
        .then(claim_state(BOB))
        .then(claim_withdrawal(BOFF, OFF_WITHDRAWAL_CLAIM))
        .then(all {
            assert(chain_state.clean_claim_paid == 2),
            assert(chain_state.refunded_deposits.get(BOB) == 2),
            assert(chain_state.terminal_residuals.get(BOB) == 3),
            assert(chain_state.released == 17),
            assert(chain_state.terminal == Settled),
            rejected_call,
        })
        .expect(all_invariants)
}
