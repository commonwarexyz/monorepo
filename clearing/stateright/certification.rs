use super::settlement::{Batch, RegistrationId};
use stateright::{Checker, Model, Property};

const VALIDATORS: usize = 4;
const SLICE_COUNT: usize = 2;
const HONEST: u8 = 0b0111;
const QUORUM: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RegistrationContext {
    anchor: u8,
    epoch: u8,
    predecessor_root: u8,
    deposit_root: u8,
    withdrawal_root: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Registration {
    identity: u8,
    context: RegistrationContext,
}

const REGISTRATION: Registration = Registration {
    identity: 7,
    context: RegistrationContext {
        anchor: 11,
        epoch: 13,
        predecessor_root: 17,
        deposit_root: 19,
        withdrawal_root: 23,
    },
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CertifiedClose {
    registration: RegistrationId,
    batch: Batch,
}

impl CertifiedClose {
    pub(crate) const fn registration(self) -> RegistrationId {
        self.registration
    }

    pub(crate) const fn batch(self) -> Batch {
        self.batch
    }
}

// These finite profiles are outcomes of the production verifier, not implementations of its
// cryptographic and Merkle checks. `Entries` abstracts the batched-send entry rejections: a
// non-canonical or oversized entry vector, or a terminal batch total exceeding the debit advance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ProofFault {
    None,
    PredecessorRole,
    ChangeRole,
    WithdrawalOutputRole,
    SuccessorRole,
    CoverageRole,
    DomainSeparation,
    VectorLength,
    Position,
    HeaderContext,
    HeaderRoots,
    CoverageStart,
    CoverageGap,
    CoverageRange,
    TerminalTail,
    RowEquation,
    TerminalDebit,
    OutgoingDigest,
    Entries,
    TransposeRoot,
    SettlementOutput,
    PayerSignature,
    OperatorSignature,
    PaymentLink,
    SignatureBatch,
    WithdrawalSignature,
    WithdrawalLink,
    WithdrawalPosition,
}

const PROOF_FAULTS: [ProofFault; 28] = [
    ProofFault::None,
    ProofFault::PredecessorRole,
    ProofFault::ChangeRole,
    ProofFault::WithdrawalOutputRole,
    ProofFault::SuccessorRole,
    ProofFault::CoverageRole,
    ProofFault::DomainSeparation,
    ProofFault::VectorLength,
    ProofFault::Position,
    ProofFault::HeaderContext,
    ProofFault::HeaderRoots,
    ProofFault::CoverageStart,
    ProofFault::CoverageGap,
    ProofFault::CoverageRange,
    ProofFault::TerminalTail,
    ProofFault::RowEquation,
    ProofFault::TerminalDebit,
    ProofFault::OutgoingDigest,
    ProofFault::Entries,
    ProofFault::TransposeRoot,
    ProofFault::SettlementOutput,
    ProofFault::PayerSignature,
    ProofFault::OperatorSignature,
    ProofFault::PaymentLink,
    ProofFault::SignatureBatch,
    ProofFault::WithdrawalSignature,
    ProofFault::WithdrawalLink,
    ProofFault::WithdrawalPosition,
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProofSlice {
    fault: ProofFault,
}

impl ProofSlice {
    const fn valid() -> Self {
        Self {
            fault: ProofFault::None,
        }
    }

    const fn is_valid(self) -> bool {
        matches!(self.fault, ProofFault::None)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AttemptGeneration {
    Initial,
    Retry,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CandidateSubject {
    registration: RegistrationId,
    batch: Batch,
}

impl CandidateSubject {
    fn new(registration: RegistrationId, batch: Batch) -> Option<Self> {
        if batch.registration() != registration {
            return None;
        }
        Some(Self {
            registration,
            batch,
        })
    }
}

const MODEL_SUBJECT: CandidateSubject = CandidateSubject {
    registration: RegistrationId::B0,
    batch: Batch::B0,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CandidateAttempt {
    registration: u8,
    generation: AttemptGeneration,
    subject: CandidateSubject,
    slices: [ProofSlice; SLICE_COUNT],
}

impl CandidateAttempt {
    const fn valid(
        registration: u8,
        generation: AttemptGeneration,
        subject: CandidateSubject,
    ) -> Self {
        Self {
            registration,
            generation,
            subject,
            slices: [ProofSlice::valid(); SLICE_COUNT],
        }
    }

    const fn with_fault(
        registration: u8,
        slice: usize,
        fault: ProofFault,
        subject: CandidateSubject,
    ) -> Self {
        let mut attempt = Self::valid(registration, AttemptGeneration::Initial, subject);
        attempt.slices[slice].fault = fault;
        attempt
    }

    fn is_valid(&self) -> bool {
        self.slices.iter().all(|slice| slice.is_valid())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Stage {
    Registered,
    Prepared,
    Dealt,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Delivery {
    Missing,
    Incomplete,
    Exact,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CertificationState {
    registration: Registration,
    attempt: CandidateAttempt,
    stage: Stage,
    failed_attempt: bool,
    deliveries: [[Delivery; SLICE_COUNT]; VALIDATORS],
    votes: u8,
    retained: [u8; VALIDATORS],
    certificate: bool,
    issued: bool,
}

impl CertificationState {
    const fn valid() -> Self {
        Self::new(CandidateAttempt::valid(
            REGISTRATION.identity,
            AttemptGeneration::Initial,
            MODEL_SUBJECT,
        ))
    }

    const fn with_fault(slice: usize, fault: ProofFault) -> Self {
        Self::new(CandidateAttempt::with_fault(
            REGISTRATION.identity,
            slice,
            fault,
            MODEL_SUBJECT,
        ))
    }

    const fn valid_for(subject: CandidateSubject) -> Self {
        Self::new(CandidateAttempt::valid(
            REGISTRATION.identity,
            AttemptGeneration::Initial,
            subject,
        ))
    }

    const fn new(attempt: CandidateAttempt) -> Self {
        Self {
            registration: REGISTRATION,
            attempt,
            stage: Stage::Registered,
            failed_attempt: false,
            deliveries: [[Delivery::Missing; SLICE_COUNT]; VALIDATORS],
            votes: 0,
            retained: [0; VALIDATORS],
            certificate: false,
            issued: false,
        }
    }

    const fn replace_with_valid_retry(&mut self) {
        self.attempt = CandidateAttempt::valid(
            self.registration.identity,
            AttemptGeneration::Retry,
            self.attempt.subject,
        );
        self.stage = Stage::Registered;
        self.failed_attempt = false;
        self.deliveries = [[Delivery::Missing; SLICE_COUNT]; VALIDATORS];
        self.votes = 0;
        self.retained = [0; VALIDATORS];
        self.certificate = false;
        self.issued = false;
    }

    fn issue_close(&self) -> Option<CertifiedClose> {
        let subject = self.attempt.subject;
        if !self.issued
            || !self.certificate
            || !self.attempt.is_valid()
            || !certificate_is_sound(&CertificationModel, self)
            || subject.batch.registration() != subject.registration
        {
            return None;
        }
        Some(CertifiedClose {
            registration: subject.registration,
            batch: subject.batch,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertificationAction {
    Prepare,
    Deal,
    DeliverIncomplete(usize, usize),
    DeliverExact(usize, usize),
    Seal(usize),
    RejectInvalid(usize, usize),
    ByzantineVote,
    FormCertificate,
    Issue,
    RetryValid,
}

#[derive(Clone)]
struct CertificationModel;

fn issued_valid_state(subject: CandidateSubject) -> CertificationState {
    let model = CertificationModel;
    let mut state = CertificationState::valid_for(subject);
    for action in [
        CertificationAction::Prepare,
        CertificationAction::Deal,
        CertificationAction::DeliverExact(0, 0),
        CertificationAction::DeliverExact(0, 1),
        CertificationAction::Seal(0),
        CertificationAction::DeliverExact(1, 0),
        CertificationAction::Seal(1),
        CertificationAction::DeliverExact(2, 0),
        CertificationAction::DeliverExact(2, 1),
        CertificationAction::Seal(2),
        CertificationAction::FormCertificate,
        CertificationAction::Issue,
    ] {
        state = model
            .next_state(&state, action)
            .expect("the canonical certification trace is valid");
    }
    state
}

pub(crate) fn certify_close(registration: RegistrationId, batch: Batch) -> Option<CertifiedClose> {
    let subject = CandidateSubject::new(registration, batch)?;
    issued_valid_state(subject).issue_close()
}

pub(crate) fn certified_closes() -> [CertifiedClose; 8] {
    [
        (RegistrationId::B0, Batch::B0),
        (RegistrationId::B1, Batch::B1),
        (RegistrationId::B2, Batch::B2),
        (RegistrationId::B3, Batch::B3),
        (RegistrationId::Offset, Batch::Offset),
        (RegistrationId::B1C, Batch::B1C),
        (RegistrationId::B2, Batch::B2D),
        (RegistrationId::OffsetC, Batch::OffsetC),
    ]
    .map(|(registration, batch)| {
        certify_close(registration, batch).expect("every canonical fixture is certified")
    })
}

const fn validator_bit(validator: usize) -> u8 {
    1 << validator
}

const fn slice_bit(slice: usize) -> u8 {
    1 << slice
}

/// Returns the first holder of one slice on the validator ring.
///
/// Mirrors the production window rule: the quorum window slides monotonically around the
/// ring as the slice index grows, so every dealing is contiguous.
const fn window_start(slice: usize) -> usize {
    slice * VALIDATORS / SLICE_COUNT
}

/// Returns the slices whose quorum window covers `validator`.
///
/// In this instance slice 0 is held by validators 0, 1, and 2 and slice 1 by validators 2, 3,
/// and 0, so validators 0 and 2 hold both slices while validators 1 and 3 hold one each.
const fn assigned_slices(validator: usize) -> u8 {
    if validator >= VALIDATORS {
        return 0;
    }
    let mut assigned = 0;
    let mut slice = 0;
    while slice < SLICE_COUNT {
        let offset = (validator + VALIDATORS - window_start(slice)) % VALIDATORS;
        if offset < QUORUM as usize {
            assigned |= slice_bit(slice);
        }
        slice += 1;
    }
    assigned
}

fn assigned_dealing_is_exact_and_valid(state: &CertificationState, validator: usize) -> bool {
    let assigned = assigned_slices(validator);
    (0..SLICE_COUNT).all(|slice| {
        assigned & slice_bit(slice) == 0
            || (state.deliveries[validator][slice] == Delivery::Exact
                && state.attempt.slices[slice].is_valid())
    })
}

fn honest_can_seal(state: &CertificationState, validator: usize) -> bool {
    let bit = validator_bit(validator);
    state.stage == Stage::Dealt
        && validator < VALIDATORS
        && HONEST & bit != 0
        && state.votes.count_ones() < QUORUM
        && state.votes & bit == 0
        && assigned_dealing_is_exact_and_valid(state, validator)
}

fn honest_can_reject(state: &CertificationState, validator: usize, slice: usize) -> bool {
    validator < VALIDATORS
        && slice < SLICE_COUNT
        && state.stage == Stage::Dealt
        && !state.failed_attempt
        && matches!(state.attempt.generation, AttemptGeneration::Initial)
        && HONEST & validator_bit(validator) != 0
        && assigned_slices(validator) & slice_bit(slice) != 0
        && state.deliveries[validator][slice] == Delivery::Exact
        && !state.attempt.slices[slice].is_valid()
}

fn certified_slice_has_valid_honest_holder(state: &CertificationState, slice: usize) -> bool {
    (0..VALIDATORS).any(|validator| {
        let bit = validator_bit(validator);
        HONEST & bit != 0
            && state.votes & bit != 0
            && assigned_slices(validator) & slice_bit(slice) != 0
            && state.retained[validator] & slice_bit(slice) != 0
            && state.deliveries[validator][slice] == Delivery::Exact
            && state.attempt.slices[slice].fault == ProofFault::None
    })
}

fn certificate_is_sound(_: &CertificationModel, state: &CertificationState) -> bool {
    !state.certificate
        || (state.votes.count_ones() == QUORUM
            && (0..SLICE_COUNT).all(|slice| certified_slice_has_valid_honest_holder(state, slice)))
}

fn certified_slices_are_retained(_: &CertificationModel, state: &CertificationState) -> bool {
    if !state.certificate {
        return true;
    }
    (0..SLICE_COUNT).all(|slice| {
        (0..VALIDATORS).any(|validator| {
            let bit = validator_bit(validator);
            HONEST & bit != 0
                && state.votes & bit != 0
                && state.retained[validator] & slice_bit(slice) != 0
        })
    })
}

fn honest_votes_follow_exact_valid_delivery(
    _: &CertificationModel,
    state: &CertificationState,
) -> bool {
    (0..VALIDATORS).all(|validator| {
        let bit = validator_bit(validator);
        if state.votes & HONEST & bit == 0 {
            return true;
        }
        let assigned = assigned_slices(validator);
        (0..SLICE_COUNT).all(|slice| {
            assigned & slice_bit(slice) == 0
                || (state.deliveries[validator][slice] == Delivery::Exact
                    && state.attempt.slices[slice].fault == ProofFault::None)
        })
    })
}

fn registration_is_immutable(_: &CertificationModel, state: &CertificationState) -> bool {
    state.registration.identity == REGISTRATION.identity
        && state.registration.context.anchor == REGISTRATION.context.anchor
        && state.registration.context.epoch == REGISTRATION.context.epoch
        && state.registration.context.predecessor_root == REGISTRATION.context.predecessor_root
        && state.registration.context.deposit_root == REGISTRATION.context.deposit_root
        && state.registration.context.withdrawal_root == REGISTRATION.context.withdrawal_root
        && state.attempt.registration == state.registration.identity
        && state.attempt.subject.batch.registration() == state.attempt.subject.registration
}

fn issuance_requires_a_sound_certificate(
    model: &CertificationModel,
    state: &CertificationState,
) -> bool {
    !state.issued || (state.certificate && certificate_is_sound(model, state))
}

fn invalid_proof_slices_never_certify(_: &CertificationModel, state: &CertificationState) -> bool {
    state.attempt.is_valid() || !state.certificate
}

const fn reaches_certificate(_: &CertificationModel, state: &CertificationState) -> bool {
    state.certificate
}

const fn reaches_issuance(_: &CertificationModel, state: &CertificationState) -> bool {
    state.issued
}

const fn retries_one_registration(_: &CertificationModel, state: &CertificationState) -> bool {
    matches!(state.attempt.generation, AttemptGeneration::Retry)
        && state.registration.identity == REGISTRATION.identity
        && !state.failed_attempt
        && state.issued
}

const fn reaches_failed_attempt(_: &CertificationModel, state: &CertificationState) -> bool {
    state.failed_attempt
}

fn reaches_incomplete_delivery(_: &CertificationModel, state: &CertificationState) -> bool {
    state
        .deliveries
        .iter()
        .flatten()
        .any(|delivery| *delivery == Delivery::Incomplete)
}

fn reaches_partial_delivery(_: &CertificationModel, state: &CertificationState) -> bool {
    (0..VALIDATORS).any(|validator| {
        let assigned = assigned_slices(validator);
        if assigned.count_ones() < 2 {
            return false;
        }
        let delivered = (0..SLICE_COUNT)
            .filter(|slice| {
                assigned & slice_bit(*slice) != 0
                    && state.deliveries[validator][*slice] != Delivery::Missing
            })
            .count();
        delivered > 0 && delivered < assigned.count_ones() as usize
    })
}

const fn quorum_012(_: &CertificationModel, state: &CertificationState) -> bool {
    state.certificate && state.votes == 0b0111
}

const fn quorum_013(_: &CertificationModel, state: &CertificationState) -> bool {
    state.certificate && state.votes == 0b1011
}

const fn quorum_023(_: &CertificationModel, state: &CertificationState) -> bool {
    state.certificate && state.votes == 0b1101
}

const fn quorum_123(_: &CertificationModel, state: &CertificationState) -> bool {
    state.certificate && state.votes == 0b1110
}

impl Model for CertificationModel {
    type State = CertificationState;
    type Action = CertificationAction;

    fn init_states(&self) -> Vec<Self::State> {
        let mut states = vec![CertificationState::valid()];
        for fault in PROOF_FAULTS.into_iter().skip(1) {
            for slice in 0..SLICE_COUNT {
                states.push(CertificationState::with_fault(slice, fault));
            }
        }
        states
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.issued {
            return;
        }
        if state.failed_attempt {
            actions.push(CertificationAction::RetryValid);
            return;
        }
        match state.stage {
            Stage::Registered => actions.push(CertificationAction::Prepare),
            Stage::Prepared => actions.push(CertificationAction::Deal),
            Stage::Dealt if state.certificate => actions.push(CertificationAction::Issue),
            Stage::Dealt if state.votes.count_ones() == QUORUM => {
                actions.push(CertificationAction::FormCertificate);
            }
            Stage::Dealt => {
                for validator in 0..VALIDATORS {
                    let assigned = assigned_slices(validator);
                    for slice in 0..SLICE_COUNT {
                        if assigned & slice_bit(slice) == 0 {
                            continue;
                        }
                        match state.deliveries[validator][slice] {
                            Delivery::Missing => {
                                actions
                                    .push(CertificationAction::DeliverIncomplete(validator, slice));
                                actions.push(CertificationAction::DeliverExact(validator, slice));
                            }
                            Delivery::Incomplete => {
                                actions.push(CertificationAction::DeliverExact(validator, slice))
                            }
                            Delivery::Exact => {}
                        }
                        if honest_can_reject(state, validator, slice) {
                            actions.push(CertificationAction::RejectInvalid(validator, slice));
                        }
                    }
                    if honest_can_seal(state, validator) {
                        actions.push(CertificationAction::Seal(validator));
                    }
                }
                if state.votes & validator_bit(3) == 0 {
                    actions.push(CertificationAction::ByzantineVote);
                }
            }
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        if last.failed_attempt && !matches!(action, CertificationAction::RetryValid) {
            return None;
        }
        let mut state = last.clone();
        match action {
            CertificationAction::Prepare if state.stage == Stage::Registered => {
                state.stage = Stage::Prepared;
            }
            CertificationAction::Deal if state.stage == Stage::Prepared => {
                state.stage = Stage::Dealt;
            }
            CertificationAction::DeliverIncomplete(validator, slice)
                if state.stage == Stage::Dealt
                    && validator < VALIDATORS
                    && slice < SLICE_COUNT
                    && assigned_slices(validator) & slice_bit(slice) != 0
                    && state.deliveries[validator][slice] == Delivery::Missing =>
            {
                state.deliveries[validator][slice] = Delivery::Incomplete;
            }
            CertificationAction::DeliverExact(validator, slice)
                if state.stage == Stage::Dealt
                    && validator < VALIDATORS
                    && slice < SLICE_COUNT
                    && assigned_slices(validator) & slice_bit(slice) != 0
                    && state.deliveries[validator][slice] != Delivery::Exact =>
            {
                state.deliveries[validator][slice] = Delivery::Exact;
            }
            CertificationAction::Seal(validator) if honest_can_seal(last, validator) => {
                state.votes |= validator_bit(validator);
                state.retained[validator] = assigned_slices(validator);
            }
            CertificationAction::RejectInvalid(validator, slice)
                if honest_can_reject(last, validator, slice) =>
            {
                state.failed_attempt = true;
            }
            CertificationAction::ByzantineVote
                if state.stage == Stage::Dealt
                    && state.votes.count_ones() < QUORUM
                    && state.votes & validator_bit(3) == 0 =>
            {
                state.votes |= validator_bit(3);
            }
            CertificationAction::FormCertificate
                if state.stage == Stage::Dealt
                    && state.votes.count_ones() == QUORUM
                    && !state.certificate =>
            {
                state.certificate = true;
            }
            CertificationAction::Issue if state.certificate => {
                state.issued = true;
            }
            CertificationAction::RetryValid
                if state.failed_attempt
                    && !state.attempt.is_valid()
                    && matches!(state.attempt.generation, AttemptGeneration::Initial) =>
            {
                state.replace_with_valid_retry();
            }
            _ => return None,
        }
        Some(state)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(
                "an exact quorum gives every slice an honest valid holder",
                certificate_is_sound,
            ),
            Property::always(
                "every certified slice has an honest retaining signer",
                certified_slices_are_retained,
            ),
            Property::always(
                "every honest vote follows exact valid assigned delivery",
                honest_votes_follow_exact_valid_delivery,
            ),
            Property::always(
                "candidate retries preserve one immutable registration",
                registration_is_immutable,
            ),
            Property::always(
                "capability issuance requires a sound certificate",
                issuance_requires_a_sound_certificate,
            ),
            Property::always(
                "invalid proof slices never certify",
                invalid_proof_slices_never_certify,
            ),
            Property::sometimes("a valid candidate certifies", reaches_certificate),
            Property::sometimes("a valid candidate issues a capability", reaches_issuance),
            Property::sometimes(
                "invalid construction retries under one registration",
                retries_one_registration,
            ),
            Property::sometimes(
                "an exact invalid assigned slice records a failed attempt",
                reaches_failed_attempt,
            ),
            Property::sometimes(
                "an incomplete slice delivery is represented",
                reaches_incomplete_delivery,
            ),
            Property::sometimes(
                "a multi-slice validator receives a partial dealing",
                reaches_partial_delivery,
            ),
            Property::sometimes("quorum v0-v1-v2 certifies", quorum_012),
            Property::sometimes("quorum v0-v1-v3 certifies", quorum_013),
            Property::sometimes("quorum v0-v2-v3 certifies", quorum_023),
            Property::sometimes("quorum v1-v2-v3 certifies", quorum_123),
        ]
    }
}

#[cfg(not(test))]
pub(crate) fn explore(address: &str) {
    CertificationModel.checker().threads(1).serve(address);
}

#[test]
fn every_finite_fault_profile_can_be_placed_on_either_slice() {
    for fault in PROOF_FAULTS {
        for faulty_slice in 0..SLICE_COUNT {
            let state = CertificationState::with_fault(faulty_slice, fault);
            for slice in 0..SLICE_COUNT {
                assert_eq!(
                    state.attempt.slices[slice].is_valid(),
                    fault == ProofFault::None || slice != faulty_slice,
                    "unexpected {fault:?} result at slice {slice}"
                );
            }
        }
    }
}

#[test]
fn ring_window_assignment_gives_every_slice_one_quorum() {
    assert_eq!(assigned_slices(0), 0b11);
    assert_eq!(assigned_slices(1), 0b01);
    assert_eq!(assigned_slices(2), 0b11);
    assert_eq!(assigned_slices(3), 0b10);
    assert_eq!(assigned_slices(VALIDATORS), 0);
    for slice in 0..SLICE_COUNT {
        let holders = (0..VALIDATORS)
            .filter(|validator| assigned_slices(*validator) & slice_bit(slice) != 0)
            .count();
        assert_eq!(holders, QUORUM as usize);
    }
}

#[test]
fn certified_close_requires_issued_matching_candidate() {
    let registered = CertificationState::valid();
    assert_eq!(registered.issue_close(), None);

    let issued = issued_valid_state(MODEL_SUBJECT);
    let token = issued
        .issue_close()
        .expect("the fully certified close is issuable");
    assert_eq!(token.registration(), RegistrationId::B0);
    assert_eq!(token.batch(), Batch::B0);
    assert_eq!(certify_close(RegistrationId::B0, Batch::B1), None);
}

#[test]
fn a_bad_slice_does_not_block_an_unaffected_honest_validator() {
    let model = CertificationModel;
    let mut state = CertificationState::with_fault(1, ProofFault::CoverageGap);
    state.stage = Stage::Dealt;
    for validator in 0..3 {
        for slice in 0..SLICE_COUNT {
            if assigned_slices(validator) & slice_bit(slice) != 0 {
                state.deliveries[validator][slice] = Delivery::Exact;
            }
        }
    }

    assert!(
        model
            .next_state(&state, CertificationAction::Seal(0))
            .is_none()
    );
    assert!(
        model
            .next_state(&state, CertificationAction::Seal(2))
            .is_none()
    );
    let unaffected = model
        .next_state(&state, CertificationAction::Seal(1))
        .expect("validator assigned only the valid slice can seal");
    assert_eq!(unaffected.votes, validator_bit(1));
    assert!(
        model
            .next_state(&state, CertificationAction::ByzantineVote)
            .is_some()
    );
}

#[test]
fn a_multi_slice_validator_needs_every_exact_delivery() {
    let model = CertificationModel;
    let mut state = CertificationState::valid();
    state.stage = Stage::Dealt;

    let state = model
        .next_state(&state, CertificationAction::DeliverExact(0, 0))
        .expect("first assigned slice is deliverable");
    assert!(reaches_partial_delivery(&model, &state));
    assert!(
        model
            .next_state(&state, CertificationAction::Seal(0))
            .is_none()
    );

    let state = model
        .next_state(&state, CertificationAction::DeliverIncomplete(0, 1))
        .expect("second assigned slice may be incomplete");
    assert!(reaches_incomplete_delivery(&model, &state));
    assert!(
        model
            .next_state(&state, CertificationAction::Seal(0))
            .is_none()
    );

    let state = model
        .next_state(&state, CertificationAction::DeliverExact(0, 1))
        .expect("incomplete delivery can be replaced exactly");
    assert!(
        model
            .next_state(&state, CertificationAction::Seal(0))
            .is_some()
    );
}

#[test]
fn every_exact_quorum_intersects_each_slice_in_an_honest_holder() {
    for votes in [0b0111, 0b1011, 0b1101, 0b1110] {
        let mut state = CertificationState::valid();
        state.stage = Stage::Dealt;
        state.votes = votes;
        state.certificate = true;
        for validator in 0..VALIDATORS {
            let bit = validator_bit(validator);
            if votes & HONEST & bit == 0 {
                continue;
            }
            state.retained[validator] = assigned_slices(validator);
            for slice in 0..SLICE_COUNT {
                if assigned_slices(validator) & slice_bit(slice) != 0 {
                    state.deliveries[validator][slice] = Delivery::Exact;
                }
            }
        }
        assert!(certificate_is_sound(&CertificationModel, &state));
        assert!(certified_slices_are_retained(&CertificationModel, &state));
    }
}

#[test]
fn retry_replaces_only_candidate_scoped_state() {
    let model = CertificationModel;
    let mut state = CertificationState::with_fault(0, ProofFault::HeaderContext);
    state.stage = Stage::Dealt;
    state.deliveries[3][1] = Delivery::Incomplete;
    state.votes = validator_bit(3);
    let registration = state.registration;
    let failed_attempt = state.attempt;

    assert!(
        model
            .next_state(&state, CertificationAction::RetryValid)
            .is_none()
    );
    assert!(
        model
            .next_state(&state, CertificationAction::RejectInvalid(0, 0))
            .is_none()
    );

    state.deliveries[0][0] = Delivery::Exact;
    let failed = model
        .next_state(&state, CertificationAction::RejectInvalid(0, 0))
        .expect("an honest holder records an exactly delivered invalid slice");
    assert!(failed.failed_attempt);
    let mut actions = Vec::new();
    model.actions(&failed, &mut actions);
    assert_eq!(actions, vec![CertificationAction::RetryValid]);
    assert!(
        model
            .next_state(&failed, CertificationAction::DeliverExact(0, 1))
            .is_none()
    );

    let retry = model
        .next_state(&failed, CertificationAction::RetryValid)
        .expect("a recorded failed candidate can be retried");
    assert_eq!(retry.registration, registration);
    assert_ne!(retry.attempt, failed_attempt);
    assert_eq!(retry.attempt.registration, registration.identity);
    assert_eq!(retry.attempt.generation, AttemptGeneration::Retry);
    assert!(retry.attempt.is_valid());
    assert_eq!(retry.stage, Stage::Registered);
    assert!(!retry.failed_attempt);
    assert_eq!(
        retry.deliveries,
        [[Delivery::Missing; SLICE_COUNT]; VALIDATORS]
    );
    assert_eq!(retry.votes, 0);
    assert_eq!(retry.retained, [0; VALIDATORS]);
    assert!(!retry.certificate);
    assert!(!retry.issued);
}

#[test]
fn certification_checker_exhausts_every_quorum_and_proof_fault_placement() {
    let checker = CertificationModel.checker().threads(1).spawn_bfs().join();
    assert!(checker.is_done());
    assert_eq!(checker.unique_state_count(), 153_886);
    checker.assert_properties();
}

#[test]
fn every_certification_invariant_has_a_direct_negative_control() {
    let mut unsound = CertificationState::with_fault(1, ProofFault::CoverageGap);
    unsound.stage = Stage::Dealt;
    unsound.votes = 0b1110;
    unsound.certificate = true;
    unsound.retained[1] = assigned_slices(1);
    unsound.retained[2] = assigned_slices(2);
    unsound.deliveries[1][0] = Delivery::Exact;
    unsound.deliveries[2] = [Delivery::Exact; SLICE_COUNT];
    assert!(!certificate_is_sound(&CertificationModel, &unsound));

    let mut unretained = CertificationState::valid();
    unretained.stage = Stage::Dealt;
    unretained.votes = 0b1110;
    unretained.certificate = true;
    unretained.retained[1] = assigned_slices(1);
    assert!(!certified_slices_are_retained(
        &CertificationModel,
        &unretained
    ));

    let mut unverified_vote = CertificationState::valid();
    unverified_vote.stage = Stage::Dealt;
    unverified_vote.votes = validator_bit(0);
    unverified_vote.deliveries[0][0] = Delivery::Exact;
    assert!(!honest_votes_follow_exact_valid_delivery(
        &CertificationModel,
        &unverified_vote
    ));

    let mut changed_registration = CertificationState::valid();
    changed_registration.registration.context.epoch += 1;
    assert!(!registration_is_immutable(
        &CertificationModel,
        &changed_registration
    ));

    let mut unsound_issuance = unsound;
    unsound_issuance.issued = true;
    assert!(!issuance_requires_a_sound_certificate(
        &CertificationModel,
        &unsound_issuance
    ));

    let mut invalid_certificate = CertificationState::with_fault(0, ProofFault::Position);
    invalid_certificate.certificate = true;
    assert!(!invalid_proof_slices_never_certify(
        &CertificationModel,
        &invalid_certificate
    ));
}
