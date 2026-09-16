use super::settlement::{Batch, RegistrationId};
use stateright::{Checker, Model, Property};

const FAULTS: u32 = 1;
const VALIDATORS: usize = (3 * FAULTS + 1) as usize;
const HONEST: u8 = 0b0111;
const QUORUM: u32 = 2 * FAULTS + 1;

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

// The production verifier has two transition outcomes for one identical complete dealing.
// Cryptographic, commitment, and semantic failures all reject; their byte-level checks belong
// to production tests. Delivery completeness is modeled independently for each validator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Verification {
    Valid,
    Invalid,
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
    verification: Verification,
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
            verification: Verification::Valid,
        }
    }

    const fn invalid(registration: u8, subject: CandidateSubject) -> Self {
        Self {
            verification: Verification::Invalid,
            ..Self::valid(registration, AttemptGeneration::Initial, subject)
        }
    }

    const fn is_valid(&self) -> bool {
        matches!(self.verification, Verification::Valid)
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
    deliveries: [Delivery; VALIDATORS],
    votes: u8,
    retained: u8,
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

    const fn invalid() -> Self {
        Self::new(CandidateAttempt::invalid(
            REGISTRATION.identity,
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
            deliveries: [Delivery::Missing; VALIDATORS],
            votes: 0,
            retained: 0,
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
        self.deliveries = [Delivery::Missing; VALIDATORS];
        self.votes = 0;
        self.retained = 0;
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
    DeliverIncomplete(usize),
    DeliverExact(usize),
    Seal(usize),
    RejectInvalid(usize),
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
        CertificationAction::DeliverExact(0),
        CertificationAction::Seal(0),
        CertificationAction::DeliverExact(1),
        CertificationAction::Seal(1),
        CertificationAction::DeliverExact(2),
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

fn honest_can_seal(state: &CertificationState, validator: usize) -> bool {
    validator < VALIDATORS
        && state.stage == Stage::Dealt
        && HONEST & validator_bit(validator) != 0
        && state.votes.count_ones() < QUORUM
        && state.votes & validator_bit(validator) == 0
        && state.deliveries[validator] == Delivery::Exact
        && state.attempt.is_valid()
}

fn honest_can_reject(state: &CertificationState, validator: usize) -> bool {
    validator < VALIDATORS
        && state.stage == Stage::Dealt
        && !state.failed_attempt
        && matches!(state.attempt.generation, AttemptGeneration::Initial)
        && HONEST & validator_bit(validator) != 0
        && state.deliveries[validator] == Delivery::Exact
        && !state.attempt.is_valid()
}

fn certificate_is_sound(model: &CertificationModel, state: &CertificationState) -> bool {
    !state.certificate
        || (state.votes.count_ones() == QUORUM
            && state.attempt.is_valid()
            && certified_dealing_is_retained(model, state)
            && honest_votes_follow_exact_valid_delivery(model, state))
}

const fn certified_dealing_is_retained(_: &CertificationModel, state: &CertificationState) -> bool {
    if !state.certificate {
        return true;
    }
    // A quorum guarantees q-f honest retainers. Byzantine signers need not retain anything.
    let honest_signers = state.votes & HONEST;
    honest_signers.count_ones() >= QUORUM - FAULTS
        && state.retained & honest_signers == honest_signers
}

fn honest_votes_follow_exact_valid_delivery(
    _: &CertificationModel,
    state: &CertificationState,
) -> bool {
    (0..VALIDATORS).all(|validator| {
        let bit = validator_bit(validator);
        state.votes & HONEST & bit == 0
            || (state.deliveries[validator] == Delivery::Exact
                && state.attempt.is_valid()
                && state.retained & bit != 0)
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

const fn invalid_dealings_never_certify(
    _: &CertificationModel,
    state: &CertificationState,
) -> bool {
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
    state.deliveries.contains(&Delivery::Incomplete)
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
        vec![CertificationState::valid(), CertificationState::invalid()]
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
                    match state.deliveries[validator] {
                        Delivery::Missing => {
                            actions.push(CertificationAction::DeliverIncomplete(validator));
                            actions.push(CertificationAction::DeliverExact(validator));
                        }
                        Delivery::Incomplete => {
                            actions.push(CertificationAction::DeliverExact(validator));
                        }
                        Delivery::Exact => {}
                    }
                    if honest_can_reject(state, validator) {
                        actions.push(CertificationAction::RejectInvalid(validator));
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
            CertificationAction::DeliverIncomplete(validator)
                if state.stage == Stage::Dealt
                    && validator < VALIDATORS
                    && state.deliveries[validator] == Delivery::Missing =>
            {
                state.deliveries[validator] = Delivery::Incomplete;
            }
            CertificationAction::DeliverExact(validator)
                if state.stage == Stage::Dealt
                    && validator < VALIDATORS
                    && state.deliveries[validator] != Delivery::Exact =>
            {
                state.deliveries[validator] = Delivery::Exact;
            }
            CertificationAction::Seal(validator) if honest_can_seal(last, validator) => {
                // Retention and voting are atomic here; the embedding persists evidence first.
                state.retained |= validator_bit(validator);
                state.votes |= validator_bit(validator);
            }
            CertificationAction::RejectInvalid(validator) if honest_can_reject(last, validator) => {
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
                "an exact quorum certifies one valid complete dealing",
                certificate_is_sound,
            ),
            Property::always(
                "every honest signer retains the complete certified dealing",
                certified_dealing_is_retained,
            ),
            Property::always(
                "every honest vote follows exact valid delivery and retention",
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
                "invalid dealings never certify",
                invalid_dealings_never_certify,
            ),
            Property::sometimes("a valid candidate certifies", reaches_certificate),
            Property::sometimes("a valid candidate issues a capability", reaches_issuance),
            Property::sometimes(
                "invalid construction retries under one registration",
                retries_one_registration,
            ),
            Property::sometimes(
                "an exact invalid dealing records a failed attempt",
                reaches_failed_attempt,
            ),
            Property::sometimes(
                "an incomplete dealing delivery is represented",
                reaches_incomplete_delivery,
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
fn an_invalid_complete_dealing_blocks_every_honest_validator() {
    let model = CertificationModel;
    let mut state = CertificationState::invalid();
    state.stage = Stage::Dealt;
    state.deliveries = [Delivery::Exact; VALIDATORS];
    for validator in 0..VALIDATORS - 1 {
        assert!(
            model
                .next_state(&state, CertificationAction::Seal(validator))
                .is_none()
        );
        assert!(
            model
                .next_state(&state, CertificationAction::RejectInvalid(validator))
                .is_some()
        );
    }
    assert!(
        model
            .next_state(&state, CertificationAction::ByzantineVote)
            .is_some()
    );
}

#[test]
fn every_honest_validator_needs_exact_delivery_and_retains_before_voting() {
    let model = CertificationModel;
    for validator in 0..VALIDATORS - 1 {
        let mut state = CertificationState::valid();
        state.stage = Stage::Dealt;
        assert!(
            model
                .next_state(&state, CertificationAction::Seal(validator))
                .is_none()
        );
        let state = model
            .next_state(&state, CertificationAction::DeliverIncomplete(validator))
            .expect("a dealing may be truncated");
        assert!(reaches_incomplete_delivery(&model, &state));
        assert!(
            model
                .next_state(&state, CertificationAction::Seal(validator))
                .is_none()
        );
        let state = model
            .next_state(&state, CertificationAction::DeliverExact(validator))
            .expect("incomplete delivery can be replaced exactly");
        let sealed = model
            .next_state(&state, CertificationAction::Seal(validator))
            .expect("a complete valid dealing can seal");
        assert_eq!(sealed.votes, validator_bit(validator));
        assert_eq!(sealed.retained, validator_bit(validator));
        assert!(honest_votes_follow_exact_valid_delivery(&model, &sealed));
    }
}

#[test]
fn every_exact_quorum_retains_the_complete_dealing_at_every_honest_signer() {
    let model = CertificationModel;
    for votes in [0b0111, 0b1011, 0b1101, 0b1110] {
        let mut state = CertificationState::valid();
        for action in [CertificationAction::Prepare, CertificationAction::Deal] {
            state = model.next_state(&state, action).unwrap();
        }
        for validator in 0..VALIDATORS {
            if votes & validator_bit(validator) == 0 {
                continue;
            }
            if HONEST & validator_bit(validator) != 0 {
                state = model
                    .next_state(&state, CertificationAction::DeliverExact(validator))
                    .unwrap();
                state = model
                    .next_state(&state, CertificationAction::Seal(validator))
                    .unwrap();
            } else {
                state = model
                    .next_state(&state, CertificationAction::ByzantineVote)
                    .unwrap();
            }
        }
        state = model
            .next_state(&state, CertificationAction::FormCertificate)
            .unwrap();
        assert_eq!(state.votes, votes);
        assert_eq!(state.retained, votes & HONEST);
        assert!(state.retained.count_ones() >= QUORUM - FAULTS);
        assert!(certificate_is_sound(&model, &state));
        assert!(certified_dealing_is_retained(&model, &state));
    }
}

#[test]
fn retry_replaces_only_candidate_scoped_state() {
    let model = CertificationModel;
    let mut state = CertificationState::invalid();
    state.stage = Stage::Dealt;
    state.deliveries[3] = Delivery::Incomplete;
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
            .next_state(&state, CertificationAction::RejectInvalid(0))
            .is_none()
    );
    state.deliveries[0] = Delivery::Incomplete;
    assert!(
        model
            .next_state(&state, CertificationAction::RejectInvalid(0))
            .is_none()
    );
    state.deliveries[0] = Delivery::Exact;
    let failed = model
        .next_state(&state, CertificationAction::RejectInvalid(0))
        .expect("an honest validator records an exactly delivered invalid dealing");
    assert!(failed.failed_attempt);
    let mut actions = Vec::new();
    model.actions(&failed, &mut actions);
    assert_eq!(actions, vec![CertificationAction::RetryValid]);
    assert!(
        model
            .next_state(&failed, CertificationAction::DeliverExact(1))
            .is_none()
    );

    let retry = model
        .next_state(&failed, CertificationAction::RetryValid)
        .expect("a recorded failed candidate can be retried");
    assert_eq!(retry.registration, registration);
    assert_ne!(retry.attempt, failed_attempt);
    assert_eq!(retry.attempt.subject, failed_attempt.subject);
    assert_eq!(retry.attempt.registration, registration.identity);
    assert_eq!(retry.attempt.generation, AttemptGeneration::Retry);
    assert!(retry.attempt.is_valid());
    assert_eq!(retry.stage, Stage::Registered);
    assert!(!retry.failed_attempt);
    assert_eq!(retry.deliveries, [Delivery::Missing; VALIDATORS]);
    assert_eq!(retry.votes, 0);
    assert_eq!(retry.retained, 0);
    assert!(!retry.certificate);
    assert!(!retry.issued);
}

#[test]
fn certification_checker_exhausts_every_quorum_and_verifier_outcome() {
    let checker = CertificationModel.checker().threads(1).spawn_bfs().join();
    assert!(checker.is_done());
    // Each valid generation has 2 pre-dealing, 381 delivery/vote, 30 certified, and 30
    // issued states. Invalid attempts have 2 pre-dealing, 162 delivery/vote, and 114
    // rejected states. The valid initial and retry generations are distinct.
    assert_eq!(
        checker.unique_state_count(),
        2 * (2 + 381 + 30 + 30) + 2 + 162 + 114
    );
    checker.assert_properties();
}

#[test]
fn every_certification_invariant_has_a_direct_negative_control() {
    let model = CertificationModel;
    let issued = issued_valid_state(MODEL_SUBJECT);

    let mut unsound = issued.clone();
    unsound.attempt.verification = Verification::Invalid;
    assert!(!certificate_is_sound(&model, &unsound));
    assert!(!issuance_requires_a_sound_certificate(&model, &unsound));
    assert!(!invalid_dealings_never_certify(&model, &unsound));
    assert_eq!(unsound.issue_close(), None);

    let mut wrong_quorum = issued.clone();
    wrong_quorum.votes = 0b0011;
    assert!(!certificate_is_sound(&model, &wrong_quorum));
    wrong_quorum.votes = 0b1111;
    assert!(!certificate_is_sound(&model, &wrong_quorum));

    let mut unretained = issued.clone();
    unretained.retained &= !validator_bit(0);
    assert!(!certified_dealing_is_retained(&model, &unretained));
    assert!(!honest_votes_follow_exact_valid_delivery(
        &model,
        &unretained
    ));
    assert_eq!(unretained.issue_close(), None);

    for delivery in [Delivery::Missing, Delivery::Incomplete] {
        let mut unverified_vote = issued.clone();
        unverified_vote.deliveries[0] = delivery;
        assert!(!honest_votes_follow_exact_valid_delivery(
            &model,
            &unverified_vote
        ));
        assert!(!certificate_is_sound(&model, &unverified_vote));
    }

    let mut changed_registration = CertificationState::valid();
    changed_registration.registration.context.epoch += 1;
    assert!(!registration_is_immutable(&model, &changed_registration));

    let mut uncertified_issuance = issued;
    uncertified_issuance.certificate = false;
    assert!(!issuance_requires_a_sound_certificate(
        &model,
        &uncertified_issuance
    ));
    assert_eq!(uncertified_issuance.issue_close(), None);
}
