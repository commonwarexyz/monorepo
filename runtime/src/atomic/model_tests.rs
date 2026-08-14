//! Independent bounded semantic specification for coordinator-free atomic publication.
//!
//! This module models protocol authority rather than production decoding. A complete prepared
//! vector stands for an already validated bound candidate ring, a torn prepare is never authority,
//! and a successful durability outcome guarantees the complete local prepare. Production-linked
//! scheduled tests exercise decoding and recovery. The ordinal shape checked here only keeps
//! bounded vectors internally well formed.

const MAX_PARTICIPANTS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Publish,
    Rewind,
    Remove,
}

impl Operation {
    const ALL: [Self; 3] = [Self::Publish, Self::Rewind, Self::Remove];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum World {
    Predecessor,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareState {
    Absent,
    Torn,
    Complete,
}

impl PrepareState {
    const ALL: [Self; 3] = [Self::Absent, Self::Torn, Self::Complete];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurabilityOutcome {
    NotAttempted,
    Failed,
    Succeeded,
}

impl DurabilityOutcome {
    const ALL: [Self; 3] = [Self::NotAttempted, Self::Failed, Self::Succeeded];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadProof {
    Invalid,
    Valid,
    NotRequired,
}

impl PayloadProof {
    fn authorizes(self, operation: Operation) -> bool {
        match operation {
            Operation::Publish => self == Self::Valid,
            Operation::Rewind | Operation::Remove => self == Self::NotRequired,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalState {
    Absent,
    Torn,
    Complete,
}

impl FinalState {
    const ALL: [Self; 3] = [Self::Absent, Self::Torn, Self::Complete];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Participant {
    ordinal: usize,
    operation: Operation,
    prepare: PrepareState,
    publication_sync: DurabilityOutcome,
    proof: PayloadProof,
    final_state: FinalState,
    final_durable: bool,
    recovery_sync: DurabilityOutcome,
    resized: bool,
    unlinked: bool,
}

impl Participant {
    const PLACEHOLDER: Self = Self {
        ordinal: MAX_PARTICIPANTS,
        operation: Operation::Publish,
        prepare: PrepareState::Absent,
        publication_sync: DurabilityOutcome::NotAttempted,
        proof: PayloadProof::Invalid,
        final_state: FinalState::Absent,
        final_durable: false,
        recovery_sync: DurabilityOutcome::NotAttempted,
        resized: false,
        unlinked: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Image {
    count: usize,
    participants: [Participant; MAX_PARTICIPANTS],
    decision_without_authority: bool,
    live_cleanup_without_completed_cut: bool,
    unlink_before_completed_final_cut: bool,
}

impl Image {
    fn participants(&self) -> &[Participant] {
        &self.participants[..self.count]
    }

    fn participants_mut(&mut self) -> &mut [Participant] {
        &mut self.participants[..self.count]
    }

    fn ordinal_shape(&self) -> bool {
        (1..=MAX_PARTICIPANTS).contains(&self.count)
            && self
                .participants()
                .iter()
                .enumerate()
                .all(|(ordinal, participant)| participant.ordinal == ordinal)
    }

    fn complete_prepared_vector(&self, require_payload_proofs: bool) -> bool {
        self.ordinal_shape()
            && self.participants().iter().all(|participant| {
                !participant.unlinked
                    && participant.prepare == PrepareState::Complete
                    && (!require_payload_proofs
                        || participant.proof.authorizes(participant.operation))
            })
    }

    fn retained_final_vector(&self) -> bool {
        self.ordinal_shape()
            && self
                .participants()
                .iter()
                .all(|participant| participant.final_state == FinalState::Complete)
    }

    fn completed_final_cut(&self) -> bool {
        self.retained_final_vector()
            && self
                .participants()
                .iter()
                .all(|participant| participant.final_durable)
    }

    fn candidate_authority(&self) -> bool {
        self.complete_prepared_vector(true) || self.retained_final_vector()
    }

    fn completed_publication_cut(&self) -> bool {
        self.participants()
            .iter()
            .all(|participant| participant.publication_sync == DurabilityOutcome::Succeeded)
    }

    fn selected_worlds(&self, variant: Variant) -> [World; MAX_PARTICIPANTS] {
        let mut worlds = [World::Predecessor; MAX_PARTICIPANTS];
        let independent = self.retained_final_vector();
        let complete_vector = match variant {
            Variant::IgnorePayloadProof => self.complete_prepared_vector(false),
            _ => self.complete_prepared_vector(true),
        };

        for (world, participant) in worlds.iter_mut().zip(self.participants()) {
            let local_final = participant.final_state == FinalState::Complete
                || (participant.operation == Operation::Remove && participant.unlinked);
            let local_prepare = participant.prepare == PrepareState::Complete
                && participant.proof.authorizes(participant.operation);
            let candidate = match variant {
                Variant::LocalPrepareDecides => independent || local_final || local_prepare,
                _ => independent || complete_vector || local_final,
            };
            if candidate {
                *world = World::Candidate;
            }
        }
        worlds
    }

    fn uniform_world(&self, variant: Variant) -> Option<World> {
        let worlds = self.selected_worlds(variant);
        let first = worlds[0];
        worlds[..self.count]
            .iter()
            .all(|world| *world == first)
            .then_some(first)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Variant {
    Reference,
    LocalPrepareDecides,
    FailedSyncIsCut,
    IgnorePayloadProof,
    FinalizeBeforeCompletedCut,
    UnlinkBeforeCompletedFinalCut,
}

impl Variant {
    const MUTANTS: [Self; 5] = [
        Self::LocalPrepareDecides,
        Self::FailedSyncIsCut,
        Self::IgnorePayloadProof,
        Self::FinalizeBeforeCompletedCut,
        Self::UnlinkBeforeCompletedFinalCut,
    ];

    fn permits_live_cleanup(self, image: &Image) -> bool {
        match self {
            Self::FailedSyncIsCut => image
                .participants()
                .iter()
                .all(|participant| participant.publication_sync != DurabilityOutcome::NotAttempted),
            Self::FinalizeBeforeCompletedCut => image
                .participants()
                .iter()
                .any(|participant| participant.prepare != PrepareState::Absent),
            _ => image.completed_publication_cut(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvariantViolation {
    InvalidOrdinalShape,
    MixedWorld,
    CandidateWithoutAuthority,
    LiveCleanupWithoutCompletedCut,
    CleanupWithoutDiskAuthority,
    UnlinkBeforeCompletedFinalCut,
    InvalidCleanupTarget,
    DurableTornFinal,
}

fn first_violation(image: &Image, variant: Variant) -> Option<InvariantViolation> {
    if !image.ordinal_shape() {
        return Some(InvariantViolation::InvalidOrdinalShape);
    }
    if image.unlink_before_completed_final_cut {
        return Some(InvariantViolation::UnlinkBeforeCompletedFinalCut);
    }
    if image.live_cleanup_without_completed_cut {
        return Some(InvariantViolation::LiveCleanupWithoutCompletedCut);
    }
    if image.decision_without_authority {
        return Some(InvariantViolation::CandidateWithoutAuthority);
    }

    let worlds = image.selected_worlds(variant);
    if worlds[..image.count]
        .iter()
        .any(|world| *world != worlds[0])
    {
        return Some(InvariantViolation::MixedWorld);
    }
    if worlds[0] == World::Candidate && !image.candidate_authority() {
        return Some(InvariantViolation::CandidateWithoutAuthority);
    }

    let completed_final_cut = image.completed_final_cut();
    for participant in image.participants() {
        if participant.final_durable && participant.final_state != FinalState::Complete {
            return Some(InvariantViolation::DurableTornFinal);
        }
        if (participant.final_state != FinalState::Absent || participant.resized)
            && !image.candidate_authority()
        {
            return Some(InvariantViolation::CleanupWithoutDiskAuthority);
        }
        if participant.unlinked && participant.operation != Operation::Remove {
            return Some(InvariantViolation::InvalidCleanupTarget);
        }
        if participant.unlinked && !completed_final_cut {
            return Some(InvariantViolation::UnlinkBeforeCompletedFinalCut);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RecoveryWork {
    final_writes: usize,
    barriers: usize,
    clears: usize,
    resizes: usize,
    unlinks: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryResult {
    image: Image,
    decision: Option<World>,
    work: RecoveryWork,
}

fn recover_fault_free(mut image: Image, variant: Variant) -> RecoveryResult {
    let Some(decision) = image.uniform_world(variant) else {
        return RecoveryResult {
            image,
            decision: None,
            work: RecoveryWork::default(),
        };
    };
    let mut work = RecoveryWork::default();

    match decision {
        World::Predecessor => {
            for participant in image.participants_mut() {
                if participant.prepare != PrepareState::Absent
                    || participant.final_state != FinalState::Absent
                {
                    participant.prepare = PrepareState::Absent;
                    participant.final_state = FinalState::Absent;
                    participant.final_durable = false;
                    participant.recovery_sync = DurabilityOutcome::Succeeded;
                    work.clears += 1;
                }
            }
        }
        World::Candidate => {
            let authority = image.candidate_authority();
            if !authority {
                image.decision_without_authority = true;
            }
            for participant in image.participants_mut() {
                if participant.unlinked || participant.final_state == FinalState::Complete {
                    continue;
                }
                participant.final_state = FinalState::Complete;
                work.final_writes += 1;
            }

            if variant == Variant::UnlinkBeforeCompletedFinalCut {
                let completed_final_cut = image.completed_final_cut();
                let unlinking = image.participants().iter().any(|participant| {
                    participant.operation == Operation::Remove && !participant.unlinked
                });
                image.unlink_before_completed_final_cut |= !completed_final_cut && unlinking;
                for participant in image.participants_mut() {
                    if participant.operation == Operation::Remove && !participant.unlinked {
                        participant.unlinked = true;
                        work.unlinks += 1;
                    }
                }
            }

            for participant in image.participants_mut() {
                if participant.unlinked {
                    continue;
                }
                participant.final_state = FinalState::Complete;
                participant.final_durable = true;
                participant.recovery_sync = DurabilityOutcome::Succeeded;
                work.barriers += 1;
            }

            if image.completed_final_cut() {
                for participant in image.participants_mut() {
                    match participant.operation {
                        Operation::Publish => {}
                        Operation::Rewind if !participant.resized => {
                            participant.resized = true;
                            work.resizes += 1;
                        }
                        Operation::Remove if !participant.unlinked => {
                            participant.unlinked = true;
                            work.unlinks += 1;
                        }
                        Operation::Rewind | Operation::Remove => {}
                    }
                }
            }
        }
    }

    RecoveryResult {
        image,
        decision: Some(decision),
        work,
    }
}

fn quiescent(image: &Image) -> bool {
    if first_violation(image, Variant::Reference).is_some() {
        return false;
    }
    let Some(world) = image.uniform_world(Variant::Reference) else {
        return false;
    };
    image.participants().iter().all(|participant| match world {
        World::Predecessor => {
            participant.prepare == PrepareState::Absent
                && participant.final_state == FinalState::Absent
                && !participant.final_durable
                && !participant.resized
                && !participant.unlinked
        }
        World::Candidate => {
            participant.final_state == FinalState::Complete
                && participant.final_durable
                && match participant.operation {
                    Operation::Publish => !participant.resized && !participant.unlinked,
                    Operation::Rewind => participant.resized && !participant.unlinked,
                    Operation::Remove => participant.unlinked,
                }
        }
    })
}

fn choice_vectors<T: Copy>(choices: &[T], count: usize) -> Vec<[T; MAX_PARTICIPANTS]> {
    assert!(!choices.is_empty());
    assert!((1..=MAX_PARTICIPANTS).contains(&count));
    let combinations = choices.len().pow(count as u32);
    let mut vectors = Vec::with_capacity(combinations);
    for encoded in 0..combinations {
        let mut encoded = encoded;
        let mut vector = [choices[0]; MAX_PARTICIPANTS];
        for value in &mut vector[..count] {
            *value = choices[encoded % choices.len()];
            encoded /= choices.len();
        }
        vectors.push(vector);
    }
    vectors
}

fn proof_vectors(
    operations: &[Operation; MAX_PARTICIPANTS],
    count: usize,
) -> Vec<[PayloadProof; MAX_PARTICIPANTS]> {
    let publishes = operations[..count]
        .iter()
        .filter(|operation| **operation == Operation::Publish)
        .count();
    let mut vectors = Vec::with_capacity(1 << publishes);
    for mask in 0..1usize << publishes {
        let mut vector = [PayloadProof::NotRequired; MAX_PARTICIPANTS];
        let mut publish = 0;
        for (proof, operation) in vector.iter_mut().zip(&operations[..count]) {
            if *operation == Operation::Publish {
                *proof = if mask & (1 << publish) == 0 {
                    PayloadProof::Invalid
                } else {
                    PayloadProof::Valid
                };
                publish += 1;
            }
        }
        vectors.push(vector);
    }
    vectors
}

fn publication_image(
    count: usize,
    operations: [Operation; MAX_PARTICIPANTS],
    prepares: [PrepareState; MAX_PARTICIPANTS],
    proofs: [PayloadProof; MAX_PARTICIPANTS],
    outcomes: [DurabilityOutcome; MAX_PARTICIPANTS],
) -> Option<Image> {
    let mut participants = [Participant::PLACEHOLDER; MAX_PARTICIPANTS];
    for ordinal in 0..count {
        let operation = operations[ordinal];
        let prepare = prepares[ordinal];
        let proof = proofs[ordinal];
        let outcome = outcomes[ordinal];
        if outcome == DurabilityOutcome::Succeeded
            && (prepare != PrepareState::Complete || !proof.authorizes(operation))
        {
            return None;
        }
        participants[ordinal] = Participant {
            ordinal,
            operation,
            prepare,
            publication_sync: outcome,
            proof,
            final_state: FinalState::Absent,
            final_durable: false,
            recovery_sync: DurabilityOutcome::NotAttempted,
            resized: false,
            unlinked: false,
        };
    }
    Some(Image {
        count,
        participants,
        decision_without_authority: false,
        live_cleanup_without_completed_cut: false,
        unlink_before_completed_final_cut: false,
    })
}

fn live_cleanup_image(
    mut image: Image,
    final_states: [FinalState; MAX_PARTICIPANTS],
    resize_mask: usize,
    variant: Variant,
) -> Image {
    let completed_cut = image.completed_publication_cut();
    let retained_cleanup = final_states[..image.count]
        .iter()
        .any(|state| *state != FinalState::Absent)
        || resize_mask != 0;
    image.live_cleanup_without_completed_cut |= retained_cleanup && !completed_cut;
    for (ordinal, participant) in image.participants_mut().iter_mut().enumerate() {
        participant.final_state = final_states[ordinal];
        if participant.operation == Operation::Rewind && resize_mask & (1 << ordinal) != 0 {
            participant.resized = true;
        }
    }
    debug_assert!(variant.permits_live_cleanup(&image));
    image
}

fn cleanup_positions(image: &Image, include_remove: bool) -> usize {
    image
        .participants()
        .iter()
        .enumerate()
        .fold(0, |mask, (ordinal, participant)| {
            let cleanup = participant.operation == Operation::Rewind
                || (include_remove && participant.operation == Operation::Remove);
            if cleanup { mask | (1 << ordinal) } else { mask }
        })
}

fn assert_reference_contract(image: Image) {
    assert_eq!(
        first_violation(&image, Variant::Reference),
        None,
        "invalid reference image: {image:?}"
    );
    let expected = if image.candidate_authority() {
        World::Candidate
    } else {
        World::Predecessor
    };
    assert_eq!(image.uniform_world(Variant::Reference), Some(expected));

    let first = recover_fault_free(image, Variant::Reference);
    assert_eq!(first.decision, Some(expected));
    assert_eq!(
        first_violation(&first.image, Variant::Reference),
        None,
        "recovery violated the model: {first:?}"
    );
    assert!(
        quiescent(&first.image),
        "recovery did not converge: {first:?}"
    );

    let second = recover_fault_free(first.image, Variant::Reference);
    assert_eq!(second.decision, first.decision);
    assert_eq!(
        second.image, first.image,
        "second recovery changed the image"
    );
    // Reopen may repeat durability barriers, but settled metadata and namespace mutations do not.
    assert_eq!(
        second.work,
        RecoveryWork {
            barriers: second.work.barriers,
            ..RecoveryWork::default()
        }
    );
}

fn for_each_candidate_recovery_crash(mut seed: Image, mut check: impl FnMut(Image)) {
    assert!(seed.candidate_authority());
    for participant in seed.participants_mut() {
        participant.final_state = FinalState::Absent;
        participant.final_durable = false;
    }
    let outcomes = choice_vectors(&DurabilityOutcome::ALL, seed.count);
    let final_states = choice_vectors(&FinalState::ALL, seed.count);
    for outcome in outcomes {
        for retained in &final_states {
            let mut crash = seed;
            let mut reachable = true;
            for ordinal in 0..crash.count {
                if outcome[ordinal] == DurabilityOutcome::Succeeded
                    && retained[ordinal] != FinalState::Complete
                {
                    reachable = false;
                    break;
                }
                let participant = &mut crash.participants[ordinal];
                participant.final_state = retained[ordinal];
                participant.final_durable = outcome[ordinal] == DurabilityOutcome::Succeeded;
                participant.recovery_sync = outcome[ordinal];
            }
            if !reachable {
                continue;
            }
            check(crash);

            if crash.completed_final_cut() {
                let positions = cleanup_positions(&crash, true);
                for cleanup_mask in 0..1usize << crash.count {
                    if cleanup_mask & !positions != 0 {
                        continue;
                    }
                    let mut cleanup_crash = crash;
                    for ordinal in 0..cleanup_crash.count {
                        if cleanup_mask & (1 << ordinal) == 0 {
                            continue;
                        }
                        let participant = &mut cleanup_crash.participants[ordinal];
                        match participant.operation {
                            Operation::Publish => unreachable!("publish has no physical cleanup"),
                            Operation::Rewind => participant.resized = true,
                            Operation::Remove => participant.unlinked = true,
                        }
                    }
                    check(cleanup_crash);
                }
            }
        }
    }
}

fn clear_retention_reachable(
    before: PrepareState,
    outcome: DurabilityOutcome,
    after: PrepareState,
) -> bool {
    match (before, outcome) {
        (PrepareState::Absent, _) | (_, DurabilityOutcome::Succeeded) => {
            after == PrepareState::Absent
        }
        (PrepareState::Torn, _) => after != PrepareState::Complete,
        (PrepareState::Complete, _) => true,
    }
}

fn for_each_predecessor_recovery_crash(seed: Image, mut check: impl FnMut(Image)) {
    assert!(!seed.candidate_authority());
    let outcomes = choice_vectors(&DurabilityOutcome::ALL, seed.count);
    let retained = choice_vectors(&PrepareState::ALL, seed.count);
    for outcome in outcomes {
        for after in &retained {
            if (0..seed.count).any(|ordinal| {
                !clear_retention_reachable(
                    seed.participants[ordinal].prepare,
                    outcome[ordinal],
                    after[ordinal],
                )
            }) {
                continue;
            }
            let mut crash = seed;
            for ordinal in 0..crash.count {
                let participant = &mut crash.participants[ordinal];
                participant.prepare = after[ordinal];
                participant.recovery_sync = outcome[ordinal];
            }
            assert!(!crash.candidate_authority());
            check(crash);
        }
    }
}

const SLOT_CLASS_COUNT: usize = 3;
const HEADER_CLASS: u8 = 1;
const ALL_SLOT_CLASSES: u8 = (1u8 << SLOT_CLASS_COUNT) - 1;

// Root header, witness frame, and witness body are the only byte-equivalence classes. Retention
// chooses the old or program-issued value for each whole class; it never fabricates slot bytes.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotCandidate {
    generation: u8,
    attempt: u8,
}

impl SlotCandidate {
    fn slot(self) -> usize {
        usize::from(self.generation & 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotAtom {
    Zero,
    PreparedHeader(SlotCandidate),
    FinalHeader(SlotCandidate),
    WitnessFrame(SlotCandidate),
    WitnessBody(SlotCandidate),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SemanticSlot {
    atoms: [SlotAtom; SLOT_CLASS_COUNT],
}

impl SemanticSlot {
    const ZERO: Self = Self {
        atoms: [SlotAtom::Zero; SLOT_CLASS_COUNT],
    };

    fn apply(&mut self, write: CanonicalSlotWrite, retained: u8) {
        assert_eq!(retained & !write.touched, 0);
        for (class, atom) in self.atoms.iter_mut().enumerate() {
            if retained & (1u8 << class) != 0 {
                *atom = write.atoms[class];
            }
        }
    }

    fn meaning(self) -> SlotMeaning {
        match self.atoms {
            [SlotAtom::Zero, SlotAtom::Zero, SlotAtom::Zero] => SlotMeaning::Zero,
            [
                SlotAtom::PreparedHeader(candidate),
                SlotAtom::WitnessFrame(frame),
                SlotAtom::WitnessBody(body),
            ] if candidate == frame && candidate == body => SlotMeaning::Prepared(candidate),
            [
                SlotAtom::FinalHeader(candidate),
                SlotAtom::WitnessFrame(frame),
                SlotAtom::WitnessBody(body),
            ] if candidate == frame && candidate == body => SlotMeaning::Final(candidate),
            _ => SlotMeaning::Torn,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalSlotWrite {
    touched: u8,
    atoms: [SlotAtom; SLOT_CLASS_COUNT],
}

impl CanonicalSlotWrite {
    fn prepared(candidate: SlotCandidate) -> Self {
        Self {
            touched: ALL_SLOT_CLASSES,
            atoms: [
                SlotAtom::PreparedHeader(candidate),
                SlotAtom::WitnessFrame(candidate),
                SlotAtom::WitnessBody(candidate),
            ],
        }
    }

    fn final_root(candidate: SlotCandidate) -> Self {
        Self {
            touched: HEADER_CLASS,
            atoms: [
                SlotAtom::FinalHeader(candidate),
                SlotAtom::Zero,
                SlotAtom::Zero,
            ],
        }
    }

    const fn clear() -> Self {
        Self {
            touched: ALL_SLOT_CLASSES,
            atoms: [SlotAtom::Zero; SLOT_CLASS_COUNT],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotMeaning {
    Zero,
    Prepared(SlotCandidate),
    Final(SlotCandidate),
    Torn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TwoSlotHistory {
    slots: [SemanticSlot; 2],
}

impl TwoSlotHistory {
    fn new() -> Self {
        Self {
            slots: [SemanticSlot::ZERO; 2],
        }
    }

    fn apply(&mut self, candidate: SlotCandidate, write: CanonicalSlotWrite, retained: u8) {
        self.slots[candidate.slot()].apply(write, retained);
    }

    /// Establish a generation after a completed recovery barrier.
    fn install_durable_final(&mut self, candidate: SlotCandidate) {
        self.apply(
            candidate,
            CanonicalSlotWrite::prepared(candidate),
            ALL_SLOT_CLASSES,
        );
        self.apply(
            candidate,
            CanonicalSlotWrite::final_root(candidate),
            HEADER_CLASS,
        );
        assert_eq!(
            self.slots[candidate.slot()].meaning(),
            SlotMeaning::Final(candidate)
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RejectedSlotAction {
    Clear {
        outcome: DurabilityOutcome,
        retained: u8,
    },
    Skip,
}

fn synced_clear_retention_reachable(outcome: DurabilityOutcome, retained: u8) -> bool {
    match outcome {
        DurabilityOutcome::Failed => true,
        DurabilityOutcome::Succeeded => retained == ALL_SLOT_CLASSES,
        DurabilityOutcome::NotAttempted => false,
    }
}

fn consume_rejected_slot(
    history: &mut TwoSlotHistory,
    rejected: SlotCandidate,
    action: RejectedSlotAction,
) -> usize {
    let RejectedSlotAction::Clear { outcome, retained } = action else {
        return 0;
    };
    assert!(synced_clear_retention_reachable(outcome, retained));
    history.apply(rejected, CanonicalSlotWrite::clear(), retained);
    if outcome == DurabilityOutcome::Failed {
        history.apply(rejected, CanonicalSlotWrite::clear(), ALL_SLOT_CLASSES);
    }
    assert_eq!(history.slots[rejected.slot()].meaning(), SlotMeaning::Zero);
    1 + usize::from(outcome == DurabilityOutcome::Failed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotReuseObservation {
    retained: SlotMeaning,
    clear_writes: usize,
}

fn three_generation_slot_reuse(
    rejected_prepared_retained: u8,
    retry_retained: u8,
    retry_final_retained: u8,
    rejected_slot_action: RejectedSlotAction,
) -> SlotReuseObservation {
    let generation_one = SlotCandidate {
        generation: 1,
        attempt: 0,
    };
    let generation_two = SlotCandidate {
        generation: 2,
        attempt: 0,
    };
    let rejected = SlotCandidate {
        generation: 3,
        attempt: 0,
    };
    let retry = SlotCandidate {
        generation: 3,
        attempt: 1,
    };
    let mut history = TwoSlotHistory::new();
    history.install_durable_final(generation_one);
    history.install_durable_final(generation_two);
    assert_eq!(generation_one.slot(), rejected.slot());
    assert_ne!(generation_two.slot(), rejected.slot());

    history.apply(
        rejected,
        CanonicalSlotWrite::prepared(rejected),
        rejected_prepared_retained,
    );
    assert!(
        rejected_prepared_retained != 0
            && matches!(
                history.slots[rejected.slot()].meaning(),
                SlotMeaning::Prepared(candidate) if candidate == rejected
            )
            || matches!(history.slots[rejected.slot()].meaning(), SlotMeaning::Torn)
    );
    let clear_writes = consume_rejected_slot(&mut history, rejected, rejected_slot_action);
    history.apply(retry, CanonicalSlotWrite::prepared(retry), retry_retained);
    assert!(retry_retained == ALL_SLOT_CLASSES || retry_final_retained == 0);
    if retry_retained == ALL_SLOT_CLASSES {
        history.apply(
            retry,
            CanonicalSlotWrite::final_root(retry),
            retry_final_retained,
        );
    }
    SlotReuseObservation {
        retained: history.slots[retry.slot()].meaning(),
        clear_writes,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverlapVariant {
    Reference,
    SkipHiddenDebt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenOrder {
    SuccessorFirst,
    PredecessorFirst,
}

impl OpenOrder {
    const ALL: [Self; 2] = [Self::SuccessorFirst, Self::PredecessorFirst];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostSuccessor {
    CrashBeforeReuse,
    ConsumePredecessorEdges,
}

impl PostSuccessor {
    const ALL: [Self; 2] = [Self::CrashBeforeReuse, Self::ConsumePredecessorEdges];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OverlapCase {
    count: usize,
    successor_mask: usize,
    // A set bit still depends on the predecessor ring rather than an independent durable final.
    predecessor_final_debt: usize,
    barrier_outcomes: [DurabilityOutcome; MAX_PARTICIPANTS],
    retained_successor_evidence: usize,
}

impl OverlapCase {
    fn participant_mask(&self) -> usize {
        (1usize << self.count) - 1
    }

    fn omitted_mask(&self) -> usize {
        self.participant_mask() & !self.successor_mask
    }

    fn reachable(&self, variant: OverlapVariant) -> bool {
        if !(2..=MAX_PARTICIPANTS).contains(&self.count)
            || self.successor_mask == 0
            || self.successor_mask & !self.participant_mask() != 0
            || self.predecessor_final_debt & !self.participant_mask() != 0
            || self.retained_successor_evidence & !self.successor_mask != 0
        {
            return false;
        }

        for ordinal in 0..self.count {
            let bit = 1usize << ordinal;
            let successor_participant = self.successor_mask & bit != 0;
            let hidden_debt = self.predecessor_final_debt & self.omitted_mask() & bit != 0;
            let barrier_is_issued =
                successor_participant || (variant == OverlapVariant::Reference && hidden_debt);
            let outcome = self.barrier_outcomes[ordinal];
            if !barrier_is_issued && outcome != DurabilityOutcome::NotAttempted {
                return false;
            }
            if successor_participant
                && outcome == DurabilityOutcome::Succeeded
                && self.retained_successor_evidence & bit == 0
            {
                return false;
            }
        }
        true
    }

    fn successor_authority(&self) -> bool {
        self.retained_successor_evidence & self.successor_mask == self.successor_mask
    }

    fn completed_successor_cut(&self, variant: OverlapVariant) -> bool {
        let participant_barriers_succeeded = (0..self.count).all(|ordinal| {
            let bit = 1usize << ordinal;
            self.successor_mask & bit == 0
                || self.barrier_outcomes[ordinal] == DurabilityOutcome::Succeeded
        });
        let hidden_barriers_succeeded = match variant {
            OverlapVariant::Reference => (0..self.count).all(|ordinal| {
                let bit = 1usize << ordinal;
                self.predecessor_final_debt & self.omitted_mask() & bit == 0
                    || self.barrier_outcomes[ordinal] == DurabilityOutcome::Succeeded
            }),
            OverlapVariant::SkipHiddenDebt => true,
        };
        participant_barriers_succeeded && hidden_barriers_succeeded
    }

    fn remaining_predecessor_debt(&self) -> usize {
        (0..self.count).fold(self.predecessor_final_debt, |debt, ordinal| {
            if self.barrier_outcomes[ordinal] == DurabilityOutcome::Succeeded {
                debt & !(1usize << ordinal)
            } else {
                debt
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverlapRecovery {
    Recovered { world: World, remaining_debt: usize },
    Stranded { omitted_member: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryStep {
    Predecessor,
    Successor,
}

fn recover_overlap(
    case: OverlapCase,
    variant: OverlapVariant,
    order: OpenOrder,
    post_successor: PostSuccessor,
) -> OverlapRecovery {
    let remaining_debt = case.remaining_predecessor_debt();
    let predecessor_edges_consumed = post_successor == PostSuccessor::ConsumePredecessorEdges
        && case.completed_successor_cut(variant)
        && case.successor_authority();
    let steps = match order {
        OpenOrder::SuccessorFirst => [RecoveryStep::Successor, RecoveryStep::Predecessor],
        OpenOrder::PredecessorFirst => [RecoveryStep::Predecessor, RecoveryStep::Successor],
    };
    let mut predecessor_closed = remaining_debt == 0;
    let mut world = World::Predecessor;

    for step in steps {
        let needs_predecessor = step == RecoveryStep::Predecessor
            || (step == RecoveryStep::Successor && case.successor_authority());
        if needs_predecessor && !predecessor_closed {
            if predecessor_edges_consumed {
                let hidden_debt = remaining_debt & case.omitted_mask();
                return OverlapRecovery::Stranded {
                    omitted_member: hidden_debt.trailing_zeros() as usize,
                };
            }
            predecessor_closed = true;
        }
        if step == RecoveryStep::Successor && case.successor_authority() {
            world = World::Candidate;
        }
    }

    OverlapRecovery::Recovered {
        world,
        remaining_debt: usize::from(!predecessor_closed) * remaining_debt,
    }
}

fn for_each_overlap_case(variant: OverlapVariant, mut check: impl FnMut(OverlapCase)) {
    for count in 2..=MAX_PARTICIPANTS {
        let outcomes = choice_vectors(&DurabilityOutcome::ALL, count);
        let participant_mask = (1usize << count) - 1;
        for successor_mask in 1..=participant_mask {
            for predecessor_final_debt in 0..=participant_mask {
                for retained_successor_evidence in 0..=participant_mask {
                    if retained_successor_evidence & !successor_mask != 0 {
                        continue;
                    }
                    for barrier_outcomes in &outcomes {
                        let case = OverlapCase {
                            count,
                            successor_mask,
                            predecessor_final_debt,
                            barrier_outcomes: *barrier_outcomes,
                            retained_successor_evidence,
                        };
                        if case.reachable(variant) {
                            check(case);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn publication_crashes_select_one_complete_world() {
    let mut images = 0usize;
    let mut participant_counts = [false; MAX_PARTICIPANTS + 1];
    let mut operations_seen = [false; Operation::ALL.len()];
    let mut prepares_seen = [false; PrepareState::ALL.len()];
    let mut outcomes_seen = [false; DurabilityOutcome::ALL.len()];
    let mut retained_candidate_after_failed_sync = false;
    let mut failed_sync_without_candidate = false;

    for (count, covered) in participant_counts.iter_mut().enumerate().skip(1) {
        *covered = true;
        let operations = choice_vectors(&Operation::ALL, count);
        let prepares = choice_vectors(&PrepareState::ALL, count);
        let outcomes = choice_vectors(&DurabilityOutcome::ALL, count);
        for operation in operations {
            for prepare in &prepares {
                for proof in proof_vectors(&operation, count) {
                    for outcome in &outcomes {
                        let Some(image) =
                            publication_image(count, operation, *prepare, proof, *outcome)
                        else {
                            continue;
                        };
                        images += 1;
                        for participant in image.participants() {
                            operations_seen[participant.operation as usize] = true;
                            prepares_seen[participant.prepare as usize] = true;
                            outcomes_seen[participant.publication_sync as usize] = true;
                        }
                        let any_failed = image.participants().iter().any(|participant| {
                            participant.publication_sync == DurabilityOutcome::Failed
                        });
                        retained_candidate_after_failed_sync |=
                            any_failed && image.candidate_authority();
                        failed_sync_without_candidate |= any_failed && !image.candidate_authority();
                        assert_reference_contract(image);

                        if !Variant::Reference.permits_live_cleanup(&image) {
                            continue;
                        }
                        let final_states = choice_vectors(&FinalState::ALL, count);
                        let resize_positions = cleanup_positions(&image, false);
                        for retained in final_states {
                            for resize_mask in 0..1usize << count {
                                if resize_mask & !resize_positions != 0 {
                                    continue;
                                }
                                images += 1;
                                assert_reference_contract(live_cleanup_image(
                                    image,
                                    retained,
                                    resize_mask,
                                    Variant::Reference,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(images > 20_000, "bounded exploration unexpectedly shrank");
    assert!(participant_counts[1..].iter().all(|covered| *covered));
    assert!(operations_seen.iter().all(|covered| *covered));
    assert!(prepares_seen.iter().all(|covered| *covered));
    assert!(outcomes_seen.iter().all(|covered| *covered));
    assert!(retained_candidate_after_failed_sync);
    assert!(failed_sync_without_candidate);
}

#[test]
fn crashes_during_recovery_converge_idempotently() {
    let mut crash_images = 0usize;
    for count in 1..=MAX_PARTICIPANTS {
        let operations = choice_vectors(&Operation::ALL, count);
        let prepares = choice_vectors(&PrepareState::ALL, count);
        for operation in operations {
            let proofs = proof_vectors(&operation, count);

            let candidate = publication_image(
                count,
                operation,
                [PrepareState::Complete; MAX_PARTICIPANTS],
                proofs
                    .iter()
                    .copied()
                    .find(|proof| {
                        (0..count).all(|ordinal| proof[ordinal].authorizes(operation[ordinal]))
                    })
                    .expect("every operation vector has valid proofs"),
                [DurabilityOutcome::Succeeded; MAX_PARTICIPANTS],
            )
            .expect("successful durability has complete local evidence");
            for_each_candidate_recovery_crash(candidate, |crash| {
                crash_images += 1;
                assert_reference_contract(crash);
            });

            for prepare in &prepares {
                for proof in &proofs {
                    let seed = publication_image(
                        count,
                        operation,
                        *prepare,
                        *proof,
                        [DurabilityOutcome::NotAttempted; MAX_PARTICIPANTS],
                    )
                    .expect("an unattempted durability operation imposes no retained state");
                    if seed.candidate_authority() {
                        continue;
                    }
                    for_each_predecessor_recovery_crash(seed, |crash| {
                        crash_images += 1;
                        assert_reference_contract(crash);
                    });
                }
            }
        }
    }
    assert!(
        crash_images > 200_000,
        "recovery-cut exploration unexpectedly shrank: {crash_images}"
    );
}

#[test]
fn rejected_slot_is_consumed_before_three_generation_reuse() {
    let retry = SlotCandidate {
        generation: 3,
        attempt: 1,
    };
    let mut explored = 0usize;
    for rejected_retained in 1..=ALL_SLOT_CLASSES {
        for clear_outcome in [DurabilityOutcome::Failed, DurabilityOutcome::Succeeded] {
            for clear_retained in 0..=ALL_SLOT_CLASSES {
                if !synced_clear_retention_reachable(clear_outcome, clear_retained) {
                    continue;
                }
                for retry_retained in 0..=ALL_SLOT_CLASSES {
                    let final_retentions: &[u8] = if retry_retained == ALL_SLOT_CLASSES {
                        &[0, HEADER_CLASS]
                    } else {
                        &[0]
                    };
                    for retry_final_retained in final_retentions {
                        explored += 1;
                        let observation = three_generation_slot_reuse(
                            rejected_retained,
                            retry_retained,
                            *retry_final_retained,
                            RejectedSlotAction::Clear {
                                outcome: clear_outcome,
                                retained: clear_retained,
                            },
                        );
                        let expected = match (retry_retained, *retry_final_retained) {
                            (0, _) => SlotMeaning::Zero,
                            (ALL_SLOT_CLASSES, HEADER_CLASS) => SlotMeaning::Final(retry),
                            (ALL_SLOT_CLASSES, _) => SlotMeaning::Prepared(retry),
                            _ => SlotMeaning::Torn,
                        };
                        assert_eq!(observation.retained, expected);
                        assert_eq!(
                            observation.clear_writes,
                            if clear_outcome == DurabilityOutcome::Failed {
                                2
                            } else {
                                1
                            }
                        );
                    }
                }
            }
        }
    }
    assert_eq!(explored, 567);
}

#[test]
fn skipping_durable_slot_clear_resurrects_rejected_generation() {
    let rejected = SlotCandidate {
        generation: 3,
        attempt: 0,
    };
    let counterexample =
        three_generation_slot_reuse(ALL_SLOT_CLASSES, 0, 0, RejectedSlotAction::Skip);
    assert_eq!(counterexample.clear_writes, 0);
    assert_eq!(counterexample.retained, SlotMeaning::Prepared(rejected));
}

#[test]
fn overlapping_successors_pay_every_predecessor_member() {
    let mut explored = 0usize;
    let mut memberships_seen = [[false; 1 << MAX_PARTICIPANTS]; MAX_PARTICIPANTS + 1];
    let mut debt_masks_seen = [[false; 1 << MAX_PARTICIPANTS]; MAX_PARTICIPANTS + 1];
    let mut participant_outcomes_seen = [false; DurabilityOutcome::ALL.len()];
    let mut hidden_outcomes_seen = [false; DurabilityOutcome::ALL.len()];
    let mut retained_full_successor = false;
    let mut retained_partial_successor = false;

    for_each_overlap_case(OverlapVariant::Reference, |case| {
        explored += 1;
        memberships_seen[case.count][case.successor_mask] = true;
        debt_masks_seen[case.count][case.predecessor_final_debt] = true;
        retained_full_successor |= case.successor_authority();
        retained_partial_successor |= !case.successor_authority();
        for ordinal in 0..case.count {
            let bit = 1usize << ordinal;
            let outcome = case.barrier_outcomes[ordinal] as usize;
            if case.successor_mask & bit != 0 {
                participant_outcomes_seen[outcome] = true;
            } else if case.predecessor_final_debt & bit != 0 {
                hidden_outcomes_seen[outcome] = true;
            }
        }

        for post_successor in PostSuccessor::ALL {
            let successor_first = recover_overlap(
                case,
                OverlapVariant::Reference,
                OpenOrder::SuccessorFirst,
                post_successor,
            );
            let predecessor_first = recover_overlap(
                case,
                OverlapVariant::Reference,
                OpenOrder::PredecessorFirst,
                post_successor,
            );
            assert_eq!(successor_first, predecessor_first, "order changed {case:?}");
            assert!(matches!(
                successor_first,
                OverlapRecovery::Recovered {
                    remaining_debt: 0,
                    ..
                }
            ));
        }
        if case.completed_successor_cut(OverlapVariant::Reference) {
            assert_eq!(
                case.remaining_predecessor_debt() & case.omitted_mask(),
                0,
                "completed successor stranded predecessor debt: {case:?}"
            );
        }
    });

    assert!(explored > 2_500, "overlap exploration unexpectedly shrank");
    for count in 2..=MAX_PARTICIPANTS {
        assert!(
            memberships_seen[count][1..1 << count]
                .iter()
                .all(|seen| *seen)
        );
        assert!(
            debt_masks_seen[count][..1 << count]
                .iter()
                .all(|seen| *seen)
        );
    }
    assert!(participant_outcomes_seen.iter().all(|seen| *seen));
    assert!(hidden_outcomes_seen.iter().all(|seen| *seen));
    assert!(retained_full_successor);
    assert!(retained_partial_successor);
}

#[test]
fn skipping_hidden_debt_has_a_stranded_peer_counterexample() {
    let mut counterexample = None;
    for_each_overlap_case(OverlapVariant::SkipHiddenDebt, |case| {
        if counterexample.is_some() {
            return;
        }
        if let OverlapRecovery::Stranded { omitted_member } = recover_overlap(
            case,
            OverlapVariant::SkipHiddenDebt,
            OpenOrder::SuccessorFirst,
            PostSuccessor::ConsumePredecessorEdges,
        ) {
            counterexample = Some((case, omitted_member));
        }
    });

    let (case, omitted_member) = counterexample.expect("skip-hidden-debt mutant survived");
    assert!(case.completed_successor_cut(OverlapVariant::SkipHiddenDebt));
    assert!(case.successor_authority());
    assert_eq!(case.successor_mask & (1usize << omitted_member), 0);
    assert_ne!(
        case.remaining_predecessor_debt() & (1usize << omitted_member),
        0
    );
    assert!(matches!(
        recover_overlap(
            case,
            OverlapVariant::SkipHiddenDebt,
            OpenOrder::SuccessorFirst,
            PostSuccessor::CrashBeforeReuse,
        ),
        OverlapRecovery::Recovered {
            remaining_debt: 0,
            ..
        }
    ));
    for order in OpenOrder::ALL {
        assert_eq!(
            recover_overlap(
                case,
                OverlapVariant::SkipHiddenDebt,
                order,
                PostSuccessor::ConsumePredecessorEdges,
            ),
            OverlapRecovery::Stranded { omitted_member }
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counterexample {
    variant: Variant,
    violation: InvariantViolation,
    image: Image,
}

fn find_counterexample(variant: Variant) -> Option<Counterexample> {
    for count in 1..=MAX_PARTICIPANTS {
        let operations = choice_vectors(&Operation::ALL, count);
        let prepares = choice_vectors(&PrepareState::ALL, count);
        let outcomes = choice_vectors(&DurabilityOutcome::ALL, count);
        let final_states = choice_vectors(&FinalState::ALL, count);
        for operation in operations {
            for prepare in &prepares {
                for proof in proof_vectors(&operation, count) {
                    for outcome in &outcomes {
                        let Some(image) =
                            publication_image(count, operation, *prepare, proof, *outcome)
                        else {
                            continue;
                        };
                        if let Some(violation) = first_violation(&image, variant) {
                            return Some(Counterexample {
                                variant,
                                violation,
                                image,
                            });
                        }

                        let recovered = recover_fault_free(image, variant);
                        if let Some(violation) = first_violation(&recovered.image, variant) {
                            return Some(Counterexample {
                                variant,
                                violation,
                                image: recovered.image,
                            });
                        }
                        if !variant.permits_live_cleanup(&image) {
                            continue;
                        }
                        for retained in &final_states {
                            let cleanup = live_cleanup_image(image, *retained, 0, variant);
                            if let Some(violation) = first_violation(&cleanup, variant) {
                                return Some(Counterexample {
                                    variant,
                                    violation,
                                    image: cleanup,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[test]
fn every_critical_semantic_mutant_has_a_counterexample() {
    for variant in Variant::MUTANTS {
        let counterexample = find_counterexample(variant)
            .unwrap_or_else(|| panic!("semantic mutant survived bounded exploration: {variant:?}"));
        let expected = match variant {
            Variant::LocalPrepareDecides => InvariantViolation::MixedWorld,
            Variant::FailedSyncIsCut | Variant::FinalizeBeforeCompletedCut => {
                InvariantViolation::LiveCleanupWithoutCompletedCut
            }
            Variant::IgnorePayloadProof => InvariantViolation::CandidateWithoutAuthority,
            Variant::UnlinkBeforeCompletedFinalCut => {
                InvariantViolation::UnlinkBeforeCompletedFinalCut
            }
            Variant::Reference => unreachable!("the reference is not a semantic mutant"),
        };
        assert_eq!(
            counterexample.violation, expected,
            "unexpected counterexample for {variant:?}: {counterexample:?}"
        );
    }
}
