use super::settlement::{Account, Batch, ChallengeKind};
use stateright::{Checker, Model, Property};

// One retained acknowledgment endpoint, context-relative. The body a challenge reconstructs
// is exactly these fields bound to the adjudicated close's payment context.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    payer: Account,
    seq: u8,
    cumulative_debit: u8,
    send_root: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Witness {
    endpoint: Endpoint,
    payer_signature_valid: bool,
    operator_signature_valid: bool,
    context: Batch,
}

impl Witness {
    const fn valid(endpoint: Endpoint, context: Batch) -> Self {
        Self {
            endpoint,
            payer_signature_valid: true,
            operator_signature_valid: true,
            context,
        }
    }

    fn authenticated(self, target: Batch) -> bool {
        self.payer_signature_valid && self.operator_authenticated(target)
    }

    // A fork is the operator's fault regardless of whose key produced the payer half, so
    // fork adjudication authenticates the operator countersignature alone.
    fn operator_authenticated(self, target: Batch) -> bool {
        self.operator_signature_valid && self.context == target
    }

    const fn with_auth_mask(mut self, mask: u8, wrong_context: Batch) -> Self {
        self.payer_signature_valid = mask & 0b001 != 0;
        self.operator_signature_valid = mask & 0b010 != 0;
        if mask & 0b100 == 0 {
            self.context = wrong_context;
        }
        self
    }
}

// One retained per-edge terminal opened under the witness acknowledgment's send root.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Entry {
    recipient: Account,
    cumulative: u8,
    count: u8,
}

impl Entry {
    // The adjudicator refuses entries no honest sender vector can contain.
    const fn feasible(self) -> bool {
        self.count > 0 && self.cumulative >= self.count
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Evidence {
    HigherDebit {
        ack: Witness,
        typed_opening: bool,
    },
    HigherEntry {
        ack: Witness,
        entry: Entry,
        typed_entry_opening: bool,
        typed_sender_opening: bool,
    },
    Fork {
        left: Witness,
        right: Witness,
    },
}

impl Evidence {
    const fn kind(self) -> ChallengeKind {
        match self {
            Self::HigherDebit { .. } => ChallengeKind::HigherDebit,
            Self::HigherEntry { .. } => ChallengeKind::HigherEntry,
            Self::Fork { .. } => ChallengeKind::Fork,
        }
    }

    fn all_witnesses_authenticated(self, target: Batch) -> bool {
        match self {
            Self::HigherDebit { ack, .. } | Self::HigherEntry { ack, .. } => {
                ack.authenticated(target)
            }
            Self::Fork { left, right } => {
                left.operator_authenticated(target) && right.operator_authenticated(target)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProvenChallenge {
    target: Batch,
    kind: ChallengeKind,
}

impl ProvenChallenge {
    pub(crate) const fn target(self) -> Batch {
        self.target
    }

    pub(crate) const fn kind(self) -> ChallengeKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Verdict {
    Fault(ChallengeKind),
    NoContradiction,
    InvalidEvidence,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ChallengeState {
    target: Batch,
    evidence: Evidence,
    expected: Verdict,
    verdict: Option<Verdict>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChallengeAction {
    Adjudicate,
}

#[derive(Clone)]
struct ChallengeModel;

const BATCHES: [Batch; 5] = [Batch::B0, Batch::B1, Batch::B2, Batch::B3, Batch::Offset];

// Committed terminal endpoint for the payer with public activity.
const PUBLIC_TERMINAL: Endpoint = Endpoint {
    payer: Account::Alice,
    seq: 1,
    cumulative_debit: 3,
    send_root: 1,
};

// Retained acknowledgment strictly above the committed terminal debit.
const HIGHER_DEBIT: Endpoint = Endpoint {
    payer: Account::Alice,
    seq: 2,
    cumulative_debit: 4,
    send_root: 2,
};

// Retained acknowledgment whose vector credits an edge above its committed terminal entry.
const HIGHER_ENTRY_ACK: Endpoint = Endpoint {
    payer: Account::Alice,
    seq: 1,
    cumulative_debit: 3,
    send_root: 3,
};

const HIGHER_ENTRY: Entry = Entry {
    recipient: Account::Carol,
    cumulative: 2,
    count: 1,
};

// Two operator-countersigned bodies at one payer sequence number.
const FORK_LEFT: Endpoint = Endpoint {
    payer: Account::Bob,
    seq: 1,
    cumulative_debit: 1,
    send_root: 4,
};

// Differs from the left endpoint in both debit value and vector root.
const FORK_VALUE: Endpoint = Endpoint {
    payer: Account::Bob,
    seq: 1,
    cumulative_debit: 2,
    send_root: 5,
};

// Differs from the left endpoint in the vector root alone.
const FORK_ROOT: Endpoint = Endpoint {
    payer: Account::Bob,
    seq: 1,
    cumulative_debit: 1,
    send_root: 5,
};

// The same sequence number acknowledged under a different payer.
const FORK_OTHER_PAYER: Endpoint = Endpoint {
    payer: Account::Carol,
    seq: 1,
    cumulative_debit: 2,
    send_root: 5,
};

// The adjacent sequence number under the same payer.
const FORK_NEXT_SEQ: Endpoint = Endpoint {
    payer: Account::Bob,
    seq: 2,
    cumulative_debit: 2,
    send_root: 5,
};

const fn other_batch(target: Batch) -> Batch {
    match target {
        Batch::B0 => Batch::B1,
        Batch::B1 => Batch::B2,
        Batch::B2 => Batch::B3,
        Batch::B3 => Batch::Offset,
        Batch::Offset | Batch::B1C | Batch::B2D | Batch::OffsetC => Batch::B0,
    }
}

fn public_debit(_target: Batch, payer: Account) -> u8 {
    if payer == Account::Alice { 3 } else { 0 }
}

const fn public_entry(_target: Batch, payer: Account, recipient: Account) -> (u8, u8) {
    match (payer, recipient) {
        (Account::Alice, Account::Carol) => (1, 1),
        (Account::Alice, Account::Bob) => (2, 1),
        _ => (0, 0),
    }
}

fn structurally_valid(target: Batch, evidence: Evidence) -> bool {
    if !evidence.all_witnesses_authenticated(target) {
        return false;
    }
    match evidence {
        Evidence::HigherDebit { typed_opening, .. } => typed_opening,
        Evidence::HigherEntry {
            entry,
            typed_entry_opening,
            typed_sender_opening,
            ..
        } => typed_entry_opening && typed_sender_opening && entry.feasible(),
        Evidence::Fork { .. } => true,
    }
}

fn semantic_contradiction(target: Batch, evidence: Evidence) -> bool {
    match evidence {
        Evidence::HigherDebit { ack, .. } => {
            // Every counted value is a terminal opening under a payer-signed root, so only a
            // strictly higher retained endpoint contradicts the close. An equal endpoint is
            // the committed terminal itself.
            ack.endpoint.cumulative_debit > public_debit(target, ack.endpoint.payer)
        }
        Evidence::HigherEntry { ack, entry, .. } => {
            let (cumulative, count) = public_entry(target, ack.endpoint.payer, entry.recipient);
            entry.cumulative > cumulative || entry.count > count
        }
        Evidence::Fork { left, right } => {
            let left = left.endpoint;
            let right = right.endpoint;
            left.payer == right.payer && left.seq == right.seq && left != right
        }
    }
}

fn adjudicate(target: Batch, evidence: Evidence) -> Verdict {
    if !structurally_valid(target, evidence) {
        Verdict::InvalidEvidence
    } else if semantic_contradiction(target, evidence) {
        Verdict::Fault(evidence.kind())
    } else {
        Verdict::NoContradiction
    }
}

fn positive_cases(target: Batch) -> Vec<(Evidence, ChallengeKind)> {
    vec![
        (
            Evidence::HigherDebit {
                ack: Witness::valid(HIGHER_DEBIT, target),
                typed_opening: true,
            },
            ChallengeKind::HigherDebit,
        ),
        (
            Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, target),
                entry: HIGHER_ENTRY,
                typed_entry_opening: true,
                typed_sender_opening: true,
            },
            ChallengeKind::HigherEntry,
        ),
        (
            Evidence::Fork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_VALUE, target),
            },
            ChallengeKind::Fork,
        ),
        (
            Evidence::Fork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_ROOT, target),
            },
            ChallengeKind::Fork,
        ),
    ]
}

pub(crate) fn adjudicated_proven_challenges(target: Batch) -> Vec<ProvenChallenge> {
    let mut proven = Vec::new();
    for (evidence, _) in positive_cases(target) {
        let Verdict::Fault(kind) = adjudicate(target, evidence) else {
            continue;
        };
        if proven
            .iter()
            .any(|token: &ProvenChallenge| token.kind == kind)
        {
            continue;
        }
        proven.push(ProvenChallenge { target, kind });
    }
    proven
}

const fn map_auth(
    evidence: Evidence,
    left_mask: u8,
    right_mask: u8,
    wrong_context: Batch,
) -> Evidence {
    match evidence {
        Evidence::HigherDebit { ack, typed_opening } => Evidence::HigherDebit {
            ack: ack.with_auth_mask(left_mask, wrong_context),
            typed_opening,
        },
        Evidence::HigherEntry {
            ack,
            entry,
            typed_entry_opening,
            typed_sender_opening,
        } => Evidence::HigherEntry {
            ack: ack.with_auth_mask(left_mask, wrong_context),
            entry,
            typed_entry_opening,
            typed_sender_opening,
        },
        Evidence::Fork { left, right } => Evidence::Fork {
            left: left.with_auth_mask(left_mask, wrong_context),
            right: right.with_auth_mask(right_mask, wrong_context),
        },
    }
}

// Operator countersignature and context binding alone gate fork validity.
const fn operator_mask(mask: u8) -> bool {
    mask & 0b110 == 0b110
}

fn adversarial_cases() -> Vec<ChallengeState> {
    let mut cases = Vec::new();
    for target in BATCHES {
        let wrong_context = other_batch(target);
        for (evidence, proven_kind) in positive_cases(target) {
            match evidence {
                Evidence::HigherDebit { .. } | Evidence::HigherEntry { .. } => {
                    for auth in 0..8 {
                        cases.push(ChallengeState {
                            target,
                            evidence: map_auth(evidence, auth, auth, wrong_context),
                            expected: if auth == 0b111 {
                                Verdict::Fault(proven_kind)
                            } else {
                                Verdict::InvalidEvidence
                            },
                            verdict: None,
                        });
                    }
                }
                Evidence::Fork { .. } => {
                    for left_auth in 0..8 {
                        for right_auth in 0..8 {
                            cases.push(ChallengeState {
                                target,
                                evidence: map_auth(evidence, left_auth, right_auth, wrong_context),
                                expected: if operator_mask(left_auth) && operator_mask(right_auth) {
                                    Verdict::Fault(proven_kind)
                                } else {
                                    Verdict::InvalidEvidence
                                },
                                verdict: None,
                            });
                        }
                    }
                }
            }
            cases.push(ChallengeState {
                target: wrong_context,
                evidence,
                expected: Verdict::InvalidEvidence,
                verdict: None,
            });
        }
    }

    cases.extend([
        // An equal retained endpoint is the committed terminal itself.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherDebit {
                ack: Witness::valid(PUBLIC_TERMINAL, Batch::B1),
                typed_opening: true,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherDebit {
                ack: Witness::valid(HIGHER_DEBIT, Batch::B1),
                typed_opening: false,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, Batch::B1),
                entry: HIGHER_ENTRY,
                typed_entry_opening: false,
                typed_sender_opening: true,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, Batch::B1),
                entry: HIGHER_ENTRY,
                typed_entry_opening: true,
                typed_sender_opening: false,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        // No honest sender vector carries a zero-count entry.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, Batch::B1),
                entry: Entry {
                    recipient: Account::Carol,
                    cumulative: 2,
                    count: 0,
                },
                typed_entry_opening: true,
                typed_sender_opening: true,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        // No honest sender vector counts more payments than it credits.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, Batch::B1),
                entry: Entry {
                    recipient: Account::Carol,
                    cumulative: 1,
                    count: 2,
                },
                typed_entry_opening: true,
                typed_sender_opening: true,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        // A retained entry equal to the committed terminal entry does not contradict it.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, Batch::B1),
                entry: Entry {
                    recipient: Account::Carol,
                    cumulative: 1,
                    count: 1,
                },
                typed_entry_opening: true,
                typed_sender_opening: true,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // A count above the committed count convicts even at an equal cumulative value.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherEntry {
                ack: Witness::valid(HIGHER_ENTRY_ACK, Batch::B1),
                entry: Entry {
                    recipient: Account::Bob,
                    cumulative: 2,
                    count: 2,
                },
                typed_entry_opening: true,
                typed_sender_opening: true,
            },
            expected: Verdict::Fault(ChallengeKind::HigherEntry),
            verdict: None,
        },
        // A reissued identical acknowledgment is a retry, not a fork.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Fork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_LEFT, Batch::B1),
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // Distinct bodies under different payers never fork.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Fork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_OTHER_PAYER, Batch::B1),
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // Distinct bodies at adjacent sequence numbers never fork.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Fork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_NEXT_SEQ, Batch::B1),
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // A fork convicts on the operator countersignatures alone.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Fork {
                left: Witness {
                    payer_signature_valid: false,
                    ..Witness::valid(FORK_LEFT, Batch::B1)
                },
                right: Witness {
                    payer_signature_valid: false,
                    ..Witness::valid(FORK_VALUE, Batch::B1)
                },
            },
            expected: Verdict::Fault(ChallengeKind::Fork),
            verdict: None,
        },
    ]);
    cases
}

fn fault_implies_valid_contradiction(_: &ChallengeModel, state: &ChallengeState) -> bool {
    let Some(Verdict::Fault(kind)) = state.verdict else {
        return true;
    };
    structurally_valid(state.target, state.evidence)
        && semantic_contradiction(state.target, state.evidence)
        && kind == state.evidence.kind()
}

fn invalid_evidence_never_faults(_: &ChallengeModel, state: &ChallengeState) -> bool {
    structurally_valid(state.target, state.evidence)
        || !matches!(state.verdict, Some(Verdict::Fault(_)))
}

fn adjudication_matches_case_oracle(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state
        .verdict
        .is_none_or(|verdict| verdict == state.expected)
}

fn higher_debit_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::Fault(ChallengeKind::HigherDebit))
}

fn higher_entry_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::Fault(ChallengeKind::HigherEntry))
}

fn fork_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::Fault(ChallengeKind::Fork))
}

fn no_contradiction_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::NoContradiction)
}

fn invalid_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::InvalidEvidence)
}

impl Model for ChallengeModel {
    type State = ChallengeState;
    type Action = ChallengeAction;

    fn init_states(&self) -> Vec<Self::State> {
        adversarial_cases()
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.verdict.is_none() {
            actions.push(ChallengeAction::Adjudicate);
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        if action != ChallengeAction::Adjudicate || last.verdict.is_some() {
            return None;
        }
        Some(ChallengeState {
            verdict: Some(adjudicate(last.target, last.evidence)),
            ..*last
        })
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(
                "adjudication matches the independent case oracle",
                adjudication_matches_case_oracle,
            ),
            Property::always(
                "fault requires structurally valid contradictory evidence of the reported kind",
                fault_implies_valid_contradiction,
            ),
            Property::always(
                "structurally invalid evidence never faults",
                invalid_evidence_never_faults,
            ),
            Property::sometimes("higher-debit contradiction faults", higher_debit_reached),
            Property::sometimes("higher-entry contradiction faults", higher_entry_reached),
            Property::sometimes("acknowledgment fork faults", fork_reached),
            Property::sometimes(
                "valid non-contradiction remains clean",
                no_contradiction_reached,
            ),
            Property::sometimes(
                "wrong signatures or selected context are invalid",
                invalid_reached,
            ),
        ]
    }
}

#[cfg(not(test))]
pub(crate) fn explore(address: &str) {
    ChallengeModel.checker().threads(1).serve(address);
}

#[test]
fn challenge_checker_exhausts_authentication_classes() {
    let checker = ChallengeModel.checker().threads(1).spawn_bfs().join();
    assert!(checker.is_done());
    assert_eq!(checker.unique_state_count(), 1_502);
    checker.assert_properties();
}

#[test]
fn proven_challenges_are_opaque_adjudicated_target_tokens() {
    let expected = [
        ChallengeKind::HigherDebit,
        ChallengeKind::HigherEntry,
        ChallengeKind::Fork,
    ];
    for target in BATCHES {
        let proven = adjudicated_proven_challenges(target);
        assert_eq!(proven.len(), expected.len());
        assert!(proven.iter().all(|token| token.target() == target));
        for kind in expected {
            assert!(proven.iter().any(|token| token.kind() == kind));
        }
    }
}

#[test]
fn every_always_property_has_a_direct_negative_control() {
    let oracle_control = ChallengeState {
        target: Batch::B1,
        evidence: Evidence::HigherDebit {
            ack: Witness::valid(HIGHER_DEBIT, Batch::B1),
            typed_opening: true,
        },
        expected: Verdict::Fault(ChallengeKind::HigherDebit),
        verdict: Some(Verdict::NoContradiction),
    };
    assert!(!adjudication_matches_case_oracle(
        &ChallengeModel,
        &oracle_control
    ));

    let contradiction_control = ChallengeState {
        target: Batch::B1,
        evidence: Evidence::HigherDebit {
            ack: Witness::valid(PUBLIC_TERMINAL, Batch::B1),
            typed_opening: true,
        },
        expected: Verdict::Fault(ChallengeKind::HigherDebit),
        verdict: Some(Verdict::Fault(ChallengeKind::HigherDebit)),
    };
    assert!(!fault_implies_valid_contradiction(
        &ChallengeModel,
        &contradiction_control
    ));

    let invalid_control = ChallengeState {
        target: Batch::B1,
        evidence: Evidence::HigherDebit {
            ack: Witness::valid(HIGHER_DEBIT, Batch::B1),
            typed_opening: false,
        },
        expected: Verdict::Fault(ChallengeKind::HigherDebit),
        verdict: Some(Verdict::Fault(ChallengeKind::HigherDebit)),
    };
    assert!(!invalid_evidence_never_faults(
        &ChallengeModel,
        &invalid_control
    ));
}
