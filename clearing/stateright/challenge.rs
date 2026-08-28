use super::settlement::{Account, Batch, ChallengeKind, ForkRelation};
use stateright::{Checker, Model, Property};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    transaction: u8,
    payer: Account,
    recipient: Account,
    amount: u8,
    cumulative_debit: u8,
    shard: u8,
    cumulative_shard_credit: u8,
    index: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Witness {
    endpoint: Endpoint,
    payer_signature_valid: bool,
    payer_signature_identity: u8,
    operator_signature_valid: bool,
    exact_link: bool,
    context: Batch,
}

impl Witness {
    const fn valid(endpoint: Endpoint, context: Batch) -> Self {
        Self {
            endpoint,
            payer_signature_valid: true,
            payer_signature_identity: 1,
            operator_signature_valid: true,
            exact_link: true,
            context,
        }
    }

    fn authenticated(self, target: Batch) -> bool {
        self.payer_signature_valid
            && self.operator_signature_valid
            && self.exact_link
            && self.context == target
            && self.endpoint.amount > 0
            && self.endpoint.cumulative_debit >= self.endpoint.amount
    }

    const fn with_auth_mask(mut self, mask: u8, wrong_context: Batch) -> Self {
        self.payer_signature_valid = mask & 0b0001 != 0;
        self.operator_signature_valid = mask & 0b0010 != 0;
        self.exact_link = mask & 0b0100 != 0;
        if mask & 0b1000 == 0 {
            self.context = wrong_context;
        }
        self
    }

    const fn with_payer_signature_identity(mut self, identity: u8) -> Self {
        self.payer_signature_identity = identity;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RangeLower {
    ShardStart,
    Payment(Witness),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Evidence {
    Latest {
        payment: Witness,
        typed_opening: bool,
    },
    HigherShardTip {
        payment: Witness,
        typed_parent_opening: bool,
        typed_child_opening: bool,
    },
    ReceiptRange {
        lower: RangeLower,
        upper: Witness,
    },
    ReceiptFork {
        left: Witness,
        right: Witness,
        canonical_order: bool,
        encoded_relation: ForkRelation,
    },
}

impl Evidence {
    const fn kind(self) -> ChallengeKind {
        match self {
            Self::Latest { .. } => ChallengeKind::LatestAcknowledgedSend,
            Self::HigherShardTip { .. } => ChallengeKind::HigherShardTip,
            Self::ReceiptRange { .. } => ChallengeKind::InconsistentReceiptRange,
            Self::ReceiptFork {
                encoded_relation, ..
            } => ChallengeKind::ReceiptFork(encoded_relation),
        }
    }

    fn all_witnesses_authenticated(self, target: Batch) -> bool {
        match self {
            Self::Latest { payment, .. } | Self::HigherShardTip { payment, .. } => {
                payment.authenticated(target)
            }
            Self::ReceiptRange { lower, upper } => {
                upper.authenticated(target)
                    && match lower {
                        RangeLower::ShardStart => true,
                        RangeLower::Payment(lower) => lower.authenticated(target),
                    }
            }
            Self::ReceiptFork { left, right, .. } => {
                left.authenticated(target) && right.authenticated(target)
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

const PUBLIC_OUTGOING: Endpoint = Endpoint {
    transaction: 1,
    payer: Account::Alice,
    recipient: Account::Carol,
    amount: 1,
    cumulative_debit: 3,
    shard: 0,
    cumulative_shard_credit: 1,
    index: 1,
};

const LATEST: Endpoint = Endpoint {
    transaction: 2,
    payer: Account::Alice,
    recipient: Account::Bob,
    amount: 1,
    cumulative_debit: 4,
    shard: 0,
    cumulative_shard_credit: 3,
    index: 2,
};

const HIGHER: Endpoint = Endpoint {
    transaction: 3,
    payer: Account::Bob,
    recipient: Account::Carol,
    amount: 1,
    cumulative_debit: 1,
    shard: 0,
    cumulative_shard_credit: 2,
    index: 2,
};

const RANGE_LOWER: Endpoint = Endpoint {
    transaction: 4,
    payer: Account::Alice,
    recipient: Account::Bob,
    amount: 1,
    cumulative_debit: 1,
    shard: 1,
    cumulative_shard_credit: 1,
    index: 1,
};

const RANGE_UPPER: Endpoint = Endpoint {
    transaction: 5,
    payer: Account::Alice,
    recipient: Account::Bob,
    amount: 2,
    cumulative_debit: 3,
    shard: 1,
    cumulative_shard_credit: 2,
    index: 2,
};

const FORK_LEFT: Endpoint = Endpoint {
    transaction: 6,
    payer: Account::Alice,
    recipient: Account::Bob,
    amount: 1,
    cumulative_debit: 1,
    shard: 2,
    cumulative_shard_credit: 1,
    index: 1,
};

const FORK_SAME_INDEX: Endpoint = Endpoint {
    transaction: 7,
    payer: Account::Bob,
    recipient: Account::Bob,
    amount: 2,
    cumulative_debit: 2,
    shard: 2,
    cumulative_shard_credit: 2,
    index: 1,
};

const FORK_SAME_SEND: Endpoint = Endpoint {
    transaction: 6,
    payer: Account::Alice,
    recipient: Account::Bob,
    amount: 1,
    cumulative_debit: 1,
    shard: 3,
    cumulative_shard_credit: 2,
    index: 2,
};

const FORK_BOTH_RELATIONS: Endpoint = Endpoint {
    transaction: 6,
    payer: Account::Alice,
    recipient: Account::Bob,
    amount: 1,
    cumulative_debit: 1,
    shard: 2,
    cumulative_shard_credit: 2,
    index: 1,
};

const FORK_AMOUNT_ONLY: Endpoint = Endpoint {
    transaction: 6,
    payer: Account::Bob,
    recipient: Account::Bob,
    amount: 2,
    cumulative_debit: 2,
    shard: 2,
    cumulative_shard_credit: 1,
    index: 1,
};

const FORK_UNRELATED: Endpoint = Endpoint {
    transaction: 8,
    payer: Account::Carol,
    recipient: Account::Carol,
    amount: 1,
    cumulative_debit: 1,
    shard: 4,
    cumulative_shard_credit: 1,
    index: 1,
};

const FORK_SIBLING_ENTRY: Endpoint = Endpoint {
    transaction: 6,
    payer: Account::Alice,
    recipient: Account::Carol,
    amount: 1,
    cumulative_debit: 1,
    shard: 5,
    cumulative_shard_credit: 1,
    index: 1,
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

fn public_outgoing(_target: Batch, payer: Account) -> Option<Endpoint> {
    (payer == Account::Alice).then_some(PUBLIC_OUTGOING)
}

fn public_tip(_target: Batch, recipient: Account, shard: u8) -> (u8, u8) {
    if recipient == Account::Carol && shard == 0 {
        (1, 1)
    } else {
        (0, 0)
    }
}

fn range_feasible(lower_credit: u8, lower_index: u8, upper: Endpoint) -> bool {
    let Some(distance) = upper.index.checked_sub(lower_index) else {
        return false;
    };
    let Some(explicit_credit) = lower_credit.checked_add(upper.amount) else {
        return false;
    };
    if upper.amount == 0 || distance == 0 {
        return false;
    }
    if distance == 1 {
        upper.cumulative_shard_credit == explicit_credit
    } else {
        explicit_credit
            .checked_add(distance - 1)
            .is_some_and(|minimum| upper.cumulative_shard_credit >= minimum)
    }
}

fn same_signed_send(left: Witness, right: Witness) -> bool {
    left.endpoint.transaction == right.endpoint.transaction
        && left.endpoint.payer == right.endpoint.payer
        && left.endpoint.recipient == right.endpoint.recipient
        && left.endpoint.amount == right.endpoint.amount
        && left.endpoint.cumulative_debit == right.endpoint.cumulative_debit
        && left.payer_signature_identity == right.payer_signature_identity
}

fn same_index(left: Endpoint, right: Endpoint) -> bool {
    left.recipient == right.recipient && left.shard == right.shard && left.index == right.index
}

const fn same_transaction(left: Endpoint, right: Endpoint) -> bool {
    left.transaction == right.transaction
}

fn receipt_equal(left: Endpoint, right: Endpoint) -> bool {
    left.transaction == right.transaction
        && left.recipient == right.recipient
        && left.amount == right.amount
        && left.shard == right.shard
        && left.cumulative_shard_credit == right.cumulative_shard_credit
        && left.index == right.index
}

fn canonical_fork_relation(left: Witness, right: Witness) -> ForkRelation {
    if same_signed_send(left, right) {
        ForkRelation::SameSend
    } else if same_index(left.endpoint, right.endpoint) {
        ForkRelation::SameIndex
    } else {
        ForkRelation::Full
    }
}

fn structurally_valid(target: Batch, evidence: Evidence) -> bool {
    if !evidence.all_witnesses_authenticated(target) {
        return false;
    }
    match evidence {
        Evidence::Latest { typed_opening, .. } => typed_opening,
        Evidence::HigherShardTip {
            typed_parent_opening,
            typed_child_opening,
            ..
        } => typed_parent_opening && typed_child_opening,
        Evidence::ReceiptRange { lower, upper } => match lower {
            RangeLower::ShardStart => true,
            RangeLower::Payment(lower) => {
                upper.endpoint.recipient == lower.endpoint.recipient
                    && upper.endpoint.shard == lower.endpoint.shard
                    && upper.endpoint.index > lower.endpoint.index
            }
        },
        Evidence::ReceiptFork {
            left,
            right,
            canonical_order,
            encoded_relation,
        } => canonical_order && encoded_relation == canonical_fork_relation(left, right),
    }
}

fn semantic_contradiction(target: Batch, evidence: Evidence) -> bool {
    match evidence {
        Evidence::Latest { payment, .. } => {
            let endpoint = payment.endpoint;
            let committed = public_debit(target, endpoint.payer);

            // The committed leaf pins the terminal signed send only. A batched send is
            // acknowledged by one receipt per entry, so equal endpoints contradict exactly when
            // the disclosed transaction differs from the committed one.
            endpoint.cumulative_debit > committed
                || (endpoint.cumulative_debit == committed
                    && public_outgoing(target, endpoint.payer)
                        .is_none_or(|outgoing| outgoing.transaction != endpoint.transaction))
        }
        Evidence::HigherShardTip { payment, .. } => {
            let endpoint = payment.endpoint;
            let (credit, index) = public_tip(target, endpoint.recipient, endpoint.shard);
            endpoint.cumulative_shard_credit > credit || endpoint.index > index
        }
        Evidence::ReceiptRange { lower, upper } => match lower {
            RangeLower::ShardStart => !range_feasible(0, 0, upper.endpoint),
            RangeLower::Payment(lower) => {
                let upper = upper.endpoint;
                let lower = lower.endpoint;
                !range_feasible(lower.cumulative_shard_credit, lower.index, upper)
            }
        },
        Evidence::ReceiptFork { left, right, .. } => {
            let left = left.endpoint;
            let right = right.endpoint;

            // Sibling entries of one batched send share a transaction identifier, so a
            // transaction fork requires the same credited entry recipient.
            !receipt_equal(left, right)
                && (same_index(left, right)
                    || (same_transaction(left, right) && left.recipient == right.recipient))
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
            Evidence::Latest {
                payment: Witness::valid(LATEST, target),
                typed_opening: true,
            },
            ChallengeKind::LatestAcknowledgedSend,
        ),
        (
            Evidence::HigherShardTip {
                payment: Witness::valid(HIGHER, target),
                typed_parent_opening: true,
                typed_child_opening: true,
            },
            ChallengeKind::HigherShardTip,
        ),
        (
            Evidence::ReceiptRange {
                lower: RangeLower::Payment(Witness::valid(RANGE_LOWER, target)),
                upper: Witness::valid(RANGE_UPPER, target),
            },
            ChallengeKind::InconsistentReceiptRange,
        ),
        (
            Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_SAME_SEND, target),
                canonical_order: true,
                encoded_relation: ForkRelation::SameSend,
            },
            ChallengeKind::ReceiptFork(ForkRelation::SameSend),
        ),
        (
            Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_SAME_INDEX, target),
                canonical_order: true,
                encoded_relation: ForkRelation::SameIndex,
            },
            ChallengeKind::ReceiptFork(ForkRelation::SameIndex),
        ),
        (
            Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_SAME_SEND, target).with_payer_signature_identity(2),
                canonical_order: true,
                encoded_relation: ForkRelation::Full,
            },
            ChallengeKind::ReceiptFork(ForkRelation::Full),
        ),
        (
            Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_BOTH_RELATIONS, target),
                canonical_order: true,
                encoded_relation: ForkRelation::SameSend,
            },
            ChallengeKind::ReceiptFork(ForkRelation::SameSend),
        ),
        (
            Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, target),
                right: Witness::valid(FORK_AMOUNT_ONLY, target),
                canonical_order: true,
                encoded_relation: ForkRelation::SameIndex,
            },
            ChallengeKind::ReceiptFork(ForkRelation::SameIndex),
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
        Evidence::Latest {
            payment,
            typed_opening,
        } => Evidence::Latest {
            payment: payment.with_auth_mask(left_mask, wrong_context),
            typed_opening,
        },
        Evidence::HigherShardTip {
            payment,
            typed_parent_opening,
            typed_child_opening,
        } => Evidence::HigherShardTip {
            payment: payment.with_auth_mask(left_mask, wrong_context),
            typed_parent_opening,
            typed_child_opening,
        },
        Evidence::ReceiptRange { lower, upper } => Evidence::ReceiptRange {
            lower: match lower {
                RangeLower::ShardStart => RangeLower::ShardStart,
                RangeLower::Payment(lower) => {
                    RangeLower::Payment(lower.with_auth_mask(left_mask, wrong_context))
                }
            },
            upper: upper.with_auth_mask(right_mask, wrong_context),
        },
        Evidence::ReceiptFork {
            left,
            right,
            canonical_order,
            encoded_relation,
        } => Evidence::ReceiptFork {
            left: left.with_auth_mask(left_mask, wrong_context),
            right: right.with_auth_mask(right_mask, wrong_context),
            canonical_order,
            encoded_relation,
        },
    }
}

fn adversarial_cases() -> Vec<ChallengeState> {
    let mut cases = Vec::new();
    for target in BATCHES {
        let wrong_context = other_batch(target);
        for (evidence, proven_kind) in positive_cases(target) {
            match evidence {
                Evidence::Latest { .. } | Evidence::HigherShardTip { .. } => {
                    for auth in 0..16 {
                        cases.push(ChallengeState {
                            target,
                            evidence: map_auth(evidence, auth, auth, wrong_context),
                            expected: if auth == 0b1111 {
                                Verdict::Fault(proven_kind)
                            } else {
                                Verdict::InvalidEvidence
                            },
                            verdict: None,
                        });
                    }
                }
                Evidence::ReceiptRange { .. } | Evidence::ReceiptFork { .. } => {
                    for left_auth in 0..16 {
                        for right_auth in 0..16 {
                            cases.push(ChallengeState {
                                target,
                                evidence: map_auth(evidence, left_auth, right_auth, wrong_context),
                                expected: if left_auth == 0b1111 && right_auth == 0b1111 {
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
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Latest {
                payment: Witness::valid(PUBLIC_OUTGOING, Batch::B1),
                typed_opening: true,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Latest {
                payment: Witness::valid(LATEST, Batch::B1),
                typed_opening: false,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherShardTip {
                payment: Witness::valid(HIGHER, Batch::B1),
                typed_parent_opening: false,
                typed_child_opening: true,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::HigherShardTip {
                payment: Witness::valid(HIGHER, Batch::B1),
                typed_parent_opening: true,
                typed_child_opening: false,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptRange {
                lower: RangeLower::ShardStart,
                upper: Witness::valid(RANGE_UPPER, Batch::B1),
            },
            expected: Verdict::Fault(ChallengeKind::InconsistentReceiptRange),
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptRange {
                lower: RangeLower::Payment(Witness::valid(RANGE_UPPER, Batch::B1)),
                upper: Witness::valid(RANGE_LOWER, Batch::B1),
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptFork {
                left: Witness::valid(FORK_SAME_INDEX, Batch::B1),
                right: Witness::valid(FORK_LEFT, Batch::B1),
                canonical_order: false,
                encoded_relation: ForkRelation::SameIndex,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_SAME_SEND, Batch::B1),
                canonical_order: true,
                encoded_relation: ForkRelation::SameIndex,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_BOTH_RELATIONS, Batch::B1),
                canonical_order: true,
                encoded_relation: ForkRelation::SameIndex,
            },
            expected: Verdict::InvalidEvidence,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_LEFT, Batch::B1),
                canonical_order: true,
                encoded_relation: ForkRelation::SameSend,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_UNRELATED, Batch::B1),
                canonical_order: true,
                encoded_relation: ForkRelation::Full,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // Sibling entries of one batched send share a transaction without forking it.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::ReceiptFork {
                left: Witness::valid(FORK_LEFT, Batch::B1),
                right: Witness::valid(FORK_SIBLING_ENTRY, Batch::B1),
                canonical_order: true,
                encoded_relation: ForkRelation::Full,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // A receipt for another entry of the committed terminal send does not contradict an
        // equal committed endpoint.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Latest {
                payment: Witness::valid(
                    Endpoint {
                        recipient: Account::Bob,
                        amount: 2,
                        shard: 5,
                        cumulative_shard_credit: 2,
                        index: 1,
                        ..PUBLIC_OUTGOING
                    },
                    Batch::B1,
                ),
                typed_opening: true,
            },
            expected: Verdict::NoContradiction,
            verdict: None,
        },
        // Two different acknowledged authorizations at one committed endpoint fork the payer's
        // debit chain.
        ChallengeState {
            target: Batch::B1,
            evidence: Evidence::Latest {
                payment: Witness::valid(
                    Endpoint {
                        transaction: 9,
                        amount: 3,
                        ..PUBLIC_OUTGOING
                    },
                    Batch::B1,
                ),
                typed_opening: true,
            },
            expected: Verdict::Fault(ChallengeKind::LatestAcknowledgedSend),
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

fn latest_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::Fault(ChallengeKind::LatestAcknowledgedSend))
}

fn higher_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::Fault(ChallengeKind::HigherShardTip))
}

fn range_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict == Some(Verdict::Fault(ChallengeKind::InconsistentReceiptRange))
}

fn same_send_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict
        == Some(Verdict::Fault(ChallengeKind::ReceiptFork(
            ForkRelation::SameSend,
        )))
}

fn same_index_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict
        == Some(Verdict::Fault(ChallengeKind::ReceiptFork(
            ForkRelation::SameIndex,
        )))
}

fn full_reached(_: &ChallengeModel, state: &ChallengeState) -> bool {
    state.verdict
        == Some(Verdict::Fault(ChallengeKind::ReceiptFork(
            ForkRelation::Full,
        )))
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
            Property::sometimes("latest-send contradiction faults", latest_reached),
            Property::sometimes("higher-tip contradiction faults", higher_reached),
            Property::sometimes("receipt-range contradiction faults", range_reached),
            Property::sometimes("same-send fork faults", same_send_reached),
            Property::sometimes("same-index fork faults", same_index_reached),
            Property::sometimes("full-fallback fork faults", full_reached),
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
fn challenge_checker_exhausts_authentication_and_relation_classes() {
    let checker = ChallengeModel.checker().threads(1).spawn_bfs().join();
    assert!(checker.is_done());
    assert_eq!(checker.unique_state_count(), 15_788);
    checker.assert_properties();
}

#[test]
fn proven_challenges_are_opaque_adjudicated_target_tokens() {
    let expected = [
        ChallengeKind::LatestAcknowledgedSend,
        ChallengeKind::HigherShardTip,
        ChallengeKind::InconsistentReceiptRange,
        ChallengeKind::ReceiptFork(ForkRelation::SameSend),
        ChallengeKind::ReceiptFork(ForkRelation::SameIndex),
        ChallengeKind::ReceiptFork(ForkRelation::Full),
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
        evidence: Evidence::Latest {
            payment: Witness::valid(LATEST, Batch::B1),
            typed_opening: true,
        },
        expected: Verdict::Fault(ChallengeKind::LatestAcknowledgedSend),
        verdict: Some(Verdict::NoContradiction),
    };
    assert!(!adjudication_matches_case_oracle(
        &ChallengeModel,
        &oracle_control
    ));

    let contradiction_control = ChallengeState {
        target: Batch::B1,
        evidence: Evidence::Latest {
            payment: Witness::valid(PUBLIC_OUTGOING, Batch::B1),
            typed_opening: true,
        },
        expected: Verdict::Fault(ChallengeKind::LatestAcknowledgedSend),
        verdict: Some(Verdict::Fault(ChallengeKind::LatestAcknowledgedSend)),
    };
    assert!(!fault_implies_valid_contradiction(
        &ChallengeModel,
        &contradiction_control
    ));

    let invalid_control = ChallengeState {
        target: Batch::B1,
        evidence: Evidence::Latest {
            payment: Witness::valid(LATEST, Batch::B1),
            typed_opening: false,
        },
        expected: Verdict::Fault(ChallengeKind::LatestAcknowledgedSend),
        verdict: Some(Verdict::Fault(ChallengeKind::LatestAcknowledgedSend)),
    };
    assert!(!invalid_evidence_never_faults(
        &ChallengeModel,
        &invalid_control
    ));
}
