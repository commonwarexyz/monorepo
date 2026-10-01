use stateright::{Checker, Model, Property};

// One payer, two payment intents, and four epochs. Three cut epochs can await admission while
// the fourth takes payments. A body's vector and predecessor are intent sets: the vector names
// the intents its epoch-cumulative vector carries, and the predecessor names the intents of the
// terminal vector it signed for the preceding epoch. The empty set is the empty vector root.
const EPOCHS: usize = 4;
// Vectors strictly grow within an epoch, so two intents allow at most two bodies per epoch.
const BODIES: usize = 2;
const EMPTY: u8 = 0;
const X: u8 = 0b01;
const Z: u8 = 0b10;
const INTENTS: [u8; 2] = [X, Z];
const ADDITIONS: [u8; 3] = [X, Z, X | Z];
const PROPERTY: &str = "each intent is carried at most once";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Body {
    vector: u8,
    predecessor: u8,
    receipted: bool,
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct LineageState {
    // Epochs below `live` are cut. `EPOCHS` means every epoch is cut.
    live: usize,
    // Epochs below `admitted` are admitted in FIFO order.
    admitted: usize,
    bodies: [[Option<Body>; BODIES]; EPOCHS],
    // The first usable Stale report per epoch: how many bodies lie at or below its endpoint.
    reports: [Option<usize>; EPOCHS],
    // The body each admitted epoch carried, if any.
    terminals: [Option<usize>; EPOCHS],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum LineageAction {
    // The wallet signs its next live-epoch body, adding these intents.
    Sign(u8),
    // The operator receipts a live-epoch body.
    Receipt(usize),
    // The operator answers a resubmitted body of a cut epoch with the endpoint of that epoch. A
    // silent operator takes no action.
    Stale { epoch: usize, endpoint: usize },
    // The operator cuts the live epoch.
    Cut,
    // Validators admit the oldest cut epoch carrying this body, or no terminal.
    Admit(Option<usize>),
}

// The rule a variant applies. Only `Specified` must satisfy the property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Variant {
    // The specified wallet lineage rule and validator predecessor check.
    Specified,
    // The wallet re-signs whenever the previous endpoint excludes the payment.
    Eager,
    // The wallet also re-signs whenever the previous endpoint is nonempty.
    Nonempty,
    // Validators accept a body whatever predecessor it signed.
    Unbound,
}

pub(crate) struct LineageModel {
    variant: Variant,
}

impl LineageModel {
    pub(crate) const fn new(variant: Variant) -> Self {
        Self { variant }
    }

    fn bodies(state: &LineageState, epoch: usize) -> impl Iterator<Item = (usize, Body)> + '_ {
        state.bodies[epoch]
            .iter()
            .enumerate()
            .filter_map(|(index, body)| body.map(|body| (index, body)))
    }

    fn count(state: &LineageState, epoch: usize) -> usize {
        Self::bodies(state, epoch).count()
    }

    fn vector(state: &LineageState, epoch: usize, body: Option<usize>) -> u8 {
        body.and_then(|index| state.bodies[epoch][index])
            .map_or(EMPTY, |body| body.vector)
    }

    // The root an admitted predecessor fixes for bodies of `epoch`. Epoch zero has no
    // predecessor close.
    fn fixed(state: &LineageState, epoch: usize) -> Option<u8> {
        if epoch == 0 {
            Some(EMPTY)
        } else if epoch - 1 < state.admitted {
            Some(Self::vector(state, epoch - 1, state.terminals[epoch - 1]))
        } else {
            None
        }
    }

    // A body is dead once its predecessor epoch is admitted with another terminal root.
    fn dead(state: &LineageState, epoch: usize, body: Body) -> bool {
        Self::fixed(state, epoch).is_some_and(|root| root != body.predecessor)
    }

    fn decided(state: &LineageState, epoch: usize, body: Body) -> bool {
        epoch < state.admitted || Self::dead(state, epoch, body)
    }

    // The terminal vector the wallet knows for a cut epoch: the admitted terminal, the first
    // usable report, or its highest receipted live body once no body is undecided.
    fn endpoint(state: &LineageState, epoch: usize) -> Option<u8> {
        if epoch < state.admitted {
            return Some(Self::vector(state, epoch, state.terminals[epoch]));
        }
        if let Some(count) = state.reports[epoch] {
            return Some(Self::vector(state, epoch, count.checked_sub(1)));
        }
        let mut endpoint = EMPTY;
        for (_, body) in Self::bodies(state, epoch) {
            if Self::dead(state, epoch, body) {
                continue;
            }
            if !body.receipted {
                return None;
            }
            endpoint = body.vector;
        }
        Some(endpoint)
    }

    // The predecessor the wallet binds in the live epoch, when it knows one.
    fn bound(state: &LineageState) -> Option<u8> {
        if state.live == 0 {
            return Some(EMPTY);
        }
        Self::endpoint(state, state.live - 1)
    }

    fn settled(state: &LineageState, intent: u8) -> bool {
        (0..state.admitted)
            .any(|epoch| Self::vector(state, epoch, state.terminals[epoch]) & intent != 0)
    }

    // Whether the wallet may add `intent` to a body of `live` bound to the predecessor `bound`.
    fn signable(&self, state: &LineageState, intent: u8, live: usize, bound: u8) -> bool {
        let Some(latest) = (0..live)
            .rev()
            .find(|epoch| Self::bodies(state, *epoch).any(|(_, body)| body.vector & intent != 0))
        else {
            return true;
        };
        if Self::settled(state, intent) {
            return false;
        }

        // The latest epoch that signed the intent must have excluded it.
        let excluded = if Self::bodies(state, latest)
            .filter(|(_, body)| body.vector & intent != 0)
            .all(|(_, body)| Self::dead(state, latest, body))
        {
            true
        } else {
            Self::endpoint(state, latest).is_some_and(|endpoint| endpoint & intent == 0)
        };
        if !excluded {
            return false;
        }

        // Every other body carrying the intent outside the preceding epoch must be decided.
        let lineage = (0..live).filter(|epoch| *epoch + 1 != live).all(|epoch| {
            Self::bodies(state, epoch)
                .filter(|(_, body)| body.vector & intent != 0)
                .all(|(_, body)| Self::decided(state, epoch, body))
        });
        match self.variant {
            Variant::Specified | Variant::Unbound => lineage,
            Variant::Eager => true,
            Variant::Nonempty => bound != EMPTY || lineage,
        }
    }

    fn sign(&self, state: &LineageState, add: u8) -> Option<LineageState> {
        let live = state.live;
        if live == EPOCHS || !ADDITIONS.contains(&add) {
            return None;
        }
        let bodies = Self::bodies(state, live).collect::<Vec<_>>();
        let (vector, predecessor) = match bodies.last() {
            // Every body of an epoch binds the predecessor of its first body, and the wallet signs
            // nothing more there once they are dead.
            Some((_, last)) => {
                if Self::dead(state, live, *last) || last.vector & add != 0 {
                    return None;
                }
                (last.vector | add, last.predecessor)
            }
            None => (add, Self::bound(state)?),
        };
        if !INTENTS
            .into_iter()
            .filter(|intent| add & intent != 0)
            .all(|intent| self.signable(state, intent, live, predecessor))
        {
            return None;
        }
        let mut next = state.clone();
        next.bodies[live][bodies.len()] = Some(Body {
            vector,
            predecessor,
            receipted: false,
        });
        Some(next)
    }

    fn receipt(state: &LineageState, index: usize) -> Option<LineageState> {
        let live = state.live;
        let body = state.bodies.get(live)?.get(index).copied().flatten()?;
        if body.receipted {
            return None;
        }
        let mut next = state.clone();
        next.bodies[live][index] = Some(Body {
            receipted: true,
            ..body
        });
        Some(next)
    }

    // A usable report is empty only while the wallet holds no receipt in that epoch. Otherwise
    // it names a body at or above every receipt, whose receipt the wallet fetches.
    fn stale(state: &LineageState, epoch: usize, endpoint: usize) -> Option<LineageState> {
        if epoch >= state.live || epoch < state.admitted || state.reports[epoch].is_some() {
            return None;
        }
        let bodies = Self::bodies(state, epoch).collect::<Vec<_>>();
        if bodies.iter().all(|(_, body)| body.receipted) {
            return None;
        }
        let receipted = bodies
            .iter()
            .rposition(|(_, body)| body.receipted)
            .map_or(0, |index| index + 1);
        if endpoint > bodies.len() || endpoint < receipted {
            return None;
        }
        let mut next = state.clone();
        next.reports[epoch] = Some(endpoint);
        if let Some(index) = endpoint.checked_sub(1) {
            let body = bodies[index].1;
            next.bodies[epoch][index] = Some(Body {
                receipted: true,
                ..body
            });
        }
        Some(next)
    }

    // Validators check a body against the terminal root of the admitted predecessor.
    fn admit(&self, state: &LineageState, terminal: Option<usize>) -> Option<LineageState> {
        let epoch = state.admitted;
        if epoch >= state.live {
            return None;
        }
        if let Some(index) = terminal {
            let body = state.bodies[epoch].get(index).copied().flatten()?;
            let root = Self::fixed(state, epoch).expect("the predecessor epoch is admitted");
            if self.variant != Variant::Unbound && body.predecessor != root {
                return None;
            }
        }
        let mut next = state.clone();
        next.terminals[epoch] = terminal;
        next.admitted += 1;
        Some(next)
    }
}

impl Model for LineageModel {
    type State = LineageState;
    type Action = LineageAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![LineageState::default()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        for add in ADDITIONS {
            actions.push(LineageAction::Sign(add));
        }
        for index in 0..BODIES {
            actions.push(LineageAction::Receipt(index));
        }
        for epoch in state.admitted..state.live {
            for endpoint in 0..=Self::count(state, epoch) {
                actions.push(LineageAction::Stale { epoch, endpoint });
            }
        }
        if state.live < EPOCHS {
            actions.push(LineageAction::Cut);
        }
        if state.admitted < state.live {
            actions.push(LineageAction::Admit(None));
            for index in 0..Self::count(state, state.admitted) {
                actions.push(LineageAction::Admit(Some(index)));
            }
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            LineageAction::Sign(add) => self.sign(last, add),
            LineageAction::Receipt(index) => Self::receipt(last, index),
            LineageAction::Stale { epoch, endpoint } => Self::stale(last, epoch, endpoint),
            LineageAction::Cut => {
                let mut next = last.clone();
                next.live += 1;
                Some(next)
            }
            LineageAction::Admit(terminal) => self.admit(last, terminal),
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(PROPERTY, carried_once),
            Property::sometimes(
                "three cut epochs await admission while a fourth takes payments",
                three_open,
            ),
            Property::sometimes(
                "a payment settles in an epoch after its first signature",
                resign_settles,
            ),
            Property::sometimes(
                "a payment settles two epochs after its first signature",
                late_resign_settles,
            ),
            Property::sometimes(
                "an admitted terminal kills a body bound to a reported endpoint",
                report_contradicted,
            ),
        ]
    }
}

fn carried(state: &LineageState, intent: u8) -> usize {
    (0..state.admitted)
        .filter(|epoch| LineageModel::vector(state, *epoch, state.terminals[*epoch]) & intent != 0)
        .count()
}

fn carried_once(_: &LineageModel, state: &LineageState) -> bool {
    INTENTS
        .into_iter()
        .all(|intent| carried(state, intent) <= 1)
}

const fn three_open(_: &LineageModel, state: &LineageState) -> bool {
    state.live < EPOCHS && state.live >= state.admitted + 3
}

// The first epoch that signed `intent`, and the epoch that carried it.
fn span(state: &LineageState, intent: u8) -> Option<(usize, usize)> {
    let first = (0..EPOCHS).find(|epoch| {
        LineageModel::bodies(state, *epoch).any(|(_, body)| body.vector & intent != 0)
    })?;
    let settled = (0..state.admitted)
        .find(|epoch| LineageModel::vector(state, *epoch, state.terminals[*epoch]) & intent != 0)?;
    Some((first, settled))
}

fn resign_settles(_: &LineageModel, state: &LineageState) -> bool {
    INTENTS
        .into_iter()
        .any(|intent| span(state, intent).is_some_and(|(first, settled)| settled > first))
}

fn late_resign_settles(_: &LineageModel, state: &LineageState) -> bool {
    INTENTS
        .into_iter()
        .any(|intent| span(state, intent).is_some_and(|(first, settled)| settled >= first + 2))
}

fn report_contradicted(_: &LineageModel, state: &LineageState) -> bool {
    (1..EPOCHS).any(|epoch| {
        let Some(count) = state.reports[epoch - 1] else {
            return false;
        };
        let reported = LineageModel::vector(state, epoch - 1, count.checked_sub(1));
        LineageModel::bodies(state, epoch)
            .any(|(_, body)| body.predecessor == reported && LineageModel::dead(state, epoch, body))
    })
}

#[cfg(not(test))]
pub(crate) fn explore(address: &str) {
    LineageModel::new(Variant::Specified)
        .checker()
        .threads(1)
        .serve(address);
}

/// Exhausts the specified wallet and validator rules and checks that each intent settles at
/// most once.
#[test]
fn lineage_checker_carries_each_intent_at_most_once() {
    let checker = LineageModel::new(Variant::Specified)
        .checker()
        .threads(4)
        .spawn_bfs()
        .join();
    assert!(checker.is_done());
    checker.assert_properties();
    assert_eq!(checker.unique_state_count(), 4_606_033);
}

/// Without the lineage rule, the wallet re-signs a payment into `e+2` against the empty
/// endpoint of `e+1` while its original is still undecided in `e`. The operator carries the
/// original in `e`, so the `e+1` re-sign dies and the `e+2` re-sign settles a second time.
#[test]
fn eager_resign_settles_twice() {
    let checker = LineageModel::new(Variant::Eager)
        .checker()
        .threads(4)
        .spawn_bfs()
        .join();
    checker.assert_discovery(
        PROPERTY,
        vec![
            // Epoch 0: the original goes unanswered, and the report after the cut is empty.
            LineageAction::Sign(X),
            LineageAction::Cut,
            LineageAction::Stale {
                epoch: 0,
                endpoint: 0,
            },
            // Epoch 1: the first re-sign goes unanswered, and its report is empty too.
            LineageAction::Sign(X),
            LineageAction::Cut,
            LineageAction::Stale {
                epoch: 1,
                endpoint: 0,
            },
            // Epoch 2: the second re-sign binds the empty endpoint of epoch 1.
            LineageAction::Sign(X),
            LineageAction::Cut,
            // Admission carries the original, rejects the first re-sign, and carries the second.
            LineageAction::Admit(Some(0)),
            LineageAction::Admit(None),
            LineageAction::Admit(Some(0)),
        ],
    );
}

/// Keying the rule on an empty preceding endpoint also fails. A fresh payment accepted in `e+2`
/// makes its endpoint nonempty, but that payment binds the empty endpoint of `e+1` and pins
/// nothing in `e`, so a re-sign into `e+3` settles a second time.
#[test]
fn nonempty_endpoint_resign_settles_twice() {
    let checker = LineageModel::new(Variant::Nonempty)
        .checker()
        .threads(4)
        .spawn_bfs()
        .join();
    checker.assert_discovery(
        PROPERTY,
        vec![
            // Epochs 0 and 1: the original and its first re-sign both see empty reports.
            LineageAction::Sign(X),
            LineageAction::Cut,
            LineageAction::Stale {
                epoch: 0,
                endpoint: 0,
            },
            LineageAction::Sign(X),
            LineageAction::Cut,
            LineageAction::Stale {
                epoch: 1,
                endpoint: 0,
            },
            // Epoch 2: a fresh payment is receipted, which makes its endpoint nonempty.
            LineageAction::Sign(Z),
            LineageAction::Receipt(0),
            LineageAction::Cut,
            // Epoch 3: the re-sign binds the fresh payment's root.
            LineageAction::Sign(X),
            LineageAction::Cut,
            // Admission carries the original, rejects the first re-sign, and carries both
            // bodies that bind the empty endpoint of epoch 1.
            LineageAction::Admit(Some(0)),
            LineageAction::Admit(None),
            LineageAction::Admit(Some(0)),
            LineageAction::Admit(Some(0)),
        ],
    );
}

/// Without the validator predecessor check, a re-sign into `e+1` against a report that excludes
/// the original settles beside the original that `e` carries.
#[test]
fn unbound_resign_settles_twice() {
    let checker = LineageModel::new(Variant::Unbound)
        .checker()
        .threads(4)
        .spawn_bfs()
        .join();
    checker.assert_discovery(
        PROPERTY,
        vec![
            // Epoch 0: the operator reports an empty endpoint after the cut.
            LineageAction::Sign(X),
            LineageAction::Cut,
            LineageAction::Stale {
                epoch: 0,
                endpoint: 0,
            },
            // Epoch 1: the re-sign binds that report.
            LineageAction::Sign(X),
            LineageAction::Cut,
            // Admission carries both the original and the re-sign.
            LineageAction::Admit(Some(0)),
            LineageAction::Admit(Some(0)),
        ],
    );
}

/// The at-most-once property fails on a state that carries one intent in two epochs and holds
/// once the second carry is removed.
#[test]
fn lineage_invariant_has_a_direct_negative_control() {
    // Epochs 0 and 1 both admit a terminal carrying intent `X`, the second bound to the first.
    let body = Body {
        vector: X,
        predecessor: EMPTY,
        receipted: false,
    };
    let mut twice = LineageState {
        live: 2,
        admitted: 2,
        ..LineageState::default()
    };
    twice.bodies[0][0] = Some(body);
    twice.bodies[1][0] = Some(Body {
        predecessor: X,
        ..body
    });
    twice.terminals = [Some(0), Some(0), None, None];
    let model = LineageModel::new(Variant::Specified);
    assert!(!carried_once(&model, &twice));

    // Dropping the epoch-1 terminal leaves a single carry, which satisfies the property.
    twice.terminals[1] = None;
    assert!(carried_once(&model, &twice));
}
