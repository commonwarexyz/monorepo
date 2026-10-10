//! Byte-driven exercise of the world model, the body of the `fuzz_machine` target.
//!
//! [`exercise`] reads its input by position, treating missing bytes as zero:
//!
//! | Bytes | Meaning |
//! |---|---|
//! | 0 | transaction blocks per chain, two through six |
//! | 1 to 5 | per-replica flags, bit `r` for replica `r`: proposal first, newest verification first, reversed votes, full Byzantine vote, reversed blocks |
//! | 6 | two bits of crash cut per replica |
//! | 7 | malformed completion offset |
//! | 8 to 10 | the prefix-crash selector |
//! | 8 onward | when present, up to 40 four-byte opcodes for [`World::apply_encoded`], applied to a separate world before the scenario runs |

use super::{
    Action, CompletionOrder, Fixture, MalformedCompletion, REPLICAS, ReplayPlan, ReplicaKnobs,
    Scenario, World, order,
};
use crate::{
    multimmit::{
        fuzz::ByteSchedule,
        machine::{
            capability::{Capability, ResolverCommand},
            testing::{
                driver::{CapabilityExt as _, Until},
                fixtures::BarrierCut,
            },
        },
    },
    types::View,
};
use std::array::from_fn;

impl World<'_> {
    /// Applies the action one four-byte opcode selects, if it is enabled.
    ///
    /// Byte 1 selects the replica (modulo the replica count), byte 2 the fixture artifact (modulo
    /// the artifact count) and the malformed completion, and the low bit of byte 3 the completion
    /// order (0 oldest, 1 newest). Byte 0 selects the action; an opcode whose precondition does not
    /// hold, or any other byte, applies nothing:
    ///
    /// | Byte 0 | Action | Enabled when |
    /// |---|---|---|
    /// | `p` | poll one work turn | the machine reported work |
    /// | `d` | deliver one artifact | the machine is live |
    /// | `D` | deliver two adjacent artifacts | the machine is live |
    /// | `q` | deliver one artifact twice | the machine is live |
    /// | `v` / `x` | complete a verification valid / invalid | a verification is pending |
    /// | `m` | submit a malformed verification completion | a suitable job is pending |
    /// | `s` | append and acknowledge a barrier | a barrier is pending |
    /// | `a` | append a barrier, then crash | a barrier is pending |
    /// | `c` | crash and restore | always |
    /// | `k` | acknowledge a barrier, then crash | a barrier is pending |
    /// | `t` / `T` | fire the view / production timer | the timer is armed |
    /// | `w` | wake the producer | the machine is live |
    /// | `b` / `B` | complete a build with a payload / empty | a build is pending |
    /// | `u` | complete custody | a custody request is pending |
    /// | `r` | complete a view-proof fetch | the fixture holds the requested proof |
    /// | `C` | drop a resolver cancel, reject, or prune | one is pending |
    /// | `g` / `G` | assemble a V-QC / L-QC | an aggregation is pending |
    /// | `i` / `I` | sign one request / a batch | a signing choice is released |
    /// | `l` / `o` | acknowledge a publication delivery | a publication is released |
    fn apply_encoded(&mut self, step: usize, encoded: [u8; 4]) {
        let replica = usize::from(encoded[1]) % REPLICAS;
        let order = if encoded[3] & 1 == 0 {
            CompletionOrder::Oldest
        } else {
            CompletionOrder::Newest
        };
        let artifact = usize::from(encoded[2]) % self.fixture.artifacts.len();
        let malformed = malformed_completion(encoded[2], replica);
        self.fuzz_coordinate = Some((step, encoded));

        let action = match encoded[0] {
            b'p' if self.replicas[replica].driver.poll_ready => Some(Action::Poll { replica }),
            b'd' if self.replicas[replica].driver.runner.inspect().is_live() => {
                Some(Action::Deliver { replica, artifact })
            }
            b'D' if self.replicas[replica].driver.runner.inspect().is_live() => Some(Action::DeliverPair {
                replica,
                artifacts: [artifact, (artifact + 1) % self.fixture.artifacts.len()],
            }),
            b'q' if self.replicas[replica].driver.runner.inspect().is_live() => Some(Action::DeliverPair {
                replica,
                artifacts: [artifact, artifact],
            }),
            b'v' if self.has(replica, Capability::is_verify) => Some(Action::Verify {
                replica,
                order,
                valid: true,
            }),
            b'x' if self.has(replica, Capability::is_verify) => Some(Action::Verify {
                replica,
                order,
                valid: false,
            }),
            b'm' if self.can_malformed(replica, malformed) => {
                Some(Action::MalformedVerify {
                    replica,
                    kind: malformed,
                })
            }
            b's' if self.has(replica, Capability::is_journal) => Some(Action::Persist { replica }),
            b'a' if self.has(replica, Capability::is_journal) => Some(Action::CrashAfterAppend { replica }),
            b'c' => Some(Action::CrashAndRestore { replica }),
            b'k' if self.has(replica, Capability::is_journal) => {
                self.apply(Action::Persist { replica });
                Some(Action::CrashAndRestore { replica })
            }
            b't' if self.replicas[replica].driver.view_timer.is_some() => {
                Some(Action::FireTimer { replica })
            }
            b'T' if self.replicas[replica].driver.production_timer.is_some() => {
                Some(Action::FireProductionTimer { replica })
            }
            b'w' if self.replicas[replica].driver.runner.inspect().is_live() => {
                Some(Action::ProducerWake { replica })
            }
            b'b' if self.has(replica, Capability::is_build) => Some(Action::Build {
                replica,
                empty: false,
            }),
            b'B' if self.has(replica, Capability::is_build) => Some(Action::Build {
                replica,
                empty: true,
            }),
            b'u' if self.has(replica, Capability::is_custody) => Some(Action::Custody { replica, order }),
            b'r'
                if self.replicas[replica].driver.pending.iter().any(|effect| {
                    matches!(effect, Capability::Resolver(ResolverCommand::Resolve(job)) if self.fixture.resolution(job.view()).is_some())
                }) =>
            {
                Some(Action::Resolve { replica })
            }
            b'C' if self.has(replica, Capability::is_resolver_control) => {
                Some(Action::HandleResolutionEffect { replica })
            }
            b'g' if self.has(replica, Capability::is_aggregate_vqc) => Some(Action::AggregateVqc { replica, order }),
            b'G' if self.has(replica, Capability::is_aggregate_lqc) => Some(Action::AggregateLqc { replica, order }),
            b'i' if self.has(replica, Capability::is_sign) => Some(Action::Sign { replica, order }),
            b'I' if self.has(replica, Capability::is_sign_batch) => {
                Some(Action::SignBatch { replica, order })
            }
            b'l' if self.has(replica, Capability::is_publish) => {
                Some(Action::AcknowledgeDelivery { replica })
            }
            b'o' if self.has(replica, Capability::is_publish) => {
                Some(Action::AcknowledgeDelivery { replica })
            }
            _ => None,
        };
        if let Some(action) = action {
            self.apply(action);
        }
        self.fuzz_coordinate = None;
    }
}

/// Decodes `replica`'s crash cut from two bits of `bits`.
pub(super) const fn crash_cut(bits: u8, replica: usize) -> Option<BarrierCut> {
    match (bits >> (replica * 2)) & 0b11 {
        0 => None,
        1 => Some(BarrierCut::BeforeAppend),
        2 => Some(BarrierCut::AfterAppend),
        _ => Some(BarrierCut::AfterAck),
    }
}

/// Decodes `replica`'s malformed verification completion from `bits`.
pub(super) fn malformed_completion(bits: u8, replica: usize) -> MalformedCompletion {
    const CASES: [MalformedCompletion; 7] = [
        MalformedCompletion::StaleGeneration,
        MalformedCompletion::MissingVerdict,
        MalformedCompletion::DuplicateVerdict,
        MalformedCompletion::ForeignTicket,
        MalformedCompletion::ReorderedVerdicts,
        MalformedCompletion::WrongArtifact,
        MalformedCompletion::WrongObservation,
    ];
    CASES[usize::from(bits.wrapping_add(replica as u8)) % CASES.len()]
}

/// Decodes `replica`'s flag from one bit of `bits`.
const fn flag(bits: u8, replica: usize) -> bool {
    bits & (1 << replica) != 0
}

pub(super) fn exercise_prefix_crash(fixture: &Fixture, plan: &ReplayPlan, selector: [u8; 3]) {
    let boundaries = plan
        .actions
        .iter()
        .enumerate()
        .filter(|(_, action)| match selector[0] % 5 {
            0 => matches!(action, Action::Custody { .. }),
            1 => matches!(action, Action::Sign { .. } | Action::SignBatch { .. }),
            2 => matches!(action, Action::Persist { .. }),
            3 => matches!(action, Action::AcknowledgeDelivery { .. }),
            _ => matches!(
                action,
                Action::AggregateVqc { .. } | Action::AggregateLqc { .. }
            ),
        })
        .collect::<Vec<_>>();
    assert!(
        !boundaries.is_empty(),
        "scenario must reach each boundary family"
    );
    let (index, action) = boundaries[usize::from(selector[1]) % boundaries.len()];
    let replica = action.replica().unwrap();
    let cut = index + usize::from(selector[2] & 1 != 0);
    let mut world = World::replay(fixture, &plan.actions[..cut]);
    let order = order(selector[2] & 2 != 0);
    let crash = if selector[2] & 4 != 0 && world.has(replica, Capability::is_journal) {
        Action::CrashAfterAppend { replica }
    } else {
        Action::CrashAndRestore { replica }
    };
    world.apply(crash);
    world.drive(replica, Until::Quiesce, order, order, true);

    // Network retries carry artifacts, while completions belong to their original generation.
    for action in &plan.actions {
        if action.replica() == Some(replica)
            && matches!(action, Action::Deliver { .. } | Action::DeliverPair { .. })
        {
            world.apply(action.clone());
            world.drive(replica, Until::Quiesce, order, order, true);
        }
    }
    world.assert_locally_drained(replica);
    assert!(world.replicas[replica].driver.runner.inspect().view() >= View::new(3));
    assert!(
        world.replicas[replica]
            .driver
            .runner
            .inspect()
            .finality()
            .len()
            >= 2
    );
    world.apply(Action::CrashAndRestore { replica });
    world.drive(replica, Until::Quiesce, order, order, true);
    world.assert_locally_drained(replica);

    let replayed = World::replay(fixture, &world.actions);
    assert_eq!(replayed.durable_outcome(), world.durable_outcome());
}

/// Runs one byte-selected schedule and checks that replay reproduces its durable outcome.
///
/// The module documentation maps input positions to schedule choices, and
/// [`World::apply_encoded`] documents the four-byte opcodes. The same interpreter backs the
/// generated unit property and the cargo-fuzz entry point. Every applied opcode checks
/// journal-prefix replay, finality state, publication oracles, signature exposure, and production
/// resource ceilings. The historical schedule then checks convergence.
pub(crate) fn exercise(input: &[u8]) {
    let header: [u8; 11] = ByteSchedule::padded(input).take();
    let blocks = usize::from(header[0] % 5) + 2;
    if input.len() > 8 {
        let structured_fixture = Fixture::new(blocks);
        let mut structured = World::new(&structured_fixture);
        for replica in 0..REPLICAS {
            structured.apply(Action::Start { replica });
            structured.drive(
                replica,
                Until::Quiesce,
                CompletionOrder::Oldest,
                CompletionOrder::Oldest,
                false,
            );
        }
        let mut opcodes = ByteSchedule::padded(&input[8..]);
        for step in 0..(input.len() - 8).div_ceil(4).min(40) {
            structured.apply_encoded(step, opcodes.take());
        }
    }
    let (plan, durable) = Scenario::new(
        blocks,
        from_fn(|replica| ReplicaKnobs {
            proposal_first: flag(header[1], replica),
            newest_verification: flag(header[2], replica),
            reverse_votes: flag(header[3], replica),
            byzantine_full: flag(header[4], replica),
            reverse_blocks: flag(header[5], replica),
            malformed: malformed_completion(header[7], replica),
            crash: crash_cut(header[6], replica),
        }),
    )
    .run();
    let replay_fixture = Fixture::new(plan.blocks);
    let replayed = World::replay(&replay_fixture, &plan.actions);
    for replica in 0..REPLICAS {
        replayed.assert_locally_drained(replica);
    }
    assert_eq!(replayed.durable_outcome(), durable);
    exercise_prefix_crash(&replay_fixture, &plan, [header[8], header[9], header[10]]);
}
