//! The Mallory backend's stable fault catalog, per-step legal mask, and the
//! concrete [`FaultPlan`] the runner enacts.
//!
//! The Q-core is fault-agnostic (it sees only numeric ids); this catalog is the
//! Mallory binding of those ids to concrete adversarial faults. Selection is
//! split in two: [`Fault::sample`] draws a fault's concrete parameters from
//! the runtime RNG synchronously and returns a [`FaultPlan`], and the runner then
//! enacts that plan against the network asynchronously. Later PRs append packet,
//! lifecycle, and adversary-profile faults to the END of [`CATALOG`].

use crate::{
    mallory::{adversary::AdversaryRole, policy::ActionId},
    utils::SetPartition,
    SniffChannel,
};
use rand::{Rng, RngExt as _};
use std::time::Duration;

/// The `n = 4` set partitions (indices into [`SetPartition::N4`]) that split the
/// validators two-against-two: `{{0,1},{2,3}}`, `{{0,2},{1,3}}`, `{{0,3},{1,2}}`.
/// None contains a singleton, so neither side reaches the N4F0C4 quorum of three
/// during the window -- all progress stalls until the partition heals.
const PARTITION_2_2: [usize; 3] = [5, 6, 7];

/// Mallory fixes `n = 4` honest validators (see [`crate::mallory`]); a packet
/// fault may target any of them, since all four run honest engines behind a pump.
const MALLORY_N: usize = 4;
/// Sampled packet-delay bounds (ms): a sub-window per-packet slowdown, so delayed
/// packets still arrive within the observation window and the channel recovers as
/// soon as the fault heals.
const PACKET_DELAY_MS_MIN: u64 = 10;
const PACKET_DELAY_MS_MAX: u64 = 250;
/// Sampled packet-loss bounds: a small count so a run still completes -- Simplex
/// backfills the gap once the fault heals.
const PACKET_LOSS_MIN: u32 = 1;
const PACKET_LOSS_MAX: u32 = 8;
/// Sampled packet-corrupt bounds: how many of the next matching packets are byte-
/// mutated. Bounded like loss (a corrupted message fails to decode, so it acts as
/// an effective loss) so backfill still recovers and a run completes.
const PACKET_CORRUPT_MIN: u32 = 1;
const PACKET_CORRUPT_MAX: u32 = 6;
/// The corrupt XOR is applied at `offset % len`; a small offset (exclusive upper
/// bound) biases the mutation toward a message's header bytes, so it is more
/// likely to break the structural decode and drop the message from HB.
const PACKET_CORRUPT_OFFSET_MAX: u16 = 8;
/// The corrupt XOR mask is nonzero so the byte always changes.
const PACKET_CORRUPT_MASK_MIN: u8 = 1;
const PACKET_CORRUPT_MASK_MAX: u8 = 255;
/// Sampled packet-duplicate bounds: extra identical copies per matching packet,
/// hard-bounded so the internal FIFO cannot blow up.
const PACKET_DUPLICATE_MIN: u32 = 1;
const PACKET_DUPLICATE_MAX: u32 = 3;
/// Sampled packet-reorder bounds: the per-pump reorder-buffer capacity, hard-
/// bounded so held memory (and the reorder distance) stays small.
const PACKET_REORDER_MIN: u32 = 2;
const PACKET_REORDER_MAX: u32 = 8;

/// The adversarial fault the policy chooses per step.
///
/// # Stable catalog order (contract)
///
/// [`CATALOG`] fixes each fault's [`ActionId`]: index `i` has id `i`. That order
/// is the contract between the runner's `select` and its enactment, and it is the
/// column layout of a Q-table persisted across the whole libFuzzer campaign, so
/// it MUST NOT change. New faults are APPENDED after the last existing entry;
/// existing ids never move (so a growing catalog reuses a warm Q-table). PR4a:
/// - `NoFault = 0`
/// - `IsolateNodeWindow = 1`
/// - `PartitionWindow = 2`
/// - `PacketDelay = 3`
/// - `PacketLoss = 4`
///
/// PR4b appends the remaining packet faults on the same pump:
/// - `PacketCorrupt = 5`
/// - `PacketDuplicate = 6`
/// - `PacketReorder = 7`
///
/// PR5 appends the managed-validator lifecycle faults, both targeting the single
/// faultable identity ([`crate::BYZANTINE_IDX`]):
/// - `CrashStop = 8`
/// - `CrashRestartDurable = 9`
///
/// PR7a appends the third lifecycle fault on the same faultable identity:
/// - `AmnesiaRestart = 10`
///
/// PR8 appends the mid-episode Byzantine role switch, legal only in a byzantine
/// episode (see [`legal_mask`]):
/// - `SetRole = 11`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// `NoFault` deliberately ends with the enum name: it is the RL "no-op fault" choice.
#[allow(clippy::enum_variant_names)]
pub(crate) enum Fault {
    /// Enact nothing and heal nothing for this step.
    NoFault,
    /// Isolate the single faultable identity ([`crate::BYZANTINE_IDX`]) from the
    /// other three validators for one window (`{{0},{1,2,3}}`).
    IsolateNodeWindow,
    /// Split the validators into a balanced 2-2 partition for one window; no side
    /// holds a quorum, so all progress stalls until the window heals.
    PartitionWindow,
    /// Slow one honest node's one channel by a per-packet delay for the window: a
    /// coarse, in-order channel slowdown applied by the packet-fault pump.
    PacketDelay,
    /// Drop a small, bounded number of packets on one honest node's one channel
    /// for the window; the dropped packets never reach the engine or the
    /// happens-before log.
    PacketLoss,
    /// Corrupt the raw wire bytes of a small, bounded number of packets on one
    /// honest node's one channel WITHOUT re-signing; each corrupted message fails
    /// to decode, so it is dropped from the happens-before log and rejected by the
    /// engine (an effective loss that exercises the decode-rejection path).
    PacketCorrupt,
    /// Duplicate each packet on one honest node's one channel with a hard-bounded
    /// number of extra identical copies for the window; the engine's idempotent
    /// vote handling tolerates them.
    PacketDuplicate,
    /// Reorder one honest node's one channel through a hard-bounded per-pump
    /// reorder buffer for the window; the buffer is drained in order when the
    /// fault heals, so no packet is lost.
    PacketReorder,
    /// Crash-stop the single faultable identity ([`crate::BYZANTINE_IDX`]): abort
    /// its engine and application tasks so they can never send again. PERMANENT but
    /// NOT terminal. Node 0 stays down for the rest of the episode while Mallory keeps
    /// perturbing the surviving quorum (nodes 1-3). The crashed node is dropped from
    /// the reactive finalization set and the liveness watch, but its retained reporter
    /// (pre-crash history) stays in the safety set.
    CrashStop,
    /// Crash then durably restart the single faultable identity on its EXISTING
    /// storage partition: the node loses volatile state, replays its journal, and
    /// catches up via resolver backfill from the quorum. Not terminal.
    CrashRestartDurable,
    /// Crash then restart the single faultable identity on a FRESH (empty) storage
    /// partition: the node forgets its durable state (including signed votes), so it
    /// may equivocate (double-vote a view it already signed) -- disk-loss /
    /// Byzantine amnesia. Counts as BYZANTINE: the node runs but is excluded from the
    /// honest safety and liveness sets for the rest of the episode. Not terminal.
    AmnesiaRestart,
    /// Swap node 0's active Byzantine profile mid-episode to another of the six
    /// Byzantine roles (see [`AdversaryRole`]). Legal ONLY in a byzantine episode
    /// (node 0 is the adversary multiplexer) and only until the per-episode switch
    /// cap ([`MALLORY_MAX_ROLE_SWITCHES`]) is reached. Persists (not a heal-able
    /// transient): the new profile keys the role region of the Q-state for the
    /// remaining steps, so the learner can compose faults across views. Not
    /// terminal.
    SetRole,
}

/// Actions in [`ActionId`] order: index `i` has id `i`. Appended-to, never
/// reordered (see [`Fault`]).
pub(crate) const CATALOG: &[Fault] = &[
    Fault::NoFault,
    Fault::IsolateNodeWindow,
    Fault::PartitionWindow,
    Fault::PacketDelay,
    Fault::PacketLoss,
    Fault::PacketCorrupt,
    Fault::PacketDuplicate,
    Fault::PacketReorder,
    Fault::CrashStop,
    Fault::CrashRestartDurable,
    Fault::AmnesiaRestart,
    Fault::SetRole,
];

/// Number of Mallory faults (the Q-table's column count).
pub(crate) const N_FAULTS: usize = CATALOG.len();

/// Maximum [`Fault::SetRole`] role switches per byzantine episode. Bounds how many
/// times node 0's Byzantine profile can be swapped so an episode composes a small
/// number of faults across views rather than thrashing the multiplexer.
pub(crate) const MALLORY_MAX_ROLE_SWITCHES: u32 = 3;

/// A concrete, enactable fault: the result of sampling an [`Fault`]'s
/// parameters. A topology fault (`IsolateByzantine`, `Partition`) is installed
/// via [`crate::mallory::network::Topology`]; a packet fault (`PacketDelay`,
/// `PacketLoss`, `PacketCorrupt`, `PacketDuplicate`, `PacketReorder`) is installed
/// by [`set`](crate::mallory::network::PacketFaultCell::set)ting the shared
/// packet-fault cell the pumps read. The runner heals every active fault at the
/// window's end (a reorder fault is additionally flushed so its held buffer
/// drains in order). `apply_partition` either installs a topology plan
/// or panics on an oracle error, so reaching the observation window is itself the
/// enactment acknowledgement -- a fault that fails to install is a wiring bug,
/// not a silently-skipped step.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FaultPlan {
    /// No perturbation this step.
    None,
    /// Isolate [`crate::BYZANTINE_IDX`] from the other three validators.
    IsolateByzantine,
    /// Apply this set partition (Mallory only ever samples a 2-2 split).
    Partition(SetPartition),
    /// Slow one honest node's one channel by `per_packet` for the window.
    PacketDelay {
        node: usize,
        channel: SniffChannel,
        per_packet: Duration,
    },
    /// Drop the next `drop_count` packets on one honest node's one channel.
    PacketLoss {
        node: usize,
        channel: SniffChannel,
        drop_count: u32,
    },
    /// Corrupt the next `count` packets on one honest node's one channel by XOR-ing
    /// `mask` into the byte at `offset % len` (no re-sign).
    PacketCorrupt {
        node: usize,
        channel: SniffChannel,
        count: u32,
        offset: u16,
        mask: u8,
    },
    /// Duplicate each packet on one honest node's one channel with `extra`
    /// additional identical copies.
    PacketDuplicate {
        node: usize,
        channel: SniffChannel,
        extra: u32,
    },
    /// Reorder one honest node's one channel through a per-pump reorder buffer of
    /// capacity `buffer`.
    PacketReorder {
        node: usize,
        channel: SniffChannel,
        buffer: u32,
    },
    /// Crash-stop [`crate::BYZANTINE_IDX`] (fixed target, no parameters). Enacted
    /// against the managed validator, not the network.
    CrashStop,
    /// Crash and durably restart [`crate::BYZANTINE_IDX`] (fixed target, no
    /// parameters). Enacted against the managed validator, not the network.
    CrashRestartDurable,
    /// Crash and restart [`crate::BYZANTINE_IDX`] on a FRESH (empty) storage
    /// partition (fixed target, no parameters). Enacted against the managed
    /// validator, not the network; marks the node Byzantine for the rest of the
    /// episode.
    AmnesiaRestart,
    /// Swap node 0's active Byzantine profile to this target role. Enacted against
    /// the [`RoleMultiplexer`](crate::mallory::multiplexer::RoleMultiplexer), not the
    /// network; the target is always Byzantine (never Honest).
    SetRole(AdversaryRole),
}

impl FaultPlan {
    /// A log-ready description of this plan's concrete parameters.
    pub(crate) fn describe(&self) -> String {
        match self {
            FaultPlan::None => "none".to_string(),
            FaultPlan::IsolateByzantine => "isolate(node=0)".to_string(),
            FaultPlan::Partition(sp) => format!("partition({sp:?})"),
            FaultPlan::PacketDelay {
                node,
                channel,
                per_packet,
            } => format!("packet_delay(node={node}, channel={channel:?}, per_packet={per_packet:?})"),
            FaultPlan::PacketLoss {
                node,
                channel,
                drop_count,
            } => format!("packet_loss(node={node}, channel={channel:?}, drop_count={drop_count})"),
            FaultPlan::PacketCorrupt {
                node,
                channel,
                count,
                offset,
                mask,
            } => format!(
                "packet_corrupt(node={node}, channel={channel:?}, count={count}, offset={offset}, mask={mask:#04x})"
            ),
            FaultPlan::PacketDuplicate {
                node,
                channel,
                extra,
            } => format!("packet_duplicate(node={node}, channel={channel:?}, extra={extra})"),
            FaultPlan::PacketReorder {
                node,
                channel,
                buffer,
            } => format!("packet_reorder(node={node}, channel={channel:?}, buffer={buffer})"),
            FaultPlan::CrashStop => "crash_stop(node=0)".to_string(),
            FaultPlan::CrashRestartDurable => "crash_restart_durable(node=0)".to_string(),
            FaultPlan::AmnesiaRestart => "amnesia_restart(node=0)".to_string(),
            FaultPlan::SetRole(role) => format!("set_role(node=0, target={})", role.label()),
        }
    }

    /// Whether this plan installs a transient network/packet fault. The lifecycle
    /// faults ([`FaultPlan::CrashStop`], [`FaultPlan::CrashRestartDurable`],
    /// [`FaultPlan::AmnesiaRestart`]) and the role switch ([`FaultPlan::SetRole`]) are
    /// NOT such faults -- they are enacted against the managed validator or the
    /// multiplexer, not the network, and the role switch persists rather than being
    /// healed. Test-only: the runner classifies each plan directly via its heal-match
    /// arms and its `Enactment` accounting, so this survives only as a catalog-property
    /// assertion.
    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        !matches!(
            self,
            FaultPlan::None
                | FaultPlan::CrashStop
                | FaultPlan::CrashRestartDurable
                | FaultPlan::AmnesiaRestart
                | FaultPlan::SetRole(_)
        )
    }
}

/// Uniformly sample one of the three consensus channels a packet fault can
/// target.
fn sample_channel(rng: &mut impl Rng) -> SniffChannel {
    match rng.random_range(0..3u8) {
        0 => SniffChannel::Vote,
        1 => SniffChannel::Certificate,
        _ => SniffChannel::Resolver,
    }
}

impl Fault {
    /// The fault an [`ActionId`] the policy returned maps to.
    pub(crate) fn from_id(id: ActionId) -> Self {
        CATALOG[id]
    }

    /// This fault's stable [`ActionId`] (its index in [`CATALOG`]).
    pub(crate) fn id(self) -> ActionId {
        CATALOG
            .iter()
            .position(|&a| a == self)
            .expect("fault is in the catalog")
    }

    /// Sample this fault's concrete parameters from the runtime RNG, producing a
    /// [`FaultPlan`] the runner enacts. [`Fault::NoFault`] and
    /// [`Fault::IsolateNodeWindow`] have a fixed shape and draw no `FuzzRng`
    /// bytes; [`Fault::PartitionWindow`] draws one uniform choice among the 2-2
    /// splits; the packet faults draw a target node, a target channel, and a
    /// bounded intensity (a per-packet delay, a drop / corrupt count, a corrupt
    /// offset and mask, a duplicate count, or a reorder-buffer capacity). All
    /// draws come from the runtime RNG so the pump applies a deterministic
    /// transform.
    ///
    /// `exclude_node0` restricts the packet-fault target: node 0 is dropped from the
    /// target set `{1, 2, 3}` (instead of all four) when it has no live pump / sniffer
    /// to match, i.e. when a Byzantine role owns it (RAW channels) or it is
    /// crash-stopped (no engine). Otherwise the target is drawn from all four exactly
    /// as before, so an Honest-episode replay is unperturbed.
    pub(crate) fn sample(self, rng: &mut impl Rng, exclude_node0: bool) -> FaultPlan {
        // The lowest packet-fault target: node 0 is excluded when it has no live
        // pump / sniffer (byzantine-owned or crashed). This does not draw RNG, so the
        // non-packet arms are unaffected.
        let node_lo = usize::from(exclude_node0);
        match self {
            Fault::NoFault => FaultPlan::None,
            Fault::IsolateNodeWindow => FaultPlan::IsolateByzantine,
            Fault::PartitionWindow => {
                let idx = PARTITION_2_2[rng.random_range(0..PARTITION_2_2.len())];
                FaultPlan::Partition(SetPartition::n4(idx))
            }
            Fault::PacketDelay => FaultPlan::PacketDelay {
                node: rng.random_range(node_lo..MALLORY_N),
                channel: sample_channel(rng),
                per_packet: Duration::from_millis(
                    rng.random_range(PACKET_DELAY_MS_MIN..=PACKET_DELAY_MS_MAX),
                ),
            },
            Fault::PacketLoss => FaultPlan::PacketLoss {
                node: rng.random_range(node_lo..MALLORY_N),
                channel: sample_channel(rng),
                drop_count: rng.random_range(PACKET_LOSS_MIN..=PACKET_LOSS_MAX),
            },
            Fault::PacketCorrupt => FaultPlan::PacketCorrupt {
                node: rng.random_range(node_lo..MALLORY_N),
                channel: sample_channel(rng),
                count: rng.random_range(PACKET_CORRUPT_MIN..=PACKET_CORRUPT_MAX),
                offset: rng.random_range(0..PACKET_CORRUPT_OFFSET_MAX),
                mask: rng.random_range(PACKET_CORRUPT_MASK_MIN..=PACKET_CORRUPT_MASK_MAX),
            },
            Fault::PacketDuplicate => FaultPlan::PacketDuplicate {
                node: rng.random_range(node_lo..MALLORY_N),
                channel: sample_channel(rng),
                extra: rng.random_range(PACKET_DUPLICATE_MIN..=PACKET_DUPLICATE_MAX),
            },
            Fault::PacketReorder => FaultPlan::PacketReorder {
                node: rng.random_range(node_lo..MALLORY_N),
                channel: sample_channel(rng),
                buffer: rng.random_range(PACKET_REORDER_MIN..=PACKET_REORDER_MAX),
            },
            // The lifecycle faults have a fixed target (BYZANTINE_IDX) and draw no
            // parameters, so a same-seed replay is unperturbed by their presence.
            Fault::CrashStop => FaultPlan::CrashStop,
            Fault::CrashRestartDurable => FaultPlan::CrashRestartDurable,
            Fault::AmnesiaRestart => FaultPlan::AmnesiaRestart,
            // The role switch draws one target uniformly among the six Byzantine
            // roles (never Honest) from the runtime RNG, so the multiplexer applies a
            // deterministic swap on replay.
            Fault::SetRole => FaultPlan::SetRole(AdversaryRole::sample_byzantine(rng)),
        }
    }
}

/// The per-step legal-fault mask: which catalog faults the policy may select
/// this step. With an Honest faultable identity running, every catalog fault
/// except [`Fault::SetRole`] (which needs a byzantine multiplexer) is legal -- the
/// loop heals every transient topology/packet fault before the next decision, so at
/// most one is ever active without any masking, and all three lifecycle faults
/// target the running managed node 0.
///
/// Once that node is crash-stopped (`node0_crashed`) the crash is PERMANENT for the
/// episode, but the episode CONTINUES over the surviving quorum. The three lifecycle
/// faults are masked (no re-crash of a dead node, and no resurrection, since a
/// crash-stop is permanent within the episode) and so is [`Fault::IsolateNodeWindow`]
/// (cutting off an already-dead node is a no-op). The transient
/// [`Fault::PartitionWindow`] and
/// packet faults stay legal, so Mallory can keep perturbing nodes 1-3 (their targets
/// exclude node 0 at sample time). [`Fault::SetRole`] stays masked (a crashed Honest
/// node 0 has no multiplexer). Because node 0 never returns, `node0_crashed` stays set
/// for every later step.
///
/// When a Byzantine role owns node 0 (`role_active`) OR node 0 has become an
/// amnesiac (`node0_amnesiac`, an empty-storage restart that may equivocate), node 0
/// is now the single Byzantine identity, so ALL THREE lifecycle faults
/// ([`Fault::CrashStop`], [`Fault::CrashRestartDurable`], [`Fault::AmnesiaRestart`])
/// are masked out -- this enforces the one-faultable-identity contract (no lifecycle
/// fault on a second node; no further lifecycle fault on the already-Byzantine
/// identity). Under a role node 0 is UNMANAGED, so there is no
/// [`ManagedValidator`](crate::ManagedValidator) to target at all. The topology
/// faults stay legal and are complementary -- [`Fault::IsolateNodeWindow`]
/// temporarily MUTES the adversary by cutting node 0 off, and
/// [`Fault::PartitionWindow`] still stalls progress. The packet faults stay legal
/// too; under a role their target is restricted to the honest managed nodes at
/// sample time (see [`Fault::sample`]), while post-amnesia node 0 still has a
/// pump/sniffer so it stays a valid packet target.
///
/// [`Fault::SetRole`] is the inverse case: it is legal ONLY when a Byzantine role
/// owns node 0 (`role_active`, so a [`RoleMultiplexer`](crate::mallory::multiplexer::RoleMultiplexer)
/// exists to swap) AND the episode's switch cap is not yet reached
/// (`role_switches_exhausted` is false, i.e. the count is below
/// [`MALLORY_MAX_ROLE_SWITCHES`]). Under the Honest environment there is no
/// multiplexer, so it is masked out; once the cap is hit it is masked out too. The
/// swap only ever composes Byzantine profiles, so node 0 stays Byzantine throughout
/// and the oracle treatment is unchanged.
pub(crate) fn legal_mask(
    node0_crashed: bool,
    role_active: bool,
    node0_amnesiac: bool,
    role_switches_exhausted: bool,
) -> [bool; N_FAULTS] {
    if node0_crashed {
        // Node 0 is permanently down, but the episode keeps perturbing nodes 1-3.
        // Legal: NoFault, PartitionWindow, and the five packet faults (targets exclude
        // node 0). Masked: the three lifecycle faults, IsolateNodeWindow, and SetRole.
        let mut mask = [true; N_FAULTS];
        mask[Fault::CrashStop.id()] = false;
        mask[Fault::CrashRestartDurable.id()] = false;
        mask[Fault::AmnesiaRestart.id()] = false;
        mask[Fault::IsolateNodeWindow.id()] = false;
        mask[Fault::SetRole.id()] = false;
        return mask;
    }
    let mut mask = [true; N_FAULTS];
    if role_active || node0_amnesiac {
        mask[Fault::CrashStop.id()] = false;
        mask[Fault::CrashRestartDurable.id()] = false;
        mask[Fault::AmnesiaRestart.id()] = false;
    }
    // A role switch needs a byzantine multiplexer at node 0 and a remaining switch
    // budget; illegal under Honest (no multiplexer) and once the cap is reached.
    if !role_active || role_switches_exhausted {
        mask[Fault::SetRole.id()] = false;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::FuzzRng;

    #[test]
    fn catalog_ids_round_trip() {
        assert_eq!(N_FAULTS, 12);
        assert_eq!(N_FAULTS, CATALOG.len());
        for (id, &fault) in CATALOG.iter().enumerate() {
            assert_eq!(fault.id(), id, "catalog index must equal the fault id");
            assert_eq!(
                Fault::from_id(id),
                fault,
                "from_id must invert id for every catalog entry"
            );
        }
    }

    #[test]
    fn catalog_order_is_stable() {
        // The stable-order contract: existing ids never move as the catalog
        // grows, so a warm Q-table's columns stay valid.
        assert_eq!(Fault::NoFault.id(), 0);
        assert_eq!(Fault::IsolateNodeWindow.id(), 1);
        assert_eq!(Fault::PartitionWindow.id(), 2);
        assert_eq!(Fault::PacketDelay.id(), 3);
        assert_eq!(Fault::PacketLoss.id(), 4);
        assert_eq!(Fault::PacketCorrupt.id(), 5);
        assert_eq!(Fault::PacketDuplicate.id(), 6);
        assert_eq!(Fault::PacketReorder.id(), 7);
        assert_eq!(Fault::CrashStop.id(), 8);
        assert_eq!(Fault::CrashRestartDurable.id(), 9);
        assert_eq!(Fault::AmnesiaRestart.id(), 10);
        assert_eq!(Fault::SetRole.id(), 11);
        assert_eq!(Fault::from_id(0), Fault::NoFault);
        assert_eq!(Fault::from_id(1), Fault::IsolateNodeWindow);
        assert_eq!(Fault::from_id(2), Fault::PartitionWindow);
        assert_eq!(Fault::from_id(3), Fault::PacketDelay);
        assert_eq!(Fault::from_id(4), Fault::PacketLoss);
        assert_eq!(Fault::from_id(5), Fault::PacketCorrupt);
        assert_eq!(Fault::from_id(6), Fault::PacketDuplicate);
        assert_eq!(Fault::from_id(7), Fault::PacketReorder);
        assert_eq!(Fault::from_id(8), Fault::CrashStop);
        assert_eq!(Fault::from_id(9), Fault::CrashRestartDurable);
        assert_eq!(Fault::from_id(10), Fault::AmnesiaRestart);
        assert_eq!(Fault::from_id(11), Fault::SetRole);
    }

    #[test]
    fn legal_mask_running_is_all_true_but_set_role_and_sized() {
        // Under the Honest running environment every fault except SetRole is legal:
        // SetRole needs a byzantine multiplexer at node 0, which the Honest
        // environment never builds.
        let mask = legal_mask(false, false, false, false);
        assert_eq!(mask.len(), N_FAULTS);
        assert_eq!(mask.len(), 12);
        assert!(
            !mask[Fault::SetRole.id()],
            "SetRole is illegal under the Honest environment"
        );
        for &fault in CATALOG.iter().filter(|&&a| a != Fault::SetRole) {
            assert!(
                mask[fault.id()],
                "{fault:?} is legal while the faultable node is running"
            );
        }
    }

    #[test]
    fn legal_mask_crashed_keeps_survivor_faults_and_masks_lifecycle() {
        // A crash-stop is permanent but the episode continues over the surviving
        // quorum. NoFault, PartitionWindow, and the five packet faults stay legal;
        // the three lifecycle faults, IsolateNodeWindow (a no-op on a dead node), and
        // SetRole are masked.
        let mask = legal_mask(true, false, false, false);
        assert_eq!(mask.len(), N_FAULTS);
        let masked = [
            Fault::CrashStop,
            Fault::CrashRestartDurable,
            Fault::AmnesiaRestart,
            Fault::IsolateNodeWindow,
            Fault::SetRole,
        ];
        for &fault in CATALOG.iter() {
            let want = !masked.contains(&fault);
            assert_eq!(
                mask[fault.id()],
                want,
                "{fault:?} legality once node 0 is crashed"
            );
        }
    }

    /// The three lifecycle faults are masked out whenever node 0 is the Byzantine
    /// identity -- under a byzantine role or once it is amnesiac -- while the
    /// topology and packet faults stay legal. Shared by the role and amnesia cases,
    /// which impose the same one-faultable-identity masking.
    fn assert_lifecycle_masked_topology_and_packet_legal(mask: [bool; N_FAULTS]) {
        assert_eq!(mask.len(), N_FAULTS);
        assert!(!mask[Fault::CrashStop.id()], "CrashStop masked");
        assert!(
            !mask[Fault::CrashRestartDurable.id()],
            "CrashRestartDurable masked"
        );
        assert!(!mask[Fault::AmnesiaRestart.id()], "AmnesiaRestart masked");
        for fault in [
            Fault::NoFault,
            Fault::IsolateNodeWindow,
            Fault::PartitionWindow,
            Fault::PacketDelay,
            Fault::PacketLoss,
            Fault::PacketCorrupt,
            Fault::PacketDuplicate,
            Fault::PacketReorder,
        ] {
            assert!(mask[fault.id()], "{fault:?} stays legal");
        }
    }

    #[test]
    fn legal_mask_role_active_masks_lifecycle_keeps_topology_and_packet() {
        // A byzantine role owns node 0 as an unmanaged adversary: the lifecycle
        // faults have no ManagedValidator to target and are masked, but the
        // topology and packet faults stay legal (isolation mutes the adversary; a
        // partition still stalls; packet faults retarget the honest nodes).
        assert_lifecycle_masked_topology_and_packet_legal(legal_mask(false, true, false, false));
    }

    #[test]
    fn legal_mask_amnesiac_masks_lifecycle_keeps_topology_and_packet() {
        // After an amnesia restart node 0 is Running but Byzantine (empty storage,
        // may equivocate): the one-faultable-identity contract masks every lifecycle
        // fault (including a second amnesia restart), while the topology and packet
        // faults stay legal -- node 0 keeps its pump, so it is still a packet target.
        assert_lifecycle_masked_topology_and_packet_legal(legal_mask(false, false, true, false));
    }

    #[test]
    fn legal_mask_amnesia_only_under_honest_running() {
        // AmnesiaRestart is legal ONLY when node 0 is an Honest, running managed
        // node: masked once it is crashed, under a byzantine role, or once amnesiac.
        assert!(
            legal_mask(false, false, false, false)[Fault::AmnesiaRestart.id()],
            "AmnesiaRestart legal under Honest + Running"
        );
        assert!(!legal_mask(true, false, false, false)[Fault::AmnesiaRestart.id()]);
        assert!(!legal_mask(false, true, false, false)[Fault::AmnesiaRestart.id()]);
        assert!(!legal_mask(false, false, true, false)[Fault::AmnesiaRestart.id()]);
    }

    #[test]
    fn legal_mask_set_role_only_under_byzantine_role_below_cap() {
        // SetRole is legal ONLY when a byzantine role owns node 0 and the switch cap
        // is not yet reached: masked under Honest (no multiplexer), under a crashed
        // node, under an amnesiac node (role_active is false there), and once the cap
        // is hit even while a role is active.
        assert!(
            legal_mask(false, true, false, false)[Fault::SetRole.id()],
            "SetRole legal under a byzantine role below the switch cap"
        );
        assert!(
            !legal_mask(false, true, false, true)[Fault::SetRole.id()],
            "SetRole masked once the switch cap is reached"
        );
        assert!(
            !legal_mask(false, false, false, false)[Fault::SetRole.id()],
            "SetRole masked under the Honest environment"
        );
        assert!(
            !legal_mask(true, false, false, false)[Fault::SetRole.id()],
            "SetRole masked once node 0 is crashed"
        );
        assert!(
            !legal_mask(false, false, true, false)[Fault::SetRole.id()],
            "SetRole masked while node 0 is amnesiac (not role-owned)"
        );
    }

    #[test]
    fn packet_target_never_node0_under_role() {
        // Under a byzantine role node 0 has no pump/sniffer, so every packet fault
        // must target an honest managed node in {1, 2, 3}.
        let mut rng = FuzzRng::new(vec![0x24, 0x8b, 0xf1, 0x0e, 0x77, 0x35, 0xac, 0x51]);
        for _ in 0..256 {
            for fault in [
                Fault::PacketDelay,
                Fault::PacketLoss,
                Fault::PacketCorrupt,
                Fault::PacketDuplicate,
                Fault::PacketReorder,
            ] {
                let node = match fault.sample(&mut rng, true) {
                    FaultPlan::PacketDelay { node, .. }
                    | FaultPlan::PacketLoss { node, .. }
                    | FaultPlan::PacketCorrupt { node, .. }
                    | FaultPlan::PacketDuplicate { node, .. }
                    | FaultPlan::PacketReorder { node, .. } => node,
                    other => panic!("{fault:?} must sample a packet plan, got {other:?}"),
                };
                assert!(
                    (1..MALLORY_N).contains(&node),
                    "{fault:?} must target an honest node under a role, got node {node}"
                );
            }
        }
    }

    #[test]
    fn lifecycle_actions_draw_no_rng_and_fix_the_target() {
        // CrashStop / CrashRestartDurable / AmnesiaRestart target BYZANTINE_IDX with
        // no sampled parameters, so they must not advance the RNG (a same-seed replay
        // is unperturbed by their presence in the catalog).
        for fault in [
            Fault::CrashStop,
            Fault::CrashRestartDurable,
            Fault::AmnesiaRestart,
        ] {
            let seed = vec![0xa5, 0x5a, 0xc3, 0x3c, 0x0f, 0xf0, 0x99, 0x66];
            let mut consumed = FuzzRng::new(seed.clone());
            let mut untouched = FuzzRng::new(seed);
            let plan = fault.sample(&mut consumed, false);
            assert!(
                matches!(
                    plan,
                    FaultPlan::CrashStop
                        | FaultPlan::CrashRestartDurable
                        | FaultPlan::AmnesiaRestart
                ),
                "a lifecycle fault samples a lifecycle plan, got {plan:?}"
            );
            assert!(
                !plan.is_active(),
                "a lifecycle fault is not a network/packet fault"
            );
            assert_eq!(
                consumed.random_range(0u64..u64::MAX),
                untouched.random_range(0u64..u64::MAX),
                "{fault:?} must not consume any FuzzRng bytes"
            );
        }
    }

    #[test]
    fn set_role_samples_a_byzantine_target() {
        // SetRole samples a FaultPlan::SetRole whose target is always a Byzantine
        // role (never Honest); it is not a heal-able transient fault; and over many
        // draws it reaches every one of the six Byzantine profiles.
        let mut rng = FuzzRng::new(vec![0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15]);
        let mut seen_disrupter = false;
        let mut seen_other = false;
        for _ in 0..256 {
            let FaultPlan::SetRole(role) = Fault::SetRole.sample(&mut rng, true) else {
                panic!("SetRole must sample a SetRole plan");
            };
            assert!(
                role.is_byzantine(),
                "SetRole target must be byzantine, got {role:?}"
            );
            assert!(
                !FaultPlan::SetRole(role).is_active(),
                "SetRole persists, not a transient"
            );
            seen_disrupter |= role == AdversaryRole::Disrupter;
            seen_other |= role != AdversaryRole::Disrupter;
        }
        assert!(
            seen_disrupter && seen_other,
            "SetRole must reach multiple byzantine roles"
        );
    }

    #[test]
    fn no_fault_samples_none_and_draws_no_rng() {
        let seed = vec![0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15];
        let mut consumed = FuzzRng::new(seed.clone());
        let mut untouched = FuzzRng::new(seed);
        let plan = Fault::NoFault.sample(&mut consumed, false);
        assert!(matches!(plan, FaultPlan::None));
        assert!(!plan.is_active());
        // NoFault must not advance the RNG, so a subsequent draw matches an
        // untouched stream at the same offset.
        assert_eq!(
            consumed.random_range(0u64..u64::MAX),
            untouched.random_range(0u64..u64::MAX),
            "NoFault must not consume any FuzzRng bytes"
        );
    }

    #[test]
    fn isolate_always_isolates_byzantine_and_draws_no_rng() {
        let seed = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut consumed = FuzzRng::new(seed.clone());
        let mut untouched = FuzzRng::new(seed);
        for _ in 0..32 {
            let plan = Fault::IsolateNodeWindow.sample(&mut consumed, false);
            assert!(matches!(plan, FaultPlan::IsolateByzantine));
            assert!(plan.is_active());
        }
        // A fixed-target isolate draws no parameters.
        assert_eq!(
            consumed.random_range(0u64..u64::MAX),
            untouched.random_range(0u64..u64::MAX),
            "IsolateNodeWindow must not consume any FuzzRng bytes"
        );
    }

    #[test]
    fn partition_window_only_yields_2_2_splits() {
        let mut rng = FuzzRng::new(vec![0x5a, 0xa5, 0x0f, 0xf0, 0x33, 0xcc, 0x11, 0xee]);
        let allowed: Vec<SetPartition> =
            PARTITION_2_2.iter().map(|&i| SetPartition::n4(i)).collect();
        for _ in 0..256 {
            let FaultPlan::Partition(sp) = Fault::PartitionWindow.sample(&mut rng, false) else {
                panic!("PartitionWindow must sample a Partition plan");
            };
            assert!(
                allowed.contains(&sp),
                "PartitionWindow must only yield a balanced 2-2 split, got {sp:?}"
            );
            // A 2-2 split has exactly two blocks: node 0 is connected to exactly
            // one other node, never isolated.
            let peers = (1..4).filter(|&j| sp.connected(0, j)).count();
            assert_eq!(peers, 1, "a 2-2 split pairs node 0 with exactly one node");
        }
    }

    #[test]
    fn packet_actions_sample_valid_targets_and_bounded_params() {
        let mut rng = FuzzRng::new(vec![0x13, 0x37, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x99]);
        let is_channel = |c: SniffChannel| {
            matches!(
                c,
                SniffChannel::Vote | SniffChannel::Certificate | SniffChannel::Resolver
            )
        };
        for _ in 0..256 {
            let delay = Fault::PacketDelay.sample(&mut rng, false);
            assert!(delay.is_active(), "PacketDelay installs a transient fault");
            let FaultPlan::PacketDelay {
                node,
                channel,
                per_packet,
            } = delay
            else {
                panic!("PacketDelay must sample a PacketDelay plan, got {delay:?}");
            };
            assert!(node < MALLORY_N, "delay must target a valid receiving node");
            assert!(is_channel(channel));
            let ms = per_packet.as_millis() as u64;
            assert!(
                (PACKET_DELAY_MS_MIN..=PACKET_DELAY_MS_MAX).contains(&ms),
                "per-packet delay {ms}ms out of bounds"
            );

            let loss = Fault::PacketLoss.sample(&mut rng, false);
            assert!(loss.is_active(), "PacketLoss installs a transient fault");
            let FaultPlan::PacketLoss {
                node,
                channel,
                drop_count,
            } = loss
            else {
                panic!("PacketLoss must sample a PacketLoss plan, got {loss:?}");
            };
            assert!(node < MALLORY_N, "loss must target a valid receiving node");
            assert!(is_channel(channel));
            assert!(
                (PACKET_LOSS_MIN..=PACKET_LOSS_MAX).contains(&drop_count),
                "drop count {drop_count} out of bounds"
            );

            let corrupt = Fault::PacketCorrupt.sample(&mut rng, false);
            assert!(
                corrupt.is_active(),
                "PacketCorrupt installs a transient fault"
            );
            let FaultPlan::PacketCorrupt {
                node,
                channel,
                count,
                offset,
                mask,
            } = corrupt
            else {
                panic!("PacketCorrupt must sample a PacketCorrupt plan, got {corrupt:?}");
            };
            assert!(
                node < MALLORY_N,
                "corrupt must target a valid receiving node"
            );
            assert!(is_channel(channel));
            assert!(
                (PACKET_CORRUPT_MIN..=PACKET_CORRUPT_MAX).contains(&count),
                "corrupt count {count} out of bounds"
            );
            assert!(
                offset < PACKET_CORRUPT_OFFSET_MAX,
                "corrupt offset out of bounds"
            );
            assert!(
                mask != 0,
                "corrupt mask must be nonzero so a byte always changes"
            );

            let duplicate = Fault::PacketDuplicate.sample(&mut rng, false);
            assert!(
                duplicate.is_active(),
                "PacketDuplicate installs a transient fault"
            );
            let FaultPlan::PacketDuplicate {
                node,
                channel,
                extra,
            } = duplicate
            else {
                panic!("PacketDuplicate must sample a PacketDuplicate plan, got {duplicate:?}");
            };
            assert!(
                node < MALLORY_N,
                "duplicate must target a valid receiving node"
            );
            assert!(is_channel(channel));
            assert!(
                (PACKET_DUPLICATE_MIN..=PACKET_DUPLICATE_MAX).contains(&extra),
                "duplicate extra {extra} out of bounds"
            );

            let reorder = Fault::PacketReorder.sample(&mut rng, false);
            assert!(
                reorder.is_active(),
                "PacketReorder installs a transient fault"
            );
            let FaultPlan::PacketReorder {
                node,
                channel,
                buffer,
            } = reorder
            else {
                panic!("PacketReorder must sample a PacketReorder plan, got {reorder:?}");
            };
            assert!(
                node < MALLORY_N,
                "reorder must target a valid receiving node"
            );
            assert!(is_channel(channel));
            assert!(
                (PACKET_REORDER_MIN..=PACKET_REORDER_MAX).contains(&buffer),
                "reorder buffer {buffer} out of bounds"
            );
        }
    }
}
