//! The report interface of `SPEC.md`, section 5.4: how many records the check
//! of each invariant judged in a run, the aggregate of those reports over a
//! sequence of runs, and what a fuzz process writes of both.
//!
//! The counts themselves are made by the checks in `invariants`, in the units
//! section 8.1 names. A count of zero is never a pass: its invariant is
//! unmeasured and gives the one reason section 8.1 fixes for it.

use std::{
    fmt,
    io::{self, Write as _},
};

/// An invariant of `SPEC.md`, section 8, that a run checks and reports.
///
/// I7 is withdrawn, I10 compares two runs, and I11 constrains the working
/// tree, so no run reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Invariant {
    /// Output agreement.
    I1,
    /// Share validity.
    I2,
    /// Reconstruction.
    I3,
    /// Reshare continuity.
    I4,
    /// Cross-epoch isolation.
    I5,
    /// Failed ceremony.
    I6,
    /// No panic, except in a compromised half.
    I8,
    /// Correct nodes do not block each other.
    I9,
    /// Probe floor provenance.
    I12,
    /// Probe artifact consistency.
    I13,
    /// Probe response isolation.
    I14,
    /// Single, durable state sync.
    I15,
    /// Joiner floor provenance.
    I16,
    /// Agreement after sync.
    I17,
    /// Payload placement.
    I18,
}

impl Invariant {
    /// Every invariant a run can report, in ascending order.
    pub const ALL: [Self; 15] = [
        Self::I1,
        Self::I2,
        Self::I3,
        Self::I4,
        Self::I5,
        Self::I6,
        Self::I8,
        Self::I9,
        Self::I12,
        Self::I13,
        Self::I14,
        Self::I15,
        Self::I16,
        Self::I17,
        Self::I18,
    ];

    /// The `k` of `I<k>`.
    pub const fn number(self) -> u8 {
        match self {
            Self::I1 => 1,
            Self::I2 => 2,
            Self::I3 => 3,
            Self::I4 => 4,
            Self::I5 => 5,
            Self::I6 => 6,
            Self::I8 => 8,
            Self::I9 => 9,
            Self::I12 => 12,
            Self::I13 => 13,
            Self::I14 => 14,
            Self::I15 => 15,
            Self::I16 => 16,
            Self::I17 => 17,
            Self::I18 => 18,
        }
    }

    /// The reason the invariant gives when its count is zero: the record its
    /// check lacked. How the run ended is never one.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::I1 => "no result was compared",
            Self::I2 => "no share or registration was recorded",
            Self::I3 => "too few shares of one output",
            Self::I4 => "no ceremony completed",
            Self::I5 => "no mixed set of shares",
            Self::I6 => "no failed ceremony was reported",
            Self::I8 | Self::I9 => "nothing ran",
            Self::I12 | Self::I13 => "no artifact was emitted",
            Self::I14 => "no delivery was judged",
            Self::I15 => "no start followed a floor",
            Self::I16 => "no floor was entered",
            Self::I17 => "no sync completed",
            Self::I18 => "no block was delivered",
        }
    }

    /// The invariant's position in [`Self::ALL`].
    const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Invariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I{}", self.number())
    }
}

/// A fuzz target of `SPEC.md`, section 5.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// `dkg_bootstrap`.
    Bootstrap,
    /// `dkg_bootstrap_restarts`.
    BootstrapRestarts,
    /// `dkg_reshare`.
    Reshare,
    /// `dkg_reshare_restarts`.
    ReshareRestarts,
    /// `dkg_probe`.
    Probe,
    /// `dkg_state_sync`.
    StateSync,
}

/// The invariants a bootstrap run reports.
const BOOTSTRAP: &[Invariant] = &[
    Invariant::I1,
    Invariant::I2,
    Invariant::I3,
    Invariant::I6,
    Invariant::I8,
    Invariant::I9,
];

/// The invariants a reshare run reports.
const RESHARE: &[Invariant] = &[
    Invariant::I1,
    Invariant::I2,
    Invariant::I3,
    Invariant::I4,
    Invariant::I5,
    Invariant::I6,
    Invariant::I8,
    Invariant::I9,
    Invariant::I18,
];

/// The invariants a probe run reports.
const PROBE: &[Invariant] = &[
    Invariant::I8,
    Invariant::I12,
    Invariant::I13,
    Invariant::I14,
];

/// The invariants a state-sync run reports.
const STATE_SYNC: &[Invariant] = &[
    Invariant::I1,
    Invariant::I2,
    Invariant::I3,
    Invariant::I4,
    Invariant::I5,
    Invariant::I6,
    Invariant::I8,
    Invariant::I9,
    Invariant::I15,
    Invariant::I16,
    Invariant::I17,
    Invariant::I18,
];

impl Target {
    /// Every target.
    pub const ALL: [Self; 6] = [
        Self::Bootstrap,
        Self::BootstrapRestarts,
        Self::Reshare,
        Self::ReshareRestarts,
        Self::Probe,
        Self::StateSync,
    ];

    /// The name of the target's fuzz binary.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bootstrap => "dkg_bootstrap",
            Self::BootstrapRestarts => "dkg_bootstrap_restarts",
            Self::Reshare => "dkg_reshare",
            Self::ReshareRestarts => "dkg_reshare_restarts",
            Self::Probe => "dkg_probe",
            Self::StateSync => "dkg_state_sync",
        }
    }

    /// The invariants every run of the target reports, in ascending order:
    /// the target's row in the table of section 8.1.
    pub const fn invariants(self) -> &'static [Invariant] {
        match self {
            Self::Bootstrap | Self::BootstrapRestarts => BOOTSTRAP,
            Self::Reshare | Self::ReshareRestarts => RESHARE,
            Self::Probe => PROBE,
            Self::StateSync => STATE_SYNC,
        }
    }

    /// Whether every run of the target reports `invariant`.
    fn reports(self, invariant: Invariant) -> bool {
        self.invariants().contains(&invariant)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a run reports of one invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The invariant.
    pub invariant: Invariant,
    /// How many records the invariant's check judged, in the unit section 8.1
    /// names for it.
    pub count: usize,
    /// Why the invariant is unmeasured. Present exactly when the count is
    /// zero.
    pub reason: Option<&'static str>,
}

impl Entry {
    /// The entry of `invariant` with `count`.
    const fn new(invariant: Invariant, count: usize) -> Self {
        Self {
            invariant,
            count,
            reason: if count == 0 {
                Some(invariant.reason())
            } else {
                None
            },
        }
    }

    /// Whether the run measured the invariant: its count is above zero.
    pub const fn measured(&self) -> bool {
        self.count > 0
    }
}

/// How many records the check of each invariant judged in one run of a
/// target: one entry for each invariant of the target's row in section 8.1,
/// and none for any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judged {
    target: Target,
    /// The count of each invariant, by its position in [`Invariant::ALL`].
    /// An invariant the target does not report stays at zero.
    counts: [usize; Invariant::ALL.len()],
}

impl Judged {
    /// What a run of `target` that judged nothing reports: every invariant
    /// of the target unmeasured.
    pub const fn new(target: Target) -> Self {
        Self {
            target,
            counts: [0; Invariant::ALL.len()],
        }
    }

    /// This report with the count of `invariant` set to `count`.
    ///
    /// Panics if the target does not report `invariant`.
    #[must_use]
    pub fn with(mut self, invariant: Invariant, count: usize) -> Self {
        assert!(
            self.target.reports(invariant),
            "harness defect: {} does not report {invariant}",
            self.target,
        );
        self.counts[invariant.index()] = count;
        self
    }

    /// The target the run was of.
    pub const fn target(&self) -> Target {
        self.target
    }

    /// The entry of every invariant the target reports, in ascending order.
    pub fn entries(&self) -> Vec<Entry> {
        self.target
            .invariants()
            .iter()
            .map(|invariant| Entry::new(*invariant, self.counts[invariant.index()]))
            .collect()
    }

    /// The entry of `invariant`, if the target reports it.
    pub fn entry(&self, invariant: Invariant) -> Option<Entry> {
        self.target
            .reports(invariant)
            .then(|| Entry::new(invariant, self.counts[invariant.index()]))
    }

    /// The count of `invariant`, if the target reports it.
    pub fn count(&self, invariant: Invariant) -> Option<usize> {
        self.entry(invariant).map(|entry| entry.count)
    }

    /// Why `invariant` is unmeasured, if the target reports it with a count
    /// of zero.
    pub fn reason(&self, invariant: Invariant) -> Option<&'static str> {
        self.entry(invariant).and_then(|entry| entry.reason)
    }
}

impl fmt::Display for Judged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, entry) in self.entries().iter().enumerate() {
            if position > 0 {
                f.write_str(" ")?;
            }
            match entry.reason {
                None => write!(f, "{}={}", entry.invariant, entry.count)?,
                Some(reason) => write!(f, "{}=unmeasured({reason})", entry.invariant)?,
            }
        }
        Ok(())
    }
}

/// What one run of a driver observed. Its `Display` is the full report of
/// the run.
pub trait Report: fmt::Display {
    /// How many records the check of each invariant judged.
    fn judged(&self) -> Judged;
}

impl Report for Judged {
    fn judged(&self) -> Judged {
        *self
    }
}

/// What an aggregate holds of one invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tally {
    /// The invariant.
    pub invariant: Invariant,
    /// Runs whose count for the invariant was above zero.
    pub measured: usize,
    /// Runs whose count for the invariant was zero.
    pub unmeasured: usize,
}

/// The reports of a sequence of runs of one target, folded: the number of
/// runs and, for each invariant the target reports, how many of them measured
/// it and how many did not.
///
/// Its `Display` is the aggregate line a fuzz process writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aggregate {
    target: Target,
    runs: usize,
    /// Runs that measured each invariant, by its position in
    /// [`Invariant::ALL`].
    measured: [usize; Invariant::ALL.len()],
}

impl Aggregate {
    /// The aggregate of no run of `target`.
    pub const fn new(target: Target) -> Self {
        Self {
            target,
            runs: 0,
            measured: [0; Invariant::ALL.len()],
        }
    }

    /// Fold the report of one more run into the aggregate.
    ///
    /// Panics if the run was of another target.
    pub fn add(&mut self, judged: &Judged) {
        assert!(
            judged.target() == self.target,
            "harness defect: a report of {} was folded into the aggregate of {}",
            judged.target(),
            self.target,
        );
        self.runs += 1;
        for entry in judged.entries() {
            self.measured[entry.invariant.index()] += usize::from(entry.measured());
        }
    }

    /// The target the runs were of.
    pub const fn target(&self) -> Target {
        self.target
    }

    /// The number of runs folded.
    pub const fn runs(&self) -> usize {
        self.runs
    }

    /// What the aggregate holds of every invariant the target reports, in
    /// ascending order.
    pub fn tallies(&self) -> Vec<Tally> {
        self.target
            .invariants()
            .iter()
            .map(|invariant| {
                let measured = self.measured[invariant.index()];
                Tally {
                    invariant: *invariant,
                    measured,
                    unmeasured: self.runs - measured,
                }
            })
            .collect()
    }

    /// What the aggregate holds of `invariant`, if the target reports it.
    pub fn tally(&self, invariant: Invariant) -> Option<Tally> {
        self.tallies()
            .into_iter()
            .find(|tally| tally.invariant == invariant)
    }
}

impl fmt::Display for Aggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] aggregate runs={}", self.target, self.runs)?;
        for tally in self.tallies() {
            write!(
                f,
                " {}={}/{}",
                tally.invariant, tally.measured, tally.unmeasured
            )?;
        }
        Ok(())
    }
}

/// Fold the reports of a sequence of runs of `target` into their aggregate.
pub fn fold<'a, R: Report + 'a>(
    target: Target,
    reports: impl IntoIterator<Item = &'a R>,
) -> Aggregate {
    let mut aggregate = Aggregate::new(target);
    for report in reports {
        aggregate.add(&report.judged());
    }
    aggregate
}

/// Completed runs between two aggregate lines of a fuzz process.
pub const AGGREGATE_INTERVAL: usize = 250;

/// Where a fuzz process writes its aggregate lines.
pub trait Sink {
    /// Write one aggregate line.
    fn aggregate(&mut self, line: &str);
}

/// Standard error, where every fuzz process writes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stderr;

impl Sink for Stderr {
    fn aggregate(&mut self, line: &str) {
        // A process whose standard error is closed still fuzzes.
        let _ = writeln!(io::stderr(), "{line}");
    }
}

/// A sink that keeps every line it is given, in order.
impl Sink for Vec<String> {
    fn aggregate(&mut self, line: &str) {
        self.push(line.to_string());
    }
}

/// What a fuzz process writes of the runs it completes: the aggregate over
/// them, every [`AGGREGATE_INTERVAL`] runs and once more at its end.
///
/// The emitter reads a report and never changes one, and the interval is
/// counted in completed runs, so writing changes nothing a run does or
/// measures. The full report of a run is not written here: the report helper
/// the drivers share with the stateful harness writes it when reports are
/// asked for.
#[derive(Clone, Debug)]
pub struct Emitter<S> {
    aggregate: Aggregate,
    sink: S,
}

impl<S: Sink> Emitter<S> {
    /// An emitter for a process that runs `target` and writes to `sink`.
    pub const fn new(target: Target, sink: S) -> Self {
        Self {
            aggregate: Aggregate::new(target),
            sink,
        }
    }

    /// Take the report of a run the process completed.
    pub fn completed<R: Report>(&mut self, report: &R) {
        self.aggregate.add(&report.judged());
        if self.aggregate.runs().is_multiple_of(AGGREGATE_INTERVAL) {
            self.write();
        }
    }

    /// Write the aggregate over every run the process completed, as the
    /// process ends.
    pub fn finish(&mut self) {
        self.write();
    }

    /// The fold of the reports taken so far.
    pub const fn aggregate(&self) -> &Aggregate {
        &self.aggregate
    }

    /// Where the emitter writes.
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    fn write(&mut self) {
        self.sink.aggregate(&self.aggregate.to_string());
    }
}
