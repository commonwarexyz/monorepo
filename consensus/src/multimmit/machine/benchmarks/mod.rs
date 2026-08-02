//! Fixed benchmark scenarios over the private Multimmit core and durable stores.

mod fabric;
mod journal;
mod machine;

pub use fabric::{
    CompletionProfile, MACHINE_SCALE_BLOCKS_PER_CHAIN, MACHINE_SCALE_COMPLETION_PROFILE,
    MACHINE_SCALE_PARTICIPANTS, MACHINE_SCALE_VIEWS, MachineScaleReport, machine_scale_report,
};
pub use journal::{JournalScenario, run_journal};
pub use machine::{MachineScenario, run_machine};
