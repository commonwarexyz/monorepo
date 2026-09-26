//! Fixed benchmark scenarios over the private Multimmit core and durable stores.

mod engine;
pub(crate) mod fabric;
mod machine;

pub use engine::{
    ENGINE_BLOCKS_PER_CHAIN, ENGINE_NODES, ENGINE_VIEW_ADVANCE, EngineReport, EngineRun,
    engine_parameters, run_engine_profile,
};
pub use fabric::{
    CompletionProfile, MACHINE_SCALE_BLOCKS_PER_CHAIN, MACHINE_SCALE_COMPLETION_PROFILE,
    MACHINE_SCALE_PARTICIPANTS, MACHINE_SCALE_VIEWS, MachineScaleReport, machine_scale_report,
};
pub use machine::{HotPathOperations, IdleOperations, MachineScenario, run_machine};
