mod contributor;
pub use contributor::Contributor;
mod orchestrator;
pub use orchestrator::Orchestrator;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
