mod contributor;
mod orchestrator;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
