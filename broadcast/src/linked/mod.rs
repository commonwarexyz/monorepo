pub mod signer;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
