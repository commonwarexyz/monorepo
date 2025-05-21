//! TODO: Aggregation module

pub mod wire;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod ingress;
        pub use ingress::Mailbox;
        mod metrics;
        mod tip;
        pub mod types;
    }
}
