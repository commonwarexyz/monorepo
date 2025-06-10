//! Aggregation module

pub mod types;
pub mod wire;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod safe_tip;

        #[cfg(test)]
        pub mod mocks;
    }
}
