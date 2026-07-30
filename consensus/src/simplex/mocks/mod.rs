//! Collection of mocks used to test `simplex`.

pub mod application;
pub mod conflicter;
pub mod equivocator;
pub mod impersonator;
#[cfg(not(target_arch = "wasm32"))]
pub mod network;
pub mod nuller;
pub mod nullify_only;
pub mod outdated;
pub mod reconfigurer;
pub mod relay;
pub mod reporter;
pub mod scheme;
pub mod twins;
pub mod wrapped;
