//! Shared input grammars for Commonware procedural macros and source tools.
//!
//! This is an internal crate. Use [`commonware-macros`](https://docs.rs/commonware-macros)
//! instead.

#![doc(hidden)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

#[cfg(not(commonware_stability_RESERVED))]
mod select;
#[cfg(not(commonware_stability_RESERVED))]
mod stability;

#[cfg(not(commonware_stability_RESERVED))]
pub use select::{
    SelectBranch, SelectInput, SelectLoopBranch, SelectLoopElse, SelectLoopInput,
    SelectLoopLifecycle,
};
#[cfg(not(commonware_stability_RESERVED))]
pub use stability::{
    StabilityCfg, StabilityLevel, StabilityLevelSyntax, StabilityModInput, StabilityScopeInput,
};
